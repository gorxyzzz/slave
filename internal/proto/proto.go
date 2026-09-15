// Package proto contains the zheng wire protocol helpers shared by the
// master and slave binaries. The format is newline-delimited JSON for
// control messages and raw bytes for shell traffic; a resize frame is
// sent in-band as "\x00R{...}\n" while a shell is active.
package proto

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// ResizeMark is the first byte of an in-band terminal resize frame.
const ResizeMark = 0x00

// ResizeTag identifies a resize frame right after ResizeMark.
const ResizeTag = 'R'

// Recon is the identification payload a slave sends right after connecting.
type Recon struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Kernel   string `json:"kernel"`
	IP       string `json:"ip"`
	PublicIP string `json:"public_ip"`
}

// AuthMessage is the HMAC challenge/response envelope.
type AuthMessage struct {
	Challenge string `json:"challenge,omitempty"`
	HMAC      string `json:"hmac,omitempty"`
	Status    string `json:"status,omitempty"`
}

// readLine reads bytes up to (not including) '\n'. It reads directly from
// the conn without buffering: during shell sessions the same conn carries
// raw bytes, so any read-ahead would swallow shell input/output.
func readLine(conn net.Conn) (string, error) {
	var buf []byte
	tmp := make([]byte, 1)
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			return "", err
		}
		for _, b := range tmp[:n] {
			if b == '\n' {
				return string(buf), nil
			}
			buf = append(buf, b)
		}
	}
}

// ReadJSON reads one newline-delimited JSON message.
func ReadJSON(conn net.Conn, v interface{}) error {
	line, err := readLine(conn)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(line), v)
}

// ReadJSONDeadline is ReadJSON with a read deadline applied around the call.
func ReadJSONDeadline(conn net.Conn, v interface{}, d time.Duration) error {
	if d > 0 {
		conn.SetReadDeadline(time.Now().Add(d))
		defer conn.SetReadDeadline(time.Time{})
	}
	return ReadJSON(conn, v)
}

// WriteJSON writes one newline-delimited JSON message.
func WriteJSON(conn net.Conn, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = conn.Write(data)
	return err
}

// ReadResizeFrame consumes a "\x00R{rows,cols}\n" frame and returns the size.
// Call it only when the previous byte was ResizeMark and the next is ResizeTag.
func ReadResizeFrame(br *bufio.Reader) (rows, cols int, err error) {
	if _, err = br.ReadByte(); err != nil { // consume the tag byte 'R'
		return 0, 0, err
	}
	line, err := br.ReadBytes('\n')
	if err != nil {
		return 0, 0, err
	}
	var rs struct {
		Rows int `json:"rows"`
		Cols int `json:"cols"`
	}
	if err := json.Unmarshal(line, &rs); err != nil || rs.Rows <= 0 || rs.Cols <= 0 {
		return 0, 0, fmt.Errorf("invalid resize frame: %q", line)
	}
	return rs.Rows, rs.Cols, nil
}

// FormatResizeFrame builds the wire form of a resize frame.
func FormatResizeFrame(rows, cols int) []byte {
	return []byte(fmt.Sprintf("\x00R{\"rows\":%d,\"cols\":%d}\n", rows, cols))
}

// SanitizeToken trims whitespace from a token string.
func SanitizeToken(token string) string {
	return strings.TrimSpace(token)
}

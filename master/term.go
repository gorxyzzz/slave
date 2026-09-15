package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"zheng/internal/proto"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const shellHandshakeTimeout = 5 * time.Second

// handleShell runs the interactive raw-mode shell relay between the local
// terminal and the slave's pty. It returns when the slave closes the
// connection (shell exited or slave died), which is signalled via EOF on
// the stdout copy.
func handleShell(c *client) error {
	if err := c.sendCmd("shell"); err != nil {
		return fmt.Errorf("send command: %v", err)
	}
	c.setShell(true)
	defer c.setShell(false)

	// Wait for the slave's shell_ready (JSON) handshake.
	var ready struct {
		Status string `json:"status"`
	}
	if err := proto.ReadJSONDeadline(c.conn, &ready, shellHandshakeTimeout); err != nil || ready.Status != "shell_ready" {
		return fmt.Errorf("no shell_ready from slave: %v", err)
	}

	// Local terminal into raw mode for the duration of the session.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("set raw terminal mode: %v", err)
	}
	defer func() {
		term.Restore(int(os.Stdin.Fd()), oldState)
		fmt.Println("\r\n--- Exited Shell ---")
	}()

	// Initial size + forward resizes on SIGWINCH.
	sendWinchSize(c)
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	go func() {
		for range winch {
			sendWinchSize(c)
		}
	}()

	done := make(chan struct{})

	// stdout relay: conn -> os.Stdout. Terminates when the slave closes the
	// conn (shell exited) or the slave dies.
	go func() {
		io.Copy(os.Stdout, c.conn)
		close(done)
	}()

	// stdin relay: os.Stdin -> conn. Poll with a 100ms timeout so it notices
	// done within 100ms and never swallows input after the shell ends.
	// (The stdout relay above is the sole closer of done.)
	go func() {
		stdinFd := int(os.Stdin.Fd())
		buf := make([]byte, 4096)
		fds := []unix.PollFd{{Fd: int32(stdinFd), Events: unix.POLLIN}}
		for {
			select {
			case <-done:
				return
			default:
			}
			n, err := unix.Poll(fds, 100)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			if fds[0].Revents&unix.POLLIN == 0 {
				continue
			}
			nr, err := unix.Read(stdinFd, buf)
			if err != nil || nr == 0 {
				return
			}
			if _, err := c.conn.Write(buf[:nr]); err != nil {
				return
			}
		}
	}()

	<-done
	return nil
}

// sendWinchSize sends the current terminal size to the slave if it changed.
func sendWinchSize(c *client) {
	rows, cols, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil || rows <= 0 || cols <= 0 {
		return
	}
	lastMu.Lock()
	if lastSize[c.id] == [2]uint16{uint16(rows), uint16(cols)} {
		lastMu.Unlock()
		return
	}
	lastSize[c.id] = [2]uint16{uint16(rows), uint16(cols)}
	lastMu.Unlock()

	c.sendResize(rows, cols)
}

var (
	lastMu   sync.Mutex
	lastSize = make(map[int][2]uint16)
)

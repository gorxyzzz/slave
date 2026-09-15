package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"github.com/creack/pty"
	"zheng/internal/proto"
)

// errShellEnded tells the reconnect loop that a shell session finished
// (normally or because the master dropped) and the slave should reconnect.
var errShellEnded = errors.New("shell session ended")

// runShell spawns a pty-backed shell and bridges it over conn until either
// side finishes. Both directions are torn down unconditionally so the master
// always observes EOF promptly when the shell exits — this is what makes
// 'exit' return the operator to the master prompt instead of hanging.
func runShell(conn net.Conn) error {
	conn.Write([]byte(`{"status":"shell_ready"}` + "\n"))

	cmd := exec.Command("/bin/sh")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		proto.WriteJSON(conn, map[string]string{"status": "shell_fail", "error": err.Error()})
		return fmt.Errorf("pty start: %v", err)
	}

	// shellExited is closed when the shell's output stream hits EOF, i.e. the
	// shell process exited.
	shellExited := make(chan struct{})

	// pty -> conn (shell output). On EOF the shell is gone: close the conn so
	// the master's stdout relay gets EOF immediately.
	go func() {
		io.Copy(conn, ptmx)
		close(shellExited)
	}()

	// conn -> pty (operator input), demuxing in-band resize frames.
	go func() {
		relayInput(conn, ptmx)
		// Master input gone (conn closed/dead): hang up the shell.
		ptmx.Close()
	}()

	<-shellExited

	// Shell exited: stop the input relay and reap the child.
	conn.Close()
	ptmx.Close()
	cmd.Wait()
	return errShellEnded
}

// relayInput copies operator input from conn into the pty. Resize frames
// ("\x00R{...}\n") are intercepted and applied to the pty; everything else
// passes through byte-for-byte. It stops on read error, conn close, or the
// first pty write error.
func relayInput(conn net.Conn, ptmx *os.File) {
	br := bufio.NewReader(conn)
	for {
		b, err := br.ReadByte()
		if err != nil {
			return
		}
		if b != proto.ResizeMark {
			if _, err := ptmx.Write([]byte{b}); err != nil {
				return
			}
			continue
		}
		// Possible resize frame: peek the tag byte.
		peek, err := br.Peek(1)
		if err != nil {
			return
		}
		if peek[0] != proto.ResizeTag {
			// Lone 0x00 byte: pass through.
			if _, err := ptmx.Write([]byte{proto.ResizeMark}); err != nil {
				return
			}
			continue
		}
		rows, cols, err := proto.ReadResizeFrame(br)
		if err != nil {
			return
		}
		pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
	}
}

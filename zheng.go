package main

import (
	"fmt"
	"io"
	"net"
	"os"
)

const PORT = "4443"

func main() {
	listener, err := net.Listen("tcp", ":"+PORT)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on :%s: %v\n", PORT, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Fprintf(os.Stderr, "listening on :%s, waiting for connection...\n", PORT)

	conn, err := listener.Accept()
	if err != nil {
		fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Fprintf(os.Stderr, "connection from %s\n", conn.RemoteAddr())

	go func() {
		io.Copy(os.Stdout, conn)
		fmt.Fprintf(os.Stderr, "\nconnection closed\n")
		os.Exit(0)
	}()

	io.Copy(conn, os.Stdin)
}

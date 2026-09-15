package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"

	"zheng/internal/proto"
)

// sendAuth performs the challenge/response HMAC handshake as the client side.
func sendAuth(conn net.Conn, token string) error {
	var challenge proto.AuthMessage
	if err := proto.ReadJSON(conn, &challenge); err != nil {
		return fmt.Errorf("read challenge: %v", err)
	}
	if challenge.Challenge == "" {
		return fmt.Errorf("no challenge received")
	}

	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(challenge.Challenge))
	if err := proto.WriteJSON(conn, proto.AuthMessage{HMAC: hex.EncodeToString(mac.Sum(nil))}); err != nil {
		return fmt.Errorf("send hmac: %v", err)
	}

	var result proto.AuthMessage
	if err := proto.ReadJSON(conn, &result); err != nil {
		return fmt.Errorf("read auth result: %v", err)
	}
	if result.Status != "auth_ok" {
		return fmt.Errorf("auth failed: %s", result.Status)
	}
	return nil
}

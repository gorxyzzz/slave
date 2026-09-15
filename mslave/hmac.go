package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"

	"zheng/internal/proto"
)

func computeHMAC(token, challenge string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(challenge))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyHMAC(token, challenge, expected string) bool {
	return hmac.Equal([]byte(computeHMAC(token, challenge)), []byte(expected))
}

func handleAuth(conn net.Conn, token string) error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generate challenge: %v", err)
	}
	challenge := hex.EncodeToString(b)

	if err := json.NewEncoder(conn).Encode(proto.AuthMessage{Challenge: challenge}); err != nil {
		return fmt.Errorf("send challenge: %v", err)
	}

	var authMsg proto.AuthMessage
	if err := json.NewDecoder(conn).Decode(&authMsg); err != nil {
		return fmt.Errorf("read hmac: %v", err)
	}

	if !verifyHMAC(token, challenge, authMsg.HMAC) {
		json.NewEncoder(conn).Encode(proto.AuthMessage{Status: "auth_fail"})
		return fmt.Errorf("hmac verification failed")
	}

	if err := json.NewEncoder(conn).Encode(proto.AuthMessage{Status: "auth_ok"}); err != nil {
		return fmt.Errorf("send auth_ok: %v", err)
	}
	return nil
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

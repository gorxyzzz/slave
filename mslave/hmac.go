package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

type AuthMessage struct {
	Challenge string `json:"challenge,omitempty"`
	HMAC      string `json:"hmac,omitempty"`
	Status    string `json:"status,omitempty"`
}

func generateChallenge() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func computeHMAC(token, challenge string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(challenge))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyHMAC(token, challenge, expected string) bool {
	computed := computeHMAC(token, challenge)
	return hmac.Equal([]byte(computed), []byte(expected))
}

func handleAuth(conn net.Conn, token string) error {
	challenge := generateChallenge()
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(AuthMessage{Challenge: challenge}); err != nil {
		return fmt.Errorf("send challenge: %v", err)
	}

	var authMsg AuthMessage
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&authMsg); err != nil {
		return fmt.Errorf("read hmac: %v", err)
	}

	if !verifyHMAC(token, challenge, authMsg.HMAC) {
		encoder.Encode(AuthMessage{Status: "auth_fail"})
		return fmt.Errorf("hmac verification failed")
	}

	if err := encoder.Encode(AuthMessage{Status: "auth_ok"}); err != nil {
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

func sanitizeToken(token string) string {
	return strings.TrimSpace(token)
}

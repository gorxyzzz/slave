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

func clientAuth(conn net.Conn, token string) error {
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	// Read challenge
	var challenge AuthMessage
	if err := decoder.Decode(&challenge); err != nil {
		return fmt.Errorf("read challenge: %v", err)
	}

	if challenge.Challenge == "" {
		return fmt.Errorf("no challenge received")
	}

	// Compute HMAC
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(challenge.Challenge))
	hmacHex := hex.EncodeToString(mac.Sum(nil))

	// Send response
	if err := encoder.Encode(AuthMessage{HMAC: hmacHex}); err != nil {
		return fmt.Errorf("send hmac: %v", err)
	}

	// Read result
	var result AuthMessage
	if err := decoder.Decode(&result); err != nil {
		return fmt.Errorf("read auth result: %v", err)
	}

	if result.Status != "auth_ok" {
		return fmt.Errorf("auth failed: %s", result.Status)
	}

	return nil
}

func generateChallenge() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sanitizeToken(token string) string {
	return strings.TrimSpace(token)
}

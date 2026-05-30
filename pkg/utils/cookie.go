package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"strings"
)

var secretKeySession string

func init() {
	secretKeySession = os.Getenv("SECRET_KEY_SESSION")
	if secretKeySession == "" {
		log.Fatal("secretKeySession environment variable is not set")
	}
	if len(secretKeySession) < 32 {
		log.Fatal("secretKeySession must be at least 32 characters")
	}
}

func SignCookie(value string) string {
	h := hmac.New(sha256.New, []byte(secretKeySession))
	h.Write([]byte(value))
	return value + "." + hex.EncodeToString(h.Sum(nil))
}

func VerifyCookie(cookieValue string) (string, bool) {
	idx := strings.LastIndex(cookieValue, ".")
	if idx < 0 {
		log.Printf("[VerifyCookie] No separator found")
		return "", false
	}

	value := cookieValue[:idx]
	got := cookieValue[idx+1:]

	h := hmac.New(sha256.New, []byte(secretKeySession))
	h.Write([]byte(value))
	want := hex.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(got), []byte(want)) {
		log.Printf("[VerifyCookie] Signature mismatch for value=%q", value)
		return "", false
	}
	return value, true
}

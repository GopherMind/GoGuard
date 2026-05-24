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
	log.Printf("Loaded secretKeySession: %s", secretKeySession)
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

	signature := hex.EncodeToString(h.Sum(nil))

	return value + "." + signature
}

func VerifyCookie(CookieValue string) (string, bool) {
	part := strings.Split(CookieValue, ".")

	if len(part) != 2 {
		log.Printf("[VerifyCookie] Invalid cookie format (parts: %d)", len(part))
		return "", false
	}

	value := part[0]
	signature := part[1]

	h := hmac.New(sha256.New, []byte(secretKeySession))
	h.Write([]byte(value))
	expectedSignature := hex.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		log.Printf("[VerifyCookie] Signature mismatch! Value: '%s', Expected: '%s', Got: '%s'", value, expectedSignature, signature)
		return "", false
	}

	return value, true
}

package proxy

import (
	"GoGuard/internal/database"
	"GoGuard/pkg/utils"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type ChallengeSolution struct {
	Target string `json:"target"`
	Nonce  int    `json:"nonce"`
	Hash   string `json:"hash"`
}

type ScreenInfo struct {
	Width      int `json:"width"`
	Height     int `json:"height"`
	ColorDepth int `json:"colorDepth"`
}

type ClientFingerprint struct {
	Screen              ScreenInfo `json:"screen"`
	Timezone            int        `json:"timezone"`
	Languages           []string   `json:"languages"`
	Platform            string     `json:"platform"`
	HardwareConcurrency int        `json:"hardwareConcurrency"`
	Webdriver           bool       `json:"webdriver"`
}

type VerifyRequest struct {
	Challenge   ChallengeSolution `json:"challenge"`
	Fingerprint ClientFingerprint `json:"fingerprint"`
	Token       string            `json:"token"`
}

func VerifyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Verify] Verification request received from IP: %s", utils.GetIp(r))
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ Verify decode error: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if req.Token == "" {
		log.Printf("❌ Verify failed: empty token")
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	expectedTarget, err := database.Get("goguard:challenge:" + req.Token)
	if err != nil {
		log.Printf("❌ Verify failed: challenge not found or expired for token: %s", req.Token)
		http.Error(w, "Challenge not found or expired", http.StatusBadRequest)
		return
	}

	if req.Challenge.Target != expectedTarget {
		log.Printf("❌ Verify failed: challenge target mismatch. Expected: %s, Got: %s", expectedTarget, req.Challenge.Target)
		http.Error(w, "Challenge target mismatch", http.StatusBadRequest)
		return
	}

	data := req.Challenge.Target + strconv.Itoa(req.Challenge.Nonce)
	h := sha256.Sum256([]byte(data))
	hashHex := hex.EncodeToString(h[:])

	if hashHex != req.Challenge.Hash {
		log.Printf("❌ Verify failed: challenge hash mismatch. Expected: %s, Got: %s", hashHex, req.Challenge.Hash)
		http.Error(w, "Challenge hash mismatch", http.StatusBadRequest)
		return
	}

	if !strings.HasPrefix(hashHex, "00") {
		log.Printf("❌ Verify failed: invalid proof of work prefix for hash: %s", hashHex)
		http.Error(w, "Invalid proof of work", http.StatusBadRequest)
		return
	}

	fp := req.Fingerprint
	if fp.Webdriver {
		log.Printf("❌ Verify failed: automation tool detected (webdriver)")
		http.Error(w, "Automation detected", http.StatusBadRequest)
		return
	}
	if len(fp.Languages) == 0 {
		log.Printf("❌ Verify failed: missing browser languages")
		http.Error(w, "Invalid browser profile", http.StatusBadRequest)
		return
	}
	if fp.Platform == "" {
		log.Printf("❌ Verify failed: missing platform")
		http.Error(w, "Invalid browser profile", http.StatusBadRequest)
		return
	}
	if fp.Screen.Width <= 0 || fp.Screen.Height <= 0 {
		log.Printf("❌ Verify failed: invalid screen dimensions %dx%d", fp.Screen.Width, fp.Screen.Height)
		http.Error(w, "Invalid browser profile", http.StatusBadRequest)
		return
	}
	if fp.HardwareConcurrency <= 0 {
		log.Printf("❌ Verify failed: invalid hardware concurrency %d", fp.HardwareConcurrency)
		http.Error(w, "Invalid browser profile", http.StatusBadRequest)
		return
	}

	if err := database.Del("goguard:challenge:" + req.Token); err != nil {
		log.Printf("[Warning] Failed to delete challenge token %s from Redis: %v", req.Token, err)
	}

	ip := utils.GetIp(r)
	log.Printf("✅ Verify success for IP: %s. Setting clearance cookie...", ip)

	token := generateClearanceToken()
	clearanceValue := utils.SignCookie(token)

	secure := r.TLS != nil
	if !secure && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		secure = true
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "X-GoGuard-Clearance",
		Value:    clearanceValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})

	log.Printf("✅ Clearance cookie set for IP: %s | Value: %s", ip, clearanceValue)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func generateClearanceToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

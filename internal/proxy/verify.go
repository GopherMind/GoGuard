package proxy

import (
	"GoGuard/pkg/utils"
	"encoding/json"
	"log"
	"net/http"
)

type VerifyRequest struct {
	Challenge   interface{} `json:"challenge"`
	Fingerprint interface{} `json:"fingerprint"`
	Token       string      `json:"token"`
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

	ip := utils.GetIp(r)
	log.Printf("✅ Verify success for IP: %s. Setting clearance cookie...", ip)
	
	// Устанавливаем куку "клиренса", которая говорит прокси, что этот клиент проверен
	clearanceValue := utils.SignCookie(ip)
	
	http.SetCookie(w, &http.Cookie{
		Name:     "X-GoGuard-Clearance",
		Value:    clearanceValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 час
	})

	log.Printf("✅ Clearance cookie set for IP: %s | Value: %s", ip, clearanceValue)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

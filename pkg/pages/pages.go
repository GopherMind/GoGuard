package pages

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"time"
)

// BlockedPageData содержит данные для страницы блокировки
type BlockedPageData struct {
	Reason       string
	IP           string
	Risk         int
	BlockedUntil string
	IncidentID   string
}

// ChallengePageData содержит данные для страницы challenge
type ChallengePageData struct {
	Challenge string
	Token     string
}

// SendBlockedPage отправляет страницу блокировки
// ServeChallengePage — handler для маршрута /goguard/challenge
func ServeChallengePage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("web/templates/challenge.html")
	if err != nil {
		log.Printf("❌ Template error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	data := ChallengePageData{
		Challenge: generateChallenge(),
		Token:     generateToken(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("❌ Execute error: %v", err)
	}
}

// ServeBlockedPage — handler для маршрута /goguard/blocked
func ServeBlockedPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("web/templates/blocked.html")
	if err != nil {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	data := BlockedPageData{
		Reason:       "Suspicious activity detected",
		IP:           r.RemoteAddr,
		Risk:         100,
		BlockedUntil: time.Now().Add(24 * time.Hour).Format("2006-01-02 15:04:05"),
		IncidentID:   generateIncidentID(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	tmpl.Execute(w, data)
}

func isAjaxRequest(r *http.Request) bool {
	return r.Header.Get("X-Requested-With") == "XMLHttpRequest" ||
		r.Header.Get("Accept") == "application/json" ||
		r.Header.Get("Sec-Fetch-Mode") == "cors" ||
		r.Header.Get("Sec-Fetch-Mode") == "same-origin" && r.Header.Get("Sec-Fetch-Dest") == "empty"
}

// generateIncidentID генерирует уникальный ID инцидента
func generateIncidentID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateChallenge генерирует случайную строку для challenge
func generateChallenge() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateToken генерирует токен для верификации
func generateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

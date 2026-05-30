package pages

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"time"

	"GoGuard/internal/database"
)

type BlockedPageData struct {
	Reason       string
	IP           string
	Risk         int
	BlockedUntil string
	IncidentID   string
}

type ChallengePageData struct {
	Challenge string
	Token     string
}

func ServeChallengePage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("web/templates/challenge.html")
	if err != nil {
		log.Printf("❌ Template error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	challenge := generateChallenge()
	token := generateToken()

	err = database.Set("goguard:challenge:"+token, challenge, 5*time.Minute)
	if err != nil {
		log.Printf("❌ Failed to store challenge in Redis: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	data := ChallengePageData{
		Challenge: challenge,
		Token:     token,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("❌ Execute error: %v", err)
	}
}

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

func generateIncidentID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateChallenge() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// internal/collect/handler.go
package proxy

import (
	"encoding/json"
	"net/http"
)

type SnapshotPayload struct {
	SiteKey    string          `json:"siteKey"`
	SessionId  string          `json:"sessionId"`
	TimeOnPage int64           `json:"timeOnPage"`
	Automation map[string]bool `json:"automation"`
	Events     struct {
		Moves  int `json:"moves"`
		Clicks int `json:"clicks"`
		Keys   int `json:"keys"`
	} `json:"events"`
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

	var payload SnapshotPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if _, exists := Domains[payload.SiteKey]; !exists {
		http.Error(w, "Site not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}
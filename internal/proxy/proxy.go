package proxy

import (
	"GoGuard/internal/middleware"
	"GoGuard/pkg/pages"
	"GoGuard/pkg/utils"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

func handleInternal(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Internal] Handling internal route: %s", r.URL.Path)
	if strings.HasPrefix(r.URL.Path, "/goguard/sdk/") {
		fs := http.StripPrefix("/goguard/sdk/", http.FileServer(http.Dir("web/static")))
		fs.ServeHTTP(w, r)
		return
	}
	switch r.URL.Path {
	case "/goguard/challenge":
		pages.ServeChallengePage(w, r)
	case "/goguard/blocked":
		pages.ServeBlockedPage(w, r)
	case "/goguard/verify":
		VerifyHandler(w, r)
	case "/goguard/collect":
		Handler(w, r)
	default:
		http.NotFound(w, r)
	}
}

func resolveDomain(r *http.Request) *Domain {
	if k := r.Header.Get("X-GoGuard-SiteKey"); k != "" {
		if d, ok := LookupDomain(k); ok {
			return d
		}
	}
	if d, ok := LookupDomain(r.Host); ok {
		return d
	}
	return nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	ip := utils.GetIp(r)
	log.Printf("[Request] %s %s | IP: %s | Host: %s", r.Method, r.URL.Path, ip, r.Host)

	if strings.HasPrefix(r.URL.Path, "/goguard/") {
		handleInternal(w, r)
		return
	}

	domain := resolveDomain(r)
	if domain == nil {
		log.Printf("[Reject] No domain mapping for Host=%q SiteKey=%q (path=%s)",
			r.Host, r.Header.Get("X-GoGuard-SiteKey"), r.URL.Path)
		http.Error(w, "Site not configured", http.StatusNotFound)
		return
	}

	if r.URL.Path == "/favicon.ico" || r.URL.Path == "/robots.txt" {
		proxyThrough(w, r, domain)
		return
	}

	if cookie, err := r.Cookie("X-GoGuard-Clearance"); err == nil {
		if _, ok := utils.VerifyCookie(cookie.Value); ok {
			proxyThrough(w, r, domain)
			return
		}
		log.Printf("[Clearance] Invalid or tampered cookie from %s", ip)
	}

	if utils.IsBlocked(r.Host, ip) {
		log.Printf("[Blocked IP] %s | IP: %s", r.URL.Path, ip)
		if isAjaxRequest(r) {
			sendBlockedJSON(w, "IP blocked")
			return
		}
		pages.ServeBlockedPage(w, r)
		return
	}

	rateCount, _, _ := utils.TrackUser(r)
	serverRisk := utils.CheckHeaders(r, rateCount)
	clientRisk := utils.CheckClientFingerprint(r)
	risk := serverRisk + clientRisk

	log.Printf("[Risk Check] %s | IP: %s | Risk: %d (S:%d, C:%d) | Rate: %d | UA: %q",
		r.URL.Path, ip, risk, serverRisk, clientRisk, rateCount, r.UserAgent())

	if risk >= 60 {
		log.Printf("[Blocking] IP %s blocked for path %s. Reason: High risk (%d)", ip, r.URL.Path, risk)
		utils.BlockIP(r.Host, ip, "Critical risk", 24*time.Hour)
		if isAjaxRequest(r) {
			sendBlockedJSON(w, "High risk")
			return
		}
		pages.ServeBlockedPage(w, r)
		return
	} else if risk >= 30 {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			log.Printf("[Warning] WebSocket from %s challenged but passed through to avoid breaking handshake", ip)
			proxyThrough(w, r, domain)
			return
		}

		if isAjaxRequest(r) {
			log.Printf("[Challenge] Sending JSON challenge for AJAX request: %s", r.URL.Path)
			sendChallengeJSON(w, "Verification required")
			return
		}
		log.Printf("[Challenge] Serving inline challenge page for: %s", r.URL.Path)
		pages.ServeChallengePage(w, r)
		return
	}

	rawSessionID := uuid.New().String()
	signedValue := utils.SignCookie(rawSessionID)
	http.SetCookie(w, &http.Cookie{
		Name:     "X-GoGuard-SessionId",
		Value:    signedValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   isRequestSecure(r),
		SameSite: http.SameSiteLaxMode,
	})

	proxyThrough(w, r, domain)
}

func proxyThrough(w http.ResponseWriter, r *http.Request, domain *Domain) {
	publicHost := r.Header.Get("X-Forwarded-Host")
	if publicHost == "" {
		publicHost = r.Host
	}
	iw := newInjectWriter(w, domain.Host)
	domain.Proxy.ServeHTTP(iw, r)
	iw.flush()
}

func isRequestSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}
	return false
}

func isAjaxRequest(r *http.Request) bool {
	fetchDest := r.Header.Get("Sec-Fetch-Dest")
	fetchMode := r.Header.Get("Sec-Fetch-Mode")
	requestedWith := r.Header.Get("X-Requested-With")
	accept := r.Header.Get("Accept")

	if fetchDest == "document" {
		return false
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return true
	}
	if requestedWith == "XMLHttpRequest" {
		return true
	}
	if fetchMode == "cors" || fetchMode == "same-origin" {
		return true
	}
	if strings.Contains(accept, "application/json") {
		return true
	}
	return false
}

func sendBlockedJSON(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-GoGuard-Blocked", "true")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"blocked": true,
		"reason":  reason,
	})
}

func sendChallengeJSON(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-GoGuard-Challenge", "true")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"challenge": true,
		"action":    "challenge",
		"reason":    reason,
	})
}

func StartProxy() {
	InitDomains()

	middleware.IsAllowedOriginFunc = func(origin string) bool {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return LookupOrigin(u.Host)
	}

	http.Handle("/", middleware.CorsMiddleware(http.HandlerFunc(handler)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("GoGuard Transparent Proxy started on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

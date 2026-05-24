package proxy

import (
	"GoGuard/internal/middleware"
	"GoGuard/pkg/pages"
	"GoGuard/pkg/utils"
	"encoding/json"
	"log"
	"net/http"
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

// resolveDomain selects the backend mapping for a request. The X-GoGuard-SiteKey
// header takes precedence (the SDK injects it on subsequent requests) and we
// fall back to the public Host header. Matching is case-insensitive and
// tolerant of a missing port.
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

	// Internal GoGuard routes are served regardless of clearance/domain so the
	// challenge page, SDK, verification endpoint, etc. always work.
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

	// 1. Clearance cookie — equivalent of Cloudflare's cf_clearance. If valid
	//    for this IP, proxy straight through without re-running risk checks.
	if cookie, err := r.Cookie("X-GoGuard-Clearance"); err == nil {
		if val, ok := utils.VerifyCookie(cookie.Value); ok && val == ip {
			proxyThrough(w, r, domain)
			return
		}
	}

	// 2. IP block list.
	if utils.IsBlocked(r.Host, ip) {
		log.Printf("[Blocked IP] %s | IP: %s", r.URL.Path, ip)
		if isAjaxRequest(r) {
			sendBlockedJSON(w, "IP blocked")
			return
		}
		pages.ServeBlockedPage(w, r)
		return
	}

	// 3. Compute risk.
	rateCount, _, _ := utils.TrackUser(r)
	serverRisk := utils.CheckHeaders(r, rateCount)
	clientRisk := utils.CheckClientFingerprint(r)
	risk := serverRisk + clientRisk

	log.Printf("[Risk Check] %s | IP: %s | Risk: %d (S:%d, C:%d) | Rate: %d",
		r.URL.Path, ip, risk, serverRisk, clientRisk, rateCount)

	// 4. React to risk.
	if risk >= 60 {
		utils.BlockIP(r.Host, ip, "Critical risk", 24*time.Hour)
		if isAjaxRequest(r) {
			sendBlockedJSON(w, "High risk")
			return
		}
		pages.ServeBlockedPage(w, r)
		return
	} else if risk >= 30 {
		if isAjaxRequest(r) {
			sendChallengeJSON(w, "Verification required")
			return
		}
		// Serve the challenge inline so the browser stays on the same URL —
		// the page reloads on success.
		pages.ServeChallengePage(w, r)
		return
	}

	// 5. Issue a session cookie and forward the request transparently.
	rawSessionID := uuid.New().String()
	signedValue := utils.SignCookie(rawSessionID)
	http.SetCookie(w, &http.Cookie{
		Name:     "X-GoGuard-SessionId",
		Value:    signedValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   isRequestSecure(r),
		// Lax keeps the cookie attached on top-level navigations from other
		// sites (e.g. clicking a link to the protected site).
		SameSite: http.SameSiteLaxMode,
	})

	proxyThrough(w, r, domain)
}

// proxyThrough wraps the response writer with the script injector and calls
// the backend reverse proxy.
func proxyThrough(w http.ResponseWriter, r *http.Request, domain *Domain) {
	iw := newInjectWriter(w, domain.Host)
	domain.Proxy.ServeHTTP(iw, r)
	iw.flush()
}

// isRequestSecure returns true if the request reached us over TLS, either
// directly or via a TLS-terminating proxy in front of GoGuard.
func isRequestSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}
	return false
}

// isAjaxRequest identifies fetch/XHR/websocket-like requests that should not
// receive an HTML challenge page.
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
	// 401 makes more sense here than 403 — the client can retry after the
	// challenge succeeds and a clearance cookie is issued.
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"challenge": true,
		"action":    "challenge",
		"reason":    reason,
	})
}

func StartProxy() {
	InitDomains()
	http.Handle("/", middleware.CorsMiddleware(http.HandlerFunc(handler)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("GoGuard Transparent Proxy started on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

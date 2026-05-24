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

func handler(w http.ResponseWriter, r *http.Request) {
	ip := utils.GetIp(r)
	log.Printf("[Request] %s %s | IP: %s | Host: %s", r.Method, r.URL.Path, ip, r.Host)

	// 1. Проверка клиренса (Cloudflare-like) - САМЫЙ ПЕРВЫЙ ШАГ
	cookie, err := r.Cookie("X-GoGuard-Clearance")
	if err == nil {
		val, isValid := utils.VerifyCookie(cookie.Value)
		if isValid && val == ip {
			siteKey := r.Header.Get("X-GoGuard-SiteKey")
			if siteKey == "" {
				siteKey = r.Host
			}

			domain, exists := Domains[siteKey]
			if exists {
				if strings.HasPrefix(r.URL.Path, "/goguard/") {
					handleInternal(w, r)
					return
				}
				iw := newInjectWriter(w, siteKey)
				domain.Proxy.ServeHTTP(iw, r)
				iw.flush()
				return
			}
		}
	}

	// Исключаем внутренние маршруты GoGuard из проверки рисков
	if strings.HasPrefix(r.URL.Path, "/goguard/") {
		handleInternal(w, r)
		return
	}

	siteKey := r.Header.Get("X-GoGuard-SiteKey")
	if siteKey == "" {
		host := r.Host
		if _, exists := Domains[host]; exists {
			siteKey = host
		} else {
			log.Printf("[Reject] No SiteKey and Host %s not in Domains", r.Host)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	domain, exists := Domains[siteKey]
	if !exists {
		http.Error(w, "Site not found", http.StatusNotFound)
		return
	}

	// 2. Проверка черного списка IP
	if utils.IsBlocked(r.Host, ip) {
		log.Printf("[Blocked IP] %s | IP: %s", r.URL.Path, ip)
		if isAjaxRequest(r) {
			sendBlockedJSON(w, "IP blocked")
			return
		}
		pages.ServeBlockedPage(w, r)
		return
	}

	// 3. Сбор метрик и расчет риска
	rateCount, _, _ := utils.TrackUser(r)
	serverRisk := utils.CheckHeaders(r, rateCount)
	clientRisk := utils.CheckClientFingerprint(r)
	risk := serverRisk + clientRisk

	log.Printf("[Risk Check] %s | IP: %s | Risk: %d (S:%d, C:%d) | Rate: %d",
		r.URL.Path, ip, risk, serverRisk, clientRisk, rateCount)

	// 4. Реакция на риск
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
		pages.ServeChallengePage(w, r)
		return
	}

	// 5. Если все ок — устанавливаем сессию и проксируем
	rawSessionId := uuid.New().String()
	signedValue := utils.SignCookie(rawSessionId)
	http.SetCookie(w, &http.Cookie{
		Name:     "X-GoGuard-SessionId",
		Value:    signedValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})

	iw := newInjectWriter(w, siteKey)
	domain.Proxy.ServeHTTP(iw, r)
	iw.flush()
}

// isAjaxRequest определяет fetch/XHR запросы
func isAjaxRequest(r *http.Request) bool {
	fetchDest := r.Header.Get("Sec-Fetch-Dest")
	fetchMode := r.Header.Get("Sec-Fetch-Mode")
	requestedWith := r.Header.Get("X-Requested-With")
	accept := r.Header.Get("Accept")

	if fetchDest == "document" {
		return false
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
	w.WriteHeader(http.StatusForbidden)
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

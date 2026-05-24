package middleware

import (
	"log"
	"net/http"
)

// CorsMiddleware sets permissive CORS headers that always reflect the
// incoming Origin (when present) rather than hard-coding a backend URL —
// hard-coding leaks the internal address into the browser and breaks
// credentialed requests served from the real public domain.
func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			log.Printf("[CORS] %s %s from Origin=%s", r.Method, r.URL.Path, origin)
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")

		reqHeaders := r.Header.Get("Access-Control-Request-Headers")
		if reqHeaders != "" {
			// Echo whatever the preflight asked for so the proxy doesn't
			// silently drop application headers (CSRF tokens, auth, etc.).
			w.Header().Set("Access-Control-Allow-Headers", reqHeaders)
			w.Header().Add("Vary", "Access-Control-Request-Headers")
		} else {
			w.Header().Set("Access-Control-Allow-Headers",
				"Content-Type, Authorization, X-Requested-With, X-CSRF-Token, "+
					"X-GoGuard-FP, X-GoGuard-Score, X-GoGuard-SiteKey")
		}
		w.Header().Set("Access-Control-Expose-Headers",
			"X-GoGuard-Challenge, X-GoGuard-Blocked")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

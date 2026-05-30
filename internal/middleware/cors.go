package middleware

import (
	"log"
	"net/http"
	"net/url"
)

var IsAllowedOriginFunc func(origin string) bool

func isSameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == host
}

func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			allowed := false
			if IsAllowedOriginFunc != nil {
				allowed = IsAllowedOriginFunc(origin)
			} else {
				allowed = isSameOrigin(origin, r.Host)
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			} else {
				log.Printf("[CORS Blocked] Unauthorized Origin: %s for request to %s", origin, r.Host)
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")

		reqHeaders := r.Header.Get("Access-Control-Request-Headers")
		if reqHeaders != "" {
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

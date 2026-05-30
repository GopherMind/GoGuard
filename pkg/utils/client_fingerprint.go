package utils

import (
	"net/http"
)

func CheckClientFingerprint(r *http.Request) int {
	risk := 0

	cookie, err := r.Cookie("X-GoGuard-SessionId")
	if err != nil || cookie.Value == "" {
		risk += 30
		return risk
	}

	rawValue, isValid := VerifyCookie(cookie.Value)
	if !isValid || rawValue == "" {
		risk += 30
		return risk
	}

	fingerprint := r.Header.Get("X-GoGuard-FP")
	if fingerprint == "" {
		risk += 35
	}

	return risk
}

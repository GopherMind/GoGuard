package utils

import (
	"net/http"
)

// CheckClientFingerprint проверяет fingerprint от SDK
func CheckClientFingerprint(r *http.Request) int {
	risk := 0

	// Читаем sessionId из cookie (устанавливается через http.SetCookie)
	cookie, err := r.Cookie("X-GoGuard-SessionId")
	if err != nil || cookie.Value == "" {
		risk += 30
		return risk
	}

	// Проверяем подпись cookie
	rawValue, isValid := VerifyCookie(cookie.Value)
	if rawValue == "" || !isValid {
		risk += 60
		return risk
	}

	fingerprint := r.Header.Get("X-GoGuard-FP")
	// Если нет SDK — подозрительно (возможно отключен JS или бот без рендеринга)
	if fingerprint == "" {
		risk += 40
		return risk
	}

	return risk
}

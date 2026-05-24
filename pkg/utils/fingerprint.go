package utils

import (
	"GoGuard/internal/database"
	"fmt"
	"net/http"
	"time"
)


func TrackUser(r *http.Request) (rateCount int64, userCount int64, err error) {
	ip := GetIp(r)
	ua := r.Header.Get("User-Agent")
	domain := r.Host

	rateKey := fmt.Sprintf("rate:%s:%s", domain, ip)
	if err := database.Incr(rateKey); err != nil {
		return 0, 0, err
	}
	database.Expire(rateKey, 60*time.Second)

	rateStr, _ := database.Get(rateKey)
	if rateStr != "" {
		fmt.Sscanf(rateStr, "%d", &rateCount)
	}


	userKey := fmt.Sprintf("user:%s:%s:%s", domain, ip, ua)
	if err := database.Incr(userKey); err != nil {
		return rateCount, 0, err
	}
	database.Expire(userKey, 5*time.Minute)


	userStr, _ := database.Get(userKey)
	if userStr != "" {
		fmt.Sscanf(userStr, "%d", &userCount)
	}

	return rateCount, userCount, nil
}

// IsBlocked проверяет, заблокирован ли IP для домена
func IsBlocked(domain, ip string) bool {
	if isWhitelisted(ip) {
		return false
	}
	key := fmt.Sprintf("blocked:%s:%s", domain, ip)
	val, err := database.Get(key)
	return err == nil && val != ""
}

// isWhitelisted проверяет, находится ли IP в белом списке
func isWhitelisted(ip string) bool {
	whitelist := []string{"127.0.0.1", "::1", "localhost"}
	for _, w := range whitelist {
		if ip == w {
			return true
		}
	}
	return false
}

// BlockIP блокирует IP для домена на указанное время
func BlockIP(domain, ip, reason string, duration time.Duration) error {
	if isWhitelisted(ip) {
		return nil
	}
	key := fmt.Sprintf("blocked:%s:%s", domain, ip)
	return database.Set(key, reason, duration)
}

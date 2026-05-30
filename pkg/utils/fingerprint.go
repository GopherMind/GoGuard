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
	rateCount, err = database.Incr(r.Context(), rateKey)
	if err != nil {
		return 0, 0, err
	}
	if rateCount == 1 {
		database.Expire(rateKey, 60*time.Second)
	}

	userKey := fmt.Sprintf("user:%s:%s:%s", domain, ip, ua)
	userCount, err = database.Incr(r.Context(), userKey)
	if err != nil {
		return rateCount, 0, err
	}
	if userCount == 1 {
		database.Expire(userKey, 5*time.Minute)
	}

	return rateCount, userCount, nil
}

func IsBlocked(domain, ip string) bool {
	if isWhitelisted(ip) {
		return false
	}
	key := fmt.Sprintf("blocked:%s:%s", domain, ip)
	val, err := database.Get(key)
	return err == nil && val != ""
}

func isWhitelisted(ip string) bool {
	whitelist := []string{"127.0.0.1", "::1", "localhost"}
	for _, w := range whitelist {
		if ip == w {
			return true
		}
	}
	return false
}

func BlockIP(domain, ip, reason string, duration time.Duration) error {
	if isWhitelisted(ip) {
		return nil
	}
	key := fmt.Sprintf("blocked:%s:%s", domain, ip)
	return database.Set(key, reason, duration)
}

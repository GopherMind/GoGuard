package utils

import (
	"net"
	"net/http"
	"strings"
)

// utils/ip.go — стало
func GetIp(r *http.Request) string {
	// X-Forwarded-For: client, proxy1, proxy2
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Берём самый первый IP в списке (оригинальный клиент)
		// В реальном проде лучше брать с конца списка доверенных прокси
		ip := strings.TrimSpace(parts[0])
		if parsed := net.ParseIP(ip); parsed != nil {
			return normalizeIP(parsed)
		}
	}

	// Если нет прокси — берём напрямую
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Если порта нет (например, кастомный транспорт), используем как есть
		host = r.RemoteAddr
	}
	
	// Обработка [::1] и других IPv6 loopback
	if host == "::1" {
		return "127.0.0.1"
	}

	parsed := net.ParseIP(host)
	if parsed == nil {
		return host
	}
	return normalizeIP(parsed)
}

func normalizeIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if ip.IsLoopback() {
		return "127.0.0.1"
	}
	return ip.String()
}

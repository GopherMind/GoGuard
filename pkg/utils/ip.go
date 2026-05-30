package utils

import (
	"net"
	"net/http"
	"strings"
)

var trustedSubnets = []*net.IPNet{
	mustParseCIDR("127.0.0.0/8"),
	mustParseCIDR("::1/128"),
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("fc00::/7"),
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

func isTrustedProxy(ip net.IP) bool {
	for _, subnet := range trustedSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func GetIp(r *http.Request) string {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}
	directIP := net.ParseIP(remoteIP)
	if directIP == nil {
		return remoteIP
	}

	if !isTrustedProxy(directIP) {
		return normalizeIP(directIP)
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return normalizeIP(directIP)
	}

	ips := strings.Split(xff, ",")
	for i := len(ips) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(ips[i])
		parsedIP := net.ParseIP(ipStr)
		if parsedIP == nil {
			continue
		}
		if !isTrustedProxy(parsedIP) {
			return normalizeIP(parsedIP)
		}
		if i == 0 {
			return normalizeIP(parsedIP)
		}
	}

	return normalizeIP(directIP)
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

package utils

import (
	"crypto/tls"
	"net/http"
	"strings"
)

const (
	RiskNoUserAgent     = 30
	RiskNoIP            = 40
	RiskHighRequestRate = 35

	RiskNoAcceptLanguage       = 15
	RiskNoAcceptLanguageSimple = 10
	RiskNoAcceptEncoding       = 15

	RiskNoSecFetchSite = 5
)

func CheckHeaders(r *http.Request, rateCount int64) int {

	risk := 0
	ua := r.Header.Get("User-Agent")
	isSafari := strings.Contains(ua, "Safari") && !strings.Contains(ua, "Chrome")
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		risk += RiskNoUserAgent
	}

	lang := r.Header.Get("Accept-Language")

	if lang == "" {
		risk += RiskNoAcceptLanguage
	} else if !strings.Contains(lang, ",") && !strings.Contains(lang, ";") {
		risk += RiskNoAcceptLanguageSimple
	}

	encodings := r.Header.Get("Accept-Encoding")
	if encodings == "" {
		risk += RiskNoAcceptEncoding
	}

	fetchSite := r.Header.Get("Sec-Fetch-Site")
	if fetchSite == "" {
		risk += RiskNoSecFetchSite
	}
	secFetchMode := r.Header.Get("Sec-Fetch-Mode")
	if secFetchMode == "" && !isSafari {
		risk += RiskNoSecFetchSite
	}
	secFetchDest := r.Header.Get("Sec-Fetch-Dest")
	if secFetchDest == "" && !isSafari {
		risk += RiskNoSecFetchSite
	}
	ip := GetIp(r)
	if ip == "" {
		risk += RiskNoIP
	}
	if r.TLS != nil && r.TLS.Version < tls.VersionTLS12 {
		risk += 20
	}
	// rateCount, _, err := TrackUser(r)
	if rateCount > 40 {
		risk += RiskHighRequestRate
	}

	return risk
}

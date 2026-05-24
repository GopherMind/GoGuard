package proxy

import (
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Domain struct {
	Host         string
	Target       string
	TargetURL    *url.URL
	Proxy        *httputil.ReverseProxy
	PreserveHost bool
}

type Config struct {
	Proxy struct {
		Targets []struct {
			Host         string `yaml:"host"`
			Target       string `yaml:"target"`
			PreserveHost *bool  `yaml:"preserve_host,omitempty"`
		} `yaml:"targets"`
	} `yaml:"proxy"`
}

var Domains = make(map[string]*Domain)

func InitDomains() {
	configData, err := os.ReadFile("configs/config.yaml")
	if err != nil {
		log.Printf("Warning: configs/config.yaml not found, using defaults: %v", err)
		setupDomain("localhost:8080", "http://localhost:3000", true)
		return
	}

	var cfg Config
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		log.Fatalf("Error parsing config.yaml: %v", err)
	}

	for _, t := range cfg.Proxy.Targets {
		preserve := true
		if t.PreserveHost != nil {
			preserve = *t.PreserveHost
		}
		setupDomain(t.Host, t.Target, preserve)
	}

	log.Printf("Initialized %d domains from config", len(Domains))
}

// LookupDomain finds a domain entry for a given Host header value.
// Matching is case-insensitive and tolerant of a missing port. A "*" entry,
// if present, is used as a catch-all so reasonable defaults are configurable.
func LookupDomain(host string) (*Domain, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		if d, ok := Domains["*"]; ok {
			return d, true
		}
		return nil, false
	}
	if d, ok := Domains[host]; ok {
		return d, true
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		if d, ok := Domains[h]; ok {
			return d, true
		}
	}
	if d, ok := Domains["*"]; ok {
		return d, true
	}
	return nil, false
}

func setupDomain(host, target string, preserveHost bool) {
	parsedURL, err := url.Parse(target)
	if err != nil {
		log.Fatalf("bad url %s: %v", target, err)
	}

	rp := httputil.NewSingleHostReverseProxy(parsedURL)

	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		// Capture the public-facing values BEFORE the default director rewrites the URL.
		publicHost := req.Host
		publicScheme := "http"
		if req.TLS != nil {
			publicScheme = "https"
		}
		if p := req.Header.Get("X-Forwarded-Proto"); p != "" {
			publicScheme = p
		}

		originalDirector(req)

		// Forward proxy hints so the backend can build correct absolute URLs.
		if publicHost != "" {
			req.Header.Set("X-Forwarded-Host", publicHost)
		}
		req.Header.Set("X-Forwarded-Proto", publicScheme)
		if req.Header.Get("X-Real-IP") == "" {
			if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
				req.Header.Set("X-Real-IP", strings.TrimSpace(strings.Split(xff, ",")[0]))
			}
		}

		// PreserveHost: backend receives the original Host so it generates
		// links/redirects against the public domain. Otherwise switch to the
		// target host (some virtual-hosted backends require this).
		if preserveHost {
			req.Host = publicHost
		} else {
			req.Host = parsedURL.Host
		}

		// Disable upstream compression for HTML-bearing requests so the
		// injector can safely rewrite responses. For WebSocket / Upgrade
		// requests leave Accept-Encoding alone — the body is binary framing
		// and the response isn't HTML.
		// httputil.ReverseProxy strips hop-by-hop headers itself AFTER the
		// director runs, and re-adds Connection: Upgrade for upgrade
		// requests, so we must NOT touch Connection / Upgrade here.
		if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
			req.Header.Set("Accept-Encoding", "identity")
		}

		log.Printf("[Proxy] -> %s %s%s (Host=%s, scheme=%s)",
			req.Method, parsedURL.Host, req.URL.Path, req.Host, publicScheme)
	}

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[Proxy Error] %s %s -> %s: %v", r.Method, r.URL.Path, parsedURL.Host, err)
		http.Error(w, "Backend service unavailable", http.StatusBadGateway)
	}

	rp.ModifyResponse = func(resp *http.Response) error {
		// Strip CORS headers from the backend; the proxy middleware sets its own.
		resp.Header.Del("Access-Control-Allow-Origin")
		resp.Header.Del("Access-Control-Allow-Methods")
		resp.Header.Del("Access-Control-Allow-Headers")
		resp.Header.Del("Access-Control-Allow-Credentials")

		// Rewrite absolute Location URLs that point at the backend so the
		// browser never bounces to localhost / internal ports.
		if loc := resp.Header.Get("Location"); loc != "" {
			if newLoc := rewriteLocation(loc, parsedURL, resp.Request); newLoc != loc {
				log.Printf("[Proxy] Rewriting Location: %s -> %s", loc, newLoc)
				resp.Header.Set("Location", newLoc)
			}
		}

		// Drop Domain= attributes on cookies that pin them to the backend host
		// (otherwise browsers reject the cookie when the visible URL is on a
		// different domain).
		if cookies := resp.Header.Values("Set-Cookie"); len(cookies) > 0 {
			rewritten := make([]string, 0, len(cookies))
			for _, c := range cookies {
				rewritten = append(rewritten, sanitizeCookieDomain(c, parsedURL.Hostname()))
			}
			resp.Header.Del("Set-Cookie")
			for _, c := range rewritten {
				resp.Header.Add("Set-Cookie", c)
			}
		}

		return nil
	}

	normalizedHost := strings.ToLower(strings.TrimSpace(host))
	Domains[normalizedHost] = &Domain{
		Host:         normalizedHost,
		Target:       target,
		TargetURL:    parsedURL,
		Proxy:        rp,
		PreserveHost: preserveHost,
	}
	log.Printf("Registered domain: %s -> %s (preserve_host=%v)", normalizedHost, target, preserveHost)
}

// rewriteLocation rewrites absolute backend URLs in Location headers so the
// browser stays on the public domain (e.g. mysite.com) rather than being
// bounced to http://localhost:5173.
func rewriteLocation(location string, backend *url.URL, origReq *http.Request) string {
	loc, err := url.Parse(location)
	if err != nil || !loc.IsAbs() {
		return location
	}
	if !strings.EqualFold(loc.Host, backend.Host) {
		return location
	}
	if origReq == nil {
		return location
	}

	publicHost := origReq.Header.Get("X-Forwarded-Host")
	if publicHost == "" {
		publicHost = origReq.Host
	}
	if publicHost == "" {
		return location
	}

	publicScheme := "http"
	if origReq.TLS != nil {
		publicScheme = "https"
	}
	if p := origReq.Header.Get("X-Forwarded-Proto"); p != "" {
		publicScheme = p
	}

	loc.Host = publicHost
	loc.Scheme = publicScheme
	return loc.String()
}

// sanitizeCookieDomain removes Domain attributes that reference the backend
// host (or other internal hosts) so cookies remain scoped to the public domain.
func sanitizeCookieDomain(cookie, backendHost string) string {
	parts := strings.Split(cookie, ";")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "domain=") {
			val := strings.TrimSpace(trimmed[len("domain="):])
			val = strings.TrimPrefix(val, ".")
			if strings.EqualFold(val, backendHost) ||
				strings.EqualFold(val, "localhost") ||
				strings.HasPrefix(val, "127.") ||
				val == "::1" {
				continue
			}
		}
		out = append(out, part)
	}
	return strings.Join(out, ";")
}

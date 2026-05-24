package proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

type Domain struct {
	Host   string
	Target string
	Proxy  *httputil.ReverseProxy
}

type Config struct {
	Proxy struct {
		Targets []struct {
			Host   string `yaml:"host"`
			Target string `yaml:"target"`
		} `yaml:"targets"`
	} `yaml:"proxy"`
}

var Domains = make(map[string]*Domain)

func InitDomains() {
	configData, err := os.ReadFile("configs/config.yaml")
	if err != nil {
		log.Printf("Warning: configs/config.yaml not found, using defaults: %v", err)
		// Fallback defaults
		setupDomain("localhost:8080", "http://localhost:3000")
		return
	}

	var cfg Config
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		log.Fatalf("Error parsing config.yaml: %v", err)
	}

	for _, t := range cfg.Proxy.Targets {
		setupDomain(t.Host, t.Target)
	}

	log.Printf("Initialized %d domains from config", len(Domains))
}

func setupDomain(host, target string) {
	parsedUrl, err := url.Parse(target)
	if err != nil {
		log.Fatalf("bad url %s: %v", target, err)
	}

	rp := httputil.NewSingleHostReverseProxy(parsedUrl)

	// Сохраняем оригинальный Director, но добавляем смену Host
	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = parsedUrl.Host // Важно: меняем Host на целевой (например, localhost:5173)
		log.Printf("[Proxy] Forwarding request to: %s %s (Host: %s)", req.Method, req.URL.String(), req.Host)
	}

	// Обработка ошибок проксирования (например, если бэкенд выключен)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[Proxy Error] %v", err)
		http.Error(w, "Backend service unavailable", http.StatusBadGateway)
	}

	// Удаляем CORS заголовки от бэкенда до отправки клиенту
	rp.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Access-Control-Allow-Origin")
		resp.Header.Del("Access-Control-Allow-Methods")
		resp.Header.Del("Access-Control-Allow-Headers")
		resp.Header.Del("Access-Control-Allow-Credentials")
		return nil
	}

	Domains[host] = &Domain{
		Host:   host,
		Target: target,
		Proxy:  rp,
	}
	log.Printf("Registered domain: %s -> %s", host, target)
}

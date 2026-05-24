package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// injectWriter buffers HTML response bodies so the GoGuard SDK <script> tag
// can be injected into <head> before the response is flushed to the client.
// Non-HTML responses pass through unbuffered.
//
// The wrapper also forwards Hijack and Flush to the underlying writer so
// WebSocket upgrades and Server-Sent Events keep working through the proxy.
type injectWriter struct {
	http.ResponseWriter
	buf        bytes.Buffer
	statusCode int
	isHTML     bool
	siteKey    string
}

func newInjectWriter(w http.ResponseWriter, siteKey string) *injectWriter {
	return &injectWriter{ResponseWriter: w, statusCode: http.StatusOK, siteKey: siteKey}
}

func (iw *injectWriter) WriteHeader(code int) {
	iw.statusCode = code
	ct := iw.ResponseWriter.Header().Get("Content-Type")
	enc := iw.ResponseWriter.Header().Get("Content-Encoding")

	// Only buffer/rewrite uncompressed HTML on responses that may carry a
	// body. 1xx / 204 / 205 / 304 must remain body-less per RFC 7230.
	if mustHaveEmptyBody(code) {
		iw.ResponseWriter.WriteHeader(code)
		return
	}
	if strings.Contains(ct, "text/html") && (enc == "" || strings.EqualFold(enc, "identity")) {
		iw.isHTML = true
		return
	}
	iw.ResponseWriter.WriteHeader(code)
}

func mustHaveEmptyBody(code int) bool {
	switch code {
	case http.StatusNoContent, http.StatusResetContent, http.StatusNotModified:
		return true
	}
	return code >= 100 && code < 200
}

func (iw *injectWriter) Write(data []byte) (int, error) {
	if iw.isHTML {
		return iw.buf.Write(data)
	}
	return iw.ResponseWriter.Write(data)
}

// flush is called after the upstream proxy finished writing the body. It
// rewrites the buffered HTML and emits the final response.
func (iw *injectWriter) flush() {
	if !iw.isHTML {
		return
	}
	injectScript := fmt.Sprintf(`<script src="/goguard/sdk/goguard-sdk.js" data-site-key="%s"></script>`, iw.siteKey)

	body := iw.buf.String()
	if idx := indexFoldASCII(body, "</head>"); idx >= 0 {
		body = body[:idx] + injectScript + body[idx:]
	} else {
		// Document had no <head> — still better to ship the SDK than drop it.
		body = injectScript + body
	}

	iw.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(len(body)))
	iw.ResponseWriter.Header().Del("Content-Encoding")
	iw.ResponseWriter.WriteHeader(iw.statusCode)
	iw.ResponseWriter.Write([]byte(body))
}

// Hijack delegates to the underlying ResponseWriter so httputil.ReverseProxy
// can take over the connection for WebSocket upgrades.
func (iw *injectWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := iw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("injectWriter: underlying ResponseWriter does not implement http.Hijacker")
	}
	return hj.Hijack()
}

// Flush delegates to the underlying ResponseWriter so SSE / chunked streams
// reach the client promptly. We skip flushing while buffering HTML — the
// caller will see the full document at once via flush().
func (iw *injectWriter) Flush() {
	if iw.isHTML {
		return
	}
	if f, ok := iw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// indexFoldASCII reports the index of the first case-insensitive ASCII match
// of needle in haystack, or -1 if not present.
func indexFoldASCII(haystack, needle string) int {
	return strings.Index(strings.ToLower(haystack), strings.ToLower(needle))
}

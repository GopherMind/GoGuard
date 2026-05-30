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

func (iw *injectWriter) flush() {
	if !iw.isHTML {
		return
	}

	body := iw.buf.String()

	if !strings.Contains(body, "goguard-sdk.js") {
		injectScript := fmt.Sprintf(
			`<script src="/goguard/sdk/goguard-sdk.js" data-site-key="%s"></script>`,
			iw.siteKey,
		)
		if idx := indexFoldASCII(body, "</head>"); idx >= 0 {
			body = body[:idx] + injectScript + body[idx:]
		} else {
			body = injectScript + body
		}
	}

	iw.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(len(body)))
	iw.ResponseWriter.Header().Del("Content-Encoding")
	iw.ResponseWriter.WriteHeader(iw.statusCode)
	iw.ResponseWriter.Write([]byte(body))
}

func (iw *injectWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := iw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("injectWriter: underlying ResponseWriter does not implement http.Hijacker")
	}
	return hj.Hijack()
}

func (iw *injectWriter) Flush() {
	if iw.isHTML {
		return
	}
	if f, ok := iw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func indexFoldASCII(haystack, needle string) int {
	return strings.Index(strings.ToLower(haystack), strings.ToLower(needle))
}

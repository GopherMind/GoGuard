package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// injectWriter перехватывает HTML ответы и вшивает скрипт
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
	// Инжектим скрипт в любой HTML, даже если это 403 (как для Challenge)
	if strings.Contains(ct, "text/html") {
		iw.isHTML = true
		return
	}
	iw.ResponseWriter.WriteHeader(code)
}

func (iw *injectWriter) Write(data []byte) (int, error) {
	if iw.isHTML {
		return iw.buf.Write(data)
	}
	return iw.ResponseWriter.Write(data)
}

// flush вызывается после того как proxy записал всё тело
func (iw *injectWriter) flush() {
	if !iw.isHTML {
		return
	}
	injectScript := fmt.Sprintf(`<script src="/goguard/sdk/goguard-sdk.js" data-site-key="%s"></script>`, iw.siteKey)
	body := strings.Replace(
		iw.buf.String(),
		"</head>",
		injectScript+"</head>",
		1,
	)
	iw.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(len(body)))
	iw.ResponseWriter.Header().Del("Content-Encoding") // на случай gzip
	iw.ResponseWriter.WriteHeader(iw.statusCode)
	iw.ResponseWriter.Write([]byte(body))
}

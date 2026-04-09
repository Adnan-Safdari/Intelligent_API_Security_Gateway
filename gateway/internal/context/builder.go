package context

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// NewRequestContext creates a RequestContext from an HTTP request
func NewRequestContext(r *http.Request, body string) *RequestContext {
	ip := netutil.ClientIP(r.RemoteAddr)

	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		requestID = []byte(time.Now().Format("20060102150405.000000000"))
	}

	return &RequestContext{
		RequestID:   hex.EncodeToString(requestID),
		Headers:     r.Header,
		Body:        body,
		Path:        r.URL.Path,
		Method:      r.Method,
		ClientIP:    ip,
		UserAgent:   r.UserAgent(),
		Timestamp:   time.Now(),
		QueryParams: r.URL.Query(),
		Cookies:     r.Cookies(),
	}
}

// BuildRequestContext reads the request body and creates a RequestContext
// Note: This consumes the request body, so it should be called early in the middleware chain
func BuildRequestContext(r *http.Request) (*RequestContext, error) {
	var body string
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		body = string(bodyBytes)
	}

	return NewRequestContext(r, body), nil
}

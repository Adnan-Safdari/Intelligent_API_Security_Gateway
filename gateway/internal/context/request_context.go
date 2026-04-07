package context

import (
	"net/http"
	"time"
)

// RequestContext holds all request metadata needed for security analysis
type RequestContext struct {
	RequestID   string
	Headers     http.Header
	Body        string
	Path        string
	Method      string
	ClientIP    string
	UserAgent   string
	Timestamp   time.Time
	QueryParams map[string][]string
	Cookies     []*http.Cookie
}

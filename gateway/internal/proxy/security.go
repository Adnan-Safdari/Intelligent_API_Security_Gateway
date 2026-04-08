package proxy

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---- In-memory store ----

var mu sync.Mutex
var failedAttempts = make(map[string]int)
var blockedIPs = make(map[string]time.Time)

// ---- Config (keep simple) ----

const MAX_ATTEMPTS = 5
const BLOCK_DURATION = 30 * time.Second

// ---- Helpers ----

func getIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func isBlocked(ip string) bool {
	mu.Lock()
	defer mu.Unlock()

	until, exists := blockedIPs[ip]
	return exists && time.Now().Before(until)
}

// ---- SQLi Detection ----

func isSQLi(body string) bool {
	body = strings.ToUpper(body)

	patterns := []string{
		"' OR",
		"--",
		"UNION",
		" OR 1=1",
	}

	for _, p := range patterns {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}

// ---- Security Middleware ----

func SecurityMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ip := getIP(r)

		// 1. Check if blocked
		if isBlocked(ip) {
			http.Error(w, "Blocked: Too many attempts", http.StatusForbidden)
			return
		}

		// 2. Read body (again safely)
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		bodyStr := string(bodyBytes)

		// 3. SQL Injection detection
		if isSQLi(bodyStr) {
			http.Error(w, "Blocked: SQL Injection detected", http.StatusForbidden)
			return
		}

		// 4. Capture response (for brute-force detection)
		rec := &responseRecorder{
			ResponseWriter: w,
			body:           new(bytes.Buffer),
			statusCode:     200,
		}

		next.ServeHTTP(rec, r)

		// 5. Analyze response (for login endpoint)
		if r.URL.Path == "/api/login" {

			if strings.Contains(rec.body.String(), `"success":false`) {

				mu.Lock()
				failedAttempts[ip]++

				if failedAttempts[ip] > MAX_ATTEMPTS {
					blockedIPs[ip] = time.Now().Add(BLOCK_DURATION)
				}
				mu.Unlock()

			} else {
				// reset on success
				mu.Lock()
				failedAttempts[ip] = 0
				mu.Unlock()
			}
		}
	})
}

// ---- Response Recorder ----

type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

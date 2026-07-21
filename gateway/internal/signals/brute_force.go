/*
	Brute Force Attack Detection Middleware
		- Watches login endpoints only (e.g. /api/login)
		- Counts FAILED login attempts (401/403 responses) per IP
		- Too many failures inside a time window -> security alert
		- Optionally locks the IP out for a while (429 Too Many Requests)
		- A successful login resets the counter for that IP


	Core Idea
		“ Flooding is about HOW MANY requests an IP sends.
		Brute force is about HOW MANY TIMES an IP FAILS to log in. ”

		So unlike the flood detector we cannot decide by looking at the
		request alone — we need to know how the backend responded.
		The middleware wraps the ResponseWriter in a small recorder,
		lets the request go through to the backend, and then checks
		the status code that came back.

	Password spraying vs classic brute force
		- Classic brute force : one username, many passwords
		- Password spraying   : many usernames, one password
		We also track how many DISTINCT emails an IP has tried, so the
		alert can tell the two apart.

	Lockout
		When an IP crosses the threshold we remember "locked until".
		While locked, login requests from that IP are rejected with
		429 immediately — the backend never sees them, so the attacker
		cannot keep guessing.
*/

package signals

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// bruteForceClient tracks the recent login failures for a single IP.
type bruteForceClient struct {
	Failures    []time.Time         // timestamps of failed login attempts inside the window
	Emails      map[string]struct{} // distinct emails this IP has tried (spraying indicator)
	LockedUntil time.Time           // zero value means "not locked"
}

// BruteForceDetector tracks failed login attempts per IP.
// Login endpoints are a tiny fraction of total traffic, so a single
// map + mutex is enough here (no sharding needed like the flood detector).
type BruteForceDetector struct {
	enabled     bool
	maxFailures int             // failures allowed inside the window before alerting
	window      time.Duration   // sliding window for counting failures
	lockout     time.Duration   // how long to block the IP after crossing the threshold (0 = detect only)
	loginPaths  map[string]bool // exact request paths that count as "login"

	mu      sync.Mutex
	clients map[string]*bruteForceClient
}

// NewBruteForceDetector creates a brute force detector from configuration.
func NewBruteForceDetector(cfg config.BruteForceConfig) *BruteForceDetector {
	// Sensible defaults so an empty config block still behaves
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = 5
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if len(cfg.LoginPaths) == 0 {
		cfg.LoginPaths = []string{"/api/login"}
	}

	paths := make(map[string]bool, len(cfg.LoginPaths))
	for _, p := range cfg.LoginPaths {
		paths[p] = true
	}

	bd := &BruteForceDetector{
		enabled:     cfg.Enabled,
		maxFailures: cfg.MaxFailures,
		window:      cfg.Window,
		lockout:     cfg.LockoutDuration,
		loginPaths:  paths,
		clients:     make(map[string]*bruteForceClient),
	}

	if bd.enabled {
		go bd.startCleanupTimer()
	}
	return bd
}

// startCleanupTimer removes IPs that have gone quiet so the map does not grow forever.
func (bd *BruteForceDetector) startCleanupTimer() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		now := time.Now()
		bd.mu.Lock()
		for ip, client := range bd.clients {
			stillLocked := now.Before(client.LockedUntil)
			recentFailure := len(client.Failures) > 0 &&
				now.Sub(client.Failures[len(client.Failures)-1]) <= bd.window
			if !stillLocked && !recentFailure {
				delete(bd.clients, ip)
			}
		}
		bd.mu.Unlock()
	}
}

// statusRecorder wraps a ResponseWriter so we can see which status
// code the backend replied with after the proxy has handled the request.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// Flush keeps streaming support intact — the reverse proxy relies on it.
func (sr *statusRecorder) Flush() {
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Middleware inspects login traffic for brute force patterns.
func (bd *BruteForceDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only login endpoints matter — everything else passes straight through
		if !bd.enabled || !bd.loginPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r.RemoteAddr)

		// If this IP is currently locked out, reject before touching the backend
		if bd.isLockedOut(ip) {
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", bd.lockout.Seconds()))
			http.Error(w, "Too many failed login attempts. Try again later.", http.StatusTooManyRequests)
			return
		}

		// Best-effort: pull the attempted email out of the JSON body
		// so we can tell brute force from password spraying
		email := extractEmail(r)

		// Let the request through, but record what the backend answered
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		switch {
		case rec.status == http.StatusUnauthorized || rec.status == http.StatusForbidden:
			bd.recordFailure(ip, email, r)
		case rec.status >= 200 && rec.status < 300:
			// Successful login clears the slate for this IP
			bd.reset(ip)
		}
	})
}

// isLockedOut reports whether the IP is inside an active lockout period.
func (bd *BruteForceDetector) isLockedOut(ip string) bool {
	bd.mu.Lock()
	defer bd.mu.Unlock()
	client, exists := bd.clients[ip]
	return exists && time.Now().Before(client.LockedUntil)
}

// recordFailure adds a failed attempt and raises an alert (and lockout)
// once the threshold is crossed.
func (bd *BruteForceDetector) recordFailure(ip, email string, r *http.Request) {
	now := time.Now()

	bd.mu.Lock()
	client, exists := bd.clients[ip]
	if !exists {
		client = &bruteForceClient{Emails: make(map[string]struct{})}
		bd.clients[ip] = client
	}

	// Drop failures that have aged out of the sliding window
	cutoff := now.Add(-bd.window)
	firstValid := len(client.Failures)
	for i, t := range client.Failures {
		if t.After(cutoff) {
			firstValid = i
			break
		}
	}
	client.Failures = client.Failures[firstValid:]

	client.Failures = append(client.Failures, now)
	if email != "" {
		client.Emails[email] = struct{}{}
	}

	failureCount := len(client.Failures)
	distinctEmails := len(client.Emails)

	crossed := failureCount >= bd.maxFailures
	if crossed && bd.lockout > 0 {
		client.LockedUntil = now.Add(bd.lockout)
	}
	bd.mu.Unlock()

	if crossed {
		bd.logAlert(ip, r, failureCount, distinctEmails)
	}
}

// reset clears the failure history for an IP (called after a successful login).
func (bd *BruteForceDetector) reset(ip string) {
	bd.mu.Lock()
	delete(bd.clients, ip)
	bd.mu.Unlock()
}

// extractEmail reads the request body (and restores it for the next handler)
// and returns the "email" field if the body is JSON. Failures are fine —
// this is only used to enrich the alert.
func extractEmail(r *http.Request) string {
	bodyBytes, err := readAndRestoreBody(r)
	if err != nil || len(bodyBytes) == 0 {
		return ""
	}
	var payload struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(bodyBytes, &payload) != nil {
		return ""
	}
	return payload.Email
}

// logAlert prints a high-visibility security alert to the console.
func (bd *BruteForceDetector) logAlert(ip string, r *http.Request, failures, distinctEmails int) {
	severity := "LOW"
	if failures >= bd.maxFailures*5 {
		severity = "HIGH"
	} else if failures >= bd.maxFailures*2 {
		severity = "MEDIUM"
	}

	// Many distinct emails from one IP looks like password spraying,
	// hammering one account looks like a classic brute force
	attackType := "BRUTE FORCE (single account)"
	if distinctEmails > 3 {
		attackType = "PASSWORD SPRAYING (multiple accounts)"
	}

	action := "DETECTED (ALLOWING REQUEST)"
	if bd.lockout > 0 {
		action = fmt.Sprintf("IP LOCKED OUT FOR %s", bd.lockout)
	}

	fmt.Printf(`
			========================================
			SECURITY ALERT: BRUTE FORCE DETECTED
			----------------------------------------
			IP Address     : %s
			Endpoint       : %s
			Failed Logins  : %d
			Distinct Users : %d
			Attack Type    : %s
			Time Window    : %s
			User-Agent     : %s
			Severity       : %s
			Timestamp      : %s
			ACTION         : %s
			========================================
			`,
		ip,
		r.URL.Path,
		failures,
		distinctEmails,
		attackType,
		bd.window,
		r.Header.Get("User-Agent"),
		severity,
		time.Now().Format(time.RFC3339),
		action,
	)
}

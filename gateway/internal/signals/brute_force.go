/*
	Brute Force Attack Detection Signal
		- Watches login endpoints only (e.g. /api/login)
		- Counts FAILED login attempts (401/403 responses) per IP
		- Too many failures inside a time window -> security alert + metrics
		- A successful login resets the counter for that IP
		- DOES NOT BLOCK. Every request is forwarded to the backend.


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

	Detection only — no enforcement (team decision)
		Detectors produce EVIDENCE; the centralized decision engine produces
		POLICY. This detector therefore never returns 403/429 on its own.
		It records evidence and exposes it through Metrics(ip), which the
		future risk-scoring / decision engine will consume alongside the
		other signals to make one combined Allow / Throttle / Block call.
*/

package signals

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

func (bd *BruteForceDetector) Name() string { return SignalBruteForce }

// bruteForceClient tracks the recent login failures for a single IP.
type bruteForceClient struct {
	Failures []time.Time         // timestamps of failed login attempts inside the window
	Emails   map[string]struct{} // distinct emails this IP has tried (spraying indicator)
}

// BruteForceDetector tracks failed login attempts per IP.
// Login endpoints are a tiny fraction of total traffic, so a single
// map + mutex is enough here (no sharding needed like the flood detector).
// bruteTunables is what the console can move at runtime, swapped whole so a
// request never sees a new threshold against an old window.
type bruteTunables struct {
	maxFailures int             // failures inside the window before the signal fires
	window      time.Duration   // sliding window for counting failures
	loginPaths  map[string]bool // exact request paths that count as "login"
	enabled     bool
}

type BruteForceDetector struct {
	tun atomic.Pointer[bruteTunables]

	mu      sync.Mutex
	clients map[string]*bruteForceClient
}

func (bd *BruteForceDetector) settings() bruteTunables { return *bd.tun.Load() }

// Apply swaps in new settings. Recorded failures are kept: someone part-way
// through guessing a password should not be handed a fresh allowance because
// the window was edited.
func (bd *BruteForceDetector) Apply(cfg config.BruteForceConfig) {
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
	bd.tun.Store(&bruteTunables{
		enabled:     cfg.Enabled,
		maxFailures: cfg.MaxFailures,
		window:      cfg.Window,
		loginPaths:  paths,
	})
}

// NewBruteForceDetector creates a brute force detector from configuration.
func NewBruteForceDetector(cfg config.BruteForceConfig) *BruteForceDetector {
	bd := &BruteForceDetector{clients: make(map[string]*bruteForceClient)}
	// Apply supplies the defaults, so there is one place that decides what an
	// empty config block means.
	bd.Apply(cfg)

	// Started unconditionally: the detector can be switched on from the console
	// later, and a sweeper that only exists when it booted enabled would let
	// the client map grow without bound from that point on.
	go bd.startCleanupTimer()
	return bd
}

// startCleanupTimer removes IPs that have gone quiet so the map does not grow forever.
func (bd *BruteForceDetector) startCleanupTimer() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		now := time.Now()
		bd.mu.Lock()
		for ip, client := range bd.clients {
			if len(client.Failures) == 0 ||
				now.Sub(client.Failures[len(client.Failures)-1]) > bd.settings().window {
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
// It always forwards the request; enforcement belongs to the decision engine.
func (bd *BruteForceDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only login endpoints matter — everything else passes straight through
		tun := bd.settings()
		if !tun.enabled || !tun.loginPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)

		// Best-effort: pull the attempted email out of the JSON body
		// so we can tell brute force from password spraying
		email := extractEmail(r)

		// Forward the request, but record what the backend answered
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

// recordFailure adds a failed attempt and raises an alert once the
// threshold is crossed. The request itself has already been forwarded.
func (bd *BruteForceDetector) recordFailure(ip, email string, r *http.Request) {
	now := time.Now()
	tun := bd.settings()

	bd.mu.Lock()
	client, exists := bd.clients[ip]
	if !exists {
		client = &bruteForceClient{Emails: make(map[string]struct{})}
		bd.clients[ip] = client
	}

	// Drop failures that have aged out of the sliding window
	cutoff := now.Add(-tun.window)
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
	bd.mu.Unlock()

	if failureCount >= tun.maxFailures {
		bd.logAlert(ip, r, failureCount, distinctEmails, tun.maxFailures)
	}
}

// Metrics returns brute-force evidence for an IP. Safe to call concurrently.
func (bd *BruteForceDetector) Metrics(ip string) Evidence {
	tun := bd.settings()

	bd.mu.Lock()
	defer bd.mu.Unlock()

	ev := Evidence{
		Signal: SignalBruteForce,
		Details: map[string]any{
			"failedLogins":  0,
			"distinctUsers": 0,
			"maxFailures":   tun.maxFailures,
			"window":        tun.window.String(),
		},
	}

	client, exists := bd.clients[ip]
	if !exists {
		return ev
	}

	cutoff := time.Now().Add(-tun.window)
	failures := 0
	for _, t := range client.Failures {
		if t.After(cutoff) {
			failures++
		}
	}
	distinct := len(client.Emails)
	crossed := failures >= tun.maxFailures

	ev.Details["failedLogins"] = failures
	ev.Details["distinctUsers"] = distinct
	ev.Score = bruteForceScore(failures, tun.maxFailures, distinct)
	ev.ThresholdCross = crossed
	if crossed {
		ev.AttackType = classifyAttack(distinct)
	}
	return ev
}

func bruteForceScore(failures, maxFailures, distinctEmails int) int {
	score := ratioScore(failures, maxFailures)
	if failures >= maxFailures && distinctEmails > 3 {
		score = clampScore(score + 10)
	}
	return score
}

// reset clears the failure history for an IP (called after a successful login).
func (bd *BruteForceDetector) reset(ip string) {
	bd.mu.Lock()
	delete(bd.clients, ip)
	bd.mu.Unlock()
}

// classifyAttack labels the attack shape: many distinct accounts from one IP
// looks like spraying, hammering a single account is classic brute force.
func classifyAttack(distinctEmails int) string {
	if distinctEmails > 3 {
		return "password_spraying"
	}
	return "brute_force"
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
func (bd *BruteForceDetector) logAlert(ip string, r *http.Request, failures, distinctEmails, maxFailures int) {
	severity := "LOW"
	if failures >= maxFailures*5 {
		severity = "HIGH"
	} else if failures >= maxFailures*2 {
		severity = "MEDIUM"
	}

	attackType := "BRUTE FORCE (single account)"
	if classifyAttack(distinctEmails) == "password_spraying" {
		attackType = "PASSWORD SPRAYING (multiple accounts)"
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
			ACTION         : DETECTED (ALLOWING REQUEST)
			========================================
			`,
		ip,
		r.URL.Path,
		failures,
		distinctEmails,
		attackType,
		bd.settings().window,
		r.Header.Get("User-Agent"),
		severity,
		time.Now().Format(time.RFC3339),
	)
}

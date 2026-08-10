package signals

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

// shortWindowDetector builds a detector with a deliberately tiny window so the
// sliding-window expiry can be exercised without a slow test.
func shortWindowDetector(maxFailures int, window time.Duration) *BruteForceDetector {
	return NewBruteForceDetector(config.BruteForceConfig{
		Enabled:     true,
		MaxFailures: maxFailures,
		Window:      window,
		LoginPaths:  []string{"/api/login"},
	})
}

// The sliding window is the heart of the detector: failures older than the
// window must stop counting. Without this, a user who mistypes their password
// occasionally over days would eventually be reported as an attacker.
func TestBruteForceWindowExpiresOldFailures(t *testing.T) {
	window := 150 * time.Millisecond
	bd := shortWindowDetector(3, window)
	handler := bd.Middleware(failingLoginBackend())

	// Two failures now — one short of the threshold.
	for i := 0; i < 2; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), loginRequest("10.1.0.1", "user@example.com"))
	}
	if m := bd.Metrics("10.1.0.1"); m.FailedLogins != 2 {
		t.Fatalf("expected 2 failures inside the window, got %d", m.FailedLogins)
	}

	// Let them age out of the window.
	time.Sleep(window + 50*time.Millisecond)

	if m := bd.Metrics("10.1.0.1"); m.FailedLogins != 0 {
		t.Fatalf("failures older than the window must not count, got %d", m.FailedLogins)
	}

	// Two more failures. Four total, but never 3 within one window.
	for i := 0; i < 2; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), loginRequest("10.1.0.1", "user@example.com"))
	}

	m := bd.Metrics("10.1.0.1")
	if m.FailedLogins != 2 {
		t.Fatalf("expected only the 2 recent failures to count, got %d", m.FailedLogins)
	}
	if m.ThresholdCross {
		t.Fatal("4 failures spread across two windows must not cross a threshold of 3")
	}
}

// The opposite case: the same number of failures packed inside one window
// must cross the threshold.
func TestBruteForceBurstInsideWindowTriggers(t *testing.T) {
	bd := shortWindowDetector(3, time.Second)
	handler := bd.Middleware(failingLoginBackend())

	for i := 0; i < 3; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), loginRequest("10.1.0.2", "user@example.com"))
	}

	if m := bd.Metrics("10.1.0.2"); !m.ThresholdCross {
		t.Fatalf("3 failures inside a 1s window must cross a threshold of 3, got %+v", m)
	}
}

// extractEmail reads the request body. If it fails to restore it, the proxy
// would forward an empty body and every login would break — a far worse bug
// than a missed detection. This asserts the backend still sees the full JSON.
func TestBruteForcePreservesRequestBody(t *testing.T) {
	var seen string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = string(b)
		w.WriteHeader(http.StatusUnauthorized)
	})

	bd := testDetector(5)
	handler := bd.Middleware(backend)
	handler.ServeHTTP(httptest.NewRecorder(), loginRequest("10.1.0.3", "victim@example.com"))

	want := `{"email":"victim@example.com","password":"guess"}`
	if seen != want {
		t.Fatalf("backend must receive the untouched body.\n  want: %s\n  got:  %s", want, seen)
	}

	// And it must still be valid JSON the backend can parse.
	var payload map[string]string
	if err := json.Unmarshal([]byte(seen), &payload); err != nil {
		t.Fatalf("forwarded body is not valid JSON: %v", err)
	}
	if payload["password"] != "guess" {
		t.Fatalf("password field lost in transit: %+v", payload)
	}
}

// The detector shares one map across every request goroutine. Run with
// `go test -race` to prove the mutex actually protects it.
func TestBruteForceConcurrentRequestsAreSafe(t *testing.T) {
	bd := testDetector(50)
	handler := bd.Middleware(failingLoginBackend())

	const goroutines, perGoroutine = 20, 25

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := "10.2.0." + string(rune('0'+id%10))
			for i := 0; i < perGoroutine; i++ {
				handler.ServeHTTP(httptest.NewRecorder(), loginRequest(ip, "user@example.com"))
				// Interleave reads with writes — Metrics takes the same lock.
				_ = bd.Metrics(ip)
			}
		}(g)
	}
	wg.Wait()

	// Every request was a failure, so the totals must add up exactly.
	total := 0
	for d := 0; d < 10; d++ {
		total += bd.Metrics("10.2.0." + string(rune('0'+d))).FailedLogins
	}
	if want := goroutines * perGoroutine; total != want {
		t.Fatalf("lost updates under concurrency: counted %d, expected %d", total, want)
	}
}

// One IP crossing the threshold must not implicate anyone else. Per-IP
// isolation is what stops an attacker from getting innocent users flagged.
func TestBruteForcePerIPIsolation(t *testing.T) {
	bd := testDetector(3)
	handler := bd.Middleware(failingLoginBackend())

	// Attacker hammers the endpoint.
	for i := 0; i < 5; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), loginRequest("10.3.0.1", "admin"))
	}
	// An innocent user mistypes once.
	handler.ServeHTTP(httptest.NewRecorder(), loginRequest("10.3.0.2", "alice@example.com"))

	if m := bd.Metrics("10.3.0.1"); !m.ThresholdCross {
		t.Fatal("attacker IP should have crossed the threshold")
	}
	if m := bd.Metrics("10.3.0.2"); m.ThresholdCross {
		t.Fatal("innocent IP must not be implicated by another IP's failures")
	}
	if m := bd.Metrics("10.3.0.2"); m.FailedLogins != 1 {
		t.Fatalf("innocent IP should show exactly its own 1 failure, got %d", m.FailedLogins)
	}
}

// 403 Forbidden is a rejected login too — some backends use it instead of 401.
func TestBruteForceCounts403AsFailure(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	bd := testDetector(3)
	handler := bd.Middleware(backend)
	for i := 0; i < 3; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), loginRequest("10.4.0.1", "admin"))
	}

	if m := bd.Metrics("10.4.0.1"); !m.ThresholdCross {
		t.Fatalf("403 responses must count as failed logins, got %+v", m)
	}
}

// A 500 from the backend is not a failed login — it's a broken backend.
// Counting it would turn an outage into a false attack report.
func TestBruteForceIgnoresServerErrors(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	bd := testDetector(3)
	handler := bd.Middleware(backend)
	for i := 0; i < 5; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), loginRequest("10.4.0.2", "admin"))
	}

	if m := bd.Metrics("10.4.0.2"); m.FailedLogins != 0 {
		t.Fatalf("5xx responses must not count as failed logins, got %d", m.FailedLogins)
	}
}

// Bodies that aren't the expected JSON must never panic the gateway — the
// detector degrades to counting the failure without an email.
func TestBruteForceHandlesMalformedBodies(t *testing.T) {
	bodies := []string{
		``,                   // empty
		`not json at all`,    // garbage
		`{"email": 12345}`,   // wrong type
		`{"password":"x"}`,   // missing email
		`{"email":"a@b.com"`, // truncated JSON
		`[1,2,3]`,            // JSON, but not an object
	}

	bd := testDetector(100)
	handler := bd.Middleware(failingLoginBackend())

	for _, body := range bodies {
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
		req.RemoteAddr = "10.5.0.1:1000"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req) // must not panic

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("body %q: request should still reach the backend, got %d", body, rec.Code)
		}
	}

	// All of them were failures, even though most had no readable email.
	if m := bd.Metrics("10.5.0.1"); m.FailedLogins != len(bodies) {
		t.Fatalf("expected %d failures recorded, got %d", len(bodies), m.FailedLogins)
	}
}

// An empty config block must still produce a working detector, so a missing
// YAML section doesn't silently disable detection with nonsense thresholds.
func TestBruteForceConfigDefaults(t *testing.T) {
	bd := NewBruteForceDetector(config.BruteForceConfig{Enabled: true})

	if bd.maxFailures != 5 {
		t.Errorf("expected default maxFailures 5, got %d", bd.maxFailures)
	}
	if bd.window != time.Minute {
		t.Errorf("expected default window 1m, got %s", bd.window)
	}
	if !bd.loginPaths["/api/login"] {
		t.Errorf("expected /api/login to be watched by default, got %v", bd.loginPaths)
	}
}

// Multiple configured login paths must all be watched.
func TestBruteForceWatchesAllConfiguredPaths(t *testing.T) {
	bd := NewBruteForceDetector(config.BruteForceConfig{
		Enabled:     true,
		MaxFailures: 10,
		Window:      time.Minute,
		LoginPaths:  []string{"/api/login", "/api/v2/signin", "/admin/auth"},
	})
	handler := bd.Middleware(failingLoginBackend())

	for _, path := range []string{"/api/login", "/api/v2/signin", "/admin/auth"} {
		req := httptest.NewRequest(http.MethodPost, path,
			strings.NewReader(`{"email":"a@b.com","password":"x"}`))
		req.RemoteAddr = "10.6.0.1:1000"
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	if m := bd.Metrics("10.6.0.1"); m.FailedLogins != 3 {
		t.Fatalf("all 3 configured login paths should be watched, counted %d", m.FailedLogins)
	}
}

// The classifier boundary: 3 distinct users is brute force, 4 is spraying.
func TestBruteForceAttackClassificationBoundary(t *testing.T) {
	cases := []struct {
		distinctEmails int
		want           string
	}{
		{1, "brute_force"},
		{3, "brute_force"},
		{4, "password_spraying"},
		{10, "password_spraying"},
	}

	for _, tc := range cases {
		if got := classifyAttack(tc.distinctEmails); got != tc.want {
			t.Errorf("classifyAttack(%d) = %q, want %q", tc.distinctEmails, got, tc.want)
		}
	}
}

// Measures the per-request cost the detector adds. Run with:
//
//	go test ./internal/signals/ -bench=BruteForce -benchmem
//
// The result is the latency figure to quote when arguing that detection is
// effectively free compared to the ~1ms the proxy hop itself costs.
func BenchmarkBruteForceMiddleware(b *testing.B) {
	bd := testDetector(1000000) // high threshold: never alerts, so we time the hot path
	handler := bd.Middleware(failingLoginBackend())

	body := `{"email":"user@example.com","password":"guess"}`

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
		req.RemoteAddr = "10.9.0.1:1000"
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
}

// Baseline for comparison: the same requests with no detector in the chain.
// The difference between the two benchmarks is the detector's true overhead.
func BenchmarkBaselineNoDetector(b *testing.B) {
	handler := failingLoginBackend()
	body := `{"email":"user@example.com","password":"guess"}`

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
		req.RemoteAddr = "10.9.0.1:1000"
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
}

package signals

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

// failingLoginBackend simulates a backend that rejects every login attempt.
func failingLoginBackend() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
}

func loginRequest(ip, email string) *http.Request {
	body := strings.NewReader(`{"email":"` + email + `","password":"guess"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/login", body)
	req.RemoteAddr = ip + ":54321"
	return req
}

func testDetector(maxFailures int) *BruteForceDetector {
	return NewBruteForceDetector(config.BruteForceConfig{
		Enabled:     true,
		MaxFailures: maxFailures,
		Window:      time.Minute,
		LoginPaths:  []string{"/api/login"},
	})
}

// The detector must never block: every request reaches the backend and the
// backend's own status is what the client sees. Enforcement is the decision
// engine's job, not the detector's.
func TestBruteForceNeverBlocks(t *testing.T) {
	backendCalls := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusUnauthorized)
	})

	bd := testDetector(3)
	handler := bd.Middleware(backend)

	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, loginRequest("10.0.0.1", "victim@example.com"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: detector must not alter the response, got %d", i+1, rec.Code)
		}
	}

	if backendCalls != 10 {
		t.Fatalf("all 10 requests must reach the backend, got %d", backendCalls)
	}
}

func TestBruteForceMetricsAfterThreshold(t *testing.T) {
	bd := testDetector(5)
	handler := bd.Middleware(failingLoginBackend())

	for i := 0; i < 5; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), loginRequest("10.0.0.2", "victim@example.com"))
	}

	m := bd.Metrics("10.0.0.2")
	if m.FailedLogins != 5 {
		t.Fatalf("expected 5 failed logins, got %d", m.FailedLogins)
	}
	if !m.ThresholdCross {
		t.Fatal("expected threshold to be crossed")
	}
	if m.AttackType != "brute_force" {
		t.Fatalf("expected brute_force, got %q", m.AttackType)
	}
	if m.DistinctUsers != 1 {
		t.Fatalf("expected 1 distinct user, got %d", m.DistinctUsers)
	}
}

func TestBruteForceMetricsBelowThreshold(t *testing.T) {
	bd := testDetector(5)
	handler := bd.Middleware(failingLoginBackend())

	for i := 0; i < 3; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), loginRequest("10.0.0.3", "victim@example.com"))
	}

	m := bd.Metrics("10.0.0.3")
	if m.FailedLogins != 3 {
		t.Fatalf("expected 3 failed logins, got %d", m.FailedLogins)
	}
	if m.ThresholdCross {
		t.Fatal("threshold must not be crossed at 3 of 5 failures")
	}
	if m.AttackType != "" {
		t.Fatalf("attack type must be empty below threshold, got %q", m.AttackType)
	}
}

func TestBruteForceDetectsPasswordSpraying(t *testing.T) {
	bd := testDetector(5)
	handler := bd.Middleware(failingLoginBackend())

	// One IP, five different accounts, same password: spraying
	for i := 0; i < 5; i++ {
		email := string(rune('a'+i)) + "@example.com"
		handler.ServeHTTP(httptest.NewRecorder(), loginRequest("10.0.0.4", email))
	}

	m := bd.Metrics("10.0.0.4")
	if m.DistinctUsers != 5 {
		t.Fatalf("expected 5 distinct users, got %d", m.DistinctUsers)
	}
	if m.AttackType != "password_spraying" {
		t.Fatalf("expected password_spraying, got %q", m.AttackType)
	}
}

func TestBruteForceSuccessResetsMetrics(t *testing.T) {
	// Backend fails twice, then accepts the login
	calls := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= 2 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	bd := testDetector(5)
	handler := bd.Middleware(backend)

	for i := 0; i < 3; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), loginRequest("10.0.0.5", "user@example.com"))
	}

	if m := bd.Metrics("10.0.0.5"); m.FailedLogins != 0 {
		t.Fatalf("successful login must clear the history, got %d failures", m.FailedLogins)
	}
}

func TestBruteForceIgnoresNonLoginPaths(t *testing.T) {
	bd := testDetector(1)
	handler := bd.Middleware(failingLoginBackend())

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/products", nil)
		req.RemoteAddr = "10.0.0.9:1000"
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	if m := bd.Metrics("10.0.0.9"); m.FailedLogins != 0 {
		t.Fatalf("non-login paths must not be counted, got %d", m.FailedLogins)
	}
}

func TestBruteForceDisabledCollectsNothing(t *testing.T) {
	bd := NewBruteForceDetector(config.BruteForceConfig{Enabled: false})
	handler := bd.Middleware(failingLoginBackend())

	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, loginRequest("10.0.0.7", "a@b.com"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("disabled detector must pass through, got %d", rec.Code)
		}
	}

	if m := bd.Metrics("10.0.0.7"); m.FailedLogins != 0 {
		t.Fatalf("disabled detector must collect nothing, got %d", m.FailedLogins)
	}
}

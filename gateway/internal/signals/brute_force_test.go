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

func TestBruteForceLockoutAfterMaxFailures(t *testing.T) {
	bd := NewBruteForceDetector(config.BruteForceConfig{
		Enabled:         true,
		MaxFailures:     3,
		Window:          time.Minute,
		LockoutDuration: time.Minute,
		LoginPaths:      []string{"/api/login"},
	})
	handler := bd.Middleware(failingLoginBackend())

	// First 3 failures reach the backend and come back 401
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, loginRequest("10.0.0.1", "victim@example.com"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
		}
	}

	// The 4th attempt should be rejected by the gateway itself
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, loginRequest("10.0.0.1", "victim@example.com"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after lockout, got %d", rec.Code)
	}

	// A different IP is unaffected
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, loginRequest("10.0.0.2", "victim@example.com"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("other IP: expected 401, got %d", rec.Code)
	}
}

func TestBruteForceSuccessResetsCounter(t *testing.T) {
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

	bd := NewBruteForceDetector(config.BruteForceConfig{
		Enabled:         true,
		MaxFailures:     3,
		Window:          time.Minute,
		LockoutDuration: time.Minute,
	})
	handler := bd.Middleware(backend)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, loginRequest("10.0.0.5", "user@example.com"))
		if i < 2 && rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
		}
		if i == 2 && rec.Code != http.StatusOK {
			t.Fatalf("expected successful login, got %d", rec.Code)
		}
	}

	// Success wiped the history, so two fresh failures must not trigger a lockout
	if bd.isLockedOut("10.0.0.5") {
		t.Fatal("IP should not be locked out after a successful login")
	}
}

func TestBruteForceIgnoresNonLoginPaths(t *testing.T) {
	bd := NewBruteForceDetector(config.BruteForceConfig{
		Enabled:         true,
		MaxFailures:     1,
		Window:          time.Minute,
		LockoutDuration: time.Minute,
	})
	handler := bd.Middleware(failingLoginBackend())

	// Hammer a non-login path with 401s — no lockout should happen
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/products", nil)
		req.RemoteAddr = "10.0.0.9:1000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 passthrough, got %d", rec.Code)
		}
	}
	if bd.isLockedOut("10.0.0.9") {
		t.Fatal("non-login paths must not contribute to lockout")
	}
}

func TestBruteForceDisabledPassesThrough(t *testing.T) {
	bd := NewBruteForceDetector(config.BruteForceConfig{Enabled: false})
	handler := bd.Middleware(failingLoginBackend())

	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, loginRequest("10.0.0.7", "a@b.com"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("disabled detector must pass through, got %d", rec.Code)
		}
	}
}

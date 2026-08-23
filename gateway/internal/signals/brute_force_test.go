package signals

import (
	"net/http"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

func newBruteForceTestDetector() *BruteForceDetector {
	return NewBruteForceDetector(config.BruteForceConfig{
		Enabled:     true,
		MaxFailures: 5,
		Window:      time.Minute,
		LoginPaths:  []string{"/api/login"},
	})
}

func TestBruteForceSuccessfulLoginResetsFailures(t *testing.T) {
	const ip = "203.0.113.45"
	detector := newBruteForceTestDetector()
	success := false
	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if success {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))

	for i := 0; i < 5; i++ {
		probe(handler, http.MethodPost, "/api/login", ip, "")
	}
	if !detector.Metrics(ip).ThresholdCross {
		t.Fatal("five failed logins did not fire the detector")
	}

	success = true
	if rec := probe(handler, http.MethodPost, "/api/login", ip, ""); rec.Code != http.StatusOK {
		t.Fatalf("successful login status = %d, want 200", rec.Code)
	}

	ev := detector.Metrics(ip)
	if ev.Int("failedLogins") != 0 || ev.ThresholdCross || ev.Score != 0 {
		t.Fatalf("successful login did not reset state: %+v", ev)
	}
}

func TestBruteForceExpiredFailuresFallOutOfWindow(t *testing.T) {
	const ip = "203.0.113.46"
	detector := newBruteForceTestDetector()
	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	for i := 0; i < 5; i++ {
		probe(handler, http.MethodPost, "/api/login", ip, "")
	}

	// Age the saved evidence beyond the detector's one-minute sliding window.
	detector.mu.Lock()
	for i := range detector.clients[ip].Failures {
		detector.clients[ip].Failures[i] = time.Now().Add(-2 * time.Minute)
	}
	detector.mu.Unlock()

	ev := detector.Metrics(ip)
	if ev.Int("failedLogins") != 0 || ev.ThresholdCross || ev.Score != 0 {
		t.Fatalf("expired failures remained active: %+v", ev)
	}
}

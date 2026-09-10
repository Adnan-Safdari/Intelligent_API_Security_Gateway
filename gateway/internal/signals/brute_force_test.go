package signals

import (
	"net/http"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

var loginOutcomes = []config.AuthOutcomeConfig{{
	Method: "POST", Template: "/api/login", Success: []int{http.StatusOK}, InvalidCredentials: []int{http.StatusUnauthorized},
}}

func loginMatch(method, path string) string {
	if method == http.MethodPost && path == "/api/login" {
		return "/api/login"
	}
	return unmatchedRoute
}

func newBruteForceTestDetector() *BruteForceDetector {
	return NewBruteForceDetector(config.BruteForceConfig{
		Enabled: true, MaxFailures: 5, Window: time.Minute,
	}, loginOutcomes, loginMatch)
}

func TestBruteForceConfiguredSuccessResetsOnlyItsTarget(t *testing.T) {
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
		probe(handler, http.MethodPost, "/api/login", ip, `{"username":"alice"}`)
	}
	for i := 0; i < 4; i++ {
		probe(handler, http.MethodPost, "/api/login", ip, `{"username":"bob"}`)
	}
	if !detector.Metrics(ip).ThresholdCross {
		t.Fatal("five configured invalid credentials did not fire the detector")
	}

	success = true
	probe(handler, http.MethodPost, "/api/login", ip, `{"username":"alice"}`)
	ev := detector.Metrics(ip)
	if ev.Int("consecutiveFailures") != 4 || ev.ThresholdCross || ev.Details["target"] != "bob" {
		t.Fatalf("successful alice login reset unrelated target or left own streak: %+v", ev)
	}
}

func TestBruteForceUsesOnlyConfiguredBackendOutcomes(t *testing.T) {
	const ip = "203.0.113.46"
	detector := newBruteForceTestDetector()
	status := http.StatusForbidden
	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))

	for i := 0; i < 6; i++ {
		probe(handler, http.MethodPost, "/api/login", ip, "")
	}
	if got := detector.Metrics(ip).Int("consecutiveFailures"); got != 0 {
		t.Fatalf("unconfigured 403 counted as invalid credentials: %d", got)
	}

	status = http.StatusUnauthorized
	for i := 0; i < 6; i++ {
		probe(handler, http.MethodGet, "/api/login", ip, "")
	}
	if got := detector.Metrics(ip).Int("consecutiveFailures"); got != 0 {
		t.Fatalf("a non-login route's 401 counted as a login failure: %d", got)
	}
}

func TestBruteForceExpiredStreakFallsOutOfWindow(t *testing.T) {
	const ip = "203.0.113.47"
	detector := newBruteForceTestDetector()
	tun := detector.settings()
	detector.recordFailure(ip, "/api/login", "alice", time.Now().Add(-2*time.Minute), tun)

	ev := detector.Metrics(ip)
	if ev.Int("consecutiveFailures") != 0 || ev.ThresholdCross || ev.Score != 0 {
		t.Fatalf("expired streak remained active: %+v", ev)
	}
}

func TestBruteForceNeverBlocks(t *testing.T) {
	detector := newBruteForceTestDetector()
	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("backend reached"))
	}))

	rec := probe(handler, http.MethodPost, "/api/login", "203.0.113.48", "")
	if rec.Code != http.StatusUnauthorized || rec.Body.String() != "backend reached" {
		t.Fatalf("detector changed the backend response: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

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
		Enabled: true, MaxFailures: 5, Window: time.Minute, MaxClients: 10, MaxTargetsPerClient: 10,
	}, loginOutcomes, loginMatch)
}

func TestBruteForceConsecutiveFailuresEmitEvidence(t *testing.T) {
	const ip = "203.0.113.44"
	detector := newBruteForceTestDetector()
	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	for i := 0; i < 5; i++ {
		probe(handler, http.MethodPost, "/api/login", ip, `{"username":"alice"}`)
	}
	if ev := detector.Metrics(ip); !ev.ThresholdCross || ev.AttackType != SignalBruteForce || ev.Int("consecutiveFailures") != 5 {
		t.Fatalf("five invalid credentials did not emit brute-force evidence: %+v", ev)
	}
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

func TestBruteForceReportsOnlyThresholdCrossingTargetsAsDistinctUsers(t *testing.T) {
	const ip = "203.0.113.54"
	detector := newBruteForceTestDetector()
	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	for _, username := range []string{"alice", "bob", "carol", "dana"} {
		for i := 0; i < 5; i++ {
			probe(handler, http.MethodPost, "/api/login", ip, `{"username":"`+username+`"}`)
		}
	}
	// A password spray is many accounts each crossing the failure threshold,
	// not one attacked account plus a few unrelated login mistakes.
	if got := detector.Metrics(ip).Int("distinctUsers"); got != 4 {
		t.Fatalf("distinct threshold-crossing users = %d, want 4", got)
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

func TestBruteForceGatewayRefusalDoesNotContaminateStreak(t *testing.T) {
	const ip = "203.0.113.49"
	detector := newBruteForceTestDetector()
	status := http.StatusUnauthorized
	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))

	for i := 0; i < 4; i++ {
		probe(handler, http.MethodPost, "/api/login", ip, `{"username":"alice"}`)
	}
	// A policy/reflex refusal did not reach the backend, so it is not a
	// configured credential outcome and cannot turn four bad passwords into
	// a five-failure streak.
	status = http.StatusForbidden
	probe(handler, http.MethodPost, "/api/login", ip, `{"username":"alice"}`)
	if ev := detector.Metrics(ip); ev.ThresholdCross || ev.Int("consecutiveFailures") != 4 {
		t.Fatalf("gateway refusal changed the credential streak: %+v", ev)
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

func TestBruteForceStateIsBoundedAndCleanedUp(t *testing.T) {
	detector := NewBruteForceDetector(config.BruteForceConfig{
		Enabled: true, MaxFailures: 5, Window: time.Minute, MaxClients: 2, MaxTargetsPerClient: 2,
	}, loginOutcomes, loginMatch)
	tun := detector.settings()
	now := time.Now()

	for _, target := range []string{"alice", "bob", "carol"} {
		detector.recordFailure("203.0.113.50", "/api/login", target, now.Add(time.Duration(len(target))*time.Millisecond), tun)
	}
	detector.recordFailure("203.0.113.51", "/api/login", "alice", now, tun)
	detector.recordFailure("203.0.113.52", "/api/login", "alice", now.Add(time.Second), tun)

	detector.mu.Lock()
	clients := len(detector.clients)
	targets := len(detector.clients["203.0.113.50"])
	detector.mu.Unlock()
	if clients != 2 || targets != 2 {
		t.Fatalf("brute-force state is not bounded: clients=%d targets=%d", clients, targets)
	}

	detector.recordFailure("203.0.113.53", "/api/login", "old", now.Add(-2*time.Minute), tun)
	if ev := detector.Metrics("203.0.113.53"); ev.Int("consecutiveFailures") != 0 {
		t.Fatalf("expired streak remained observable: %+v", ev)
	}
	detector.mu.Lock()
	_, retained := detector.clients["203.0.113.53"]
	detector.mu.Unlock()
	if retained {
		t.Fatal("expired client state was not cleaned up")
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

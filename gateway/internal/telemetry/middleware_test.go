package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// captureWriter stands in for Redis and keeps what telemetry recorded.
type captureWriter struct {
	events []Event
}

func (c *captureWriter) WriteEvent(_ context.Context, ev Event) error {
	c.events = append(c.events, ev)
	return nil
}

func (c *captureWriter) last() Event {
	return c.events[len(c.events)-1]
}

// silenceAlerts hides the detectors' stdout alerts for the duration of fn, so
// a test that deliberately sends an attack does not litter the run output.
func silenceAlerts(t *testing.T, fn func()) {
	t.Helper()

	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, r)
		close(done)
	}()

	fn()

	_ = w.Close()
	os.Stdout = original
	<-done
}

func send(t *testing.T, handler http.Handler, method, target, ip, body string) {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.RemoteAddr = ip + ":54321"
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

func firedContains(ev Event, signal string) bool {
	for _, name := range ev.Fired {
		if name == signal {
			return true
		}
	}
	return false
}

// A request the enforcer answers never reaches the detectors. Telemetry must
// then report no signals rather than the attack that got the address blocked:
// the control plane turns every name in Fired into a fresh piece of evidence,
// so replaying one would keep a campaign alive on traffic nobody inspected.
func TestBlockedRequestReportsNoSignalsOfItsOwn(t *testing.T) {
	const attacker = "203.0.113.7"

	sqli := signals.NewSQLiDetector(signals.DefaultSQLiDetectorConfig())
	collector := signals.NewCollector(sqli)
	writer := &captureWriter{}

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// The chain as it runs when a request is inspected.
	inspected := Middleware(writer, collector)(sqli.Middleware(backend))

	// The chain as it runs once the address is under a block: the enforcer
	// answers before the detectors get a turn.
	enforced := Middleware(writer, collector)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	silenceAlerts(t, func() {
		send(t, inspected, http.MethodPost, "/api/login", attacker, `{"email":"' OR 1=1--"}`)
	})

	attack := writer.last()
	if !firedContains(attack, signals.SignalSQLi) {
		t.Fatalf("the attack itself should fire sql_injection, got %v", attack.Fired)
	}

	// Same address, a clean request, blocked before any detector sees it.
	send(t, enforced, http.MethodGet, "/api/health", attacker, "")

	blockedEvent := writer.last()
	if firedContains(blockedEvent, signals.SignalSQLi) {
		t.Fatalf("a blocked request replayed the earlier attack: fired=%v", blockedEvent.Fired)
	}
	if len(blockedEvent.Fired) != 0 {
		t.Fatalf("expected no signals for an uninspected request, got %v", blockedEvent.Fired)
	}
	if blockedEvent.RiskScore != 0 {
		t.Fatalf("expected no risk score for an uninspected request, got %d", blockedEvent.RiskScore)
	}
	if blockedEvent.Status != http.StatusForbidden {
		t.Fatalf("expected the block to be recorded, got status %d", blockedEvent.Status)
	}
}

// The fix must not silence real detection: a request that does reach the
// detectors still reports exactly what it carried.
func TestInspectedRequestsReportTheirOwnSignals(t *testing.T) {
	const ip = "203.0.113.8"

	sqli := signals.NewSQLiDetector(signals.DefaultSQLiDetectorConfig())
	collector := signals.NewCollector(sqli)
	writer := &captureWriter{}

	handler := Middleware(writer, collector)(sqli.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
	)))

	silenceAlerts(t, func() {
		send(t, handler, http.MethodPost, "/api/login", ip, `{"email":"' OR 1=1--"}`)
	})
	if !firedContains(writer.last(), signals.SignalSQLi) {
		t.Fatalf("attack not reported: %v", writer.last().Fired)
	}

	// A clean request from the same address, inspected this time, reports clean.
	send(t, handler, http.MethodGet, "/api/health", ip, "")
	if len(writer.last().Fired) != 0 {
		t.Fatalf("clean request reported signals: %v", writer.last().Fired)
	}
}

// Windowed detectors are deliberately unaffected: "this address made N
// requests in the last minute" stays true whether or not the request being
// recorded reached the detector.
func TestWindowedDetectorsStillReportOnBlockedRequests(t *testing.T) {
	const ip = "203.0.113.9"

	flood := signals.NewFloodDetector(config.RateLimitConfig{
		Enabled:           true,
		RequestsPerMinute: 20,
		Burst:             5,
	})
	collector := signals.NewCollector(flood)
	writer := &captureWriter{}

	inspected := Middleware(writer, collector)(flood.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
	)))
	enforced := Middleware(writer, collector)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	silenceAlerts(t, func() {
		for i := 0; i < 30; i++ {
			send(t, inspected, http.MethodGet, "/api/health", ip, "")
		}
	})

	before := writer.last().Signals
	if len(before) == 0 {
		t.Fatal("flood detector reported nothing while being hammered")
	}

	send(t, enforced, http.MethodGet, "/api/health", ip, "")

	after := writer.last().Signals
	if len(after) != 1 || after[0].Signal != signals.SignalFlood {
		t.Fatalf("windowed evidence disappeared on a blocked request: %+v", after)
	}
	if after[0].Int("requestRate") == 0 {
		t.Fatalf("windowed counts should survive a block, got %+v", after[0].Details)
	}
}

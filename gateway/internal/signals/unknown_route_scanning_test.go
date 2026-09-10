package signals

import (
	"net/http"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

func scanRouteMatch(method, path string) string {
	if method == http.MethodGet && path == "/api/products" {
		return "/api/products"
	}
	return unmatchedRoute
}

func newRouteScanDetector() *UnknownRouteScanDetector {
	return NewUnknownRouteScanDetector(config.UnknownRouteScanConfig{
		Enabled: true, DistinctPaths: 3, Window: time.Minute, MaxClients: 2, MaxPathsPerClient: 4,
	}, scanRouteMatch)
}

func TestUnknownRouteScanNeedsDistinctUnmatchedPaths(t *testing.T) {
	const ip = "203.0.113.61"
	detector := newRouteScanDetector()
	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	// Repeated backend 404s for one dead link are ordinary broken-link traffic,
	// not evidence that a client is walking the application namespace.
	for i := 0; i < 10; i++ {
		probe(handler, http.MethodGet, "/missing", ip, "")
	}
	if ev := detector.Metrics(ip); ev.ThresholdCross || ev.Int("distinctPaths") != 1 {
		t.Fatalf("repeated one-path 404 became a scan: %+v", ev)
	}

	probe(handler, http.MethodGet, "/admin", ip, "")
	probe(handler, http.MethodGet, "/private", ip, "")
	ev := detector.Metrics(ip)
	if !ev.ThresholdCross || ev.Int("distinctPaths") != 3 || ev.AttackType != SignalRouteScan {
		t.Fatalf("distinct unmatched paths did not produce scan evidence: %+v", ev)
	}
	if got := ev.Details["supportingPaths"].([]string); len(got) != 3 {
		t.Fatalf("supporting paths = %v, want all three probes", got)
	}
}

func TestUnknownRouteScanIgnoresKnownRoutesRegardlessOfBackendStatus(t *testing.T) {
	const ip = "203.0.113.62"
	detector := newRouteScanDetector()
	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	for i := 0; i < 5; i++ {
		probe(handler, http.MethodGet, "/api/products", ip, "")
	}
	if ev := detector.Metrics(ip); ev.Int("distinctPaths") != 0 || ev.ThresholdCross {
		t.Fatalf("known route backend 404 created route-scan evidence: %+v", ev)
	}
}

func TestUnknownRouteScanExpiresAndBoundsClientState(t *testing.T) {
	detector := newRouteScanDetector()
	tun := detector.settings()
	detector.observe("203.0.113.63", "/old", time.Now().Add(-2*time.Minute), tun)
	if ev := detector.Metrics("203.0.113.63"); ev.Int("distinctPaths") != 0 {
		t.Fatalf("expired unknown path remained in the window: %+v", ev)
	}

	detector.observe("203.0.113.64", "/one", time.Now(), tun)
	detector.observe("203.0.113.65", "/two", time.Now(), tun)
	detector.observe("203.0.113.66", "/three", time.Now(), tun)
	detector.mu.Lock()
	clients := len(detector.clients)
	detector.mu.Unlock()
	if clients != tun.maxClients {
		t.Fatalf("client state grew to %d, want bounded %d", clients, tun.maxClients)
	}
}

func TestUnknownRouteScanNeverBlocks(t *testing.T) {
	detector := newRouteScanDetector()
	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("backend reached"))
	}))

	rec := probe(handler, http.MethodGet, "/not-a-route", "203.0.113.67", "")
	if rec.Code != http.StatusNotFound || rec.Body.String() != "backend reached" {
		t.Fatalf("detector changed the backend response: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

package signals

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

const floodMarker = "API FLOOD DETECTED"

func floodDetector(threshold int) *FloodDetector {
	return NewFloodDetector(config.RateLimitConfig{
		Enabled:           true,
		RequestsPerMinute: threshold,
	})
}

func TestFloodStaysQuietUnderThreshold(t *testing.T) {
	handler := floodDetector(5).Middleware(okBackend())

	out := captureAlerts(t, func() {
		for i := 0; i < 5; i++ {
			probe(handler, http.MethodGet, "/api/products", "203.0.113.5", "")
		}
	})

	if n := alertCount(out, floodMarker); n != 0 {
		t.Fatalf("expected no alert at or below the threshold, got %d", n)
	}
}

func TestFloodAlertsOnceOverThreshold(t *testing.T) {
	handler := floodDetector(3).Middleware(okBackend())

	out := captureAlerts(t, func() {
		for i := 0; i < 4; i++ {
			probe(handler, http.MethodGet, "/api/products", "203.0.113.5", "")
		}
	})

	if n := alertCount(out, floodMarker); n != 1 {
		t.Fatalf("expected exactly 1 alert on the 4th request, got %d", n)
	}
}

// The team's decision is detect-only. If that ever changes, this test should
// be the thing that fails and forces the conversation.
func TestFloodNeverBlocks(t *testing.T) {
	handler := floodDetector(2).Middleware(okBackend())

	captureAlerts(t, func() {
		for i := 0; i < 20; i++ {
			rec := probe(handler, http.MethodGet, "/api/products", "203.0.113.5", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("request %d got status %d, detector must not block", i, rec.Code)
			}
			if rec.Body.String() != "backend reached" {
				t.Fatalf("request %d never reached the backend", i)
			}
		}
	})
}

func TestFloodCountsPerIPNotGlobally(t *testing.T) {
	handler := floodDetector(3).Middleware(okBackend())

	out := captureAlerts(t, func() {
		// Six requests in total, but three each from two addresses, so
		// neither crosses the threshold on its own.
		for i := 0; i < 3; i++ {
			probe(handler, http.MethodGet, "/api/products", "203.0.113.5", "")
			probe(handler, http.MethodGet, "/api/products", "198.51.100.9", "")
		}
	})

	if n := alertCount(out, floodMarker); n != 0 {
		t.Fatalf("counts leaked between IPs: got %d alerts", n)
	}
}

func TestFloodSeverityRisesWithVolume(t *testing.T) {
	handler := floodDetector(2).Middleware(okBackend())

	out := captureAlerts(t, func() {
		for i := 0; i < 11; i++ {
			probe(handler, http.MethodGet, "/api/products", "203.0.113.5", "")
		}
	})

	// threshold 2: >2 is LOW, >4 is MEDIUM, >10 is HIGH
	for _, want := range []string{"LOW", "MEDIUM", "HIGH"} {
		if !strings.Contains(out, "Severity       : "+want) {
			t.Errorf("expected a %s severity alert in the run", want)
		}
	}
}

func TestFloodDisabledDetectorInspectsNothing(t *testing.T) {
	detector := NewFloodDetector(config.RateLimitConfig{Enabled: false})
	handler := detector.Middleware(okBackend())

	out := captureAlerts(t, func() {
		for i := 0; i < 50; i++ {
			if rec := probe(handler, http.MethodGet, "/api/products", "203.0.113.5", ""); rec.Code != http.StatusOK {
				t.Fatalf("got status %d", rec.Code)
			}
		}
	})

	if n := alertCount(out, floodMarker); n != 0 {
		t.Fatalf("a disabled detector alerted %d times", n)
	}
}

// Requests older than the window must stop counting, otherwise a busy but
// legitimate client eventually trips the detector.
func TestFloodWindowExpiresOldRequests(t *testing.T) {
	detector := floodDetector(3)
	handler := detector.Middleware(okBackend())

	out := captureAlerts(t, func() {
		for i := 0; i < 3; i++ {
			probe(handler, http.MethodGet, "/api/products", "203.0.113.5", "")
		}

		// Age the recorded timestamps past the one-minute window.
		shard := detector.getShard("203.0.113.5")
		shard.mu.Lock()
		client := shard.clients["203.0.113.5"]
		for i := range client.Requests {
			client.Requests[i] = client.Requests[i].Add(-2 * time.Minute)
		}
		shard.mu.Unlock()

		for i := 0; i < 3; i++ {
			probe(handler, http.MethodGet, "/api/products", "203.0.113.5", "")
		}
	})

	if n := alertCount(out, floodMarker); n != 0 {
		t.Fatalf("expired requests still counted: got %d alerts", n)
	}
}

func TestFloodConcurrentRequestsAreSafe(t *testing.T) {
	handler := floodDetector(500).Middleware(okBackend())

	captureAlerts(t, func() {
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				ip := "203.0.113." + string(rune('0'+n%10))
				for j := 0; j < 10; j++ {
					probe(handler, http.MethodGet, "/api/products", ip, "")
				}
			}(i)
		}
		wg.Wait()
	})
}

// The detector must attribute traffic to the resolved client, not the proxy,
// or one balancer address absorbs every client's count.
func TestFloodUsesResolvedClientIP(t *testing.T) {
	resolver, err := netutil.NewResolver([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	handler := resolver.Middleware(floodDetector(3).Middleware(okBackend()))

	out := captureAlerts(t, func() {
		// Same proxy, four different real clients: nobody crosses the threshold.
		for _, client := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"} {
			for i := 0; i < 3; i++ {
				proxiedProbe(handler, "/api/products", "203.0.113.9", client)
			}
		}
	})

	if n := alertCount(out, floodMarker); n != 0 {
		t.Fatalf("traffic was attributed to the proxy rather than the client: %d alerts", n)
	}
}

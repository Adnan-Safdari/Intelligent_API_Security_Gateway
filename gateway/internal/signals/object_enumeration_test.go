package signals

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

// objectRouteMatch stands in for the route table: /api/orders/{id} and
// /api/products/{id} are templates, only orders is configured as an object.
func objectRouteMatch(method, path string) (string, []string) {
	for _, prefix := range []string{"/api/orders/", "/api/products/"} {
		if method == http.MethodGet && strings.HasPrefix(path, prefix) {
			return prefix + "{id}", []string{strings.TrimPrefix(path, prefix)}
		}
	}
	return unmatchedRoute, nil
}

func newObjectDetector() *ObjectEnumerationDetector {
	return NewObjectEnumerationDetector(config.ObjectEnumerationConfig{
		Enabled: true, DistinctIDs: 5, Window: time.Minute, MaxClients: 2, MaxIDsPerClient: 8,
	}, []string{"get /api/orders/{id}"}, objectRouteMatch)
}

func backendAnswering(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("order"))
	})
}

func TestObjectEnumerationCountsDistinctIdentifiers(t *testing.T) {
	const ip = "203.0.113.81"
	detector := newObjectDetector()
	handler := detector.Middleware(backendAnswering(http.StatusOK))

	// Re-reading the same order is ordinary use, however often it happens.
	for i := 0; i < 20; i++ {
		probe(handler, http.MethodGet, "/api/orders/7", ip, "")
	}
	if ev := detector.Metrics(ip); ev.ThresholdCross || ev.Int("distinctIds") != 1 {
		t.Fatalf("one order read repeatedly became enumeration: %+v", ev)
	}

	for _, id := range []string{"3", "11", "42", "90"} {
		probe(handler, http.MethodGet, "/api/orders/"+id, ip, "")
	}
	ev := detector.Metrics(ip)
	if !ev.ThresholdCross || ev.Int("distinctIds") != 5 || ev.AttackType != SignalObjectEnum {
		t.Fatalf("five distinct orders did not produce enumeration evidence: %+v", ev)
	}
	if ev.Details["template"] != "GET /api/orders/{id}" {
		t.Errorf("template = %v", ev.Details["template"])
	}
	// Scattered ids, all readable: evidence at the threshold, with no bonus.
	if ev.Score != 60 || ev.Int("sequentialRun") != 1 {
		t.Errorf("score = %d, sequentialRun = %d; want 60 and 1", ev.Score, ev.Int("sequentialRun"))
	}
}

// A script counting through ids, and a backend refusing most of them, are the
// two things that separate harvesting from a user with a long order history.
func TestObjectEnumerationRaisesTheScoreForRefusalsAndCounting(t *testing.T) {
	cases := []struct {
		name   string
		status int
		ids    []int
		score  int
	}{
		{"sequential, readable", http.StatusOK, []int{1, 2, 3, 4, 5}, 70},
		{"scattered, refused", http.StatusNotFound, []int{2, 9, 17, 30, 44}, 80},
		{"sequential, refused", http.StatusForbidden, []int{10, 11, 12, 13, 14}, 90},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const ip = "203.0.113.82"
			detector := newObjectDetector()
			handler := detector.Middleware(backendAnswering(c.status))
			for _, id := range c.ids {
				probe(handler, http.MethodGet, fmt.Sprintf("/api/orders/%d", id), ip, "")
			}
			if ev := detector.Metrics(ip); ev.Score != c.score {
				t.Fatalf("score = %d, want %d: %+v", ev.Score, c.score, ev.Details)
			}
		})
	}
}

// Below the threshold the bonuses do not apply: three refused lookups are a
// stale bookmark, not an attack.
func TestObjectEnumerationBelowThresholdEarnsNoBonus(t *testing.T) {
	const ip = "203.0.113.83"
	detector := newObjectDetector()
	handler := detector.Middleware(backendAnswering(http.StatusNotFound))
	for _, id := range []string{"1", "2", "3"} {
		probe(handler, http.MethodGet, "/api/orders/"+id, ip, "")
	}
	if ev := detector.Metrics(ip); ev.ThresholdCross || ev.Score != 18 {
		t.Fatalf("below-threshold evidence = score %d cross %v, want 18 and false", ev.Score, ev.ThresholdCross)
	}
}

// A shopper opening many products is not an attack; only configured object
// templates are watched.
func TestObjectEnumerationIgnoresUnwatchedTemplates(t *testing.T) {
	const ip = "203.0.113.84"
	detector := newObjectDetector()
	handler := detector.Middleware(backendAnswering(http.StatusOK))
	for i := 1; i <= 30; i++ {
		probe(handler, http.MethodGet, fmt.Sprintf("/api/products/%d", i), ip, "")
		probe(handler, http.MethodPost, fmt.Sprintf("/api/orders/%d", i), ip, "")
	}
	if ev := detector.Metrics(ip); ev.Int("distinctIds") != 0 || ev.Score != 0 {
		t.Fatalf("unwatched traffic was counted: %+v", ev)
	}
}

func TestObjectEnumerationIsBoundedAndExpires(t *testing.T) {
	detector := newObjectDetector()
	tun := detector.settings()
	start := time.Now()

	for i := 0; i < 50; i++ {
		detector.observe("203.0.113.85", "GET /api/orders/{id}", fmt.Sprint(i), false, start, tun)
	}
	detector.mu.Lock()
	retained := len(detector.clients["203.0.113.85"].trails["GET /api/orders/{id}"])
	detector.mu.Unlock()
	if retained != 8 {
		t.Fatalf("retained %d ids, want the per-client cap of 8", retained)
	}

	for _, ip := range []string{"203.0.113.86", "203.0.113.87"} {
		detector.observe(ip, "GET /api/orders/{id}", "1", false, start.Add(time.Second), tun)
	}
	detector.mu.Lock()
	clients := len(detector.clients)
	_, stalestKept := detector.clients["203.0.113.85"]
	detector.mu.Unlock()
	if clients != 2 || stalestKept {
		t.Fatalf("client cap: %d clients, stalest kept = %v", clients, stalestKept)
	}

	detector.observe("203.0.113.86", "GET /api/orders/{id}", "2", false, start.Add(2*time.Minute), tun)
	detector.mu.Lock()
	got := len(detector.clients["203.0.113.86"].trails["GET /api/orders/{id}"])
	detector.mu.Unlock()
	if got != 1 {
		t.Fatalf("ids outside the window were kept: %d", got)
	}
}

func TestObjectEnumerationNeverChangesTheResponse(t *testing.T) {
	detector := newObjectDetector()
	handler := detector.Middleware(backendAnswering(http.StatusForbidden))
	for i := 1; i <= 20; i++ {
		rec := probe(handler, http.MethodGet, fmt.Sprintf("/api/orders/%d", i), "203.0.113.88", "")
		if rec.Code != http.StatusForbidden || rec.Body.String() != "order" {
			t.Fatalf("request %d: detector altered the backend response: %d %q", i, rec.Code, rec.Body.String())
		}
	}
}

func TestLongestConsecutiveRun(t *testing.T) {
	cases := map[string]struct {
		ids  []string
		want int
	}{
		"empty":             {nil, 0},
		"non-numeric":       {[]string{"a1b2", "5/17"}, 0},
		"scattered":         {[]string{"3", "9", "27"}, 1},
		"run in the middle": {[]string{"40", "12", "13", "14", "15", "2"}, 4},
		"unsorted input":    {[]string{"5", "3", "4", "1", "2"}, 5},
	}
	for name, c := range cases {
		if got := longestConsecutiveRun(c.ids); got != c.want {
			t.Errorf("%s: longestConsecutiveRun(%v) = %d, want %d", name, c.ids, got, c.want)
		}
	}
}

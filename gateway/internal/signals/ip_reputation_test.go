package signals

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/reputation"
)

const listed = "203.0.113.66"
const unlisted = "203.0.113.67"

func reputationFeed(t *testing.T) *reputation.Feed {
	t.Helper()
	networks, err := reputation.Parse(strings.NewReader(listed + "\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	feed := reputation.New()
	feed.Replace(networks, "test")
	return feed
}

func reputationDetector(t *testing.T, cfg config.IPReputationConfig) *ReputationDetector {
	t.Helper()
	return NewReputationDetector(reputationFeed(t), cfg)
}

func on() config.IPReputationConfig {
	return config.IPReputationConfig{Enabled: true, Score: 80, Cooldown: time.Minute}
}

// requestWithID sends a request carrying a request id, the way telemetry does
// before the chain runs.
func requestWithID(handler http.Handler, ip, requestID string) {
	req := httptest.NewRequest(http.MethodGet, "/products", nil)
	req.RemoteAddr = ip + ":54321"
	req.Header.Set(RequestIDHeader, requestID)
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

func TestAnUnlistedAddressScoresNothing(t *testing.T) {
	d := reputationDetector(t, on())
	handler := d.Middleware(okBackend())
	requestWithID(handler, unlisted, "req-1")

	ev := d.Metrics(unlisted)
	if ev.Score != 0 || ev.ThresholdCross {
		t.Fatalf("unlisted address produced %+v", ev)
	}
	if ev.Details["listed"] != false {
		t.Errorf("details should say listed=false, got %v", ev.Details["listed"])
	}
}

func TestAListedAddressFiresOnItsFirstRequest(t *testing.T) {
	d := reputationDetector(t, on())
	handler := d.Middleware(okBackend())

	// The whole point of this detector: no window to fill first.
	requestWithID(handler, listed, "req-1")

	ev := d.MetricsFor(listed, "req-1")
	if !ev.ThresholdCross {
		t.Fatal("a listed address should fire on request one")
	}
	if ev.Score != 80 {
		t.Errorf("want score 80, got %d", ev.Score)
	}
	if ev.AttackType != AttackTypeKnownBad {
		t.Errorf("want attack type %q, got %q", AttackTypeKnownBad, ev.AttackType)
	}
}

func TestInsideTheCooldownItScoresButDoesNotFireAgain(t *testing.T) {
	d := reputationDetector(t, on())
	handler := d.Middleware(okBackend())

	requestWithID(handler, listed, "req-1")
	requestWithID(handler, listed, "req-2")

	// Firing on every request would write one Evidence per request, swamping
	// the correlation agent's detector counts and the event stream both.
	second := d.MetricsFor(listed, "req-2")
	if second.ThresholdCross {
		t.Error("a second request inside the cooldown must not fire again")
	}
	// It still scores: being listed is a standing fact, not an event.
	if second.Score != 80 {
		t.Errorf("want the address still scored 80, got %d", second.Score)
	}
}

func TestItFiresAgainOnceTheCooldownHasPassed(t *testing.T) {
	cfg := on()
	cfg.Cooldown = 20 * time.Millisecond
	d := reputationDetector(t, cfg)
	handler := d.Middleware(okBackend())

	requestWithID(handler, listed, "req-1")
	time.Sleep(40 * time.Millisecond)
	requestWithID(handler, listed, "req-2")

	if !d.MetricsFor(listed, "req-2").ThresholdCross {
		t.Error("should fire again after the cooldown elapsed")
	}
}

func TestOnlyTheRequestThatFiredReportsACross(t *testing.T) {
	d := reputationDetector(t, on())
	handler := d.Middleware(okBackend())
	requestWithID(handler, listed, "req-1")

	// A request the enforcer answered never reached this detector, so it must
	// not inherit the firing from the request that did.
	if d.MetricsFor(listed, "some-other-request").ThresholdCross {
		t.Error("a request that never fired reported a threshold cross")
	}
	if d.MetricsFor(listed, "").ThresholdCross {
		t.Error("an empty request id should never report a cross")
	}
}

func TestDisabledDetectorReportsNothing(t *testing.T) {
	cfg := on()
	cfg.Enabled = false
	d := reputationDetector(t, cfg)
	handler := d.Middleware(okBackend())
	requestWithID(handler, listed, "req-1")

	if ev := d.Metrics(listed); ev.Score != 0 || ev.ThresholdCross {
		t.Fatalf("disabled detector produced %+v", ev)
	}
}

func TestAlertNamesTheAddressAndFiresOnce(t *testing.T) {
	d := reputationDetector(t, on())
	handler := d.Middleware(okBackend())

	output := captureAlerts(t, func() {
		requestWithID(handler, listed, "req-1")
		requestWithID(handler, listed, "req-2")
		requestWithID(handler, unlisted, "req-3")
	})

	if got := alertCount(output, "KNOWN BAD ADDRESS"); got != 1 {
		t.Fatalf("want exactly 1 alert, got %d", got)
	}
	if !strings.Contains(output, listed) {
		t.Error("alert should name the address")
	}
}

func TestReputationApplyIsSafeUnderConcurrentTraffic(t *testing.T) {
	d := reputationDetector(t, on())
	handler := d.Middleware(okBackend())

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					requestWithID(handler, listed, "req")
					_ = d.Metrics(listed)
				}
			}
		}()
	}

	for i := 0; i < 200; i++ {
		cfg := on()
		cfg.Score = 50 + i%40
		d.Apply(cfg)
	}
	close(stop)
	wg.Wait()
}

func TestApplyDoesNotHandOutAFreshCooldown(t *testing.T) {
	d := reputationDetector(t, on())
	handler := d.Middleware(okBackend())
	requestWithID(handler, listed, "req-1")

	// Editing the score mid-cooldown must not reset who has already fired,
	// or an address could be made to fire repeatedly by tweaking settings.
	cfg := on()
	cfg.Score = 90
	d.Apply(cfg)

	requestWithID(handler, listed, "req-2")
	if d.MetricsFor(listed, "req-2").ThresholdCross {
		t.Error("cooldown was reset by an unrelated settings change")
	}
	if got := d.Metrics(listed).Score; got != 90 {
		t.Errorf("new score should apply immediately, got %d", got)
	}
}

func TestDefaultsFillInForAnEmptyConfig(t *testing.T) {
	d := reputationDetector(t, config.IPReputationConfig{Enabled: true})
	if got := d.settings().score; got != DefaultReputationScore {
		t.Errorf("want default score %d, got %d", DefaultReputationScore, got)
	}
	if got := d.settings().cooldown; got != DefaultReputationCooldown {
		t.Errorf("want default cooldown %v, got %v", DefaultReputationCooldown, got)
	}
}

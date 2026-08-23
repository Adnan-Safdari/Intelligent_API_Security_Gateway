package policy

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestLimiterAllowsUpToTheLimit(t *testing.T) {
	l := NewLimiter()

	for i := 1; i <= 5; i++ {
		allowed, count, _ := l.Allow("1.2.3.4", 5)
		if !allowed {
			t.Fatalf("request %d of 5 was refused (count %d)", i, count)
		}
	}

	allowed, count, retry := l.Allow("1.2.3.4", 5)
	if allowed {
		t.Error("the sixth request against a limit of 5 was allowed")
	}
	if count != 6 {
		t.Errorf("count = %d, want 6: refused requests still count", count)
	}
	if retry <= 0 {
		t.Error("no Retry-After was suggested")
	}
}

// One address going over must not affect another. Rate limiting that leaked
// across callers would turn one attacker into an outage for everyone.
func TestLimiterKeepsAddressesApart(t *testing.T) {
	l := NewLimiter()

	for i := 0; i < 10; i++ {
		l.Allow("9.9.9.9", 2)
	}

	if allowed, _, _ := l.Allow("8.8.8.8", 2); !allowed {
		t.Error("an address was refused because a different address was over its limit")
	}
}

// The rate travels with the policy, so the same address can be judged against
// a different number the moment the control plane changes its mind.
func TestLimiterTakesTheLimitPerCall(t *testing.T) {
	l := NewLimiter()

	for i := 0; i < 30; i++ {
		l.Allow("5.5.5.5", 100)
	}

	if allowed, _, _ := l.Allow("5.5.5.5", 20); allowed {
		t.Error("30 requests were allowed under a tightened limit of 20")
	}
	if allowed, _, _ := l.Allow("5.5.5.5", 100); !allowed {
		t.Error("the same history was refused under a limit of 100")
	}
}

func TestLimiterWithNoLimitAllowsEverything(t *testing.T) {
	l := NewLimiter()
	for i := 0; i < 50; i++ {
		if allowed, _, _ := l.Allow("4.4.4.4", 0); !allowed {
			t.Fatal("a limit of 0 refused a request; it means no rate named")
		}
	}
}

// A nil limiter is the "no rate limiting" case and must not panic.
func TestNilLimiterAllows(t *testing.T) {
	var l *Limiter
	if allowed, _, _ := l.Allow("1.1.1.1", 5); !allowed {
		t.Error("a nil limiter refused a request")
	}
	l.Forget("1.1.1.1")
	if l.Size() != 0 {
		t.Error("a nil limiter reported a size")
	}
}

func TestLimiterForgetsAndSweeps(t *testing.T) {
	l := NewLimiter()
	l.Allow("7.7.7.7", 5)
	if l.Size() != 1 {
		t.Fatalf("size = %d, want 1", l.Size())
	}

	l.Forget("7.7.7.7")
	if l.Size() != 0 {
		t.Errorf("size = %d after Forget, want 0", l.Size())
	}

	l.Allow("6.6.6.6", 5)
	// Sweeping with a cutoff far in the future drops everything.
	l.sweep(time.Now().Add(2 * time.Minute))
	if l.Size() != 0 {
		t.Errorf("size = %d after a sweep past the window, want 0", l.Size())
	}
}

func TestLimiterIsSafeConcurrently(t *testing.T) {
	l := NewLimiter()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := "10.0.0." + strconv.Itoa(n%4)
			for j := 0; j < 200; j++ {
				l.Allow(ip, 50)
			}
		}(i)
	}
	wg.Wait()
}

// The end of the loop the whole feature exists for: a policy naming a rate
// turns into a 429 for the request that exceeds it.
func TestThrottlePolicyEnforcesItsRate(t *testing.T) {
	decision := Decision{Action: ActionThrottle, RequestsPerMinute: 3, CampaignID: "c-1"}
	e := NewEnforcer(fixed{"203.0.113.5": decision}, true, 0).WithLimiter(NewLimiter())

	handler := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	codes := map[int]int{}
	var lastRetry string
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, requestFrom("203.0.113.5"))
		codes[rec.Code]++
		if rec.Code == http.StatusTooManyRequests {
			lastRetry = rec.Header().Get("Retry-After")
		}
	}

	if codes[http.StatusOK] != 3 {
		t.Errorf("allowed %d requests, want 3", codes[http.StatusOK])
	}
	if codes[http.StatusTooManyRequests] != 2 {
		t.Errorf("refused %d requests with 429, want 2", codes[http.StatusTooManyRequests])
	}
	if lastRetry == "" {
		t.Error("a 429 carried no Retry-After")
	}
}

// A throttle with no rate is an older control plane's policy. It must still
// enforce something rather than becoming a pass-through.
func TestThrottleWithoutARateStillDelays(t *testing.T) {
	decision := Decision{Action: ActionThrottle}
	e := NewEnforcer(fixed{"203.0.113.6": decision}, true, 40*time.Millisecond).
		WithLimiter(NewLimiter())

	handler := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	start := time.Now()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestFrom("203.0.113.6"))

	if rec.Code != http.StatusOK {
		t.Errorf("code = %d, want 200: a rateless throttle should still serve", rec.Code)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Error("the configured throttle delay was not applied")
	}
}

// An address that is not under policy must never reach the limiter.
func TestUnthrottledAddressIsNotRateLimited(t *testing.T) {
	e := NewEnforcer(fixed{}, true, 0).WithLimiter(NewLimiter())
	handler := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 30; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, requestFrom("198.51.100.9"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d got %d, want 200", i, rec.Code)
		}
	}
	if e.limiter.Size() != 0 {
		t.Error("an address with no policy was recorded by the limiter")
	}
}

type fixed map[string]Decision

func (f fixed) Lookup(ip string) (Decision, bool) {
	d, ok := f[ip]
	return d, ok
}

func requestFrom(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
	r.RemoteAddr = ip + ":1234"
	return AttachOutcome(r)
}

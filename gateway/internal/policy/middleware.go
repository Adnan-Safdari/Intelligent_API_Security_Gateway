package policy

import (
	"log"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// Enforcer applies control-plane decisions to live requests. It is the only
// place where anything the control plane produced can affect real traffic.
// enforcerTunables is what the console can move at runtime, swapped whole.
type enforcerTunables struct {
	enabled  bool
	throttle time.Duration
}

type Enforcer struct {
	lookup Lookuper
	tun    atomic.Pointer[enforcerTunables]
	logged *logLimiter

	// Counts requests from addresses whose policy names a rate. Nil is a
	// working limiter that allows everything, so a caller that does not want
	// rate limiting simply does not set one.
	limiter *Limiter
}

func NewEnforcer(l Lookuper, enabled bool, throttleDelay time.Duration) *Enforcer {
	e := &Enforcer{lookup: l, logged: newLogLimiter(time.Minute)}
	e.Apply(enabled, throttleDelay)
	return e
}

// WithLimiter gives the enforcer a rate limiter to hold throttled addresses to
// the rate their policy names.
func (e *Enforcer) WithLimiter(l *Limiter) *Enforcer {
	e.limiter = l
	return e
}

// Apply turns enforcement on or off and sets the throttle delay. The lookup
// sources themselves are fixed at boot -- this only decides whether their
// verdicts are acted on.
func (e *Enforcer) Apply(enabled bool, throttleDelay time.Duration) {
	e.tun.Store(&enforcerTunables{enabled: enabled, throttle: throttleDelay})
}

// Middleware sits at the front of the chain, so a blocked IP is turned away
// before the detectors spend any work on it.
func (e *Enforcer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tun := e.tun.Load()
		if !tun.enabled || e.lookup == nil {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)

		decision, found := e.lookup.Lookup(ip)
		if !found {
			next.ServeHTTP(w, r)
			return
		}

		switch decision.Action {
		case ActionTempBlock, ActionEscalate:
			Record(r, decision.Action)
			e.deny(w, r, ip, decision)

		case ActionThrottle:
			// A policy that names a rate is a real limit: this address may
			// send that many requests a minute and no more. That is what
			// makes the limiting adaptive -- the number came from how bad the
			// campaign was, not from a setting that treats every throttled
			// caller alike.
			if decision.RequestsPerMinute > 0 {
				allowed, count, retryAfter := e.limiter.Allow(ip, decision.RequestsPerMinute)
				if !allowed {
					Record(r, OutcomeRateLimited)
					e.rateLimited(w, r, ip, decision, count, retryAfter)
					return
				}
				Record(r, ActionThrottle)
				next.ServeHTTP(w, r)
				return
			}

			Record(r, ActionThrottle)
			// No rate named -- an older control plane, or one that chose not
			// to. Fall back to slowing the caller down. Waiting on the request
			// context too means a client that disconnects does not pin a
			// goroutine for the full delay.
			select {
			case <-time.After(tun.throttle):
			case <-r.Context().Done():
				return
			}
			next.ServeHTTP(w, r)

		default:
			// monitor, or an action this build does not recognise. Allowing
			// is the safe default: a typo in the control plane should never
			// take the API offline.
			next.ServeHTTP(w, r)
		}
	})
}

func (e *Enforcer) deny(w http.ResponseWriter, r *http.Request, ip string, d Decision) {
	// Deliberately generic. The campaign id, confidence and reason go to the
	// log, not to the response -- telling an attacker which campaign they
	// tripped and how sure we are just helps them tune around it.
	if d.ExpiresIn > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(d.ExpiresIn))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"forbidden"}`))

	// A block fires hardest exactly when an IP is flooding, so logging every
	// rejected request would turn one attack into a disk-filling problem.
	if e.logged.allow(ip) {
		log.Printf(
			"[policy] BLOCK %s -> %s %s (action=%s campaign=%s confidence=%.2f)",
			ip, r.Method, r.URL.Path, d.Action, d.CampaignID, d.Confidence,
		)
	}
}

// logLimiter lets each IP produce at most one log line per interval.
type logLimiter struct {
	mu       sync.Mutex
	seen     map[string]time.Time
	interval time.Duration
}

func newLogLimiter(interval time.Duration) *logLimiter {
	return &logLimiter{seen: make(map[string]time.Time), interval: interval}
}

func (l *logLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if last, ok := l.seen[ip]; ok && now.Sub(last) < l.interval {
		return false
	}

	// Drop entries that have aged out, so a long run against many IPs does
	// not grow this map without bound.
	for k, t := range l.seen {
		if now.Sub(t) > l.interval {
			delete(l.seen, k)
		}
	}

	l.seen[ip] = now
	return true
}

// rateLimited turns away a throttled caller who has exceeded their allowance.
//
// 429 rather than the 403 a block gets: the difference is real and worth
// keeping. A block says "not you"; this says "not this fast", and Retry-After
// tells a well-behaved client exactly when it is worth trying again.
func (e *Enforcer) rateLimited(
	w http.ResponseWriter, r *http.Request, ip string, d Decision, count int, retryAfter time.Duration,
) {
	seconds := int(retryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))

	// Deliberately generic, like deny: the campaign id and the reason go to
	// the log, not to the caller. Telling an attacker which rate they tripped
	// is telling them what to stay under.
	http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)

	if e.logged.allow(ip) {
		log.Printf("[policy] rate limited %s: %d requests in the last minute, allowed %d (campaign %s)",
			ip, count, d.RequestsPerMinute, d.CampaignID)
	}
}

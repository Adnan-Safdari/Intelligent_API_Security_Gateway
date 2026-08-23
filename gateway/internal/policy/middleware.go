package policy

import (
	"log"
	"net"
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
	// policyOn decides whether the lookup sources are consulted at all.
	policyOn bool
	throttle time.Duration

	// baseline is the requests per minute every address is held to when no
	// policy names a rate for it. Zero means no baseline, which is the default:
	// refusing ordinary traffic is a deliberate choice, not something the
	// gateway should start doing because a threshold existed.
	baseline int

	// exempt addresses skip the baseline entirely. The reflex's list is reused
	// so there is one answer to "who does this gateway never refuse".
	exempt []*net.IPNet
}

// active reports whether the middleware has anything to do. When neither a
// policy source nor a baseline can have an opinion the request is passed
// straight through, with no lookup and no counting.
func (t *enforcerTunables) active() bool {
	return t.policyOn || t.baseline > 0
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

// Baseline is the rate every non-exempt address is held to when no policy names
// one for it, and the ranges that skip it.
type Baseline struct {
	RequestsPerMinute int
	Exempt            []*net.IPNet
}

// WithLimiter gives the enforcer a rate limiter to hold throttled addresses to
// the rate their policy names.
func (e *Enforcer) WithLimiter(l *Limiter) *Enforcer {
	e.limiter = l
	return e
}

// Apply turns enforcement on or off and sets the throttle delay. The lookup
// sources themselves are fixed at boot -- this only decides whether their
// verdicts are acted on. The baseline is left as it was.
func (e *Enforcer) Apply(enabled bool, throttleDelay time.Duration) {
	current := e.tun.Load()
	next := &enforcerTunables{policyOn: enabled, throttle: throttleDelay}
	if current != nil {
		next.baseline, next.exempt = current.baseline, current.exempt
	}
	e.tun.Store(next)
}

// ApplyAll sets the policy switch, the throttle delay and the baseline in one
// swap, so a request is never judged against a new baseline and an old
// exemption list.
func (e *Enforcer) ApplyAll(enabled bool, throttleDelay time.Duration, b Baseline) {
	e.tun.Store(&enforcerTunables{
		policyOn: enabled,
		throttle: throttleDelay,
		baseline: b.RequestsPerMinute,
		exempt:   b.Exempt,
	})
}

// Middleware sits at the front of the chain, so a blocked IP is turned away
// before the detectors spend any work on it.
func (e *Enforcer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tun := e.tun.Load()
		if !tun.active() {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)

		var decision Decision
		var found bool
		if tun.policyOn && e.lookup != nil {
			decision, found = e.lookup.Lookup(ip)
		}

		if found {
			switch decision.Action {
			case ActionTempBlock, ActionEscalate:
				Record(r, decision.Action)
				e.deny(w, r, ip, decision)
				return

			case ActionThrottle:
				// A policy that names a rate is a real limit, and it replaces
				// the baseline: the number came from how bad the campaign was,
				// which is a better answer than the figure everyone else gets.
				if decision.RequestsPerMinute > 0 {
					e.limited(w, r, next, tun, ip, decision, decision.RequestsPerMinute, ActionThrottle)
					return
				}

				Record(r, ActionThrottle)
				// No rate named -- an older control plane, or one that chose
				// not to. Fall back to slowing the caller down. Waiting on the
				// request context too means a client that disconnects does not
				// pin a goroutine for the full delay.
				select {
				case <-time.After(tun.throttle):
				case <-r.Context().Done():
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			// monitor, or an action this build does not recognise. Neither
			// restrains traffic, so the caller falls through to the baseline
			// like anyone else. Allowing is the safe default: a typo in the
			// control plane should never take the API offline.
		}

		// No policy rate applies. Hold the address to the baseline, if there is
		// one and it is not exempt.
		if tun.baseline > 0 && !netutil.NetworksContain(tun.exempt, ip) {
			e.limited(w, r, next, tun, ip, decision, tun.baseline, "")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// limited counts one request against a rate and either serves it or refuses it
// with 429. `applied` is the outcome to record when the request is allowed
// through -- empty for the baseline, where nothing was done to the request.
func (e *Enforcer) limited(
	w http.ResponseWriter, r *http.Request, next http.Handler,
	tun *enforcerTunables, ip string, d Decision, limit int, applied string,
) {
	allowed, count, retryAfter := e.limiter.Allow(ip, limit)
	if !allowed {
		Record(r, OutcomeRateLimited)
		e.rateLimited(w, r, ip, d, count, limit, retryAfter)
		return
	}
	if applied != "" {
		Record(r, applied)
	}
	next.ServeHTTP(w, r)
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
	w http.ResponseWriter, r *http.Request, ip string, d Decision, count, limit int, retryAfter time.Duration,
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
		source := "the baseline limit"
		if d.CampaignID != "" {
			source = "campaign " + d.CampaignID
		}
		log.Printf("[policy] rate limited %s: %d requests in the last minute, allowed %d (%s)",
			ip, count, limit, source)
	}
}

package policy

import (
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// Enforcer applies control-plane decisions to live requests. It is the only
// place where anything the control plane produced can affect real traffic.
type Enforcer struct {
	lookup   Lookuper
	enabled  bool
	throttle time.Duration
	logged   *logLimiter
}

func NewEnforcer(l Lookuper, enabled bool, throttleDelay time.Duration) *Enforcer {
	return &Enforcer{
		lookup:   l,
		enabled:  enabled,
		throttle: throttleDelay,
		logged:   newLogLimiter(time.Minute),
	}
}

// Middleware sits at the front of the chain, so a blocked IP is turned away
// before the detectors spend any work on it.
func (e *Enforcer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.enabled || e.lookup == nil {
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
			Record(r, ActionThrottle)
			// Slow the caller down rather than turning them away. Waiting on
			// the request context too means a client that disconnects does
			// not pin a goroutine for the full delay.
			select {
			case <-time.After(e.throttle):
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

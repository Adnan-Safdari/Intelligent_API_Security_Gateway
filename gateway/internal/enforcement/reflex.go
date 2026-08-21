// Package enforcement gives the gateway a reflex.
//
// Policy enforcement -- internal/policy -- acts on decisions the Python control
// plane has reasoned about. That is the right place for anything involving
// judgement, but it is not fast: a decision takes up to one agent cycle (30s)
// plus one snapshot refresh (5s) to reach the gateway. A flood is finished by
// then.
//
// This is the other half: when a detector the operator has explicitly trusted
// crosses its threshold, the gateway refuses that address itself, immediately,
// without asking anyone. It is deliberately the dumber of the two.
//
// Four rules keep it dumb enough to be safe:
//
//   - Only signals named in the config may trigger it. An empty list enforces
//     nothing, whatever else is switched on.
//   - The evidence has to clear a score floor as well as the detector's own
//     threshold, so a marginal hit is not enough.
//   - Every block expires by itself. Nothing renews one, exactly as with
//     policy keys, so the worst a mistake costs is block.duration.
//   - Addresses that cannot meaningfully be blocked are exempt, and loopback
//     and private ranges are exempt by default.
//
// The control plane still owns correlation, campaigns and escalation. When it
// reaches a decision about an address, that decision wins -- see the ordering
// in policy.Chain.
package enforcement

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// RecommendedSignals is what configs/config.yaml.example ships, and what an
// operator should copy if they are unsure.
//
// Both are windowed and count repetition: they fire on a pattern of behaviour
// rather than on one request that happened to contain a suspicious string.
// The request-scoped detectors are absent on purpose -- a single request
// carrying "UNION" may be an attack or may be someone searching a catalogue,
// and that is a judgement, which is the control plane's job.
//
// It is a recommendation and not a default. Nothing applies it automatically;
// see New.
var RecommendedSignals = []string{signals.SignalFlood, signals.SignalBruteForce}

// DefaultExempt are the ranges never blocked by reflex.
//
// The documentation ranges of RFC 5737 are deliberately absent: they can never
// belong to a real host, so they are safe to block, and the demo drives
// traffic from them. This mirrors the control plane's own rule in
// policy/writer.py.
var DefaultExempt = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

// Config controls the reflex. The zero value enforces nothing.
type Config struct {
	Enabled     bool
	Duration    time.Duration
	Signals     []string
	MinScore    int
	ExemptCIDRs []string
}

type block struct {
	until  time.Time
	signal string
	score  int
}

// Reflex holds the addresses the gateway has refused on its own.
//
// It satisfies policy.Lookuper, so the enforcing middleware does not need to
// know there are two sources of decisions -- there is one place that decides
// what a decision means, and it stays in internal/policy.
type Reflex struct {
	enabled  bool
	duration time.Duration
	minScore int
	signals  map[string]bool
	exempt   []*net.IPNet

	mu      sync.RWMutex
	blocked map[string]block

	stop chan struct{}
	done chan struct{}
}

// New builds a Reflex. An error means the configuration is unusable, which is
// worth refusing to start over: silently enforcing nothing would look
// identical to enforcing correctly.
func New(cfg Config) (*Reflex, error) {
	r := &Reflex{
		enabled:  cfg.Enabled,
		duration: cfg.Duration,
		minScore: cfg.MinScore,
		signals:  map[string]bool{},
		blocked:  map[string]block{},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}

	if r.duration <= 0 {
		r.duration = 5 * time.Minute
	}

	// Signals is *not* defaulted when absent. enforcement.block.enabled has
	// sat in config files since long before anything read it, so a build that
	// armed itself on that flag alone would start refusing traffic on the
	// strength of configuration nobody had revisited. Naming the detectors is
	// the act of consent; Describe reports the enabled-but-silent case so it
	// cannot be mistaken for working.
	for _, name := range cfg.Signals {
		if name = strings.TrimSpace(name); name != "" {
			r.signals[name] = true
		}
	}

	exempt := cfg.ExemptCIDRs
	if exempt == nil {
		exempt = DefaultExempt
	}
	for _, entry := range exempt {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// A bare address is the obvious thing to write, so accept it rather
		// than silently trusting nothing.
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, &configError{entry: entry}
			}
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, &configError{entry: entry, err: err}
		}
		r.exempt = append(r.exempt, network)
	}

	return r, nil
}

type configError struct {
	entry string
	err   error
}

func (e *configError) Error() string {
	if e.err != nil {
		return "enforcement: invalid exempt range " + e.entry + ": " + e.err.Error()
	}
	return "enforcement: invalid exempt range " + e.entry
}

// Active reports whether this will ever block anything, which is what the
// startup log needs to say honestly. Enabled with no signals is a
// configuration that looks armed and is not.
func (r *Reflex) Active() bool {
	return r != nil && r.enabled && len(r.signals) > 0
}

// Describe is the one-line summary for the startup log.
func (r *Reflex) Describe() string {
	if r == nil || !r.enabled {
		return "gateway-side blocking off"
	}
	if len(r.signals) == 0 {
		return "gateway-side blocking enabled but no signals listed: nothing will be blocked"
	}
	names := make([]string, 0, len(r.signals))
	for name := range r.signals {
		names = append(names, name)
	}
	// Sorted so the log line is stable between restarts.
	sortStrings(names)
	return "gateway-side blocking on for " + strings.Join(names, ", ") +
		" at score >= " + itoa(r.minScore) + " for " + r.duration.String()
}

// Observe records a block when this request's evidence justifies one.
//
// Called after the detectors have run. It never touches the current request --
// that one is already through -- so the earliest a reflex block can apply is
// the caller's next request, which is exactly when it is useful.
func (r *Reflex) Observe(ip string, snap signals.Snapshot) {
	if !r.Active() || ip == "" || r.isExempt(ip) {
		return
	}

	for _, ev := range snap.Evidence {
		if !ev.ThresholdCross || !r.signals[ev.Signal] {
			continue
		}
		// The detector's own threshold and a score floor: two independent
		// reasons to be confident, so raising the floor is how an operator
		// makes this less trigger-happy without disabling a detector.
		if ev.Score < r.minScore {
			continue
		}

		now := time.Now()
		r.mu.Lock()
		existing, held := r.blocked[ip]
		// Do not extend a block that is already running. A blocked address
		// that keeps knocking would otherwise never be released, which is the
		// unexpiring-enforcement problem in a different costume.
		if !held || !existing.until.After(now) {
			r.blocked[ip] = block{
				until:  now.Add(r.duration),
				signal: ev.Signal,
				score:  ev.Score,
			}
			log.Printf("[enforcement] blocking %s for %s: %s crossed threshold (score %d)",
				ip, r.duration, ev.Signal, ev.Score)
		}
		r.mu.Unlock()
		return
	}
}

// Lookup satisfies policy.Lookuper.
func (r *Reflex) Lookup(ip string) (policy.Decision, bool) {
	if !r.Active() {
		return policy.Decision{}, false
	}

	r.mu.RLock()
	b, held := r.blocked[ip]
	r.mu.RUnlock()

	if !held {
		return policy.Decision{}, false
	}

	// Expiry is checked on read as well as swept in the background, so a block
	// is never enforced past its deadline even if the sweeper is between runs.
	remaining := time.Until(b.until)
	if remaining <= 0 {
		return policy.Decision{}, false
	}

	return policy.Decision{
		Action:     policy.ActionTempBlock,
		CampaignID: "gateway",
		Confidence: 1,
		Reason:     b.signal + " crossed its threshold at the gateway",
		ExpiresIn:  int(remaining.Seconds()),
	}, true
}

// Start sweeps expired blocks so a long run cannot grow the map without bound.
func (r *Reflex) Start() {
	if !r.Active() {
		close(r.done)
		return
	}
	go func() {
		defer close(r.done)
		// Often enough that memory tracks reality, rarely enough to be free.
		ticker := time.NewTicker(r.duration)
		defer ticker.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-ticker.C:
				r.sweep(time.Now())
			}
		}
	}()
}

func (r *Reflex) sweep(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ip, b := range r.blocked {
		if !b.until.After(now) {
			delete(r.blocked, ip)
		}
	}
}

// Size reports how many addresses are currently blocked, for tests and logs.
func (r *Reflex) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	now := time.Now()
	for _, b := range r.blocked {
		if b.until.After(now) {
			n++
		}
	}
	return n
}

func (r *Reflex) Close() {
	if r == nil {
		return
	}
	close(r.stop)
	<-r.done
}

func (r *Reflex) isExempt(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// An address that will not parse cannot be matched against a range
		// either, so refusing to block it is the only safe answer.
		return true
	}
	for _, network := range r.exempt {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

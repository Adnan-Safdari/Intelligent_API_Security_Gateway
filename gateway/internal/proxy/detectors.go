package proxy

import (
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/reputation"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// detectors is every signal detector the gateway runs, built together so the
// chain, the collector, and the settings watcher all see the same set.
type detectors struct {
	flood      *signals.FloodDetector
	sqli       *signals.SQLiDetector
	traversal  *signals.TraversalEnumDetector
	brute      *signals.BruteForceDetector
	routeScan  *signals.UnknownRouteScanDetector
	reputation *signals.ReputationDetector
}

func newDetectors(
	cfg config.EnforcementConfig,
	authOutcomes []config.AuthOutcomeConfig,
	feed *reputation.Feed,
	routeMatch func(method, path string) string,
) detectors {
	return detectors{
		flood:      signals.NewFloodDetector(cfg.RateLimit),
		sqli:       signals.NewSQLiDetector(signals.SQLiDetectorConfigFrom(cfg.AttackDetection)),
		traversal:  signals.NewTraversalEnumDetector(cfg.Enumeration),
		brute:      signals.NewBruteForceDetector(cfg.BruteForce, authOutcomes, routeMatch),
		routeScan:  signals.NewUnknownRouteScanDetector(cfg.UnknownRouteScan, routeMatch),
		reputation: signals.NewReputationDetector(feed, cfg.IPReputation),
	}
}

// collector reads every detector's evidence. The order here is the order of
// the signals array in every telemetry event.
func (d detectors) collector() *signals.Collector {
	return signals.NewCollector(d.flood, d.sqli, d.traversal, d.brute, d.routeScan, d.reputation)
}

// middlewares is the order requests pass through the detectors. Reputation is
// first because it is the cheapest -- one set lookup, no body, no window. Its
// position does not affect when a block lands: the reflex observes after the
// handler by design, so every gateway-side block takes effect on the next
// request.
func (d detectors) middlewares() []Middleware {
	return []Middleware{
		d.reputation.Middleware,
		d.flood.Middleware,
		d.routeScan.Middleware,
		d.sqli.Middleware,
		d.traversal.Middleware,
		d.brute.Middleware,
	}
}

// apply retunes every detector. Only the reputation tunables move: where the
// list comes from is structural, so a pushed settings change can turn
// reputation on and adjust how it scores -- but never repoint it at another feed.
func (d detectors) apply(cfg config.EnforcementConfig) {
	d.flood.Apply(cfg.RateLimit)
	d.sqli.Apply(cfg.AttackDetection)
	d.brute.Apply(cfg.BruteForce)
	d.routeScan.Apply(cfg.UnknownRouteScan)
	d.traversal.Apply(cfg.Enumeration)
	d.reputation.Apply(cfg.IPReputation)
}

package proxy

import (
	"log"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/enforcement"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/settings"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// live gathers everything in the running chain whose settings can be changed
// without rebuilding it. Each of these holds its tunables behind an atomic, so
// applying new settings is a pointer swap and never interrupts a request.
type live struct {
	flood      *signals.FloodDetector
	sqli       *signals.SQLiDetector
	brute      *signals.BruteForceDetector
	routeScan  *signals.UnknownRouteScanDetector
	objectEnum *signals.ObjectEnumerationDetector
	traversal  *signals.TraversalEnumDetector
	reputation *signals.ReputationDetector
	reflex     *enforcement.Reflex
	enforcer   *policy.Enforcer
	gate       *policy.Gate
}

// apply moves the whole chain to a new enforcement config.
//
// Everything that can be rejected is checked before anything is changed. Two
// parts read the exempt list and either can refuse a CIDR that will not parse;
// doing both up front means a typo leaves the running gateway exactly as it
// was, rather than landing half a settings change on it.
func (l live) apply(cfg config.EnforcementConfig) error {
	baseline, err := baselineFrom(cfg.RateLimit, cfg.Block)
	if err != nil {
		return err
	}

	if err := l.reflex.Apply(enforcement.Config{
		Enabled:     cfg.Block.Enabled,
		Duration:    cfg.Block.Duration,
		Signals:     cfg.Block.Signals,
		MinScore:    cfg.Block.MinScore,
		ExemptCIDRs: cfg.Block.ExemptCIDRs,
	}); err != nil {
		return err
	}

	l.flood.Apply(cfg.RateLimit)
	l.sqli.Apply(cfg.AttackDetection)
	l.brute.Apply(cfg.BruteForce)
	l.routeScan.Apply(cfg.UnknownRouteScan)
	l.objectEnum.Apply(cfg.ObjectEnumeration)
	l.traversal.Apply(cfg.Enumeration)
	// Only the tunables move here. Where the list comes from is structural, so
	// a pushed settings change can turn reputation on, adjust what it scores
	// and how often it fires -- but never repoint it at another feed.
	l.reputation.Apply(cfg.IPReputation)

	l.gate.Set(cfg.Policy.Enabled)

	// Recomputed rather than read from the config: enforcement is on when
	// either source could have an opinion, and the reflex has its own idea of
	// whether it is armed (enabled, with at least one signal named).
	l.enforcer.ApplyAll(l.gate.On() || l.reflex.Active(), throttleDelay(cfg.Throttle), baseline)

	log.Printf("[enforcement] %s", l.reflex.Describe())
	return nil
}

// startSettingsWatcher begins watching Redis for console overrides. It returns
// nil when there is no Redis configured, in which case the file is the only
// source of settings and nothing can change them at runtime.
func (s *Server) startSettingsWatcher(l live) *settings.Watcher {
	if !s.config.Redis.Enabled {
		return nil
	}

	w := settings.NewWatcher(settings.Config{
		Addr:     s.config.Redis.Addr(),
		Password: s.config.Redis.Password,
		DB:       s.config.Redis.DB,
		PoolSize: s.config.Redis.PoolSize,
		Interval: s.config.Policy.RefreshInterval,
	}, s.config.Enforcement(), l.apply)

	w.Start()
	return w
}

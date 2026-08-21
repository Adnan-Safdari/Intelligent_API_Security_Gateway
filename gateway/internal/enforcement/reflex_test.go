package enforcement

import (
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

func armed(t *testing.T, mutate func(*Config)) *Reflex {
	t.Helper()
	cfg := Config{
		Enabled:  true,
		Duration: time.Minute,
		Signals:  []string{signals.SignalFlood},
		MinScore: 80,
		// The test addresses are RFC 5737 documentation ranges, which are
		// blockable on purpose; keep loopback exempt as in production.
		ExemptCIDRs: DefaultExempt,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func snap(signal string, score int, crossed bool) signals.Snapshot {
	return signals.Snapshot{
		Evidence: []signals.Evidence{
			{Signal: signal, Score: score, ThresholdCross: crossed},
		},
	}
}

func TestBlocksAnAddressWhoseSignalCrossedItsThreshold(t *testing.T) {
	r := armed(t, nil)

	r.Observe("203.0.113.10", snap(signals.SignalFlood, 90, true))

	decision, found := r.Lookup("203.0.113.10")
	if !found {
		t.Fatal("address that flooded is not blocked")
	}
	if decision.Action != policy.ActionTempBlock {
		t.Errorf("action = %q, want %q", decision.Action, policy.ActionTempBlock)
	}
	if decision.ExpiresIn <= 0 {
		t.Errorf("ExpiresIn = %d, want a positive remaining lifetime", decision.ExpiresIn)
	}
}

func TestEvidenceBelowTheThresholdIsNotEnough(t *testing.T) {
	r := armed(t, nil)

	// The detector saw something but did not consider it fired.
	r.Observe("203.0.113.11", snap(signals.SignalFlood, 95, false))

	if _, found := r.Lookup("203.0.113.11"); found {
		t.Fatal("blocked an address whose detector never crossed its threshold")
	}
}

func TestScoreFloorIsIndependentOfTheDetectorThreshold(t *testing.T) {
	r := armed(t, nil)

	// Fired, but not convincingly. The floor is what an operator raises to
	// make this less trigger-happy without disabling the detector.
	r.Observe("203.0.113.12", snap(signals.SignalFlood, 40, true))

	if _, found := r.Lookup("203.0.113.12"); found {
		t.Fatal("blocked on a score below min_score")
	}
}

func TestOnlyListedSignalsMayBlock(t *testing.T) {
	r := armed(t, nil) // flood only

	r.Observe("203.0.113.13", snap(signals.SignalSQLi, 100, true))

	if _, found := r.Lookup("203.0.113.13"); found {
		t.Fatal("a signal the operator did not list was allowed to block")
	}
}

func TestEnabledWithNoSignalsEnforcesNothing(t *testing.T) {
	r := armed(t, func(c *Config) { c.Signals = []string{} })

	if r.Active() {
		t.Fatal("Active() is true with no signals listed")
	}

	r.Observe("203.0.113.14", snap(signals.SignalFlood, 100, true))
	if _, found := r.Lookup("203.0.113.14"); found {
		t.Fatal("blocked while no signal was listed")
	}
}

func TestDisabledEnforcesNothing(t *testing.T) {
	r := armed(t, func(c *Config) { c.Enabled = false })

	r.Observe("203.0.113.15", snap(signals.SignalFlood, 100, true))
	if _, found := r.Lookup("203.0.113.15"); found {
		t.Fatal("blocked while disabled")
	}
}

func TestExemptRangesAreNeverBlocked(t *testing.T) {
	r := armed(t, nil)

	for _, ip := range []string{"127.0.0.1", "::1", "10.1.2.3", "192.168.0.5", "172.16.4.4"} {
		r.Observe(ip, snap(signals.SignalFlood, 100, true))
		if _, found := r.Lookup(ip); found {
			t.Errorf("blocked exempt address %s", ip)
		}
	}
}

func TestUnparseableAddressIsNeverBlocked(t *testing.T) {
	r := armed(t, nil)

	r.Observe("not-an-address", snap(signals.SignalFlood, 100, true))
	if _, found := r.Lookup("not-an-address"); found {
		t.Fatal("blocked something that is not an address")
	}
}

func TestABlockExpiresByItself(t *testing.T) {
	r := armed(t, func(c *Config) { c.Duration = 40 * time.Millisecond })

	r.Observe("203.0.113.16", snap(signals.SignalFlood, 100, true))
	if _, found := r.Lookup("203.0.113.16"); !found {
		t.Fatal("not blocked immediately after the signal fired")
	}

	time.Sleep(60 * time.Millisecond)

	// Nothing renews a block and nothing clears one by hand: the deadline is
	// the whole release mechanism, exactly as it is for policy keys.
	if _, found := r.Lookup("203.0.113.16"); found {
		t.Fatal("block outlived its duration")
	}
}

func TestKnockingWhileBlockedDoesNotExtendTheBlock(t *testing.T) {
	r := armed(t, func(c *Config) { c.Duration = 120 * time.Millisecond })

	r.Observe("203.0.113.17", snap(signals.SignalFlood, 100, true))
	first, _ := r.Lookup("203.0.113.17")

	time.Sleep(60 * time.Millisecond)
	// Still flooding. If this reset the clock, an address that kept knocking
	// would never be released -- unexpiring enforcement in a different costume.
	r.Observe("203.0.113.17", snap(signals.SignalFlood, 100, true))

	time.Sleep(80 * time.Millisecond)
	if _, found := r.Lookup("203.0.113.17"); found {
		t.Fatalf("block was extended by continued traffic (first expiry was %ds)", first.ExpiresIn)
	}
}

func TestSweepReleasesMemory(t *testing.T) {
	r := armed(t, func(c *Config) { c.Duration = 10 * time.Millisecond })

	for _, ip := range []string{"203.0.113.20", "203.0.113.21", "203.0.113.22"} {
		r.Observe(ip, snap(signals.SignalFlood, 100, true))
	}
	if got := r.Size(); got != 3 {
		t.Fatalf("Size() = %d, want 3", got)
	}

	time.Sleep(20 * time.Millisecond)
	r.sweep(time.Now())

	if got := r.Size(); got != 0 {
		t.Errorf("Size() = %d after sweeping expired blocks, want 0", got)
	}
}

func TestInvalidExemptRangeIsRefusedAtStartup(t *testing.T) {
	// Starting anyway would enforce against a range list the operator thinks
	// is protecting something, which is worse than refusing to start.
	if _, err := New(Config{Enabled: true, ExemptCIDRs: []string{"not-a-cidr"}}); err == nil {
		t.Fatal("accepted an unparseable exempt range")
	}
}

func TestEnabledAloneNeverArmsTheReflex(t *testing.T) {
	// enforcement.block.enabled has been present in config files since before
	// anything read it. Upgrading into a build that honours it must not start
	// refusing traffic on its own.
	r := armed(t, func(c *Config) { c.Signals = nil })

	if r.Active() {
		t.Fatal("armed on enabled alone, with no signals named")
	}
	r.Observe("203.0.113.30", snap(signals.SignalFlood, 100, true))
	if _, found := r.Lookup("203.0.113.30"); found {
		t.Error("blocked without the operator naming a signal")
	}
}

func TestRecommendedSignalsAreTheWindowedOnes(t *testing.T) {
	// A single request carrying "UNION" is a judgement call, and judgement is
	// the control plane's job. Repetition is not.
	r := armed(t, func(c *Config) { c.Signals = RecommendedSignals })

	r.Observe("203.0.113.31", snap(signals.SignalSQLi, 100, true))
	if _, found := r.Lookup("203.0.113.31"); found {
		t.Error("a request-scoped signal is in the recommended list")
	}

	r.Observe("203.0.113.32", snap(signals.SignalBruteForce, 100, true))
	if _, found := r.Lookup("203.0.113.32"); !found {
		t.Error("brute force is missing from the recommended list")
	}
}

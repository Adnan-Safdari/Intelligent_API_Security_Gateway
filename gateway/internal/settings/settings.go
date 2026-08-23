// Package settings carries live enforcement settings between the console and
// the gateway.
//
// The YAML file stays the source of truth at boot. Redis carries an optional
// override on top of it:
//
//	iasg:settings            what the console asks for. Absent means "the file".
//	iasg:settings:effective  what the gateway is actually running, republished
//	                         on every apply so the console shows the truth
//	                         rather than what it last asked for.
//
// Only the enforcement block travels this way. Listen address, backend URL,
// timeouts and the Redis connection are structural -- changing them means
// rebuilding the server, so they stay in the file where a restart applies them.
//
// The console sends a whole enforcement block, never a patch. A patch would
// need every field to be a pointer to tell "absent" from "zero", and a
// half-applied security setting is a worse failure than a rejected one.
package settings

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

// Key holds the console's override. Deleting it reverts the gateway to the
// settings it booted with.
const Key = "iasg:settings"

// EffectiveKey holds what the gateway is currently enforcing.
const EffectiveKey = "iasg:settings:effective"

// Wire is the JSON shape exchanged with the console. Field names match the
// YAML rather than the Go struct, so a value reads the same in both places,
// and durations are strings ("60s") for the same reason.
type Wire struct {
	RateLimit       RateLimit       `json:"rate_limit"`
	AttackDetection AttackDetection `json:"attack_detection"`
	BruteForce      BruteForce      `json:"brute_force"`
	Enumeration     Enumeration     `json:"enumeration_path_traversal"`
	Throttle        Throttle        `json:"throttle"`
	Block           Block           `json:"block"`
	Policy          Policy          `json:"policy"`
}

type RateLimit struct {
	Enabled bool `json:"enabled"`
	// Whether the threshold is refused rather than only reported.
	Enforce           bool `json:"enforce"`
	RequestsPerMinute int  `json:"requests_per_minute"`
}

type AttackDetection struct {
	Enabled     bool     `json:"enabled"`
	SQLPatterns []string `json:"sql_patterns"`
}

type BruteForce struct {
	Enabled     bool     `json:"enabled"`
	MaxFailures int      `json:"max_failures"`
	Window      string   `json:"window"`
	LoginPaths  []string `json:"login_paths"`
}

type Enumeration struct {
	Enabled             bool     `json:"enabled"`
	TraversalPatterns   []string `json:"traversal_patterns"`
	EnumerationPatterns []string `json:"enumeration_patterns"`
}

type Throttle struct {
	Enabled bool `json:"enabled"`
	DelayMS int  `json:"delay_ms"`
}

type Block struct {
	Enabled     bool     `json:"enabled"`
	Duration    string   `json:"duration"`
	Signals     []string `json:"signals"`
	MinScore    int      `json:"min_score"`
	ExemptCIDRs []string `json:"exempt_cidrs"`
}

// Policy carries only the flag that can move at runtime. KeyPrefix and
// RefreshInterval configure the poller itself and are fixed at boot.
type Policy struct {
	Enabled bool `json:"enabled"`
}

// FromConfig renders a config block as the wire shape.
func FromConfig(c config.EnforcementConfig) Wire {
	return Wire{
		RateLimit: RateLimit{
			Enabled:           c.RateLimit.Enabled,
			Enforce:           c.RateLimit.Enforce,
			RequestsPerMinute: c.RateLimit.RequestsPerMinute,
		},
		AttackDetection: AttackDetection{
			Enabled:     c.AttackDetection.Enabled,
			SQLPatterns: c.AttackDetection.SQLPatterns,
		},
		BruteForce: BruteForce{
			Enabled:     c.BruteForce.Enabled,
			MaxFailures: c.BruteForce.MaxFailures,
			Window:      durationString(c.BruteForce.Window),
			LoginPaths:  c.BruteForce.LoginPaths,
		},
		Enumeration: Enumeration{
			Enabled:             c.Enumeration.Enabled,
			TraversalPatterns:   c.Enumeration.TraversalPatterns,
			EnumerationPatterns: c.Enumeration.EnumerationPatterns,
		},
		Throttle: Throttle{
			Enabled: c.Throttle.Enabled,
			DelayMS: c.Throttle.DelayMS,
		},
		Block: Block{
			Enabled:     c.Block.Enabled,
			Duration:    durationString(c.Block.Duration),
			Signals:     c.Block.Signals,
			MinScore:    c.Block.MinScore,
			ExemptCIDRs: c.Block.ExemptCIDRs,
		},
		Policy: Policy{Enabled: c.Policy.Enabled},
	}
}

// ToConfig converts the wire shape back, carrying over the boot values for the
// fields that do not travel. base supplies those, so a live apply can never
// blank the key prefix or the refresh interval by omitting them.
func (w Wire) ToConfig(base config.EnforcementConfig) (config.EnforcementConfig, error) {
	out := base

	out.RateLimit.Enabled = w.RateLimit.Enabled
	out.RateLimit.Enforce = w.RateLimit.Enforce
	out.RateLimit.RequestsPerMinute = w.RateLimit.RequestsPerMinute

	out.AttackDetection.Enabled = w.AttackDetection.Enabled
	out.AttackDetection.SQLPatterns = w.AttackDetection.SQLPatterns

	window, err := parseDuration(w.BruteForce.Window, "brute_force.window")
	if err != nil {
		return config.EnforcementConfig{}, err
	}
	out.BruteForce.Enabled = w.BruteForce.Enabled
	out.BruteForce.MaxFailures = w.BruteForce.MaxFailures
	out.BruteForce.Window = window
	out.BruteForce.LoginPaths = w.BruteForce.LoginPaths

	out.Enumeration.Enabled = w.Enumeration.Enabled
	out.Enumeration.TraversalPatterns = w.Enumeration.TraversalPatterns
	out.Enumeration.EnumerationPatterns = w.Enumeration.EnumerationPatterns

	out.Throttle.Enabled = w.Throttle.Enabled
	out.Throttle.DelayMS = w.Throttle.DelayMS

	duration, err := parseDuration(w.Block.Duration, "block.duration")
	if err != nil {
		return config.EnforcementConfig{}, err
	}
	out.Block.Enabled = w.Block.Enabled
	out.Block.Duration = duration
	out.Block.MinScore = w.Block.MinScore
	// Both of these are meaningful when empty -- an empty signal list arms
	// nothing, an empty exempt list exempts nobody -- so a nil from JSON is
	// normalised to an empty slice rather than left to mean "use the default".
	out.Block.Signals = orEmpty(w.Block.Signals)
	out.Block.ExemptCIDRs = orEmpty(w.Block.ExemptCIDRs)

	out.Policy.Enabled = w.Policy.Enabled

	return out, nil
}

// Decode parses the JSON the console wrote.
func Decode(raw []byte, base config.EnforcementConfig) (config.EnforcementConfig, error) {
	var w Wire
	if err := json.Unmarshal(raw, &w); err != nil {
		return config.EnforcementConfig{}, fmt.Errorf("settings json: %w", err)
	}
	return w.ToConfig(base)
}

// Encode renders a config block as the JSON the console reads.
func Encode(c config.EnforcementConfig) ([]byte, error) {
	return json.Marshal(FromConfig(c))
}

func orEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func durationString(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.String()
}

// parseDuration accepts an empty string as "leave it to the default", which is
// what an omitted YAML key already means.
func parseDuration(in, field string) (time.Duration, error) {
	if in == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(in)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration like \"60s\" or \"5m\"", field, in)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s: %q is negative", field, in)
	}
	return d, nil
}

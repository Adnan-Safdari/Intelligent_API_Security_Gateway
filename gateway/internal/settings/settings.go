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
	// Reported for operator visibility; ToConfig preserves the boot values.
	AdaptiveRateLimit AdaptiveRateLimit `json:"adaptive_rate_limit"`
	RateLimit         RateLimit         `json:"rate_limit"`
	AttackDetection   AttackDetection   `json:"attack_detection"`
	BruteForce        BruteForce        `json:"brute_force"`
	UnknownRouteScan  UnknownRouteScan  `json:"unknown_route_scanning"`
	Enumeration       Enumeration       `json:"enumeration_path_traversal"`
	IPReputation      IPReputation      `json:"ip_reputation"`
	Throttle          Throttle          `json:"throttle"`
	Block             Block             `json:"block"`
	Policy            Policy            `json:"policy"`
}

type AdaptiveRateLimit struct {
	FallbackRequestsPerMinute int    `json:"fallback_requests_per_minute"`
	Burst                     int    `json:"burst"`
	RedisTimeout              string `json:"redis_timeout"`
	PolicyRefreshTimeout      string `json:"policy_refresh_timeout"`
	FailureBackoff            string `json:"failure_backoff"`
	CacheMaxAge               string `json:"cache_max_age"`
	BucketKeyPrefix           string `json:"bucket_key_prefix"`
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
	Enabled             bool   `json:"enabled"`
	MaxFailures         int    `json:"max_failures"`
	Window              string `json:"window"`
	MaxClients          int    `json:"max_clients"`
	MaxTargetsPerClient int    `json:"max_targets_per_client"`
}

type UnknownRouteScan struct {
	Enabled           bool   `json:"enabled"`
	DistinctPaths     int    `json:"distinct_paths"`
	Window            string `json:"window"`
	MaxClients        int    `json:"max_clients"`
	MaxPathsPerClient int    `json:"max_paths_per_client"`
}

// IPReputation carries only what may move at runtime. feed_path, feed_url and
// refresh_interval are structural and deliberately absent: repointing a running
// gateway at another list is not a settings tweak, and ToConfig keeps the boot
// values for them.
type IPReputation struct {
	Enabled  bool   `json:"enabled"`
	Score    int    `json:"score"`
	Cooldown string `json:"cooldown"`
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
		AdaptiveRateLimit: AdaptiveRateLimit{
			FallbackRequestsPerMinute: c.AdaptiveRateLimit.FallbackRequestsPerMinute,
			Burst:                     c.AdaptiveRateLimit.Burst,
			RedisTimeout:              durationString(c.AdaptiveRateLimit.RedisTimeout),
			PolicyRefreshTimeout:      durationString(c.AdaptiveRateLimit.PolicyRefreshTimeout),
			FailureBackoff:            durationString(c.AdaptiveRateLimit.FailureBackoff),
			CacheMaxAge:               durationString(c.AdaptiveRateLimit.CacheMaxAge),
			BucketKeyPrefix:           c.AdaptiveRateLimit.BucketKeyPrefix,
		},
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
			Enabled:             c.BruteForce.Enabled,
			MaxFailures:         c.BruteForce.MaxFailures,
			Window:              durationString(c.BruteForce.Window),
			MaxClients:          c.BruteForce.MaxClients,
			MaxTargetsPerClient: c.BruteForce.MaxTargetsPerClient,
		},
		UnknownRouteScan: UnknownRouteScan{
			Enabled:           c.UnknownRouteScan.Enabled,
			DistinctPaths:     c.UnknownRouteScan.DistinctPaths,
			Window:            durationString(c.UnknownRouteScan.Window),
			MaxClients:        c.UnknownRouteScan.MaxClients,
			MaxPathsPerClient: c.UnknownRouteScan.MaxPathsPerClient,
		},
		IPReputation: IPReputation{
			Enabled:  c.IPReputation.Enabled,
			Score:    c.IPReputation.Score,
			Cooldown: durationString(c.IPReputation.Cooldown),
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
	out.BruteForce.MaxClients = w.BruteForce.MaxClients
	out.BruteForce.MaxTargetsPerClient = w.BruteForce.MaxTargetsPerClient

	scanWindow, err := parseDuration(w.UnknownRouteScan.Window, "unknown_route_scanning.window")
	if err != nil {
		return config.EnforcementConfig{}, err
	}
	out.UnknownRouteScan.Enabled = w.UnknownRouteScan.Enabled
	out.UnknownRouteScan.DistinctPaths = w.UnknownRouteScan.DistinctPaths
	out.UnknownRouteScan.Window = scanWindow
	out.UnknownRouteScan.MaxClients = w.UnknownRouteScan.MaxClients
	out.UnknownRouteScan.MaxPathsPerClient = w.UnknownRouteScan.MaxPathsPerClient

	out.BruteForce, err = config.ValidatedBruteForce(out.BruteForce)
	if err != nil {
		return config.EnforcementConfig{}, err
	}
	out.UnknownRouteScan, err = config.ValidatedUnknownRouteScan(out.UnknownRouteScan)
	if err != nil {
		return config.EnforcementConfig{}, err
	}

	out.Enumeration.Enabled = w.Enumeration.Enabled
	out.Enumeration.TraversalPatterns = w.Enumeration.TraversalPatterns
	out.Enumeration.EnumerationPatterns = w.Enumeration.EnumerationPatterns

	cooldown, err := parseDuration(w.IPReputation.Cooldown, "ip_reputation.cooldown")
	if err != nil {
		return config.EnforcementConfig{}, err
	}
	out.IPReputation.Enabled = w.IPReputation.Enabled
	out.IPReputation.Score = w.IPReputation.Score
	out.IPReputation.Cooldown = cooldown

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

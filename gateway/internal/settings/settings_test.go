package settings

import (
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

func base() config.EnforcementConfig {
	return config.EnforcementConfig{
		RateLimit: config.RateLimitConfig{Enabled: true, RequestsPerMinute: 100, Burst: 20},
		BruteForce: config.BruteForceConfig{
			Enabled: true, MaxFailures: 5, Window: time.Minute, MaxClients: 10_000, MaxTargetsPerClient: 64,
		},
		UnknownRouteScan: config.UnknownRouteScanConfig{
			Enabled: true, DistinctPaths: 8, Window: 5 * time.Minute, MaxClients: 10_000, MaxPathsPerClient: 64,
		},
		ObjectEnumeration: config.ObjectEnumerationConfig{
			Enabled: true, DistinctIDs: 20, Window: 5 * time.Minute, MaxClients: 10_000, MaxIDsPerClient: 256,
		},
		Block: config.BlockConfig{
			Enabled: true, Duration: 60 * time.Second, MinScore: 50,
			Signals: []string{"api_flooding"},
		},
		Policy: config.PolicyConfig{
			Enabled: true, KeyPrefix: "policy:", RefreshInterval: 5 * time.Second,
		},
	}
}

func TestRoundTripKeepsValues(t *testing.T) {
	in := base()

	out, err := FromConfig(in).ToConfig(in)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}

	if out.RateLimit.RequestsPerMinute != 100 {
		t.Errorf("requests_per_minute = %d, want 100", out.RateLimit.RequestsPerMinute)
	}
	if out.BruteForce.Window != time.Minute || out.BruteForce.MaxClients != 10_000 || out.BruteForce.MaxTargetsPerClient != 64 {
		t.Errorf("brute-force settings = %+v, want 1m/10000/64", out.BruteForce)
	}
	if out.UnknownRouteScan.DistinctPaths != 8 || out.UnknownRouteScan.Window != 5*time.Minute {
		t.Errorf("unknown route scanning settings = %+v", out.UnknownRouteScan)
	}
	if out.ObjectEnumeration != in.ObjectEnumeration {
		t.Errorf("object enumeration settings = %+v, want %+v", out.ObjectEnumeration, in.ObjectEnumeration)
	}
	if out.Block.Duration != 60*time.Second {
		t.Errorf("duration = %s, want 60s", out.Block.Duration)
	}
}

// An override saved before object_enumeration existed has no such section. It
// must keep the file's values rather than read as all-zero, which would switch
// the detector off on upgrade.
func TestOverrideWithoutObjectEnumerationKeepsTheFileValues(t *testing.T) {
	in := base()
	wire := FromConfig(in)
	wire.ObjectEnumeration = nil

	out, err := wire.ToConfig(in)
	if err != nil {
		t.Fatalf("ToConfig: %v", err)
	}
	if !out.ObjectEnumeration.Enabled || out.ObjectEnumeration.DistinctIDs != 20 {
		t.Errorf("object enumeration after an older override = %+v, want the file's", out.ObjectEnumeration)
	}

	wire.ObjectEnumeration = &ObjectEnumeration{Enabled: true, DistinctIDs: 1, Window: "5m"}
	if _, err := wire.ToConfig(in); err == nil {
		t.Error("an override with distinct_ids 1 was accepted")
	}
}

func TestDashboardCannotResetStructuralQuotaSettings(t *testing.T) {
	in := base()
	in.AdaptiveRateLimit = config.AdaptiveRateLimitConfig{
		FallbackRequestsPerMinute: 17, Burst: 3, RedisTimeout: 40 * time.Millisecond, PolicyRefreshTimeout: 3 * time.Second,
		FailureBackoff: 2 * time.Second, CacheMaxAge: 20 * time.Second, BucketKeyPrefix: "custom-rate:",
	}
	wire := FromConfig(in)
	if wire.AdaptiveRateLimit.Burst != 3 || wire.AdaptiveRateLimit.RedisTimeout != "40ms" {
		t.Fatalf("dashboard cannot display quota settings: %+v", wire.AdaptiveRateLimit)
	}
	wire.AdaptiveRateLimit.Burst = 999
	out, err := wire.ToConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.AdaptiveRateLimit != in.AdaptiveRateLimit {
		t.Fatal("live settings changed boot-only quota contract")
	}
	out, err = (Wire{}).ToConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.AdaptiveRateLimit != in.AdaptiveRateLimit {
		t.Fatal("older dashboard silently cleared quota settings")
	}
}

// The fields that do not travel must survive a round trip, or a live apply
// would silently blank the key prefix the policy store reads.
func TestFieldsThatDoNotTravelAreKept(t *testing.T) {
	in := base()

	out, err := Wire{}.ToConfig(in)
	if err != nil {
		t.Fatalf("to config: %v", err)
	}

	if out.Policy.KeyPrefix != "policy:" {
		t.Errorf("key prefix = %q, want it carried over from the base", out.Policy.KeyPrefix)
	}
	if out.Policy.RefreshInterval != 5*time.Second {
		t.Errorf("refresh interval = %s, want it carried over from the base", out.Policy.RefreshInterval)
	}
	if out.RateLimit.Burst != 20 {
		t.Errorf("burst = %d, want it carried over from the base", out.RateLimit.Burst)
	}
}

// An empty signal list arms nothing and an empty exempt list exempts nobody.
// Both are meaningful, so neither may be turned back into "use the default".
func TestEmptyListsStayEmpty(t *testing.T) {
	w := FromConfig(base())
	w.Block.Signals = []string{}
	w.Block.ExemptCIDRs = []string{}

	out, err := w.ToConfig(base())
	if err != nil {
		t.Fatalf("to config: %v", err)
	}

	if out.Block.Signals == nil {
		t.Error("an explicitly empty signal list became nil, which means 'use the defaults'")
	}
	if out.Block.ExemptCIDRs == nil {
		t.Error("an explicitly empty exempt list became nil, which means 'use the defaults'")
	}
	if len(out.Block.Signals) != 0 || len(out.Block.ExemptCIDRs) != 0 {
		t.Error("empty lists did not stay empty")
	}
}

func TestBadDurationIsRejected(t *testing.T) {
	w := FromConfig(base())
	w.Block.Duration = "5 minutes"

	if _, err := w.ToConfig(base()); err == nil {
		t.Fatal("a duration of \"5 minutes\" was accepted; it should be rejected")
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := Decode([]byte("{not json"), base()); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
}

func TestEncodeUsesYAMLNames(t *testing.T) {
	raw, err := Encode(base())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// The console and the YAML file should name things the same way, so a
	// value can be found in both.
	for _, want := range []string{
		`"rate_limit"`, `"requests_per_minute"`, `"brute_force"`,
		`"max_failures"`, `"min_score"`, `"enumeration_path_traversal"`,
	} {
		if !contains(string(raw), want) {
			t.Errorf("encoded settings missing %s: %s", want, raw)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

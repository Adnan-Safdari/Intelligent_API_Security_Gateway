package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const minimal = `
server:
  port: 8082
proxy:
  backend_url: "http://localhost:5002"
`

func TestAdaptiveSettingsAreBoundedAndPreserveOldConfigurations(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.Enforcement.AdaptiveRateLimit
	if a.FallbackRequestsPerMinute <= 0 || a.Burst <= 0 || a.RedisTimeout <= 0 || a.RedisTimeout > time.Second || a.CacheMaxAge < cfg.Enforcement.Policy.RefreshInterval {
		t.Fatalf("unsafe defaults for old configuration: %+v", a)
	}
	cfg, err = Load(write(t, minimal+`
enforcement:
  policy:
    refresh_interval: 20s
  adaptive_rate_limit:
    fallback_requests_per_minute: 17
    burst: 3
    redis_timeout: 40ms
    policy_refresh_timeout: 3s
    failure_backoff: 2s
    bucket_key_prefix: "custom-rate:"
`))
	if err != nil {
		t.Fatal(err)
	}
	a = cfg.Enforcement.AdaptiveRateLimit
	if a.FallbackRequestsPerMinute != 17 || a.Burst != 3 || a.RedisTimeout != 40*time.Millisecond || a.PolicyRefreshTimeout != 3*time.Second || a.FailureBackoff != 2*time.Second || a.CacheMaxAge < 20*time.Second || a.BucketKeyPrefix != "custom-rate:" {
		t.Fatalf("custom settings lost: %+v", a)
	}
	for _, setting := range []string{
		"fallback_requests_per_minute: -1", "burst: -1", "redis_timeout: 2s",
		"redis_timeout: 1ns", "failure_backoff: -1s", "cache_max_age: 1s",
		"policy_refresh_timeout: 10ms", "policy_refresh_timeout: 1m",
		`bucket_key_prefix: "policy:rate:"`,
	} {
		t.Run(setting, func(t *testing.T) {
			if _, err := Load(write(t, minimal+"\nenforcement:\n  adaptive_rate_limit:\n    "+setting+"\n")); err == nil {
				t.Fatalf("unsafe adaptive configuration accepted: %s", setting)
			}
		})
	}
}

func TestLoadMinimalConfig(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Port != 8082 {
		t.Errorf("port = %d, want 8082", cfg.Server.Port)
	}
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("host = %q, want the 0.0.0.0 default", cfg.Server.Host)
	}
}

// Trusting no proxy is the safe default, and it has to survive a config that
// simply omits the key.
func TestTrustedProxiesDefaultsToEmpty(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Server.TrustedProxies) != 0 {
		t.Fatalf("want no trusted proxies by default, got %v", cfg.Server.TrustedProxies)
	}
}

func TestTrustedProxiesParsed(t *testing.T) {
	cfg, err := Load(write(t, `
server:
  port: 8082
  trusted_proxies:
    - 127.0.0.1/32
    - 10.0.0.0/8
proxy:
  backend_url: "http://localhost:5002"
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := []string{"127.0.0.1/32", "10.0.0.0/8"}
	if len(cfg.Server.TrustedProxies) != len(want) {
		t.Fatalf("got %v, want %v", cfg.Server.TrustedProxies, want)
	}
	for i, w := range want {
		if cfg.Server.TrustedProxies[i] != w {
			t.Errorf("[%d] = %q, want %q", i, cfg.Server.TrustedProxies[i], w)
		}
	}
}

func TestPolicyEnforcementParsed(t *testing.T) {
	cfg, err := Load(write(t, `
server:
  port: 8082
proxy:
  backend_url: "http://localhost:5002"
enforcement:
  policy:
    enabled: true
    key_prefix: "block:"
    refresh_interval: 10s
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	p := cfg.Enforcement.Policy
	if !p.Enabled || p.KeyPrefix != "block:" || p.RefreshInterval != 10*time.Second {
		t.Fatalf("policy config parsed wrongly: %+v", p)
	}
}

// Enforcement off unless explicitly enabled -- the whole point of the flag.
func TestPolicyEnforcementOffByDefault(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Enforcement.Policy.Enabled {
		t.Fatal("policy enforcement must default to disabled")
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"missing port":        "proxy:\n  backend_url: \"http://x\"\n",
		"zero port":           "server:\n  port: 0\nproxy:\n  backend_url: \"http://x\"\n",
		"missing backend_url": "server:\n  port: 8082\n",
		"malformed yaml":      "server:\n  port: [unclosed\n",
	}

	for name, body := range cases {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

// The config shipped in the repo must actually load.
func TestShippedConfigIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "config.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("shipped config not found: %v", err)
	}

	if _, err := Load(path); err != nil {
		t.Fatalf("configs/config.yaml does not load: %v", err)
	}
}

// The routes block is deliberately top-level rather than under enforcement:,
// so it does not travel through the settings watcher. This asserts it survives
// the load at all -- a block that parsed into nothing would leave every request
// recording an unmatched route with nothing failing.
func TestRouteTemplatesSurviveTheLoad(t *testing.T) {
	cfg, err := Load(write(t, minimal+`
routes:
  templates:
    - GET /api/products
    - GET /api/products/{id}
`))
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Routes.Templates) != 2 {
		t.Fatalf("Routes.Templates = %v, want the two configured templates", cfg.Routes.Templates)
	}
	if cfg.Routes.Templates[1] != "GET /api/products/{id}" {
		t.Errorf("template = %q, want it verbatim", cfg.Routes.Templates[1])
	}
}

// A gateway with no routes block must still load. Route templates describe the
// backend, and a deployment that has not described one is not misconfigured.
func TestMissingRoutesBlockIsNotAnError(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Routes.Templates) != 0 {
		t.Errorf("Routes.Templates = %v, want empty", cfg.Routes.Templates)
	}
}

func TestLowAndSlowDetectorLimitsAreValidated(t *testing.T) {
	for name, body := range map[string]string{
		"invalid login threshold": `brute_force:
    max_failures: -1`,
		"unbounded brute-force clients": `brute_force:
    max_clients: 100001`,
		"unbounded brute-force targets": `brute_force:
    max_targets_per_client: 10001`,
		"unbounded scanner clients": `unknown_route_scanning:
    max_clients: 100001`,
		"scanner threshold exceeds retained paths": `unknown_route_scanning:
    distinct_paths: 9
    max_paths_per_client: 8`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, minimal+"\nenforcement:\n  "+body+"\n")); err == nil {
				t.Fatal("unsafe low-and-slow detector limits were accepted")
			}
		})
	}
}

// config.own-api.yaml is what someone protecting their own API starts from. Its
// detection and enforcement must stay the example's: a detector left out of a
// config file is not defaulted, it is silently off, so a template that drifted
// would ship a gateway that detects less than the documentation describes.
func TestOwnAPITemplateDetectsWhatTheExampleDetects(t *testing.T) {
	template, err := Load(filepath.Join("..", "..", "configs", "config.own-api.yaml"))
	if err != nil {
		t.Fatalf("configs/config.own-api.yaml does not load: %v", err)
	}
	example, err := Load(filepath.Join("..", "..", "configs", "config.yaml.example"))
	if err != nil {
		t.Fatalf("configs/config.yaml.example does not load: %v", err)
	}

	if !reflect.DeepEqual(template.Enforcement, example.Enforcement) {
		t.Error("enforcement block differs from config.yaml.example; copy it across")
	}
	if !reflect.DeepEqual(template.Signals, example.Signals) {
		t.Error("signals block differs from config.yaml.example; copy it across")
	}
	if template.Proxy.PreserveHost {
		t.Error("preserve_host must default to false: most backends need their own Host")
	}
	if len(template.Routes.AuthOutcomes) == 0 {
		t.Error("the template must show an auth_outcomes entry, or brute-force detection is off")
	}
}

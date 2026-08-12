package config

import (
	"os"
	"path/filepath"
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

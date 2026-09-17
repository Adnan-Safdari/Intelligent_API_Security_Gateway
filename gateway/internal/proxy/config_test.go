package proxy

import (
	"reflect"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

// Every file section the server reads must survive ConfigFrom. Enforcement is
// carried whole, so a section added to it later cannot be dropped here and
// boot switched off with nothing to say so.
func TestConfigFromCarriesEverySection(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.Port = 8082
	cfg.Server.ReadTimeout = time.Second
	cfg.Server.WriteTimeout = 2 * time.Second
	cfg.Server.IdleTimeout = 3 * time.Second
	cfg.Server.MaxBodyBytes = 4096
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8"}
	cfg.Proxy.BackendURL = "http://backend:5002"
	cfg.Proxy.PreserveHost = true
	cfg.Proxy.Timeout = 4 * time.Second
	cfg.Proxy.MaxIdleConns = 5
	cfg.Proxy.MaxConnsPerHost = 6
	cfg.Routes.Templates = []string{"POST /api/login"}
	cfg.Storage.Redis.Enabled = true
	cfg.Storage.Redis.Host = "redis"
	cfg.Enforcement.BruteForce.Enabled = true
	cfg.Enforcement.Block.Signals = []string{"api_flooding"}
	cfg.Enforcement.AdaptiveRateLimit.Burst = 7

	got := ConfigFrom(cfg)
	want := Config{
		ListenAddr:      "127.0.0.1:8082",
		BackendURL:      "http://backend:5002",
		PreserveHost:    true,
		ReadTimeout:     time.Second,
		WriteTimeout:    2 * time.Second,
		IdleTimeout:     3 * time.Second,
		ProxyTimeout:    4 * time.Second,
		MaxIdleConns:    5,
		MaxConnsPerHost: 6,
		MaxBodyBytes:    4096,
		Routes:          cfg.Routes,
		Enforcement:     cfg.Enforcement,
		Redis:           cfg.Storage.Redis,
		TrustedProxies:  []string{"10.0.0.0/8"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConfigFrom() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestConfigFromJoinsIPv6ListenAddress(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Host = "::"
	cfg.Server.Port = 8082
	if got := ConfigFrom(cfg).ListenAddr; got != "[::]:8082" {
		t.Errorf("ListenAddr = %q, want [::]:8082", got)
	}
}

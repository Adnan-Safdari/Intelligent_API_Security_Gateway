package config

import (
	"reflect"
	"testing"
)

func TestApplyEnvOverridesReplacesOnlyWhatIsSet(t *testing.T) {
	cfg := &Config{}
	cfg.Proxy.BackendURL = "http://localhost:5002"
	cfg.Storage.Redis.Host = "localhost"

	env := map[string]string{"IASG_BACKEND_URL": "http://vulnerable_api:5002"}
	applied := ApplyEnvOverrides(cfg, func(k string) string { return env[k] })

	if cfg.Proxy.BackendURL != "http://vulnerable_api:5002" {
		t.Errorf("backend = %q, want the env value", cfg.Proxy.BackendURL)
	}
	if cfg.Storage.Redis.Host != "localhost" {
		t.Errorf("redis host = %q, an unset variable must leave the file value", cfg.Storage.Redis.Host)
	}
	want := []string{"Overriding backend URL from IASG_BACKEND_URL: http://vulnerable_api:5002"}
	if !reflect.DeepEqual(applied, want) {
		t.Errorf("applied = %q, want %q", applied, want)
	}
}

func TestApplyEnvOverridesRedisHost(t *testing.T) {
	cfg := &Config{}
	env := map[string]string{"IASG_REDIS_HOST": "redis"}
	applied := ApplyEnvOverrides(cfg, func(k string) string { return env[k] })

	if cfg.Storage.Redis.Host != "redis" || len(applied) != 1 {
		t.Errorf("host = %q, applied = %q", cfg.Storage.Redis.Host, applied)
	}
}

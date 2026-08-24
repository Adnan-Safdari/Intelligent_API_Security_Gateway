package config

import "testing"

func TestExampleConfigLoadsWithReputation(t *testing.T) {
	for _, path := range []string{"../../configs/config.yaml.example", "../../configs/config.yaml"} {
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		rep := cfg.Enforcement.IPReputation
		if !rep.Enabled {
			t.Errorf("%s: ip_reputation should be enabled", path)
		}
		if rep.FeedPath == "" {
			t.Errorf("%s: feed_path should be set", path)
		}
		if rep.Score != 80 {
			t.Errorf("%s: want score 80, got %d", path, rep.Score)
		}
		if rep.Cooldown.Minutes() != 5 {
			t.Errorf("%s: want 5m cooldown, got %v", path, rep.Cooldown)
		}
	}
}

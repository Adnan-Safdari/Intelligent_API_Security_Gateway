package policy

import (
	"context"
	"testing"
	"time"
)

// The JSON the Python control plane actually writes.
const realPolicy = `{"action": "temp_block", "campaign_id": "2", "confidence": 0.97,` +
	` "reason": "Credential Stuffing", "issued_at": "2026-08-12T06:30:30.270057+00:00",` +
	` "expires_in": 1800}`

func TestCollectDecodesAndStripsPrefix(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot,
		[]string{"policy:203.0.113.5"},
		[]any{realPolicy},
		"policy:")

	d, ok := snapshot["203.0.113.5"]
	if !ok {
		t.Fatalf("key not stored under the stripped IP, snapshot = %v", snapshot)
	}
	if d.Action != ActionTempBlock || d.CampaignID != "2" || d.ExpiresIn != 1800 {
		t.Fatalf("decoded wrongly: %+v", d)
	}
}

// A key can expire between the SCAN that listed it and the MGET that fetches
// it, in which case Redis returns nil.
func TestCollectSkipsExpiredKeys(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot,
		[]string{"policy:203.0.113.5", "policy:203.0.113.9"},
		[]any{nil, realPolicy},
		"policy:")

	if _, ok := snapshot["203.0.113.5"]; ok {
		t.Error("an expired key was stored")
	}
	if _, ok := snapshot["203.0.113.9"]; !ok {
		t.Error("the live key alongside it was lost")
	}
}

// One bad key must not cost us every good one.
func TestCollectSkipsMalformedJSON(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot,
		[]string{"policy:203.0.113.5", "policy:203.0.113.9"},
		[]any{"{not json", realPolicy},
		"policy:")

	if len(snapshot) != 1 {
		t.Fatalf("want 1 usable entry, got %d: %v", len(snapshot), snapshot)
	}
	if _, ok := snapshot["203.0.113.9"]; !ok {
		t.Error("the valid key was discarded along with the broken one")
	}
}

// Redis should never return more values than keys, but a mismatch must not
// panic on an index out of range.
func TestCollectSurvivesLengthMismatch(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot,
		[]string{"policy:203.0.113.5"},
		[]any{realPolicy, realPolicy, realPolicy},
		"policy:")

	if len(snapshot) != 1 {
		t.Fatalf("want 1 entry, got %d", len(snapshot))
	}
}

func TestCollectHandlesEmptyBatch(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot, nil, nil, "policy:")

	if len(snapshot) != 0 {
		t.Fatalf("want empty, got %v", snapshot)
	}
}

// Before the first refresh there is no snapshot at all. Lookup must report
// "no policy" rather than panicking on a nil map.
func TestLookupBeforeFirstRefresh(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:6379"})
	defer s.Close()

	if _, found := s.Lookup("203.0.113.5"); found {
		t.Fatal("found a decision before any refresh ran")
	}
	if n := s.size(); n != 0 {
		t.Fatalf("size = %d, want 0", n)
	}
}

func TestLookupReadsCurrentSnapshot(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:6379"})
	defer s.Close()

	snapshot := map[string]Decision{"203.0.113.5": {Action: ActionTempBlock}}
	s.snapshot.Store(&snapshot)

	d, found := s.Lookup("203.0.113.5")
	if !found || d.Action != ActionTempBlock {
		t.Fatalf("lookup returned %+v found=%v", d, found)
	}
	if _, found := s.Lookup("198.51.100.1"); found {
		t.Fatal("an address with no policy was reported as found")
	}
}

func TestNewStoreAppliesDefaults(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:6379"})
	defer s.Close()

	if s.prefix != "policy:" {
		t.Errorf("prefix = %q, want the default policy:", s.prefix)
	}
	if s.interval != 5*time.Second {
		t.Errorf("interval = %v, want the default 5s", s.interval)
	}
}

func TestNewStoreKeepsExplicitSettings(t *testing.T) {
	s := NewStore(Config{
		Addr:            "127.0.0.1:6379",
		KeyPrefix:       "block:",
		RefreshInterval: 30 * time.Second,
	})
	defer s.Close()

	if s.prefix != "block:" || s.interval != 30*time.Second {
		t.Fatalf("settings overridden: prefix=%q interval=%v", s.prefix, s.interval)
	}
}

// Close must be safe on a store that was never started.
func TestCloseWithoutStart(t *testing.T) {
	if err := NewStore(Config{Addr: "127.0.0.1:6379"}).Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// An unreachable Redis must leave the store empty and usable, never blocking
// or panicking -- the gateway has to keep serving when the control plane is
// down.
func TestRefreshAgainstUnreachableRedisFailsOpen(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:1", RefreshInterval: time.Second})
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.refresh(ctx); err == nil {
		t.Fatal("expected an error from an unreachable Redis")
	}
	if _, found := s.Lookup("203.0.113.5"); found {
		t.Fatal("a failed refresh must not invent policy")
	}
}

// Exercises the real SCAN/MGET path. Skipped when no Redis is running, so the
// suite still passes on a machine with nothing installed.
func TestRefreshAgainstRealRedis(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:6379", KeyPrefix: "policytest:"})
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.client.Ping(ctx).Err(); err != nil {
		t.Skipf("no Redis on 127.0.0.1:6379: %v", err)
	}

	keys := []string{"policytest:203.0.113.5", "policytest:203.0.113.9"}
	for _, k := range keys {
		if err := s.client.Set(ctx, k, realPolicy, time.Minute).Err(); err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
	}
	defer s.client.Del(ctx, keys...)

	if err := s.refresh(ctx); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	for _, ip := range []string{"203.0.113.5", "203.0.113.9"} {
		d, found := s.Lookup(ip)
		if !found {
			t.Errorf("%s missing from the snapshot", ip)
			continue
		}
		if d.Action != ActionTempBlock || d.ExpiresIn != 1800 {
			t.Errorf("%s decoded wrongly: %+v", ip, d)
		}
	}

	// Deleting the key must drop it from the next snapshot, which is what
	// makes a policy expiring in Redis restore service by itself.
	s.client.Del(ctx, "policytest:203.0.113.5")
	if err := s.refresh(ctx); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if _, found := s.Lookup("203.0.113.5"); found {
		t.Error("a deleted key survived the refresh")
	}
}

// Start must load once up front and then keep the goroutine running, and
// Close must shut it down without hanging.
func TestStartAndCloseLifecycle(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:6379", RefreshInterval: time.Second})

	s.Start()

	done := make(chan error, 1)
	go func() { done <- s.Close() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung -- the refresh goroutine did not stop")
	}
}

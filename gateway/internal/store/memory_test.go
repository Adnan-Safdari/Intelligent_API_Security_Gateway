package store

import (
	"context"
	"testing"
	"time"
)

// A key that was never written must come back as "not found" with no error.
// The gateway relies on this distinction: absence means "nothing known about
// this IP, carry on", whereas an error means "the store is broken". Collapsing
// the two would make the gateway unable to tell a healthy quiet system from a
// dead one.
func TestMemoryStoreGetMissingKey(t *testing.T) {
	m := NewMemory()

	value, found, err := m.Get(context.Background(), "nope")
	if err != nil {
		t.Fatalf("expected no error for a missing key, got %v", err)
	}
	if found {
		t.Fatalf("expected found=false for a key that was never set")
	}
	if value != "" {
		t.Fatalf("expected empty value for a missing key, got %q", value)
	}
}

// The basic round trip: what goes in comes back out.
func TestMemoryStoreSetThenGet(t *testing.T) {
	m := NewMemory()
	m.Set("policy:10.0.0.5", "throttle", 0)

	value, found, err := m.Get(context.Background(), "policy:10.0.0.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatalf("expected to find the key that was just set")
	}
	if value != "throttle" {
		t.Fatalf("expected %q, got %q", "throttle", value)
	}
}

// Keys must disappear on their own once their lifetime is up. This is the
// property that lets a wrong decision undo itself instead of stranding an IP.
//
// Timed with a real short duration and a real sleep, matching the sliding
// window tests in internal/signals.
func TestMemoryStoreExpiresAfterTTL(t *testing.T) {
	const ttl = 50 * time.Millisecond

	m := NewMemory()
	m.Set("policy:10.0.0.5", "block", ttl)

	// Still inside its lifetime.
	if _, found, _ := m.Get(context.Background(), "policy:10.0.0.5"); !found {
		t.Fatalf("key expired before its ttl elapsed")
	}

	time.Sleep(ttl + 30*time.Millisecond)

	value, found, err := m.Get(context.Background(), "policy:10.0.0.5")
	if err != nil {
		t.Fatalf("expected no error for an expired key, got %v", err)
	}
	if found {
		t.Fatalf("expected the key to have expired, got %q", value)
	}
}

// A ttl of zero means "keep forever", which is how the gateway's own fallback
// values are stored.
func TestMemoryStoreZeroTTLNeverExpires(t *testing.T) {
	m := NewMemory()
	m.Set("k", "v", 0)

	time.Sleep(20 * time.Millisecond)

	if _, found, _ := m.Get(context.Background(), "k"); !found {
		t.Fatalf("a key set with ttl=0 must not expire")
	}
}

// Appended events are readable back in order, and the store must not be
// affected by a caller that reuses its map afterwards.
func TestMemoryStoreAppendKeepsItsOwnCopy(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	fields := map[string]any{"ip": "10.0.0.1", "failedLogins": 5}
	if err := m.Append(ctx, "attack_events", fields); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The caller reuses its map for a second, different event.
	fields["ip"] = "10.0.0.2"
	fields["failedLogins"] = 9
	if err := m.Append(ctx, "attack_events", fields); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := m.Events("attack_events")
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0]["ip"] != "10.0.0.1" {
		t.Fatalf("first event was overwritten by the caller's reuse: got %v", events[0]["ip"])
	}
	if events[1]["ip"] != "10.0.0.2" {
		t.Fatalf("expected second event to hold the updated ip, got %v", events[1]["ip"])
	}
}

// Reading a stream that has never been written to is not an error.
func TestMemoryStoreEventsOnUnknownStream(t *testing.T) {
	m := NewMemory()

	if events := m.Events("never_written"); len(events) != 0 {
		t.Fatalf("expected no events, got %d", len(events))
	}
}

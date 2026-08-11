package store

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-process Store. It exists so the rest of the gateway can
// be tested without a running Redis, and so the gateway still works when Redis
// is not configured.
//
// Expiry is evaluated when a key is read rather than by a background timer.
// That keeps the type free of goroutines, which means nothing to leak and
// nothing to shut down.
type MemoryStore struct {
	mu      sync.Mutex
	keys    map[string]memoryEntry
	streams map[string][]map[string]any
}

type memoryEntry struct {
	value string
	// expiresAt is the zero time when the key should never expire.
	expiresAt time.Time
}

func NewMemory() *MemoryStore {
	return &MemoryStore{
		keys:    make(map[string]memoryEntry),
		streams: make(map[string][]map[string]any),
	}
}

// Append records one event against a stream.
func (m *MemoryStore) Append(ctx context.Context, stream string, fields map[string]any) error {
	// Copy the caller's map. Without this, a caller that reuses and mutates its
	// map would silently rewrite history we have already stored.
	event := make(map[string]any, len(fields))
	for k, v := range fields {
		event[k] = v
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.streams[stream] = append(m.streams[stream], event)
	return nil
}

// Get reads a key. A missing or expired key is reported as found=false with a
// nil error: absence is the normal case, not a failure.
func (m *MemoryStore) Get(ctx context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.keys[key]
	if !ok {
		return "", false, nil
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		delete(m.keys, key)
		return "", false, nil
	}
	return entry.value, true, nil
}

// Set stores a key, optionally with a lifetime. A ttl of zero or less means the
// key never expires.
//
// This is deliberately not part of the Store interface. Only tests and the
// agent write policy keys; the gateway itself only ever reads them.
func (m *MemoryStore) Set(key, value string, ttl time.Duration) {
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[key] = memoryEntry{value: value, expiresAt: expiresAt}
}

// Events returns everything appended to a stream, for assertions in tests.
func (m *MemoryStore) Events(stream string) []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]map[string]any, len(m.streams[stream]))
	copy(out, m.streams[stream])
	return out
}

func (m *MemoryStore) Close() error { return nil }

// Compile-time proof that *MemoryStore satisfies Store. Costs nothing at
// runtime; turns a signature typo into an error here instead of somewhere far
// away that imports this package.
var _ Store = (*MemoryStore)(nil)

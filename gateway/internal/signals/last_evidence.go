package signals

import (
	"sync"
	"time"
)

// lastEvidenceStore keeps the most recent Evidence per IP for detectors
// that are request-scoped (SQLi, traversal/enum) rather than windowed.
type lastEvidenceStore struct {
	mu   sync.Mutex
	hits map[string]datedEvidence
	ttl  time.Duration
}

type datedEvidence struct {
	at       time.Time
	evidence Evidence
}

func newLastEvidenceStore(ttl time.Duration) *lastEvidenceStore {
	return &lastEvidenceStore{
		hits: make(map[string]datedEvidence),
		ttl:  ttl,
	}
}

func (s *lastEvidenceStore) Put(ip string, e Evidence) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.hits[ip] = datedEvidence{at: time.Now(), evidence: e}
	s.mu.Unlock()
}

func (s *lastEvidenceStore) Get(ip, signal string) Evidence {
	if s == nil {
		return Evidence{Signal: signal}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hit, ok := s.hits[ip]
	if !ok || time.Since(hit.at) > s.ttl {
		return Evidence{Signal: signal}
	}
	return hit.evidence
}

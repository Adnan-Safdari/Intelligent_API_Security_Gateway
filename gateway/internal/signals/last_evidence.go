package signals

import (
	"sync"
	"time"
)

// lastEvidenceStore keeps the most recent Evidence per IP for detectors
// that are request-scoped (SQLi, traversal/enum) rather than windowed.
//
// Every entry remembers which request produced it. Request-scoped evidence
// describes one request and nothing else, so handing it to a later request
// reports an attack that request did not carry -- see GetFor.
type lastEvidenceStore struct {
	mu   sync.Mutex
	hits map[string]datedEvidence
	ttl  time.Duration
}

type datedEvidence struct {
	at        time.Time
	requestID string
	evidence  Evidence
}

func newLastEvidenceStore(ttl time.Duration) *lastEvidenceStore {
	return &lastEvidenceStore{
		hits: make(map[string]datedEvidence),
		ttl:  ttl,
	}
}

func (s *lastEvidenceStore) Put(ip, requestID string, e Evidence) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.hits[ip] = datedEvidence{at: time.Now(), requestID: requestID, evidence: e}
	s.mu.Unlock()
}

// Get returns the latest evidence held for an IP, whichever request produced
// it. It answers "what did this address last do", not "what did this request
// contain" -- for the second question use GetFor.
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

// GetFor returns evidence only when this exact request produced it.
//
// A request can reach telemetry without ever reaching the detectors: the
// policy enforcer answers a blocked address before the chain gets that far,
// which leaves the previous request's evidence in place. Matching on the
// request id makes that case report nothing, rather than replaying an attack
// from up to lastEvidenceTTL ago onto a request that was never inspected --
// evidence the control plane would otherwise ingest as a fresh hit.
func (s *lastEvidenceStore) GetFor(ip, requestID, signal string) Evidence {
	if s == nil || requestID == "" {
		return Evidence{Signal: signal}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hit, ok := s.hits[ip]
	if !ok || hit.requestID != requestID || time.Since(hit.at) > s.ttl {
		return Evidence{Signal: signal}
	}
	return hit.evidence
}

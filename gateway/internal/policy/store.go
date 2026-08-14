// Package policy lets the gateway act on decisions made by the Python control
// plane. The control plane writes policy:<ip> keys into Redis; this package
// reads them and the middleware enforces them.
//
// The read is deliberately not a Redis call per request. A GET over TCP costs
// a few hundred microseconds, which is orders of magnitude more than any
// detector in the chain, and it would tie the gateway's latency -- and its
// availability -- to Redis. Instead a background goroutine copies the whole
// policy set into a map on an interval, and requests read that map. A lookup
// is then a few nanoseconds and never touches the network.
//
// The cost is staleness: a decision takes up to RefreshInterval to take
// effect. The control plane only produces decisions every 30s, so a 5s
// refresh is already faster than new decisions arrive.
package policy

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Actions the control plane can write. Anything else is treated as unknown
// and allowed through -- an unrecognised action must never block traffic.
const (
	ActionMonitor   = "monitor"
	ActionThrottle  = "throttle"
	ActionTempBlock = "temp_block"
	ActionEscalate  = "escalate"
)

// Decision mirrors the JSON at policy:<ip>, written by PolicyDecision.to_json
// in control-plane/iasg/models.py. That method and this struct are the two
// halves of the contract between the lanes.
type Decision struct {
	Action     string  `json:"action"`
	CampaignID string  `json:"campaign_id"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	IssuedAt   string  `json:"issued_at"`
	ExpiresIn  int     `json:"expires_in"`
}

// Lookuper is what the middleware actually depends on, so tests can supply a
// map instead of standing up Redis.
type Lookuper interface {
	Lookup(ip string) (Decision, bool)
}

// Config controls how policy is fetched.
type Config struct {
	Addr            string
	Password        string
	DB              int
	PoolSize        int
	KeyPrefix       string
	RefreshInterval time.Duration
}

// Store keeps a local snapshot of every active policy key.
type Store struct {
	client   *redis.Client
	prefix   string
	interval time.Duration

	// Swapped wholesale on each refresh, so readers never see a half-built
	// map and never take a lock.
	snapshot atomic.Pointer[map[string]Decision]

	cancel context.CancelFunc
	done   chan struct{}
}

func NewStore(cfg Config) *Store {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "policy:"
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 5 * time.Second
	}

	return &Store{
		client: redis.NewClient(&redis.Options{
			Addr:     cfg.Addr,
			Password: cfg.Password,
			DB:       cfg.DB,
			PoolSize: cfg.PoolSize,
		}),
		prefix:   cfg.KeyPrefix,
		interval: cfg.RefreshInterval,
		done:     make(chan struct{}),
	}
}

// Lookup returns the decision for an IP, if one is active.
func (s *Store) Lookup(ip string) (Decision, bool) {
	m := s.snapshot.Load()
	if m == nil {
		return Decision{}, false
	}
	d, ok := (*m)[ip]
	return d, ok
}

// Start loads policy once, then keeps refreshing in the background.
func (s *Store) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	// One synchronous attempt, so a gateway restart enforces existing policy
	// immediately instead of running open for a whole interval. A failure
	// here is logged and ignored: the gateway must start even if Redis is
	// down, which is the whole point of the two lanes being independent.
	first, done := context.WithTimeout(ctx, 2*time.Second)
	if err := s.refresh(first); err != nil {
		log.Printf("[policy] initial load failed, allowing all traffic: %v", err)
	} else {
		log.Printf("[policy] loaded %d active policies", s.size())
	}
	done()

	go s.loop(ctx)
}

func (s *Store) loop(ctx context.Context) {
	defer close(s.done)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c, cancel := context.WithTimeout(ctx, s.interval)
			if err := s.refresh(c); err != nil {
				// Keep serving the last good snapshot. Redis going down must
				// never take the gateway with it, and it must never cause
				// traffic to be blocked that wasn't blocked a second ago.
				log.Printf("[policy] refresh failed, keeping last snapshot: %v", err)
			}
			cancel()
		}
	}
}

// refresh rebuilds the snapshot from Redis.
func (s *Store) refresh(ctx context.Context) error {
	next := make(map[string]Decision)

	// SCAN rather than KEYS: KEYS walks the entire keyspace in one blocking
	// call, which stalls Redis for every other client including the control
	// plane.
	var cursor uint64
	for {
		keys, cur, err := s.client.Scan(ctx, cursor, s.prefix+"*", 256).Result()
		if err != nil {
			return err
		}

		if len(keys) > 0 {
			values, err := s.client.MGet(ctx, keys...).Result()
			if err != nil {
				return err
			}
			collect(next, keys, values, s.prefix)
		}

		cursor = cur
		if cursor == 0 {
			break
		}
	}

	s.snapshot.Store(&next)
	return nil
}

// collect decodes one SCAN batch into the snapshot being built. Split out
// from refresh so the decoding rules can be tested without a Redis server.
func collect(into map[string]Decision, keys []string, values []any, prefix string) {
	for i, v := range values {
		if i >= len(keys) {
			return
		}

		raw, ok := v.(string)
		if !ok {
			continue // nil: the key expired between the SCAN and the MGET
		}

		var d Decision
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			// One malformed key must not discard every good one.
			log.Printf("[policy] ignoring unparseable key %s: %v", keys[i], err)
			continue
		}

		into[strings.TrimPrefix(keys[i], prefix)] = d
	}
}

func (s *Store) size() int {
	m := s.snapshot.Load()
	if m == nil {
		return 0
	}
	return len(*m)
}

func (s *Store) Close() error {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
	return s.client.Close()
}

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

	// How many unexpiring keys the last refresh refused, so the warning is
	// logged when the situation changes rather than on every tick.
	unexpiring atomic.Int64

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
	var unexpiring int

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

			// What Redis will actually do with the key, which is not the same
			// as what the key says about itself: expires_in inside the JSON is
			// the control plane's intent, and a key can claim half an hour
			// while carrying no expiry at all.
			ttls, err := s.ttls(ctx, keys)
			if err != nil {
				return err
			}

			unexpiring += collect(next, keys, values, ttls, s.prefix)
		}

		cursor = cur
		if cursor == 0 {
			break
		}
	}

	// Logged on change rather than every tick: this is a standing
	// misconfiguration, not a per-refresh event.
	if prev := s.unexpiring.Swap(int64(unexpiring)); int64(unexpiring) != prev {
		switch {
		case unexpiring > 0:
			log.Printf("[policy] refusing %d key(s) with no expiry: enforcement must be time-bounded", unexpiring)
		case prev > 0:
			log.Printf("[policy] no unexpiring keys remain")
		}
	}

	s.snapshot.Store(&next)
	return nil
}

// ttls fetches the remaining life of every key in one round trip.
//
// Redis reports -1 for a key with no expiry and -2 for one that is already
// gone; go-redis passes both through as negative durations.
func (s *Store) ttls(ctx context.Context, keys []string) ([]time.Duration, error) {
	pipe := s.client.Pipeline()
	cmds := make([]*redis.DurationCmd, len(keys))
	for i, key := range keys {
		cmds[i] = pipe.TTL(ctx, key)
	}
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}

	out := make([]time.Duration, len(keys))
	for i, cmd := range cmds {
		ttl, err := cmd.Result()
		if err != nil {
			// An unreadable lifetime is treated as no lifetime. The safe
			// answer is to decline to enforce, never to enforce forever on
			// the strength of a failed lookup.
			ttl = -1
		}
		out[i] = ttl
	}
	return out, nil
}

// collect decodes one SCAN batch into the snapshot being built and reports how
// many keys were refused for having no expiry. Split out from refresh so the
// decoding rules can be tested without a Redis server.
//
// ttls may be shorter than keys, in which case the missing entries are treated
// as unknown and the key is kept: a lifetime we failed to read is not evidence
// that the key is unexpiring.
func collect(into map[string]Decision, keys []string, values []any, ttls []time.Duration, prefix string) int {
	unexpiring := 0

	for i, v := range values {
		if i >= len(keys) {
			return unexpiring
		}

		raw, ok := v.(string)
		if !ok {
			continue // nil: the key expired between the SCAN and the MGET
		}

		// Every action the control plane can take is time-bounded, and the
		// gateway relies on Redis dropping the key to restore service by
		// itself. A key with no expiry has no such release: nothing renews it
		// and nothing clears it, so one mistyped key would refuse an address
		// permanently, with no record of why. Refuse it instead.
		if i < len(ttls) && ttls[i] < 0 {
			unexpiring++
			continue
		}

		var d Decision
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			// One malformed key must not discard every good one.
			log.Printf("[policy] ignoring unparseable key %s: %v", keys[i], err)
			continue
		}

		into[strings.TrimPrefix(keys[i], prefix)] = d
	}

	return unexpiring
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

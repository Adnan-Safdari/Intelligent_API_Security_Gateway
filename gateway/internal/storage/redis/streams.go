package redisstore

import (
	"context"
	"encoding/json"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
	"github.com/redis/go-redis/v9"
)

const (
	KeyArrivals = "iasg:arrivals"
	KeyHealth   = "iasg:telemetry:health"
)

// ArrivalStore appends arrival records to their own stream.
//
// Deliberately does not touch iasg:stats or iasg:attackers. Those counters
// mean "requests the gateway finished handling", and incrementing them here
// would double every number the console shows.
type ArrivalStore struct {
	client *redis.Client
	key    string
	maxLen int64
}

// HealthStore appends the telemetry heartbeat.
//
// Capped far shorter than the request streams: the heartbeat is one record a
// second, and history older than the capture run is of no use to anyone.
type HealthStore struct {
	client *redis.Client
	key    string
	maxLen int64
}

// Arrivals shares the Store's connection pool. A second pool would mean a
// second set of connections competing for the same Redis under exactly the
// load where connections are scarce.
func (s *Store) Arrivals(cfg config.RedisConfig) *ArrivalStore {
	if s == nil || s.client == nil {
		return nil
	}
	key := cfg.ArrivalStreamKey
	if key == "" {
		key = KeyArrivals
	}
	maxLen := cfg.ArrivalMaxLen
	if maxLen <= 0 {
		maxLen = s.maxLen
	}
	return &ArrivalStore{client: s.client, key: key, maxLen: maxLen}
}

func (s *Store) Health(cfg config.RedisConfig) *HealthStore {
	if s == nil || s.client == nil {
		return nil
	}
	key := cfg.HealthStreamKey
	if key == "" {
		key = KeyHealth
	}
	maxLen := cfg.HealthMaxLen
	if maxLen <= 0 {
		maxLen = 86400
	}
	return &HealthStore{client: s.client, key: key, maxLen: maxLen}
}

func (s *ArrivalStore) WriteEvent(ctx context.Context, rec telemetry.Arrival) error {
	if s == nil || s.client == nil {
		return nil
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	// Indexed fields mirror the event stream's, so a consumer can filter
	// either stream the same way without decoding the payload.
	return s.client.XAdd(ctx, &redis.XAddArgs{
		Stream: s.key,
		MaxLen: s.maxLen,
		Approx: true,
		Values: map[string]any{
			"arrival":   payload,
			"ip":        rec.IP,
			"path":      rec.Path,
			"requestId": rec.RequestID,
		},
	}).Err()
}

func (s *HealthStore) WriteEvent(ctx context.Context, rec telemetry.Health) error {
	if s == nil || s.client == nil {
		return nil
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.client.XAdd(ctx, &redis.XAddArgs{
		Stream: s.key,
		MaxLen: s.maxLen,
		Approx: true,
		Values: map[string]any{"health": payload, "seq": rec.Seq},
	}).Err()
}

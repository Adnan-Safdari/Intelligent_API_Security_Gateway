package redisstore

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
	"github.com/redis/go-redis/v9"
)

const (
	KeyEvents    = "iasg:events"
	KeyStats     = "iasg:stats"
	KeyAttackers = "iasg:attackers"
	keyIPLatest  = "iasg:ip:%s:latest"
)

// Store writes hot security telemetry to Redis.
// It is safe to call from request middleware: failures are logged, not returned to clients.
type Store struct {
	client      *redis.Client
	streamKey   string
	maxLen      int64
	ipLatestTTL time.Duration
}

func New(cfg config.RedisConfig) (*Store, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr(),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping %s: %w", cfg.Addr(), err)
	}

	streamKey := cfg.StreamKey
	if streamKey == "" {
		streamKey = KeyEvents
	}

	log.Printf("Redis telemetry connected at %s (stream=%s maxlen=%d)", cfg.Addr(), streamKey, cfg.StreamMaxLen)
	return &Store{
		client:      client,
		streamKey:   streamKey,
		maxLen:      cfg.StreamMaxLen,
		ipLatestTTL: cfg.IPLatestTTL,
	}, nil
}

func (s *Store) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

func (s *Store) WriteEvent(ctx context.Context, ev telemetry.Event) error {
	if s == nil || s.client == nil {
		return nil
	}

	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	pipe := s.client.TxPipeline()
	pipe.XAdd(ctx, &redis.XAddArgs{
		Stream: s.streamKey,
		MaxLen: s.maxLen,
		Approx: true,
		Values: map[string]any{
			"event":     payload,
			"ip":        ev.IP,
			"path":      ev.Path,
			"decision":  ev.Decision,
			"riskScore": ev.RiskScore,
			"fired":     stringsJoin(ev.Fired),
			"requestId": ev.RequestID,
		},
	})
	pipe.HIncrBy(ctx, KeyStats, "requests", 1)
	pipe.HIncrBy(ctx, KeyStats, "decision:"+ev.Decision, 1)
	if len(ev.Fired) > 0 {
		pipe.HIncrBy(ctx, KeyStats, "alerts", 1)
		pipe.ZIncrBy(ctx, KeyAttackers, 1, ev.IP)
		for _, signal := range unique(ev.Fired) {
			pipe.HIncrBy(ctx, KeyStats, "signal:"+signal, 1)
		}
	}
	pipe.Set(ctx, fmt.Sprintf(keyIPLatest, ev.IP), payload, s.ipLatestTTL)

	_, err = pipe.Exec(ctx)
	return err
}

func stringsJoin(values []string) string {
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for i := 1; i < len(values); i++ {
		out += "," + values[i]
	}
	return out
}

func unique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

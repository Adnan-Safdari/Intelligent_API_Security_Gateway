package policy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRedisBucketIdentityIsolatesClientsEndpointsMethodsAndGenerations(t *testing.T) {
	base := QuotaRequest{IP: "203.0.113.5", Route: "/api/login", Method: "POST",
		Decision: Decision{redisKey: "policy:203.0.113.5", rawPolicy: realPolicy}, RequestsPerMinute: 5, Burst: 2}
	original := bucketKey("test:", base)
	for _, change := range []func(*QuotaRequest){
		func(q *QuotaRequest) { q.IP = "203.0.113.6" },
		func(q *QuotaRequest) { q.Route = "/api/products" },
		func(q *QuotaRequest) { q.Method = "GET" },
		func(q *QuotaRequest) { q.Decision.rawPolicy += " " },
		func(q *QuotaRequest) { q.Decision.redisKey = "another:203.0.113.5" },
	} {
		q := base
		change(&q)
		if bucketKey("test:", q) == original {
			t.Fatalf("distinct quota shared identity: %+v", q)
		}
	}
	changedConfig := base
	changedConfig.RequestsPerMinute, changedConfig.Burst = 10, 4
	if bucketKey("test:", changedConfig) != original {
		t.Fatal("configuration changes invented a fresh allowance")
	}
	a := QuotaRequest{IP: "a:b", Route: "c", Method: "d"}
	b := QuotaRequest{IP: "a", Route: "b:c", Method: "d"}
	if bucketKey("test:", a) == bucketKey("test:", b) {
		t.Fatal("delimiter collision shared quotas")
	}
}

func TestRedisFailureAllowsAndBoundsSubsequentLatency(t *testing.T) {
	l := NewRedisLimiter(Config{Addr: "127.0.0.1:1", RedisTimeout: 20 * time.Millisecond, FailureBackoff: time.Hour})
	defer l.Close()
	q := QuotaRequest{IP: "203.0.113.5", Route: "/api/login", Method: "POST", RequestsPerMinute: 1, Burst: 1}
	result, err := l.Take(context.Background(), q)
	if err == nil || !result.Allowed || result.Reason != "redis_unavailable" {
		t.Fatalf("Redis outage failed closed: %+v, %v", result, err)
	}
	started := time.Now()
	for i := 0; i < 100; i++ {
		result, err = l.Take(context.Background(), q)
		if err != errRedisBackoff || !result.Allowed {
			t.Fatalf("circuit did not fail open: %+v, %v", result, err)
		}
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("open circuit added latency: %v", elapsed)
	}
}

func TestRedisUnresponsiveServerCannotStallRequests(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			var data [1024]byte
			for {
				if _, err := conn.Read(data[:]); err != nil {
					return
				}
			}
		}
	}()
	l := NewRedisLimiter(Config{Addr: listener.Addr().String(), RedisTimeout: 20 * time.Millisecond})
	started := time.Now()
	result, err := l.Take(context.Background(), QuotaRequest{RequestsPerMinute: 1, Burst: 1})
	if err == nil || !result.Allowed {
		t.Fatalf("unresponsive Redis failed closed: %+v, %v", result, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("request exceeded its bounded Redis budget: %v", elapsed)
	}
	l.Close()
	listener.Close()
	<-stopped
}

func TestRedisExpiredDecisionNeverContactsRedis(t *testing.T) {
	l := NewRedisLimiter(Config{Addr: "127.0.0.1:1"})
	defer l.Close()
	result, err := l.Take(context.Background(), QuotaRequest{RequestsPerMinute: 1, Burst: 1,
		Decision: Decision{ExpiresAt: time.Now().Add(-time.Second)}})
	if err != nil || !result.Allowed || result.Reason != "policy_inactive" {
		t.Fatalf("expired policy reached quota accounting: %+v %v", result, err)
	}
}

func TestRedisQuotaResultsRejectMalformedResponses(t *testing.T) {
	for _, values := range [][]any{nil, {int64(0), int64(-1), "bad"}, {int64(2), int64(0), "bad"}, {"0", int64(1), "bad"}} {
		if _, err := decodeQuotaResult(values); err == nil {
			t.Fatalf("accepted malformed response: %v", values)
		}
	}
}

func redisFixture(t *testing.T) (*Store, *RedisLimiter, QuotaRequest) {
	t.Helper()
	prefix := fmt.Sprintf("iasg-test:%s:%d:", t.Name(), time.Now().UnixNano())
	cfg := Config{Addr: integrationRedisAddr(t), KeyPrefix: prefix + "policy:", BucketPrefix: prefix + "rate:", RedisTimeout: 2 * time.Second, PoolSize: 64}
	s := NewStore(cfg)
	l := NewRedisLimiter(cfg)
	t.Cleanup(func() {
		ctx := context.Background()
		keys, err := s.client.Keys(ctx, prefix+"*").Result()
		if err == nil && len(keys) > 0 {
			s.client.Del(ctx, keys...)
		}
		l.Close()
		s.Close()
	})
	raw := `{"action":"throttle","source":"agent","requests_per_minute":1,"expires_in":60,"issued_at":"test"}`
	key := cfg.KeyPrefix + "203.0.113.5"
	if err := s.client.Set(context.Background(), key, raw, time.Minute).Err(); err != nil {
		t.Fatalf("seed Redis: %v", err)
	}
	if err := s.refresh(context.Background()); err != nil {
		t.Fatalf("refresh Redis: %v", err)
	}
	d, found := s.Lookup("203.0.113.5")
	if !found {
		t.Fatal("missing seeded policy")
	}
	return s, l, QuotaRequest{IP: "203.0.113.5", Route: "/api/login", Method: "POST", Decision: d, RequestsPerMinute: 1, Burst: 1}
}

func takeQuota(t *testing.T, l *RedisLimiter, q QuotaRequest) QuotaResult {
	t.Helper()
	result, err := l.Take(context.Background(), q)
	if err != nil {
		t.Fatalf("take Redis quota: %v", err)
	}
	return result
}

func TestRedisThrottleQuotaAndEndpointIsolation(t *testing.T) {
	s, l, q := redisFixture(t)
	if result := takeQuota(t, l, q); !result.Allowed {
		t.Fatalf("first request denied: %+v", result)
	}
	if result := takeQuota(t, l, q); result.Allowed || result.RetryAfter <= 0 {
		t.Fatalf("exhausted quota was not enforced: %+v", result)
	}
	other := q
	other.Route = "/api/products"
	if !takeQuota(t, l, other).Allowed {
		t.Fatal("login quota affected unrelated endpoint")
	}
	other = q
	other.Method = "GET"
	if !takeQuota(t, l, other).Allowed {
		t.Fatal("POST quota affected GET")
	}
	if n := s.client.HLen(context.Background(), bucketKey(l.prefix, q)).Val(); n != 2 {
		t.Fatalf("quota state is not bounded: hash fields=%d", n)
	}
	if ttl := s.client.PTTL(context.Background(), bucketKey(l.prefix, q)).Val(); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("bucket lifetime is unbounded: %v", ttl)
	}
}

func TestRedisConcurrentReplicasCannotBypassQuota(t *testing.T) {
	_, first, q := redisFixture(t)
	q.RequestsPerMinute, q.Burst = 60, 7
	second := NewRedisLimiter(Config{Addr: first.client.Options().Addr, BucketPrefix: first.prefix, RedisTimeout: 2 * time.Second, PoolSize: 64})
	defer second.Close()
	var allowed atomic.Int64
	var failed atomic.Int64
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 100; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			l := first
			if i%2 == 0 {
				l = second
			}
			result, err := l.Take(context.Background(), q)
			if err != nil {
				failed.Add(1)
			} else if result.Allowed {
				allowed.Add(1)
			}
		}(i)
	}
	close(start)
	workers.Wait()
	if failed.Load() != 0 || allowed.Load() != 7 {
		t.Fatalf("replicas bypassed shared allowance: allowed=%d errors=%d", allowed.Load(), failed.Load())
	}
}

func TestRedisStalePolicyCannotRestrictAfterDeletionReplacementOrTTLRemoval(t *testing.T) {
	for _, mutation := range []string{"delete", "replace", "persist"} {
		t.Run(mutation, func(t *testing.T) {
			s, l, q := redisFixture(t)
			takeQuota(t, l, q)
			switch mutation {
			case "delete":
				s.client.Del(context.Background(), q.Decision.redisKey)
			case "replace":
				s.client.Set(context.Background(), q.Decision.redisKey, `{"action":"allow"}`, time.Minute)
			case "persist":
				s.client.Persist(context.Background(), q.Decision.redisKey)
			}
			result := takeQuota(t, l, q)
			if !result.Allowed || result.Reason != "policy_inactive" {
				t.Fatalf("stale policy continued enforcing: %+v", result)
			}
		})
	}
}

func TestRedisPolicyExpiryRestoresTrafficWithoutRefresh(t *testing.T) {
	s, l, q := redisFixture(t)
	takeQuota(t, l, q)
	if err := s.client.PExpire(context.Background(), q.Decision.redisKey, time.Millisecond).Err(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if result := takeQuota(t, l, q); !result.Allowed || result.Reason != "policy_inactive" {
		t.Fatalf("expired Redis policy kept its cached quota: %+v", result)
	}
}

func TestRedisBucketsRefillAndConfigurationDoesNotResetQuota(t *testing.T) {
	_, l, q := redisFixture(t)
	q.RequestsPerMinute, q.Burst = 6000, 1
	if !takeQuota(t, l, q).Allowed {
		t.Fatal("fresh bucket refused request")
	}
	q.Burst = 2
	if takeQuota(t, l, q).Allowed {
		t.Fatal("burst change invented tokens")
	}
	time.Sleep(15 * time.Millisecond)
	if !takeQuota(t, l, q).Allowed {
		t.Fatal("time did not replenish quota")
	}
}

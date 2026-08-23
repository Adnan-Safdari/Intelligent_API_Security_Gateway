package policy

import (
	"sync"
	"time"
)

// Limiter counts requests per address inside a sliding one-minute window, so
// the enforcer can hold a throttled caller to the rate its policy names.
//
// Only addresses under a throttle policy are ever counted. Everyone else never
// touches this: the enforcer looks a decision up first, and only reaches the
// limiter when that decision carries a rate. So the map holds throttled
// addresses, not every client the gateway has seen.
//
// The limit is not stored here. It arrives with each call, because it belongs
// to the policy rather than to the counter, and a policy can be replaced by
// the control plane at any refresh. Storing it would mean keeping two copies
// of the same fact and choosing which one to believe.
type Limiter struct {
	shards []*limiterShard
	window time.Duration

	stop chan struct{}
	done chan struct{}
}

type limiterShard struct {
	mu   sync.Mutex
	seen map[string][]time.Time
}

const limiterShards = 32

// NewLimiter returns a limiter counting over a one-minute window, matching the
// "requests per minute" the policy is written in.
func NewLimiter() *Limiter {
	l := &Limiter{
		shards: make([]*limiterShard, limiterShards),
		window: time.Minute,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	for i := range l.shards {
		l.shards[i] = &limiterShard{seen: make(map[string][]time.Time)}
	}
	return l
}

// Allow records a request from ip and reports whether it is within limit.
//
// The request is counted either way. A caller who keeps hammering after being
// refused stays over the limit, rather than having their rejected requests
// forgiven and being let back in immediately.
func (l *Limiter) Allow(ip string, limit int) (allowed bool, count int, retryAfter time.Duration) {
	if l == nil || limit <= 0 {
		return true, 0, 0
	}

	now := time.Now()
	cutoff := now.Add(-l.window)
	shard := l.shardFor(ip)

	shard.mu.Lock()
	times := trimBefore(shard.seen[ip], cutoff)
	times = append(times, now)
	shard.seen[ip] = times
	count = len(times)
	oldest := times[0]
	shard.mu.Unlock()

	if count <= limit {
		return true, count, 0
	}

	// When the oldest request in the window ages out, the caller is one under
	// the limit again. That is the soonest a retry can succeed, so it is the
	// honest thing to put in Retry-After.
	retryAfter = oldest.Add(l.window).Sub(now)
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	return false, count, retryAfter
}

// Forget drops an address's history. Used when a policy stops applying, so a
// caller returning later is not judged on what they sent under the old one.
func (l *Limiter) Forget(ip string) {
	if l == nil {
		return
	}
	shard := l.shardFor(ip)
	shard.mu.Lock()
	delete(shard.seen, ip)
	shard.mu.Unlock()
}

// Size reports how many addresses are currently tracked, for tests and logs.
func (l *Limiter) Size() int {
	if l == nil {
		return 0
	}
	n := 0
	for _, shard := range l.shards {
		shard.mu.Lock()
		n += len(shard.seen)
		shard.mu.Unlock()
	}
	return n
}

// Start sweeps addresses whose requests have all aged out. Without it the map
// would keep an entry for every address ever throttled, and policies expire.
func (l *Limiter) Start() {
	go func() {
		defer close(l.done)
		ticker := time.NewTicker(l.window)
		defer ticker.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-ticker.C:
				l.sweep(time.Now())
			}
		}
	}()
}

func (l *Limiter) sweep(now time.Time) {
	cutoff := now.Add(-l.window)
	for _, shard := range l.shards {
		shard.mu.Lock()
		for ip, times := range shard.seen {
			kept := trimBefore(times, cutoff)
			if len(kept) == 0 {
				delete(shard.seen, ip)
			} else {
				shard.seen[ip] = kept
			}
		}
		shard.mu.Unlock()
	}
}

func (l *Limiter) Close() {
	if l == nil {
		return
	}
	close(l.stop)
	<-l.done
}

func (l *Limiter) shardFor(ip string) *limiterShard {
	var hash uint32
	for i := 0; i < len(ip); i++ {
		hash = 31*hash + uint32(ip[i])
	}
	return l.shards[hash%uint32(len(l.shards))]
}

// trimBefore drops timestamps at or before cutoff. The slice is ordered, so
// the first one that survives marks where the live window starts.
func trimBefore(times []time.Time, cutoff time.Time) []time.Time {
	firstValid := len(times)
	for i, t := range times {
		if t.After(cutoff) {
			firstValid = i
			break
		}
	}
	return times[firstValid:]
}

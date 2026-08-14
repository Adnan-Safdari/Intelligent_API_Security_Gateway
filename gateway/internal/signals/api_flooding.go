/*
	API Flood detection signal
		- Tracks how many requests each IP sends inside a sliding window
		- If the count exceeds the configured threshold, logs a security alert
		- Exposes Metrics(ip) for the future decision engine
		- DOES NOT BLOCK. Every request is forwarded to the backend.

	Core Idea
		“ For each IP address, track how many requests they send within a time window. ”

	Sharding
		IPs are split across 32 buckets so each bucket has its own mutex.
*/

package signals

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// floodClientData stores the timestamps of recent requests for a specific IP.
type floodClientData struct {
	Requests []time.Time
}

// FloodDetector manages request tracking across multiple shards to reduce lock contention.
type FloodDetector struct {
	enabled   bool
	shards    []*floodShard
	threshold int
	window    time.Duration
}

type floodShard struct {
	mu      sync.Mutex
	clients map[string]*floodClientData
}

func NewFloodDetector(cfg config.RateLimitConfig) *FloodDetector {
	if !cfg.Enabled {
		return &FloodDetector{enabled: false}
	}

	threshold := cfg.RequestsPerMinute
	if threshold <= 0 {
		threshold = 100
	}

	numShards := 32
	fd := &FloodDetector{
		enabled:   true,
		shards:    make([]*floodShard, numShards),
		threshold: threshold,
		window:    time.Minute,
	}

	for i := 0; i < numShards; i++ {
		fd.shards[i] = &floodShard{
			clients: make(map[string]*floodClientData),
		}
	}

	go fd.startCleanupTimer()
	return fd
}

func (fd *FloodDetector) Name() string { return SignalFlood }

func (fd *FloodDetector) getShard(ip string) *floodShard {
	var hash uint32
	for i := 0; i < len(ip); i++ {
		hash = 31*hash + uint32(ip[i])
	}
	return fd.shards[hash%uint32(len(fd.shards))]
}

func (fd *FloodDetector) startCleanupTimer() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		now := time.Now()
		for _, shard := range fd.shards {
			shard.mu.Lock()
			for ip, client := range shard.clients {
				if len(client.Requests) == 0 || now.Sub(client.Requests[len(client.Requests)-1]) > fd.window {
					delete(shard.clients, ip)
				}
			}
			shard.mu.Unlock()
		}
	}
}

func (fd *FloodDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !fd.enabled || fd.threshold <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r.RemoteAddr)
		now := time.Now()
		shard := fd.getShard(ip)

		shard.mu.Lock()
		if _, exists := shard.clients[ip]; !exists {
			shard.clients[ip] = &floodClientData{}
		}
		client := shard.clients[ip]
		client.Requests = trimExpired(client.Requests, now.Add(-fd.window))
		client.Requests = append(client.Requests, now)
		requestCount := len(client.Requests)
		shard.mu.Unlock()

		if requestCount > fd.threshold {
			fd.logAlert(ip, r, requestCount)
		}

		next.ServeHTTP(w, r)
	})
}

// Metrics returns flood evidence for an IP. Safe to call concurrently.
func (fd *FloodDetector) Metrics(ip string) Evidence {
	ev := Evidence{Signal: SignalFlood, Details: map[string]any{
		"requestRate": 0,
		"threshold":   fd.threshold,
		"window":      fd.window.String(),
	}}
	if !fd.enabled || len(fd.shards) == 0 {
		return ev
	}

	shard := fd.getShard(ip)
	shard.mu.Lock()
	client, exists := shard.clients[ip]
	count := 0
	if exists {
		count = len(trimExpired(client.Requests, time.Now().Add(-fd.window)))
	}
	shard.mu.Unlock()

	crossed := count > fd.threshold
	ev.Details["requestRate"] = count
	ev.Score = floodScore(count, fd.threshold)
	ev.ThresholdCross = crossed
	if crossed {
		ev.AttackType = SignalFlood
	}
	return ev
}

func floodScore(count, threshold int) int {
	if threshold <= 0 || count <= 0 {
		return 0
	}
	// Flood fires when count > threshold, so equal-to-threshold is still clean.
	if count <= threshold {
		return count * 30 / threshold
	}
	if count >= threshold*5 {
		return 100
	}
	if count >= threshold*2 {
		return 80
	}
	return 60
}

func trimExpired(times []time.Time, cutoff time.Time) []time.Time {
	firstValid := len(times)
	for i, t := range times {
		if t.After(cutoff) {
			firstValid = i
			break
		}
	}
	return times[firstValid:]
}

func (fd *FloodDetector) logAlert(ip string, r *http.Request, count int) {
	severity := "LOW"
	if count > fd.threshold*5 {
		severity = "HIGH"
	} else if count > fd.threshold*2 {
		severity = "MEDIUM"
	}

	fmt.Printf(`
			========================================
			SECURITY ALERT: API FLOOD DETECTED
			----------------------------------------
			IP Address     : %s
			Endpoint       : %s
			Requests       : %d
			Time Window    : %s
			User-Agent     : %s
			Severity       : %s
			Timestamp      : %s
			ACTION         : DETECTED (ALLOWING REQUEST)
			========================================
			`,
		ip,
		r.URL.Path,
		count,
		fd.window,
		r.Header.Get("User-Agent"),
		severity,
		time.Now().Format(time.RFC3339),
	)
}

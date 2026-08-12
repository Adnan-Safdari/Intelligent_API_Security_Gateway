/*
	API Flood detection Middleware
		- Sits on he backend server
		- Moniors incomming request
		- Detects if someone is sending too many requests
		- Blocks wih a 429 Too Many Requests
		- Logs a security alert


	Core Idea
		“ For each IP address, track how many requests they send within a time window.
		If it exceeds a limit -> block them. ”

	Sharding architecute (in FloodDetector & floodShard)
		Instead of putting all IP address into a giant map
		We are breaking it into multiple buckets using an architecture called sharding
		Splitting into 32 smaller "buckets"

		Each shard has its own lock "mu" (mutex) where it only locks its own data preventing race conditions
		


	func (fd *FloodDetector) getShard(ip string) *floodShard 

		similiar to String.hashCode() in jaba (polynomial rolling hash)
		starts with hash = 0, for each char in string multiplies hash with x (31 in our case)
		adds the ascii value of the character
	
		It iterates over the characters in the IP string, calculates a mathematical hash, 
		and then uses the modulo operator (%) to pin it safely between 0 and 31.

		ensures same ip goes to the same shard



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

// ClientData stores the timestamps of recent requests for a specific IP.
type ClientData struct {
	Requests []time.Time
}

// FloodDetector manages request tracking across multiple shards to reduce lock contention.
type FloodDetector struct {
	shards    []*floodShard	// Instead of one big map, we are breaking it into multiple buckets
	threshold int			// Maximum number of requests allowed in the time window
	window    time.Duration	// The time window duration

	/*
		So if
		threshold => 100 and window is 1
		:> 100 requests in 1 minute => Block
	*/
}

// floodShard represents a single bucket of IP data with its own mutex.
type floodShard struct {
	mu      sync.Mutex				// Mutex to protect the clients map
	clients map[string]*ClientData	// Map to store client data - modifying directly
}

// FloodDetector initializes a sharded detector based on the provided configuration.
func NewFloodDetector(cfg config.RateLimitConfig) *FloodDetector {
	if !cfg.Enabled {
		return &FloodDetector{threshold: 0}
	}
	numShards := 32
	fd := &FloodDetector{
		shards:    make([]*floodShard, numShards),
		threshold: cfg.RequestsPerMinute, // Using RPM as threshold for demo
		window:    time.Minute,           // Default to 1 minute to match RPM
	}

	for i := 0; i < numShards; i++ {
		fd.shards[i] = &floodShard{
			clients: make(map[string]*ClientData),
		}
	}

	go fd.startCleanupTimer()
	return fd
}

// getShard returns the specific shard for a given IP using a simple hash.
func (fd *FloodDetector) getShard(ip string) *floodShard {
	var hash uint32
	for i := 0; i < len(ip); i++ {
		hash = 31*hash + uint32(ip[i])
	}
	return fd.shards[hash%uint32(len(fd.shards))]
}

// startCleanupTimer runs a background task to remove inactive IPs every 5 minutes.
func (fd *FloodDetector) startCleanupTimer() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		now := time.Now()
		for _, shard := range fd.shards {
			shard.mu.Lock()				// Locking the shard so that no race condition occurs
			for ip, client := range shard.clients {
				// If the last request was longer than the window ago, delete the entry
				if len(client.Requests) == 0 || now.Sub(client.Requests[len(client.Requests)-1]) > fd.window {
					delete(shard.clients, ip)
				}
			}
			shard.mu.Unlock()			// unlocking after critical phase is over 
		}
	}
}

// Middleware returns an http.Handler that inspects requests for flooding attacks.
func (fd *FloodDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the detector is disabled, skip inspection
		if fd.threshold <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Extract IP without port to ensure accurate tracking
		ip := netutil.ClientIP(r)

		now := time.Now()
		shard := fd.getShard(ip)

		shard.mu.Lock()
		if _, exists := shard.clients[ip]; !exists {
			shard.clients[ip] = &ClientData{}
		}
		client := shard.clients[ip]

		// O(1) cleanup: Remove expired timestamps from the beginning of the slice
		cutoff := now.Add(-fd.window)
		firstValid := 0
		for i, t := range client.Requests {
			if t.After(cutoff) {
				firstValid = i
				break
			}
			// If all are expired, the loop will finish and firstValid will stay 0 or be set correctly
			if i == len(client.Requests)-1 {
				firstValid = len(client.Requests)
			}
		}
		client.Requests = client.Requests[firstValid:]

		// Add current request and check against threshold
		client.Requests = append(client.Requests, now)
		requestCount := len(client.Requests)

		if requestCount > fd.threshold {
			shard.mu.Unlock()
			fd.logAlert(ip, r, requestCount)
			next.ServeHTTP(w, r)
			return
		}
		shard.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// logAlert prints a high-visibility security alert to the console.
func (fd *FloodDetector) logAlert(ip string, r *http.Request, count int) {
	severity := "LOW"
	if count > fd.threshold*5 {
		severity = "HIGH "
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

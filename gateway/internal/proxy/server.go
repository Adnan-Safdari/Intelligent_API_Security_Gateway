// Package proxy provides the core HTTP reverse proxy server functionality
// for the Intelligent API Security Gateway. It handles incoming requests,
// applies security middleware, and forwards traffic to backend services.
package proxy

import (
	"log"
	"net/http"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
	redisstore "github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/storage/redis"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
)

// Config holds the configuration settings for the proxy server.
// It defines network parameters and timeout values for the gateway.
type Config struct {
	// ListenAddr is the address and port on which the gateway listens for incoming requests.
	// Format: "host:port" or ":port" (e.g., ":8082" or "0.0.0.0:8082")
	ListenAddr string

	// BackendURL is the full URL of the backend service to which requests are proxied.
	// Format: "scheme://host:port" (e.g., "http://localhost:4000")
	BackendURL string

	// ReadTimeout is the maximum duration for reading the entire request, including the body.
	// This prevents slow-client attacks and ensures timely request processing.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out writes of the response.
	// This helps prevent long-running handlers from blocking server resources.
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the next request
	// when keep-alives are enabled.
	IdleTimeout time.Duration

	// ProxyTimeout defines the timeout for communicating with upstream backends.
	ProxyTimeout time.Duration

	// MaxIdleConns controls the maximum number of idle connections in the proxy transport.
	MaxIdleConns int

	// MaxConnsPerHost limits total connections per upstream host.
	MaxConnsPerHost int

	// RateLimit holds the configuration for API flooding detection.
	RateLimit config.RateLimitConfig

	// AttackDetection holds SQL injection detection settings.
	AttackDetection config.AttackDetectionConfig

	// BruteForce holds brute force login detection settings.
	BruteForce config.BruteForceConfig

	// Enumeration holds path-traversal and forced-browsing detection settings.
	Enumeration config.EnumerationConfig

	// Policy controls enforcement of control-plane decisions.
	Policy config.PolicyConfig

	// Throttle sets the delay applied to throttled clients.
	Throttle config.ThrottleConfig

	// Redis holds hot telemetry and the policy snapshot the control plane writes.
	Redis config.RedisConfig

	// TrustedProxies lists CIDRs whose X-Forwarded-For header is believed.
	TrustedProxies []string
}

// Server represents the API gateway proxy server instance.
// It encapsulates the server configuration and manages the HTTP server lifecycle.
type Server struct {
	// config stores the server configuration settings
	config Config

	// collector gathers Metrics() from every detector for a future decision engine.
	collector *signals.Collector
}

// NewServer creates and initializes a new proxy server instance with the provided configuration.
// It returns a pointer to the Server, ready to be started.
//
// Parameters:
//   - cfg: Configuration settings for the proxy server
//
// Returns:
//   - *Server: A new server instance configured with the provided settings
func NewServer(cfg Config) *Server {
	return &Server{
		config: cfg,
	}
}

// Start initializes and starts the proxy server, listening for incoming HTTP requests.
// It sets up the reverse proxy, applies the middleware chain (logging and request inspection),
// and starts the HTTP server with configured timeouts.
//
// The middleware chain is applied in the following order (outermost first):
//  1. Telemetry — records one Redis event after the rest of the chain returns
//  2. Client-IP resolver — trusted-proxy X-Forwarded-For, then context IP
//  3. Logging
//  4. Policy enforcer — optional; blocked IPs never reach detectors
//  5. Request inspection, then flood / SQLi / traversal / brute force
//  6. Reverse proxy
//
// Returns:
//   - error: An error if the server fails to start or encounters a fatal error during operation.
//     Returns nil only if the server is gracefully shut down.
func (s *Server) Start() error {

	// Create a reverse proxy that forwards requests to the configured backend URL
	proxy := NewReverseProxy(s.config)

	// Create the flood detector signal engine
	floodDetector := signals.NewFloodDetector(s.config.RateLimit)
	sqliDetector := signals.NewSQLiDetector(signals.SQLiDetectorConfigFrom(s.config.AttackDetection))
	bruteForceDetector := signals.NewBruteForceDetector(s.config.BruteForce)
	traversalEnumDetector := signals.NewTraversalEnumDetector(s.config.Enumeration)

	s.collector = signals.NewCollector(floodDetector, sqliDetector, traversalEnumDetector, bruteForceDetector)

	var eventWriter telemetry.Writer
	if s.config.Redis.Enabled {
		store, err := redisstore.New(s.config.Redis)
		if err != nil {
			log.Printf("Redis telemetry disabled: %v", err)
		} else {
			eventWriter = store
		}
	}

	resolver, err := netutil.NewResolver(s.config.TrustedProxies)
	if err != nil {
		return err
	}

	enforcer := s.newEnforcer()

	// Telemetry is outermost so it records after every detector, including
	// brute force which inspects the backend response status, and after
	// policy so a 403 is still written to iasg:events.
	handler := ChainMiddleware(
		telemetry.Middleware(eventWriter, s.collector),
		resolver.Middleware,
		LoggingMiddleware,
		enforcer.Middleware,
		RequestInspectionMiddleware,
		floodDetector.Middleware,
		sqliDetector.Middleware,
		traversalEnumDetector.Middleware,
		bruteForceDetector.Middleware,
	)(proxy)

	// Configure the HTTP server with timeouts and the middleware-wrapped handler
	server := &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      handler,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	// Start the HTTP server and listen for incoming connections
	// This is a blocking call that returns only on error or shutdown
	return server.ListenAndServe()
}

// newEnforcer builds the policy enforcement middleware.
//
// When enforcement is disabled, no Redis client is created at all and the
// middleware becomes a pass-through. That is the default, and it is what keeps
// the gateway able to run with the control plane switched off entirely.
func (s *Server) newEnforcer() *policy.Enforcer {
	if !s.config.Policy.Enabled {
		return policy.NewEnforcer(nil, false, 0)
	}

	store := policy.NewStore(policy.Config{
		Addr:            s.config.Redis.Addr(),
		Password:        s.config.Redis.Password,
		DB:              s.config.Redis.DB,
		PoolSize:        s.config.Redis.PoolSize,
		KeyPrefix:       s.config.Policy.KeyPrefix,
		RefreshInterval: s.config.Policy.RefreshInterval,
	})
	store.Start()

	delay := time.Duration(s.config.Throttle.DelayMS) * time.Millisecond
	if !s.config.Throttle.Enabled {
		delay = 0
	}

	return policy.NewEnforcer(store, true, delay)
}

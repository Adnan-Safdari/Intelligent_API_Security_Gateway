// Package proxy provides the core HTTP reverse proxy server functionality
// for the Intelligent API Security Gateway. It handles incoming requests,
// applies security middleware, and forwards traffic to backend services.
package proxy

import (
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
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

	// Policy controls enforcement of control-plane decisions.
	Policy config.PolicyConfig

	// Throttle sets the delay applied to throttled clients.
	Throttle config.ThrottleConfig

	// Redis is where the control plane publishes policy:<ip> keys.
	Redis config.RedisConfig
}

// Server represents the API gateway proxy server instance.
// It encapsulates the server configuration and manages the HTTP server lifecycle.
type Server struct {
	// config stores the server configuration settings
	config Config
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
// The middleware chain is applied in the following order:
//  1. LoggingMiddleware - logs all incoming requests and responses
//  2. RequestInspectionMiddleware - inspects and validates requests for security threats
//  3. Reverse proxy handler - forwards requests to the backend service
//
// Returns:
//   - error: An error if the server fails to start or encounters a fatal error during operation.
//     Returns nil only if the server is gracefully shut down.
func (s *Server) Start() error {

	// Create a reverse proxy that forwards requests to the configured backend URL
	proxy := NewReverseProxy(s.config)

	// Create the flood detector signal engine
	floodDetector := signals.NewFloodDetector(s.config.RateLimit)
	sqliDetector := signals.NewSQLiDetector(signals.SQLiDetectorConfig{
		Enabled:     s.config.AttackDetection.Enabled,
		SQLPatterns: s.config.AttackDetection.SQLPatterns,
	})
	bruteForceDetector := signals.NewBruteForceDetector(s.config.BruteForce)

	traversalEnumDetector := signals.NewTraversalEnumDetector(signals.DefaultTraversalEnumConfig())

	// Enforcement of control-plane decisions. The store keeps a local snapshot
	// of policy:<ip>, so the middleware never makes a network call per request.
	enforcer := s.newEnforcer()

	// Build the middleware chain and wrap the reverse proxy handler
	// Middleware is applied in reverse order (last middleware listed executes first)
	// Policy enforcement runs directly after logging, so an IP the control
	// plane has already blocked is turned away before any detector spends
	// work on it.
	// The brute force detector sits closest to the proxy because it needs to
	// observe the backend's response status (401 = failed login)
	handler := ChainMiddleware(
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
		Addr:            net.JoinHostPort(s.config.Redis.Host, strconv.Itoa(s.config.Redis.Port)),
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

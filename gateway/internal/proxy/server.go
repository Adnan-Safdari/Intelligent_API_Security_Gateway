// Package proxy provides the core HTTP reverse proxy server functionality
// for the Intelligent API Security Gateway. It handles incoming requests,
// applies security middleware, and forwards traffic to backend services.
package proxy

import (
	"log"
	"net/http"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/enforcement"
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

	// Block holds the gateway's own blocking -- its reflex, as distinct from
	// the decisions the control plane writes as policy keys.
	Block config.BlockConfig

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
//  5. Request inspection
//  6. Reflex observer — optional; records gateway-side blocks after the
//     flood / SQLi / traversal / brute force detectors and observes after
//     they unwind, applying from the caller's next request
//  7. Reverse proxy
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

	// The gateway's own reflex, and the enforcer that acts on both it and the
	// control plane's decisions.
	reflex, err := s.newReflex()
	if err != nil {
		return err
	}
	reflex.Start()
	defer reflex.Close()
	log.Printf("[enforcement] %s", reflex.Describe())

	enforcer, gate, err := s.newEnforcer(reflex)
	if err != nil {
		return err
	}

	// Live settings. The file is what the gateway boots with; the console can
	// put an override on top of it, and deleting that override comes straight
	// back here. Only the enforcement block travels this way -- see the
	// settings package for why the structural settings do not.
	watcher := s.startSettingsWatcher(live{
		flood:     floodDetector,
		sqli:      sqliDetector,
		brute:     bruteForceDetector,
		traversal: traversalEnumDetector,
		reflex:    reflex,
		enforcer:  enforcer,
		gate:      gate,
	})
	if watcher != nil {
		defer watcher.Close()
	}

	// The resolver runs first so the trusted-proxy X-Forwarded-For IP is on the
	// request context before anything else reads it. Telemetry sits just inside
	// it -- still outside every detector, so it records after they run and after
	// policy (a 403 is written to iasg:events too), but now it reads the same
	// resolved client IP the detectors keyed their state under. When telemetry
	// wrapped the resolver instead, it held the pre-resolution request and
	// logged the peer address, then looked up detector state under that wrong
	// IP -- so every event behind a proxy recorded fired:[] and the control
	// plane never saw an attack.
	handler := ChainMiddleware(
		resolver.Middleware,
		telemetry.Middleware(eventWriter, s.collector),
		LoggingMiddleware,
		enforcer.Middleware,
		RequestInspectionMiddleware,
		observedDetectors(reflex, s.collector,
			floodDetector.Middleware,
			sqliDetector.Middleware,
			traversalEnumDetector.Middleware,
			bruteForceDetector.Middleware,
		),
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

// observedDetectors keeps the observer outside response-aware detectors. On
// the return path, brute force records the backend status before Reflex reads
// the collector. The policy enforcer remains outside this group, so a blocked
// request reaches neither the detectors nor the observer.
func observedDetectors(reflex *enforcement.Reflex, collector enforcement.Observer, detectors ...Middleware) Middleware {
	middlewares := make([]Middleware, 0, len(detectors)+1)
	middlewares = append(middlewares, enforcement.Middleware(reflex, collector))
	middlewares = append(middlewares, detectors...)
	return ChainMiddleware(middlewares...)
}

// newEnforcer builds the policy enforcement middleware.
//
// When enforcement is disabled, no Redis client is created at all and the
// middleware becomes a pass-through. That is the default, and it is what keeps
// the gateway able to run with the control plane switched off entirely.
// newEnforcer builds the enforcement middleware and the gate that switches the
// control plane's decisions on and off.
//
// Both sources are wired in whether or not they are active at boot, because
// the console can turn either on later and the chain cannot be rebuilt once
// requests are flowing. Each source answers "no opinion" while it is off:
// the gate short-circuits, and the reflex checks its own enabled flag. The
// returned gate is nil when there is no Redis to read policy from.
func (s *Server) newEnforcer(reflex *enforcement.Reflex) (*policy.Enforcer, *policy.Gate, error) {
	// The control plane first, then the gateway's own reflex. policy.Chain
	// documents why that order and not the other one.
	var sources policy.Chain
	var gate *policy.Gate

	if s.config.Redis.Enabled {
		store := policy.NewStore(policy.Config{
			Addr:            s.config.Redis.Addr(),
			Password:        s.config.Redis.Password,
			DB:              s.config.Redis.DB,
			PoolSize:        s.config.Redis.PoolSize,
			KeyPrefix:       s.config.Policy.KeyPrefix,
			RefreshInterval: s.config.Policy.RefreshInterval,
		})
		store.Start()
		gate = policy.NewGate(store, s.config.Policy.Enabled)
		sources = append(sources, gate)
	}

	sources = append(sources, reflex)

	// Holds throttled addresses to the rate their policy names. Swept in the
	// background so addresses whose policy has expired do not stay in memory.
	limiter := policy.NewLimiter()
	limiter.Start()

	enforcer := policy.NewEnforcer(
		sources, s.enforcementOn(reflex, gate), throttleDelay(s.config.Throttle),
	).WithLimiter(limiter)

	baseline, err := baselineFrom(s.config.RateLimit, s.config.Block)
	if err != nil {
		return nil, nil, err
	}
	enforcer.ApplyAll(s.enforcementOn(reflex, gate), throttleDelay(s.config.Throttle), baseline)
	if baseline.RequestsPerMinute > 0 {
		log.Printf("[enforcement] baseline rate limit %d/min for every address not under a policy",
			baseline.RequestsPerMinute)
	}

	return enforcer, gate, nil
}

// baselineFrom builds the rate every address is held to when no policy names
// one. Zero unless rate_limit.enforce is on: noticing a flood and refusing one
// are different decisions, and only the second can turn a spike into an outage.
//
// The exempt list is the reflex's, so there is a single answer to "who does
// this gateway never refuse" rather than two lists that can disagree.
func baselineFrom(rl config.RateLimitConfig, block config.BlockConfig) (policy.Baseline, error) {
	if !rl.Enforce || rl.RequestsPerMinute <= 0 {
		return policy.Baseline{}, nil
	}

	entries := block.ExemptCIDRs
	if entries == nil {
		entries = enforcement.DefaultExempt
	}
	exempt, err := netutil.ParseCIDRs(entries, "exempt range")
	if err != nil {
		return policy.Baseline{}, err
	}

	return policy.Baseline{RequestsPerMinute: rl.RequestsPerMinute, Exempt: exempt}, nil
}

// throttleDelay is the pause applied to a throttled caller, or zero when
// throttling is off.
func throttleDelay(cfg config.ThrottleConfig) time.Duration {
	if !cfg.Enabled {
		return 0
	}
	return time.Duration(cfg.DelayMS) * time.Millisecond
}

// enforcementOn reports whether any source could currently have an opinion.
// When none can, the middleware short-circuits and no lookup happens per
// request, which is what it did before either source could be toggled.
func (s *Server) enforcementOn(reflex *enforcement.Reflex, gate *policy.Gate) bool {
	return gate.On() || reflex.Active()
}

// newReflex builds the gateway's own blocking, from enforcement.block.
func (s *Server) newReflex() (*enforcement.Reflex, error) {
	return enforcement.New(enforcement.Config{
		Enabled:     s.config.Block.Enabled,
		Duration:    s.config.Block.Duration,
		Signals:     s.config.Block.Signals,
		MinScore:    s.config.Block.MinScore,
		ExemptCIDRs: s.config.Block.ExemptCIDRs,
	})
}

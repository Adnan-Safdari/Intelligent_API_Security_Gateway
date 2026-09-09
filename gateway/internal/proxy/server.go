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
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/reputation"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
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

	// MaxBodyBytes is the largest request body the gateway will read. Zero
	// falls back to DefaultMaxBodyBytes; the cap cannot be turned off from
	// config, because every stage below it buffers whatever it is handed.
	MaxBodyBytes int64

	// Routes describes the backend's own endpoints, so telemetry can record
	// which template a path matched. Structural and boot-only: changing a
	// template changes what previously recorded telemetry means, which is why
	// it is not part of the block the settings watcher carries.
	Routes config.RoutesConfig

	// RateLimit holds the configuration for API flooding detection.
	RateLimit         config.RateLimitConfig
	AdaptiveRateLimit config.AdaptiveRateLimitConfig

	// AttackDetection holds SQL injection detection settings.
	AttackDetection config.AttackDetectionConfig

	// BruteForce holds brute force login detection settings.
	BruteForce config.BruteForceConfig

	// Enumeration holds path-traversal and forced-browsing detection settings.
	Enumeration config.EnumerationConfig

	// IPReputation holds the known-bad address list and how loudly it answers.
	IPReputation config.IPReputationConfig

	// Policy controls enforcement of control-plane decisions.
	Policy config.PolicyConfig

	// Block holds the gateway's own blocking -- its reflex, as distinct from
	// the decisions the control plane writes as policy keys.
	Block config.BlockConfig

	// Throttle carries legacy console settings; quota enforcement never sleeps.
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
	collector   *signals.Collector
	closePolicy func()
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
//  1. Client-IP resolver — trusted-proxy X-Forwarded-For, then context IP
//  2. Telemetry — records one Redis event after the rest of the chain returns
//  3. Logging
//  4. Policy enforcer — optional; blocked IPs never reach detectors
//  5. Body-size cap, then redacted telemetry body capture
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

	// The reputation feed is loaded before the chain is built. A list that will
	// not parse is a configuration error and stops the gateway, exactly as a
	// bad exempt CIDR does -- a security control that silently loaded nothing
	// looks identical to one where no attacker is listed.
	reputationFeed, reputationSource := reputation.New(), reputationSourceFrom(s.config.IPReputation)
	reputationLoader := reputation.NewLoader(reputationFeed)
	if s.config.IPReputation.Enabled {
		if err := reputationLoader.Load(reputationSource); err != nil {
			return err
		}
		log.Printf("[reputation] %s", reputationFeed.Describe())

		stopFeed := make(chan struct{})
		defer close(stopFeed)
		reputationLoader.Start(reputationSource, stopFeed)
	}
	reputationDetector := signals.NewReputationDetector(reputationFeed, s.config.IPReputation)

	s.collector = signals.NewCollector(
		floodDetector, sqliDetector, traversalEnumDetector, bruteForceDetector, reputationDetector,
	)

	sinks := newTelemetrySinks(s.config.Redis)
	defer sinks.Close()

	resolver, err := netutil.NewResolver(s.config.TrustedProxies)
	if err != nil {
		return err
	}

	// A route table that would not compile stops the gateway, for the same
	// reason a bad reputation list does: one that silently loaded nothing
	// records <unmatched> for every real endpoint, and nothing downstream can
	// tell that from a client walking paths the application does not serve.
	routes, err := telemetry.NewTable(s.config.Routes.Templates)
	if err != nil {
		return err
	}
	auth := telemetry.NewAuthOutcomes(authRulesFrom(s.config.Routes.AuthOutcomes))

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
	enforcer.WithRouteResolver(routes.Match)
	defer s.closePolicy()

	// Live settings. The file is what the gateway boots with; the console can
	// put an override on top of it, and deleting that override comes straight
	// back here. Only the enforcement block travels this way -- see the
	// settings package for why the structural settings do not.
	watcher := s.startSettingsWatcher(live{
		flood:      floodDetector,
		sqli:       sqliDetector,
		brute:      bruteForceDetector,
		traversal:  traversalEnumDetector,
		reputation: reputationDetector,
		reflex:     reflex,
		enforcer:   enforcer,
		gate:       gate,
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
	// Zero means unset rather than unlimited. A gateway that reads whatever it
	// is sent is the failure this guards, so the config may raise or lower the
	// cap but may not remove it.
	maxBody := s.config.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}

	recorder := &telemetry.Recorder{
		Events:    sinks.Events,
		Arrivals:  sinks.Arrivals,
		Collector: s.collector,
		Routes:    routes,
		Auth:      auth,
	}
	if heartbeat := sinks.Heartbeat; heartbeat != nil {
		// Started here rather than beside the writers so it can report the
		// in-flight count, which only exists once the recorder does.
		heartbeat.Requests = recorder
		stopHeartbeat := make(chan struct{})
		defer close(stopHeartbeat)
		heartbeat.Start(stopHeartbeat)
	}

	// Refusals are recorded without reading a body. Accepted traffic is capped
	// before the telemetry snippet or any detector buffers client input.
	handler := ChainMiddleware(
		resolver.Middleware,
		recorder.Middleware,
		LoggingMiddleware,
		enforcer.Middleware,
		BodyLimitMiddleware(maxBody),
		telemetry.CaptureBody,
		observedDetectors(reflex, s.collector,
			// First among the detectors because it is the cheapest -- one set
			// lookup, no body, no window. Its position does not affect when a
			// block lands: the reflex observes after the handler by design, so
			// every gateway-side block takes effect on the next request.
			reputationDetector.Middleware,
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
	a := s.config.AdaptiveRateLimit.WithDefaults()
	var quota policy.QuotaLimiter
	s.closePolicy = func() {}

	if s.config.Redis.Enabled {
		cfg := policy.Config{
			Addr:            s.config.Redis.Addr(),
			Password:        s.config.Redis.Password,
			DB:              s.config.Redis.DB,
			PoolSize:        s.config.Redis.PoolSize,
			KeyPrefix:       s.config.Policy.KeyPrefix,
			RefreshInterval: s.config.Policy.RefreshInterval,
			RedisTimeout:    a.RedisTimeout,
			RefreshTimeout:  a.PolicyRefreshTimeout,
			FailureBackoff:  a.FailureBackoff,
			CacheMaxAge:     a.CacheMaxAge,
			BucketPrefix:    a.BucketKeyPrefix,
		}
		store := policy.NewStore(cfg)
		store.Start()
		limiter := policy.NewRedisLimiter(cfg)
		quota = limiter
		s.closePolicy = func() { _ = store.Close(); _ = limiter.Close() }
		gate = policy.NewGate(store, s.config.Policy.Enabled)
		sources = append(sources, gate)
	}

	sources = append(sources, reflex)

	enforcer := policy.NewEnforcer(
		sources, s.enforcementOn(reflex, gate), throttleDelay(s.config.Throttle),
	).WithQuotaLimiter(quota, a.FallbackRequestsPerMinute, a.Burst)

	baseline, err := baselineFrom(s.config.RateLimit, s.config.Block)
	if err != nil {
		s.closePolicy()
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

// Preserve the settings wire's legacy duration argument for API compatibility.
// The enforcer ignores it; adaptive quota admission is always immediate.
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

// reputationSourceFrom turns config into a feed source, applying the defaults
// for anything left unset.
func reputationSourceFrom(cfg config.IPReputationConfig) reputation.Source {
	timeout := cfg.FetchTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return reputation.Source{
		Path:            cfg.FeedPath,
		URL:             cfg.FeedURL,
		RefreshInterval: cfg.RefreshInterval,
		Timeout:         timeout,
	}
}

// Enforcement reassembles the enforcement block from the flat fields the
// server was built with.
//
// It exists so there is exactly one place that knows which sections make up
// that block. Adding a section used to mean remembering three separate
// literals -- main.go, this, and the settings wire -- and forgetting one left
// the feature silently switched off with nothing to say so.
func (c Config) Enforcement() config.EnforcementConfig {
	return config.EnforcementConfig{
		AdaptiveRateLimit: c.AdaptiveRateLimit,
		RateLimit:         c.RateLimit,
		AttackDetection:   c.AttackDetection,
		BruteForce:        c.BruteForce,
		Enumeration:       c.Enumeration,
		IPReputation:      c.IPReputation,
		Throttle:          c.Throttle,
		Block:             c.Block,
		Policy:            c.Policy,
	}
}

// authRulesFrom turns the configured endpoints into the rules telemetry reads
// an authentication outcome with. Configuration rather than inference: 401 does
// not mean "wrong password" in general, only on an endpoint documented to
// answer that way.
func authRulesFrom(entries []config.AuthOutcomeConfig) []telemetry.AuthRule {
	rules := make([]telemetry.AuthRule, 0, len(entries))
	for _, e := range entries {
		rules = append(rules, telemetry.AuthRule{
			Method:             e.Method,
			Template:           e.Template,
			Success:            e.Success,
			InvalidCredentials: e.InvalidCredentials,
		})
	}
	return rules
}

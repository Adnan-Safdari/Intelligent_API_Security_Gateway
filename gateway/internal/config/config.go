package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config maps the gateway YAML configuration.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Proxy       ProxyConfig       `yaml:"proxy"`
	Routes      RoutesConfig      `yaml:"routes"`
	Storage     StorageConfig     `yaml:"storage"`
	Enforcement EnforcementConfig `yaml:"enforcement"`
}

// RoutesConfig describes the backend, not enforcement, which is why it is a
// top-level block rather than a section under enforcement:.
//
// These settings are structural. Changing a route template changes what
// previously recorded telemetry means, so they are read at boot and are
// deliberately not carried by the settings watcher -- unlike detector
// thresholds, which are safe to retune while running.
type RoutesConfig struct {
	// Templates are "METHOD /path/{param}" entries. A path that matches none
	// of them records as unmatched, which is a real category: it is what a
	// client walking paths the application does not serve looks like.
	Templates []string `yaml:"templates"`

	// AuthOutcomes says how to read an authentication result off a backend
	// status, per endpoint. It is configuration rather than an inference
	// because 401 does not mean "wrong password" in general -- it means that
	// on an endpoint documented to answer that way, and nowhere else.
	AuthOutcomes []AuthOutcomeConfig `yaml:"auth_outcomes"`

	// ObjectTemplates names the endpoints that return one object belonging to
	// someone -- "GET /api/orders/{id}" -- and are therefore worth watching for
	// a client walking through identifiers. Configuration rather than an
	// inference: the gateway cannot tell a public catalogue lookup from a
	// private record, and a shopper browsing many products is not an attack.
	// Each must also appear in Templates and carry at least one {param}.
	ObjectTemplates []string `yaml:"object_templates"`
}

type AuthOutcomeConfig struct {
	Method   string `yaml:"method"`
	Template string `yaml:"template"`

	// Backend statuses that mean the credentials were accepted, and those
	// that mean they were rejected. A status in neither list is unknown,
	// which is not the same as a success: a 500 says the database failed,
	// not that the password was right.
	Success            []int `yaml:"success"`
	InvalidCredentials []int `yaml:"invalid_credentials"`
}

type ServerConfig struct {
	Port         int           `yaml:"port"`
	Host         string        `yaml:"host"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`

	// MaxBodyBytes caps the request body the gateway will read. Unset falls
	// back to the gateway's own default; it is deliberately not possible to
	// disable, because everything downstream buffers what it is handed.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`

	// TrustedProxies lists the CIDRs whose X-Forwarded-For header may be
	// believed. Empty means trust nothing and always use the peer address,
	// which is the safe default: anyone can set the header, so trusting it
	// unconditionally would let an attacker pin blame on another IP.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

type ProxyConfig struct {
	BackendURL string `yaml:"backend_url"`

	// PreserveHost forwards the client's Host header unchanged instead of
	// replacing it with the backend's. Off by default, because a backend that
	// routes by name -- a virtual host, a PaaS, a CDN -- answers the gateway's
	// own name with a 404 or a certificate mismatch. Turn it on only for a
	// backend that must see the public hostname, such as one building absolute
	// links from it; X-Forwarded-Host carries that name either way.
	PreserveHost bool `yaml:"preserve_host"`

	Timeout         time.Duration `yaml:"timeout"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	MaxConnsPerHost int           `yaml:"max_conns_per_host"`
}

type StorageConfig struct {
	Redis RedisConfig `yaml:"redis"`
}

type RedisConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Password     string `yaml:"password"`
	DB           int    `yaml:"db"`
	PoolSize     int    `yaml:"pool_size"`
	StreamKey    string `yaml:"stream_key"`
	StreamMaxLen int64  `yaml:"stream_maxlen"`

	// Arrival records go to their own stream so every existing consumer of
	// stream_key keeps seeing exactly what it sees today. They are capped
	// separately because there is one per request either way, but a capture
	// run wants far more history than the console does.
	ArrivalStreamKey string `yaml:"arrival_stream_key"`
	ArrivalMaxLen    int64  `yaml:"arrival_maxlen"`

	HealthStreamKey       string        `yaml:"health_stream_key"`
	HealthMaxLen          int64         `yaml:"health_maxlen"`
	IPLatestTTL           time.Duration `yaml:"ip_latest_ttl"`
	TelemetryQueueSize    int           `yaml:"telemetry_queue_size"`
	TelemetryWriteTimeout time.Duration `yaml:"telemetry_write_timeout"`
}

func (c RedisConfig) Addr() string {
	host := c.Host
	if host == "" {
		host = "localhost"
	}
	port := c.Port
	if port <= 0 {
		port = 6379
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

type EnforcementConfig struct {
	AdaptiveRateLimit AdaptiveRateLimitConfig `yaml:"adaptive_rate_limit"`
	RateLimit         RateLimitConfig         `yaml:"rate_limit"`
	AttackDetection   AttackDetectionConfig   `yaml:"attack_detection"`
	BruteForce        BruteForceConfig        `yaml:"brute_force"`
	UnknownRouteScan  UnknownRouteScanConfig  `yaml:"unknown_route_scanning"`
	ObjectEnumeration ObjectEnumerationConfig `yaml:"object_enumeration"`
	Enumeration       EnumerationConfig       `yaml:"enumeration_path_traversal"`
	IPReputation      IPReputationConfig      `yaml:"ip_reputation"`
	Throttle          ThrottleConfig          `yaml:"throttle"`
	Block             BlockConfig             `yaml:"block"`
	Policy            PolicyConfig            `yaml:"policy"`
}

// AdaptiveRateLimitConfig is fixed at boot so replicas use the same quota
// contract. Policy rates still change dynamically with the control plane.
type AdaptiveRateLimitConfig struct {
	FallbackRequestsPerMinute int           `yaml:"fallback_requests_per_minute"`
	Burst                     int           `yaml:"burst"`
	RedisTimeout              time.Duration `yaml:"redis_timeout"`
	PolicyRefreshTimeout      time.Duration `yaml:"policy_refresh_timeout"`
	FailureBackoff            time.Duration `yaml:"failure_backoff"`
	CacheMaxAge               time.Duration `yaml:"cache_max_age"`
	BucketKeyPrefix           string        `yaml:"bucket_key_prefix"`
}

func (c AdaptiveRateLimitConfig) WithDefaults() AdaptiveRateLimitConfig {
	if c.FallbackRequestsPerMinute == 0 {
		c.FallbackRequestsPerMinute = 60
	}
	if c.Burst == 0 {
		c.Burst = 20
	}
	if c.RedisTimeout == 0 {
		c.RedisTimeout = 25 * time.Millisecond
	}
	if c.PolicyRefreshTimeout == 0 {
		c.PolicyRefreshTimeout = 2 * time.Second
	}
	if c.FailureBackoff == 0 {
		c.FailureBackoff = time.Second
	}
	if c.CacheMaxAge == 0 {
		c.CacheMaxAge = 10 * time.Second
	}
	if c.BucketKeyPrefix == "" {
		c.BucketKeyPrefix = "iasg:rate:"
	}
	return c
}

// PolicyConfig controls whether the gateway acts on decisions written by the
// Python control plane. Disabled by default: enabling it is what turns the
// control plane from an observer into something that can refuse traffic.
type PolicyConfig struct {
	Enabled         bool          `yaml:"enabled"`
	KeyPrefix       string        `yaml:"key_prefix"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
}

type BruteForceConfig struct {
	Enabled             bool          `yaml:"enabled"`
	MaxFailures         int           `yaml:"max_failures"` // consecutive invalid credentials before the signal fires
	Window              time.Duration `yaml:"window"`       // maximum age of a consecutive-failure streak
	MaxClients          int           `yaml:"max_clients"`
	MaxTargetsPerClient int           `yaml:"max_targets_per_client"`
}

// UnknownRouteScanConfig bounds the detector that notices a client walking
// several paths the configured application does not expose. Route templates
// are structural, but these behavioural limits may safely move at runtime.
type UnknownRouteScanConfig struct {
	Enabled           bool          `yaml:"enabled"`
	DistinctPaths     int           `yaml:"distinct_paths"`
	Window            time.Duration `yaml:"window"`
	MaxClients        int           `yaml:"max_clients"`
	MaxPathsPerClient int           `yaml:"max_paths_per_client"`
}

// ObjectEnumerationConfig bounds the detector that notices one client
// requesting many distinct object identifiers on an object template (BOLA /
// IDOR). Which endpoints are watched is structural and lives in
// routes.object_templates; these behavioural limits may move at runtime.
type ObjectEnumerationConfig struct {
	Enabled         bool          `yaml:"enabled"`
	DistinctIDs     int           `yaml:"distinct_ids"`
	Window          time.Duration `yaml:"window"`
	MaxClients      int           `yaml:"max_clients"`
	MaxIDsPerClient int           `yaml:"max_ids_per_client"`
}

type AttackDetectionConfig struct {
	Enabled     bool     `yaml:"enabled"`
	SQLPatterns []string `yaml:"sql_patterns"`
}

type EnumerationConfig struct {
	Enabled             bool     `yaml:"enabled"`
	TraversalPatterns   []string `yaml:"traversal_patterns"`
	EnumerationPatterns []string `yaml:"enumeration_patterns"`
}

// IPReputationConfig controls the one detector that knows something before the
// attacker does anything. It lives under `enforcement` rather than the
// top-level `signals` block for two reasons: that block is parsed and never
// read by anything, and only `enforcement` travels through the settings
// watcher, which is what makes this changeable from the console.
type IPReputationConfig struct {
	Enabled bool `yaml:"enabled"`

	// Where the list comes from. Structural, like a listen address: read once
	// at startup, not carried by a live settings change.
	FeedPath        string        `yaml:"feed_path"`
	FeedURL         string        `yaml:"feed_url"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	FetchTimeout    time.Duration `yaml:"fetch_timeout"`

	// Score a listed address contributes. Defaults to the reflex's own
	// min_score floor, so naming this in `block.signals` actually lets it act.
	Score int `yaml:"score"`

	// How long an address stays quiet after firing. A listed address is listed
	// on every request; without this it would raise a signal on each one.
	Cooldown time.Duration `yaml:"cooldown"`
}

type RateLimitConfig struct {
	// Enabled turns on flood *detection*: counting requests per address and
	// raising a signal when RequestsPerMinute is exceeded.
	Enabled bool `yaml:"enabled"`

	// Enforce turns that threshold into a limit the gateway acts on, refusing
	// anything over it with 429 rather than only reporting it. Separate from
	// Enabled because refusing traffic is a different decision from noticing
	// it, and this one can turn a legitimate spike into an outage.
	//
	// An address under a throttle policy is held to the rate that policy names
	// instead; this is the baseline everyone else gets.
	Enforce bool `yaml:"enforce"`

	RequestsPerMinute int `yaml:"requests_per_minute"`
	Burst             int `yaml:"burst"`
}

type ThrottleConfig struct {
	Enabled bool `yaml:"enabled"`
	DelayMS int  `yaml:"delay_ms"`
}

// BlockConfig controls the gateway's own blocking -- its reflex, as opposed to
// the considered decisions the control plane writes as policy keys.
//
// Enabled on its own does nothing: Signals has to name at least one detector
// that may act. That is deliberate. This block existed in the config long
// before anything read it, so a build that suddenly honoured Enabled alone
// would start refusing traffic on configuration nobody had revisited.
type BlockConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Duration time.Duration `yaml:"duration"`
	// Detectors trusted to block on their own. Omit the key entirely to take
	// the safe defaults; an explicit empty list enforces nothing.
	Signals []string `yaml:"signals"`
	// A score floor on top of the detector's own threshold, so a marginal hit
	// is not enough on its own.
	MinScore int `yaml:"min_score"`
	// Never blocked. Omit to take loopback and the private ranges.
	ExemptCIDRs []string `yaml:"exempt_cidrs"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse yaml config %s: %w", path, err)
	}

	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Server.Port <= 0 {
		return nil, fmt.Errorf("invalid server.port: %d", cfg.Server.Port)
	}
	if cfg.Proxy.BackendURL == "" {
		return nil, fmt.Errorf("proxy.backend_url must be set")
	}

	if cfg.Storage.Redis.StreamKey == "" {
		cfg.Storage.Redis.StreamKey = "iasg:events"
	}
	if cfg.Storage.Redis.StreamMaxLen <= 0 {
		cfg.Storage.Redis.StreamMaxLen = 2000
	}
	if cfg.Storage.Redis.ArrivalStreamKey == "" {
		cfg.Storage.Redis.ArrivalStreamKey = "iasg:arrivals"
	}
	if cfg.Storage.Redis.ArrivalMaxLen <= 0 {
		cfg.Storage.Redis.ArrivalMaxLen = cfg.Storage.Redis.StreamMaxLen
	}
	if cfg.Storage.Redis.HealthStreamKey == "" {
		cfg.Storage.Redis.HealthStreamKey = "iasg:telemetry:health"
	}
	if cfg.Storage.Redis.HealthMaxLen <= 0 {
		// One record a second, so this is a day of heartbeats.
		cfg.Storage.Redis.HealthMaxLen = 86400
	}
	if cfg.Storage.Redis.IPLatestTTL <= 0 {
		cfg.Storage.Redis.IPLatestTTL = 24 * time.Hour
	}
	if cfg.Storage.Redis.PoolSize <= 0 {
		cfg.Storage.Redis.PoolSize = 10
	}
	if cfg.Storage.Redis.TelemetryQueueSize == 0 {
		cfg.Storage.Redis.TelemetryQueueSize = 1024
	}
	if cfg.Storage.Redis.TelemetryWriteTimeout == 0 {
		cfg.Storage.Redis.TelemetryWriteTimeout = 100 * time.Millisecond
	}
	if cfg.Storage.Redis.TelemetryQueueSize < 0 || cfg.Storage.Redis.TelemetryWriteTimeout < 0 {
		return nil, fmt.Errorf("Redis telemetry queue size and write timeout must be positive")
	}
	if cfg.Enforcement.Policy.KeyPrefix == "" {
		cfg.Enforcement.Policy.KeyPrefix = "policy:"
	}
	if cfg.Enforcement.Policy.RefreshInterval <= 0 {
		cfg.Enforcement.Policy.RefreshInterval = 5 * time.Second
	}
	a := cfg.Enforcement.AdaptiveRateLimit.WithDefaults()
	if cfg.Enforcement.AdaptiveRateLimit.CacheMaxAge == 0 && a.CacheMaxAge < 2*cfg.Enforcement.Policy.RefreshInterval {
		a.CacheMaxAge = 2 * cfg.Enforcement.Policy.RefreshInterval
	}
	if a.FallbackRequestsPerMinute < 1 || a.Burst < 1 || a.RedisTimeout < time.Millisecond || a.RedisTimeout > time.Second || a.FailureBackoff < time.Millisecond || a.CacheMaxAge < cfg.Enforcement.Policy.RefreshInterval {
		return nil, fmt.Errorf("adaptive_rate_limit requires positive rates/backoff, redis_timeout between 1ms and 1s, and cache_max_age >= policy.refresh_interval")
	}
	if a.PolicyRefreshTimeout < a.RedisTimeout || a.PolicyRefreshTimeout > 30*time.Second {
		return nil, fmt.Errorf("adaptive_rate_limit.policy_refresh_timeout must be >= redis_timeout and <= 30s")
	}
	if strings.HasPrefix(a.BucketKeyPrefix, cfg.Enforcement.Policy.KeyPrefix) || strings.HasPrefix(cfg.Enforcement.Policy.KeyPrefix, a.BucketKeyPrefix) {
		return nil, fmt.Errorf("adaptive_rate_limit.bucket_key_prefix must not overlap policy.key_prefix")
	}
	cfg.Enforcement.AdaptiveRateLimit = a
	brute, err := ValidatedBruteForce(cfg.Enforcement.BruteForce)
	if err != nil {
		return nil, err
	}
	cfg.Enforcement.BruteForce = brute
	scan, err := ValidatedUnknownRouteScan(cfg.Enforcement.UnknownRouteScan)
	if err != nil {
		return nil, err
	}
	cfg.Enforcement.UnknownRouteScan = scan
	objects, err := ValidatedObjectEnumeration(cfg.Enforcement.ObjectEnumeration)
	if err != nil {
		return nil, err
	}
	cfg.Enforcement.ObjectEnumeration = objects
	if err := validateObjectTemplates(cfg.Routes); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ValidatedBruteForce fills safe defaults and rejects a limit that would make
// the detector either unbounded or too broad to be a useful security control.
// Settings uses the same function so a hand-written Redis override receives
// exactly the validation a YAML file does.
func ValidatedBruteForce(cfg BruteForceConfig) (BruteForceConfig, error) {
	if cfg.MaxFailures == 0 {
		cfg.MaxFailures = 5
	}
	if cfg.Window == 0 {
		cfg.Window = time.Minute
	}
	if cfg.MaxClients == 0 {
		cfg.MaxClients = 10_000
	}
	if cfg.MaxTargetsPerClient == 0 {
		cfg.MaxTargetsPerClient = 64
	}
	if cfg.MaxFailures < 1 || cfg.MaxFailures > 1_000 || cfg.MaxClients < 1 || cfg.MaxClients > 100_000 || cfg.MaxTargetsPerClient < 1 || cfg.MaxTargetsPerClient > 10_000 || cfg.Window < time.Second || cfg.Window > 24*time.Hour {
		return BruteForceConfig{}, fmt.Errorf("brute_force requires max_failures 1..1000, max_clients 1..100000, max_targets_per_client 1..10000, and window 1s..24h")
	}
	return cfg, nil
}

// ValidatedUnknownRouteScan limits every retained dimension. The raw paths are
// attacker input, so capacity is part of correctness rather than tuning.
func ValidatedUnknownRouteScan(cfg UnknownRouteScanConfig) (UnknownRouteScanConfig, error) {
	if cfg.DistinctPaths == 0 {
		cfg.DistinctPaths = 8
	}
	if cfg.Window == 0 {
		cfg.Window = 5 * time.Minute
	}
	if cfg.MaxClients == 0 {
		cfg.MaxClients = 10_000
	}
	if cfg.MaxPathsPerClient == 0 {
		cfg.MaxPathsPerClient = 64
	}
	if cfg.DistinctPaths < 2 || cfg.DistinctPaths > cfg.MaxPathsPerClient || cfg.MaxPathsPerClient > 10_000 || cfg.MaxClients < 1 || cfg.MaxClients > 100_000 || cfg.Window < time.Second || cfg.Window > 24*time.Hour {
		return UnknownRouteScanConfig{}, fmt.Errorf("unknown_route_scanning requires distinct_paths 2..max_paths_per_client, max_paths_per_client <= 10000, max_clients 1..100000, and window 1s..24h")
	}
	return cfg, nil
}

// ValidatedObjectEnumeration limits every retained dimension. Identifiers are
// attacker input, so capacity is part of correctness rather than tuning.
func ValidatedObjectEnumeration(cfg ObjectEnumerationConfig) (ObjectEnumerationConfig, error) {
	if cfg.DistinctIDs == 0 {
		cfg.DistinctIDs = 20
	}
	if cfg.Window == 0 {
		cfg.Window = 5 * time.Minute
	}
	if cfg.MaxClients == 0 {
		cfg.MaxClients = 10_000
	}
	if cfg.MaxIDsPerClient == 0 {
		cfg.MaxIDsPerClient = 256
	}
	if cfg.DistinctIDs < 2 || cfg.DistinctIDs > cfg.MaxIDsPerClient || cfg.MaxIDsPerClient > 10_000 || cfg.MaxClients < 1 || cfg.MaxClients > 100_000 || cfg.Window < time.Second || cfg.Window > 24*time.Hour {
		return ObjectEnumerationConfig{}, fmt.Errorf("object_enumeration requires distinct_ids 2..max_ids_per_client, max_ids_per_client <= 10000, max_clients 1..100000, and window 1s..24h")
	}
	return cfg, nil
}

// validateObjectTemplates refuses an object template the gateway could never
// match. One missing from routes.templates, or with no {param} to read an
// identifier from, would leave the detector silently watching nothing -- which
// looks exactly like an API nobody is enumerating.
func validateObjectTemplates(routes RoutesConfig) error {
	known := make(map[string]bool, len(routes.Templates))
	for _, raw := range routes.Templates {
		known[normalizeTemplate(raw)] = true
	}
	for _, raw := range routes.ObjectTemplates {
		template := normalizeTemplate(raw)
		if !strings.Contains(template, "{") {
			return fmt.Errorf("routes.object_templates entry %q has no {param} to read an identifier from", raw)
		}
		if !known[template] {
			return fmt.Errorf("routes.object_templates entry %q is not listed in routes.templates", raw)
		}
	}
	return nil
}

func normalizeTemplate(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) != 2 {
		return strings.TrimSpace(raw)
	}
	return strings.ToUpper(fields[0]) + " " + fields[1]
}

// ApplyEnvOverrides lets a container point the file's config at its
// neighbours: IASG_BACKEND_URL replaces proxy.backend_url and IASG_REDIS_HOST
// replaces storage.redis.host. It returns one line per override applied, for
// the caller to log.
func ApplyEnvOverrides(cfg *Config, getenv func(string) string) []string {
	var applied []string
	if v := getenv("IASG_BACKEND_URL"); v != "" {
		cfg.Proxy.BackendURL = v
		applied = append(applied, "Overriding backend URL from IASG_BACKEND_URL: "+v)
	}
	if v := getenv("IASG_REDIS_HOST"); v != "" {
		cfg.Storage.Redis.Host = v
		applied = append(applied, "Overriding Redis host from IASG_REDIS_HOST: "+v)
	}
	return applied
}

package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config maps the gateway YAML configuration.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Proxy       ProxyConfig       `yaml:"proxy"`
	Storage     StorageConfig     `yaml:"storage"`
	Enforcement EnforcementConfig `yaml:"enforcement"`
	Signals     SignalsConfig     `yaml:"signals"`
	Logging     LoggingConfig     `yaml:"logging"`
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
	BackendURL      string        `yaml:"backend_url"`
	Timeout         time.Duration `yaml:"timeout"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	MaxConnsPerHost int           `yaml:"max_conns_per_host"`
}

type StorageConfig struct {
	Redis    RedisConfig    `yaml:"redis"`
	Postgres PostgresConfig `yaml:"postgres"`
}

type RedisConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	Password     string        `yaml:"password"`
	DB           int           `yaml:"db"`
	PoolSize     int           `yaml:"pool_size"`
	StreamKey    string        `yaml:"stream_key"`
	StreamMaxLen int64         `yaml:"stream_maxlen"`
	IPLatestTTL  time.Duration `yaml:"ip_latest_ttl"`
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

type PostgresConfig struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Database     string `yaml:"database"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	SSLMode      string `yaml:"ssl_mode"`
	MaxOpenConns int    `yaml:"max_open_conns"`
	MaxIdleConns int    `yaml:"max_idle_conns"`
}

type EnforcementConfig struct {
	RateLimit       RateLimitConfig       `yaml:"rate_limit"`
	AttackDetection AttackDetectionConfig `yaml:"attack_detection"`
	BruteForce      BruteForceConfig      `yaml:"brute_force"`
	Enumeration     EnumerationConfig     `yaml:"enumeration_path_traversal"`
	IPReputation    IPReputationConfig    `yaml:"ip_reputation"`
	Throttle        ThrottleConfig        `yaml:"throttle"`
	Block           BlockConfig           `yaml:"block"`
	Policy          PolicyConfig          `yaml:"policy"`
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
	Enabled     bool          `yaml:"enabled"`
	MaxFailures int           `yaml:"max_failures"` // failed logins inside the window before the signal fires
	Window      time.Duration `yaml:"window"`       // sliding window for counting failures
	LoginPaths  []string      `yaml:"login_paths"`  // request paths treated as login endpoints
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

type SignalsConfig struct {
	// ip_reputation used to be declared here and read by nothing. It now lives
	// in EnforcementConfig, where it is implemented and live-tunable.
	GeoLocation     GeoLocationSignalConfig     `yaml:"geo_location"`
	PayloadAnalysis PayloadAnalysisSignalConfig `yaml:"payload_analysis"`
	Behavioral      BehavioralSignalConfig      `yaml:"behavioral"`
}

type GeoLocationSignalConfig struct {
	Enabled bool `yaml:"enabled"`
}

type PayloadAnalysisSignalConfig struct {
	Enabled     bool   `yaml:"enabled"`
	MaxBodySize string `yaml:"max_body_size"`
}

type BehavioralSignalConfig struct {
	Enabled        bool          `yaml:"enabled"`
	LearningPeriod time.Duration `yaml:"learning_period"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
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
	if cfg.Storage.Redis.IPLatestTTL <= 0 {
		cfg.Storage.Redis.IPLatestTTL = 24 * time.Hour
	}
	if cfg.Storage.Redis.PoolSize <= 0 {
		cfg.Storage.Redis.PoolSize = 10
	}
	if cfg.Enforcement.Policy.KeyPrefix == "" {
		cfg.Enforcement.Policy.KeyPrefix = "policy:"
	}
	if cfg.Enforcement.Policy.RefreshInterval <= 0 {
		cfg.Enforcement.Policy.RefreshInterval = 5 * time.Second
	}

	return cfg, nil
}

package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config maps the gateway YAML configuration.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Proxy       ProxyConfig       `yaml:"proxy"`
	TrustEngine TrustEngineConfig `yaml:"trust_engine"`
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
}

type ProxyConfig struct {
	BackendURL      string        `yaml:"backend_url"`
	Timeout         time.Duration `yaml:"timeout"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	MaxConnsPerHost int           `yaml:"max_conns_per_host"`
}

type TrustEngineConfig struct {
	BlockThreshold    int                `yaml:"block_threshold"`
	ThrottleThreshold int                `yaml:"throttle_threshold"`
	AllowThreshold    int                `yaml:"allow_threshold"`
	Weights           TrustWeightsConfig `yaml:"weights"`
}

type TrustWeightsConfig struct {
	IPReputation    float64 `yaml:"ip_reputation"`
	RateLimiting    float64 `yaml:"rate_limiting"`
	Authentication  float64 `yaml:"authentication"`
	PayloadAnalysis float64 `yaml:"payload_analysis"`
	Behavioral      float64 `yaml:"behavioral"`
}

type StorageConfig struct {
	Redis    RedisConfig    `yaml:"redis"`
	Postgres PostgresConfig `yaml:"postgres"`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	PoolSize int    `yaml:"pool_size"`
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
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	Throttle  ThrottleConfig  `yaml:"throttle"`
	Block     BlockConfig     `yaml:"block"`
}

type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerMinute int  `yaml:"requests_per_minute"`
	Burst             int  `yaml:"burst"`
}

type ThrottleConfig struct {
	Enabled bool `yaml:"enabled"`
	DelayMS int  `yaml:"delay_ms"`
}

type BlockConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Duration time.Duration `yaml:"duration"`
}

type SignalsConfig struct {
	IPReputation    IPReputationSignalConfig    `yaml:"ip_reputation"`
	GeoLocation     GeoLocationSignalConfig     `yaml:"geo_location"`
	PayloadAnalysis PayloadAnalysisSignalConfig `yaml:"payload_analysis"`
	Behavioral      BehavioralSignalConfig      `yaml:"behavioral"`
}

type IPReputationSignalConfig struct {
	Enabled       bool          `yaml:"enabled"`
	CheckInterval time.Duration `yaml:"check_interval"`
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

	return cfg, nil
}

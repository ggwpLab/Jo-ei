// Package config loads and validates the Jōei YAML/env configuration.
package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	Registries  RegistriesConfig  `mapstructure:"registries"`
	SupplyChain SupplyChainConfig `mapstructure:"supply_chain"`
	CVE         CVEConfig         `mapstructure:"cve"`
	Malware     MalwareConfig     `mapstructure:"malware"`
	Cache       CacheConfig       `mapstructure:"cache"`
	Policy      PolicyConfig      `mapstructure:"policy"`
	Logging     LoggingConfig     `mapstructure:"logging"`
	Console     ConsoleConfig     `mapstructure:"console"`
	Health      HealthConfig      `mapstructure:"health"`
	Database    DatabaseConfig    `mapstructure:"database"`
}

// Validate checks cross-field invariants after loading.
func (c *Config) Validate() error {
	regs := map[string]RegistryConfig{
		"pypi":     c.Registries.PyPI,
		"npm":      c.Registries.NPM,
		"maven":    c.Registries.Maven,
		"rubygems": c.Registries.RubyGems,
	}
	for name, rc := range regs {
		if rc.Enabled && len(rc.Upstreams) == 0 {
			return fmt.Errorf("registry %q is enabled but has no upstreams", name)
		}
	}
	// Zero scanners is valid; malware scanning is simply skipped.
	for i, sc := range c.Malware.Scanners {
		switch sc.Type {
		case "clamav", "icap":
		case "":
			return fmt.Errorf("malware.scanners[%d]: type is required", i)
		default:
			return fmt.Errorf("malware.scanners[%d]: unknown type %q (want clamav|icap)", i, sc.Type)
		}
		if sc.Address == "" {
			return fmt.Errorf("malware.scanners[%d]: address is required", i)
		}
		if sc.Type == "icap" && sc.Service == "" {
			return fmt.Errorf("malware.scanners[%d]: icap scanner requires a service", i)
		}
	}
	if c.Health.ProbeIntervalSeconds < 0 {
		return fmt.Errorf("health.probe_interval_seconds must not be negative")
	}
	if c.Health.SlowThresholdMS < 0 {
		return fmt.Errorf("health.slow_threshold_ms must not be negative")
	}
	if c.Database.EventRetentionDays < 0 {
		return fmt.Errorf("database.event_retention_days must not be negative")
	}
	if c.Database.DailyRetentionDays < 0 {
		return fmt.Errorf("database.daily_retention_days must not be negative")
	}
	if c.Database.Path == "" {
		return fmt.Errorf("database.path is required (telemetry persists to SQLite)")
	}
	return nil
}

type ServerConfig struct {
	Listen string `mapstructure:"listen"`
}

// ConsoleConfig holds admin-console settings.
type ConsoleConfig struct {
	Auth AuthConfig `mapstructure:"auth"`
}

// AuthConfig holds the console/API Basic-auth credential list. An empty Users
// list means authentication is unconfigured; the server then serves the
// console and API as 503 (fail-closed).
type AuthConfig struct {
	Users []AuthUser `mapstructure:"users"`
}

// AuthUser is one console credential: a username and a bcrypt password hash.
type AuthUser struct {
	Username     string `mapstructure:"username"`
	PasswordHash string `mapstructure:"password_hash"`
}

type RegistriesConfig struct {
	PyPI     RegistryConfig `mapstructure:"pypi"`
	NPM      RegistryConfig `mapstructure:"npm"`
	Maven    RegistryConfig `mapstructure:"maven"`
	RubyGems RegistryConfig `mapstructure:"rubygems"`
}

type RegistryConfig struct {
	Upstreams []string `mapstructure:"upstreams"`
	Enabled   bool     `mapstructure:"enabled"`
}

type SupplyChainConfig struct {
	MinAgeHours   int    `mapstructure:"min_age_hours"`
	AllowlistPath string `mapstructure:"allowlist_path"`
	Mode          string `mapstructure:"mode"` // enforce | dry_run | off
}

type CacheConfig struct {
	Backend string     `mapstructure:"backend"` // local | s3
	Local   LocalCache `mapstructure:"local"`
	S3      S3Cache    `mapstructure:"s3"`
}

type LocalCache struct {
	Path      string `mapstructure:"path"`
	MaxSizeGB int    `mapstructure:"max_size_gb"`
}

type S3Cache struct {
	Endpoint string `mapstructure:"endpoint"`
	Bucket   string `mapstructure:"bucket"`
	Region   string `mapstructure:"region"`
}

type PolicyConfig struct {
	ActiveProfile string                   `mapstructure:"active_profile"`
	Profiles      map[string]PolicyProfile `mapstructure:"profiles"`
}

type PolicyProfile struct {
	CVEBlock         bool     `mapstructure:"cve_block"`
	CVEMinSeverity   string   `mapstructure:"cve_min_severity"` // overrides CVEConfig.BlockOn when non-empty
	SupplyChainBlock bool     `mapstructure:"supply_chain_block"`
	MalwareBlock     bool     `mapstructure:"malware_block"`
	Allowlist        []string `mapstructure:"allowlist"` // "pypi/requests" or "pypi/requests@2.31.0"
	Denylist         []string `mapstructure:"denylist"`
}

// CVEConfig configures the CVE scanner (osv.dev).
type CVEConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	BaseURL         string `mapstructure:"base_url"`          // default "https://api.osv.dev"
	BlockOn         string `mapstructure:"block_on"`          // "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"
	CacheTTLMinutes int    `mapstructure:"cache_ttl_minutes"` // default 1440
}

// MalwareConfig configures the malware-scanning engines run after download.
type MalwareConfig struct {
	Scanners []ScannerConfig `mapstructure:"scanners"`
}

// ScannerConfig configures a single malware-scanning engine.
type ScannerConfig struct {
	Type           string `mapstructure:"type"`            // "clamav" | "icap"
	Address        string `mapstructure:"address"`         // unix:///path | tcp:host:port
	TimeoutSeconds int    `mapstructure:"timeout_seconds"` // default 30
	Service        string `mapstructure:"service"`         // ICAP service name (icap only)
}

// HealthConfig tunes the scanner health probes. Zero values use defaults
// (30s probe interval, 2000ms slow threshold), applied at wiring time.
type HealthConfig struct {
	ProbeIntervalSeconds int `mapstructure:"probe_interval_seconds"`
	SlowThresholdMS      int `mapstructure:"slow_threshold_ms"`
}

// DatabaseConfig configures the embedded SQLite persistence layer. Path is required;
// telemetry is always persisted to SQLite (no in-memory fallback). Retention values
// ≤ 0 use defaults (events 30 days, daily metrics 365 days).
type DatabaseConfig struct {
	Path               string `mapstructure:"path"`
	EventRetentionDays int    `mapstructure:"event_retention_days"`
	DailyRetentionDays int    `mapstructure:"daily_retention_days"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// Load reads a YAML config file and returns a Config.
// Environment variables prefixed with JOEI_ override file values.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("JOEI")
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}
	return &cfg, nil
}

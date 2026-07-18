// Package config loads and validates the Jōei YAML/env configuration.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	Registries  RegistriesConfig  `mapstructure:"registries"`
	SupplyChain SupplyChainConfig `mapstructure:"supply_chain"`
	CVE         CVEConfig         `mapstructure:"cve"`
	ImageScan   ImageScanConfig   `mapstructure:"image_scan"`
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
		"docker":   c.Registries.Docker,
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
	if c.Malware.MaxConcurrentScans < 0 {
		return fmt.Errorf("malware.max_concurrent_scans must not be negative")
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
	if c.ImageScan.Enabled && c.ImageScan.TrivyServer == "" {
		return fmt.Errorf("image_scan.enabled is true but trivy_server is empty")
	}
	if c.ImageScan.MaxLayerBytes < 0 {
		return fmt.Errorf("image_scan.max_layer_bytes must not be negative")
	}
	if c.Cache.Revalidation.CVETTLMinutes < 0 {
		return fmt.Errorf("cache.revalidation.cve_ttl_minutes must not be negative")
	}
	if c.Cache.Revalidation.MalwareTTLMinutes < 0 {
		return fmt.Errorf("cache.revalidation.malware_ttl_minutes must not be negative")
	}
	if c.Cache.Local.StaleAfterDays < 0 {
		return fmt.Errorf("cache.local.stale_after_days must not be negative")
	}
	return nil
}

type ServerConfig struct {
	Listen string `mapstructure:"listen"`
	// UpstreamMaxConcurrent caps the number of concurrent in-flight requests to
	// each upstream registry host, across metadata fetches, transparent proxying
	// and artifact downloads. It keeps parallel dependency resolution (Gradle,
	// Maven, npm) under the registry's rate limit so it does not return HTTP 429.
	// Zero or negative selects the default (DefaultUpstreamMaxConcurrent).
	UpstreamMaxConcurrent int `mapstructure:"upstream_max_concurrent"`
	// UpstreamRatePerSecond caps the request *rate* to each upstream registry
	// host (token bucket). Registries throttle by rate, not concurrency, so this
	// is the primary 429 defense; the concurrency cap is complementary. The burst
	// allowance is twice this value. Zero or negative selects the default
	// (DefaultUpstreamRatePerSecond); set a large value to effectively disable.
	UpstreamRatePerSecond int `mapstructure:"upstream_rate_per_second"`
}

// DefaultUpstreamMaxConcurrent is the per-host outbound concurrency cap applied
// when server.upstream_max_concurrent is unset.
const DefaultUpstreamMaxConcurrent = 6

// DefaultUpstreamRatePerSecond is the per-host outbound request-rate cap applied
// when server.upstream_rate_per_second is unset.
const DefaultUpstreamRatePerSecond = 10

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
	Docker   RegistryConfig `mapstructure:"docker"`
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
	Backend      string             `mapstructure:"backend"` // local | s3
	Local        LocalCache         `mapstructure:"local"`
	S3           S3Cache            `mapstructure:"s3"`
	Revalidation RevalidationConfig `mapstructure:"revalidation"`
}

type LocalCache struct {
	Path      string `mapstructure:"path"`
	MaxSizeGB int    `mapstructure:"max_size_gb"`
	// StaleAfterDays marks entries idle this long as stale (reclaimable via
	// console cleanup). ≤0 uses the default (30) applied at wiring.
	StaleAfterDays int `mapstructure:"stale_after_days"`
}

type S3Cache struct {
	Endpoint string `mapstructure:"endpoint"`
	Bucket   string `mapstructure:"bucket"`
	Region   string `mapstructure:"region"`
}

// RevalidationConfig sets per-gate TTLs for lazy re-validation of cache hits.
// A cache hit whose CVE or malware check is older than its TTL re-runs that
// gate before serving; an entry that now fails is blocked and evicted. 0
// disables that gate's re-check. Defaults (1440 = 24h) come from viper
// defaults, so an omitted key gets the default while an explicit 0 disables.
type RevalidationConfig struct {
	CVETTLMinutes     int `mapstructure:"cve_ttl_minutes"`
	MalwareTTLMinutes int `mapstructure:"malware_ttl_minutes"`
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

// ImageScanConfig configures container-image vulnerability scanning (Trivy).
// It is separate from CVEConfig (osv.dev): a different engine and model.
type ImageScanConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	TrivyServer    string `mapstructure:"trivy_server"`    // e.g. "http://trivy:4954"
	TimeoutSeconds int    `mapstructure:"timeout_seconds"` // default 120
	Scanners       string `mapstructure:"scanners"`        // trivy --scanners value, default "vuln,secret"
	MaxLayerBytes  int64  `mapstructure:"max_layer_bytes"` // layer larger than this → fail-closed
}

// MalwareConfig configures the malware-scanning engines run after download.
type MalwareConfig struct {
	Scanners []ScannerConfig `mapstructure:"scanners"`
	// MaxConcurrentScans caps how many artifacts are scanned at once across all
	// engines. It applies backpressure so bursts don't overwhelm clamd/ICAP
	// worker pools and make scans time out. Zero uses a default (applied at
	// wiring time); a negative value is rejected.
	MaxConcurrentScans int `mapstructure:"max_concurrent_scans"`
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
// Environment variables prefixed with JOEI_ override file values: the variable
// name is the config key path with dots replaced by underscores, e.g.
// JOEI_LOGGING_LEVEL overrides logging.level and JOEI_CVE_BLOCK_ON overrides
// cve.block_on. Only keys present in the file can be overridden.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetDefault("cache.revalidation.cve_ttl_minutes", 1440)
	v.SetDefault("cache.revalidation.malware_ttl_minutes", 1440)
	v.SetConfigFile(path)
	v.SetEnvPrefix("JOEI")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
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

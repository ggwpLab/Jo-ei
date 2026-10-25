// Package config loads and validates the Jōei YAML/env configuration.
package config

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"

	"github.com/spf13/viper"
)

type Config struct {
	// UnknownEnv lists JOEI_* environment variables that set nothing (a
	// misspelt name, or one aimed at a list of objects or a map key the file
	// does not define), one problem per entry. The server refuses to start on
	// them; CLI tools only warn, so a stray variable cannot lock out recovery.
	UnknownEnv []string `mapstructure:"-"`

	Server      ServerConfig      `mapstructure:"server"`
	TLS         TLSConfig         `mapstructure:"tls"`
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
	Metrics     MetricsConfig     `mapstructure:"metrics"`
}

// Validate checks cross-field invariants after loading.
func (c *Config) Validate() error {
	regs := map[string]RegistryConfig{
		"pypi":     c.Registries.PyPI,
		"npm":      c.Registries.NPM,
		"maven":    c.Registries.Maven,
		"rubygems": c.Registries.RubyGems,
		"go":       c.Registries.Go,
		"docker":   c.Registries.Docker,
	}
	for name, rc := range regs {
		if rc.Enabled && len(rc.Upstreams) == 0 {
			return fmt.Errorf("registry %q is enabled but has no upstreams", name)
		}
	}
	for i, entry := range c.Server.TrustedProxies {
		if err := validateTrustedProxy(entry); err != nil {
			return fmt.Errorf("server.trusted_proxies[%d]: %w", i, err)
		}
	}
	switch strings.ToLower(c.Server.ClientIPHeader) {
	case "", "x-forwarded-for", "x-real-ip", "forwarded":
	default:
		return fmt.Errorf("server.client_ip_header: unknown header %q (want X-Forwarded-For|X-Real-IP|Forwarded)", c.Server.ClientIPHeader)
	}
	// Zero scanners is valid; malware scanning is simply skipped.
	scannerNames := map[string]int{}
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
		name := sc.DisplayName()
		if j, dup := scannerNames[name]; dup {
			return fmt.Errorf("malware.scanners[%d]: name %q already used by malware.scanners[%d]; set a distinct name", i, name, j)
		}
		scannerNames[name] = i
	}
	if c.Malware.MaxConcurrentScans < 0 {
		return fmt.Errorf("malware.max_concurrent_scans must not be negative")
	}
	if c.Server.MetadataFilterMaxMB < 0 {
		return fmt.Errorf("server.metadata_filter_max_mb must not be negative")
	}
	if c.Metrics.Enabled {
		if c.Metrics.Listen == "" {
			return fmt.Errorf("metrics.listen is required when metrics are enabled")
		}
		if c.Metrics.Listen == c.Server.Listen {
			return fmt.Errorf("metrics.listen must differ from server.listen (%q)", c.Server.Listen)
		}
		if !strings.HasPrefix(c.Metrics.Path, "/") {
			return fmt.Errorf("metrics.path must start with \"/\" (got %q)", c.Metrics.Path)
		}
		// ServeMux.Handle panics on method prefixes, wildcards and the like, so
		// accept only a plain path.
		if strings.ContainsAny(c.Metrics.Path, " \t\r\n{}?#") {
			return fmt.Errorf("metrics.path must be a plain URL path without spaces, braces, \"?\" or \"#\" (got %q)", c.Metrics.Path)
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
	if s := c.Console.Auth.JWTSecret; s != "" && len(s) < MinJWTSecretLen {
		return fmt.Errorf("console.auth.jwt_secret must be at least %d bytes when set, got %d", MinJWTSecretLen, len(s))
	}
	if c.Console.Auth.AccessTTLMinutes < 0 {
		return fmt.Errorf("console.auth.access_ttl_minutes must not be negative")
	}
	if c.Console.Auth.RefreshTTLHours < 0 {
		return fmt.Errorf("console.auth.refresh_ttl_hours must not be negative")
	}
	if c.Server.Listen == "" {
		return fmt.Errorf("server.listen is required")
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
	// MetadataFilterMaxMB caps the decompressed size of a registry metadata
	// document the proxy will buffer in order to hide versions policy blocks, so
	// a client's own resolver picks an allowed version instead of failing on a
	// blocked download. A document over the cap is streamed through unfiltered
	// and the artifact gate blocks it at download time instead. Zero disables
	// metadata filtering entirely; unlike UpstreamMaxConcurrent above, zero here
	// is not "unset" — the default (32) comes from Load's SetDefault, so an
	// explicit zero in YAML survives as the feature's kill switch rather than
	// being replaced.
	MetadataFilterMaxMB int `mapstructure:"metadata_filter_max_mb"`
	// ShutdownTimeoutSeconds bounds how long a stopping server drains
	// in-flight requests before closing the rest. Default 30.
	ShutdownTimeoutSeconds int `mapstructure:"shutdown_timeout_seconds"`
	// TrustedProxies lists the reverse proxies (CIDRs or bare IPs) whose
	// forwarding header is believed when resolving the client IP. Empty (the
	// default) means no header is trusted and the TCP peer address is used.
	TrustedProxies []string `mapstructure:"trusted_proxies"`
	// ClientIPHeader selects the forwarding header read from a trusted proxy:
	// X-Forwarded-For (default when empty), X-Real-IP or Forwarded.
	ClientIPHeader string `mapstructure:"client_ip_header"`
}

// DefaultUpstreamMaxConcurrent is the per-host outbound concurrency cap applied
// when server.upstream_max_concurrent is unset.
const DefaultUpstreamMaxConcurrent = 6

// DefaultUpstreamRatePerSecond is the per-host outbound request-rate cap applied
// when server.upstream_rate_per_second is unset.
const DefaultUpstreamRatePerSecond = 10

// TLSConfig configures trust for outbound connections to upstream registries.
// CAFiles lists PEM files whose certificates are added to the system root pool,
// which is what makes a mirror with a corporate or self-signed certificate
// reachable. An empty list means system roots only.
type TLSConfig struct {
	CAFiles []string `mapstructure:"ca_files"`
}

// ConsoleConfig holds admin-console settings.
type ConsoleConfig struct {
	Auth AuthConfig `mapstructure:"auth"`
}

// AuthConfig holds the console JWT session parameters. Console users live in
// the database (internal/users), not in the config.
type AuthConfig struct {
	// JWTSecret signs console session tokens (HS256). Empty means "resolve it
	// elsewhere": JOEI_CONSOLE_JWT_SECRET, then the settings store, then a
	// generated-and-persisted key. See cmd/jo-ei.
	JWTSecret string `mapstructure:"jwt_secret"`
	// AccessTTLMinutes is the access-token lifetime; zero selects the default
	// (DefaultAccessTTLMinutes).
	AccessTTLMinutes int `mapstructure:"access_ttl_minutes"`
	// RefreshTTLHours is the refresh-token lifetime; zero selects the default
	// (DefaultRefreshTTLHours).
	RefreshTTLHours int `mapstructure:"refresh_ttl_hours"`
}

// Default console session lifetimes, applied when the keys are unset. Fifteen
// minutes keeps a leaked access token short-lived; a week of refresh keeps an
// operator signed in across a working week.
const (
	DefaultAccessTTLMinutes = 15
	DefaultRefreshTTLHours  = 168
)

// MinJWTSecretLen mirrors auth.MinSecretLen. It is duplicated rather than
// imported because config imports nothing from internal/.
const MinJWTSecretLen = 32

type RegistriesConfig struct {
	PyPI     RegistryConfig `mapstructure:"pypi"`
	NPM      RegistryConfig `mapstructure:"npm"`
	Maven    RegistryConfig `mapstructure:"maven"`
	RubyGems RegistryConfig `mapstructure:"rubygems"`
	Go       RegistryConfig `mapstructure:"go"`
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
	Name           string `mapstructure:"name"`            // display name; see DisplayName
	Address        string `mapstructure:"address"`         // unix:///path | tcp:host:port
	TimeoutSeconds int    `mapstructure:"timeout_seconds"` // default 30
	Service        string `mapstructure:"service"`         // ICAP service name (icap only)
}

// DisplayName is the name the scanner is reported under in detections, logs and
// the console overview: Name when set, otherwise "icap:<service>" for ICAP and
// the bare type for everything else.
func (sc ScannerConfig) DisplayName() string {
	if n := strings.TrimSpace(sc.Name); n != "" {
		return n
	}
	if sc.Type == "icap" && sc.Service != "" {
		return "icap:" + sc.Service
	}
	return sc.Type
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

// MetricsConfig configures the Prometheus /metrics endpoint, served on its own
// listener so it is never reachable through the proxy port.
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Listen  string `mapstructure:"listen"`
	Path    string `mapstructure:"path"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// Load reads a YAML config file and returns a Config.
// Environment variables prefixed with JOEI_ override file values: the variable
// name is the config key path uppercased with dots replaced by underscores,
// e.g. JOEI_LOGGING_LEVEL sets logging.level and JOEI_CACHE_LOCAL_MAX_SIZE_GB
// sets cache.local.max_size_gb — for every scalar and string-list key, whether
// or not the file contains it (lists are comma-separated). Lists of objects
// and maps (malware.scanners, policy.profiles) can only be set in the file,
// though a field of a map entry the file defines can still be overridden.
// A non-empty JOEI_* variable that sets nothing is listed in UnknownEnv.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetDefault("cache.revalidation.cve_ttl_minutes", 1440)
	v.SetDefault("cache.revalidation.malware_ttl_minutes", 1440)
	v.SetDefault("server.listen", ":8080")
	v.SetDefault("server.metadata_filter_max_mb", 32)
	v.SetDefault("server.shutdown_timeout_seconds", 30)
	v.SetDefault("metrics.enabled", true)
	v.SetDefault("metrics.listen", ":9464")
	v.SetDefault("metrics.path", "/metrics")
	v.SetConfigFile(path)
	v.SetEnvPrefix("JOEI")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	schema := buildEnvSchema()
	if err := schema.bind(v); err != nil {
		return nil, err
	}

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	cfg.UnknownEnv = schema.unknown(v.AllKeys(), environ())
	cfg.Server.TrustedProxies = splitList(cfg.Server.TrustedProxies)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}
	return &cfg, nil
}

// splitList flattens list entries that hold several values separated by
// commas or whitespace. An environment override arrives as one string, which
// viper splits on commas only; accepting spaces too means
// JOEI_SERVER_TRUSTED_PROXIES="10.0.0.1 10.0.0.0/8" works as written.
func splitList(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, strings.FieldsFunc(e, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})...)
	}
	return out
}

// validateTrustedProxy accepts a CIDR or a bare IP address.
func validateTrustedProxy(entry string) error {
	entry = strings.TrimSpace(entry)
	if strings.Contains(entry, "/") {
		_, err := netip.ParsePrefix(entry)
		return err
	}
	_, err := netip.ParseAddr(entry)
	return err
}

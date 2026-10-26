package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
)

func TestLoad_ParsesYAML(t *testing.T) {
	yaml := `
server:
  listen: ":9090"
registries:
  pypi:
    upstreams:
      - "https://pypi.org"
      - "https://mirror.example.org/pypi"
    enabled: true
supply_chain:
  min_age_hours: 48
  mode: "enforce"
cache:
  backend: "local"
  local:
    path: "/tmp/test-cache"
    max_size_gb: 10
logging:
  level: "debug"
  format: "json"
  output: "stdout"
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`
	dir := t.TempDir()
	f := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(f, []byte(yaml), 0644))

	cfg, err := config.Load(f)
	require.NoError(t, err)

	assert.Equal(t, ":9090", cfg.Server.Listen)
	assert.Equal(t, []string{"https://pypi.org", "https://mirror.example.org/pypi"}, cfg.Registries.PyPI.Upstreams)
	assert.True(t, cfg.Registries.PyPI.Enabled)
	assert.Equal(t, 48, cfg.SupplyChain.MinAgeHours)
	assert.Equal(t, "enforce", cfg.SupplyChain.Mode)
	assert.Equal(t, "local", cfg.Cache.Backend)
	assert.Equal(t, "/tmp/test-cache", cfg.Cache.Local.Path)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestLoad_DefaultValues(t *testing.T) {
	yaml := `server:
  listen: ":8080"
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`
	dir := t.TempDir()
	f := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(f, []byte(yaml), 0644))

	cfg, err := config.Load(f)
	require.NoError(t, err)

	assert.Equal(t, ":8080", cfg.Server.Listen)
	// Unset fields should have zero values
	assert.Equal(t, "", cfg.Cache.Backend)
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	f.Close()
	return f.Name()
}

func TestLoadConfig_MalwareScannersSection(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
malware:
  scanners:
    - type: clamav
      address: "unix:///var/run/clamav/clamd.sock"
      timeout_seconds: 45
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)

	require.Len(t, cfg.Malware.Scanners, 1)
	assert.Equal(t, "clamav", cfg.Malware.Scanners[0].Type)
	assert.Equal(t, "unix:///var/run/clamav/clamd.sock", cfg.Malware.Scanners[0].Address)
	assert.Equal(t, 45, cfg.Malware.Scanners[0].TimeoutSeconds)
}

func TestLoad_ParsesMavenUpstreamsList(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  maven:
    enabled: true
    upstreams:
      - "https://repo1.maven.org/maven2"
      - "https://repo.spring.io/release"
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"https://repo1.maven.org/maven2",
		"https://repo.spring.io/release",
	}, cfg.Registries.Maven.Upstreams)
}

func TestLoad_EnabledRegistryWithoutUpstreamsFails(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  npm:
    enabled: true
    upstreams: []
`)
	_, err := config.Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "npm")
}

func TestLoad_EnabledDockerWithoutUpstreamsFails(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  docker:
    enabled: true
    upstreams: []
database:
  path: "/tmp/x.db"
`)
	_, err := config.Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "docker")
}

func TestLoad_ImageScanEnabledWithoutTrivyServerFails(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
image_scan:
  enabled: true
  trivy_server: ""
database:
  path: "/tmp/x.db"
`)
	_, err := config.Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trivy_server")
}

func TestLoad_ImageScanNegativeMaxLayerBytesFails(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
image_scan:
  enabled: true
  trivy_server: "http://trivy:4954"
  max_layer_bytes: -1
database:
  path: "/tmp/x.db"
`)
	_, err := config.Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_layer_bytes")
}

func TestLoad_DisabledRegistryWithoutUpstreamsOK(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  npm:
    enabled: false
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`)
	_, err := config.Load(path)
	require.NoError(t, err)
}

func TestLoad_ParsesRubyGemsUpstreams(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  rubygems:
    enabled: true
    upstreams:
      - "https://rubygems.org"
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://rubygems.org"}, cfg.Registries.RubyGems.Upstreams)
	assert.True(t, cfg.Registries.RubyGems.Enabled)
}

func TestLoad_ParsesGoUpstreams(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  go:
    enabled: true
    upstreams:
      - "https://proxy.golang.org"
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://proxy.golang.org"}, cfg.Registries.Go.Upstreams)
	assert.True(t, cfg.Registries.Go.Enabled)
}

func TestLoad_EnabledRubyGemsWithoutUpstreamsFails(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  rubygems:
    enabled: true
    upstreams: []
`)
	_, err := config.Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rubygems")
}

func TestLoad_ParsesMalwareScanners(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
malware:
  scanners:
    - type: clamav
      address: "unix:///var/run/clamav/clamd.sock"
      timeout_seconds: 30
    - type: icap
      address: "tcp:kaspersky:1344"
      service: "avscan"
      timeout_seconds: 15
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`)

	cfg, err := config.Load(path)
	require.NoError(t, err)
	require.Len(t, cfg.Malware.Scanners, 2)
	assert.Equal(t, "clamav", cfg.Malware.Scanners[0].Type)
	assert.Equal(t, "unix:///var/run/clamav/clamd.sock", cfg.Malware.Scanners[0].Address)
	assert.Equal(t, 30, cfg.Malware.Scanners[0].TimeoutSeconds)
	assert.Equal(t, "icap", cfg.Malware.Scanners[1].Type)
	assert.Equal(t, "avscan", cfg.Malware.Scanners[1].Service)
}

func TestValidate_RejectsBadScanners(t *testing.T) {
	cases := []config.ScannerConfig{
		{Type: "", Address: "tcp:x:1"},                  // missing type
		{Type: "bogus", Address: "tcp:x:1"},             // unknown type
		{Type: "clamav", Address: ""},                   // missing address
		{Type: "icap", Address: "tcp:x:1", Service: ""}, // icap without service
	}
	for _, sc := range cases {
		c := &config.Config{Malware: config.MalwareConfig{Scanners: []config.ScannerConfig{sc}}}
		err := c.Validate()
		require.Error(t, err, "scanner %+v should be rejected", sc)
		assert.Contains(t, err.Error(), "malware.scanners[0]", "error should reference the scanner index")
	}
}

func TestValidate_AcceptsGoodScanners(t *testing.T) {
	c := &config.Config{Malware: config.MalwareConfig{Scanners: []config.ScannerConfig{
		{Type: "clamav", Address: "unix:///s.sock"},
		{Type: "icap", Address: "tcp:k:1344", Service: "avscan"},
	}}}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c.Server.Listen = ":8080"
	assert.NoError(t, c.Validate())
}

func TestValidate_RejectsNegativeHealth(t *testing.T) {
	c := &config.Config{}
	c.Health.ProbeIntervalSeconds = -1
	err := c.Validate()
	require.Error(t, err)
}

func TestValidate_RejectsNegativeSlowThreshold(t *testing.T) {
	c := &config.Config{}
	c.Health.SlowThresholdMS = -5
	err := c.Validate()
	require.Error(t, err)
}

func TestValidate_RejectsNegativeRetention(t *testing.T) {
	c := &config.Config{}
	c.Database.EventRetentionDays = -1
	require.Error(t, c.Validate())

	c2 := &config.Config{}
	c2.Database.DailyRetentionDays = -5
	require.Error(t, c2.Validate())
}

func TestValidate_RejectsNegativeMaxConcurrentScans(t *testing.T) {
	c := &config.Config{}
	c.Malware.MaxConcurrentScans = -1
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_concurrent_scans")
}

func TestValidate_RequiresDatabasePath(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = ""
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database.path")

	c.Server.Listen = ":8080"
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	assert.NoError(t, c.Validate())
}

func TestLoadConfig_CVESection(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
cve:
  enabled: true
  base_url: "https://api.osv.dev"
  block_on: "HIGH"
  cache_ttl_minutes: 1440
policy:
  active_profile: "production"
  profiles:
    production:
      cve_block: true
      cve_min_severity: "HIGH"
      supply_chain_block: true
      allowlist:
        - "pypi/requests"
      denylist:
        - "npm/evil-pkg"
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)

	assert.True(t, cfg.CVE.Enabled)
	assert.Equal(t, "https://api.osv.dev", cfg.CVE.BaseURL)
	assert.Equal(t, "HIGH", cfg.CVE.BlockOn)
	assert.Equal(t, 1440, cfg.CVE.CacheTTLMinutes)

	prod := cfg.Policy.Profiles["production"]
	assert.True(t, prod.CVEBlock)
	assert.Equal(t, "HIGH", prod.CVEMinSeverity)
	assert.Equal(t, []string{"pypi/requests"}, prod.Allowlist)
	assert.Equal(t, []string{"npm/evil-pkg"}, prod.Denylist)
}

func TestLoadDockerAndImageScan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	const body = `
server: { listen: ":8080" }
registries:
  docker:
    upstreams: ["https://registry-1.docker.io"]
    enabled: true
image_scan:
  enabled: true
  trivy_server: "http://trivy:4954"
  timeout_seconds: 90
  scanners: "vuln,secret"
  max_layer_bytes: 1048576
database: { path: "/tmp/x.db" }
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Registries.Docker.Enabled {
		t.Error("docker registry should be enabled")
	}
	if cfg.Registries.Docker.Upstreams[0] != "https://registry-1.docker.io" {
		t.Errorf("docker upstream = %q", cfg.Registries.Docker.Upstreams[0])
	}
	if !cfg.ImageScan.Enabled || cfg.ImageScan.TrivyServer != "http://trivy:4954" {
		t.Errorf("image_scan not parsed: %+v", cfg.ImageScan)
	}
	if cfg.ImageScan.TimeoutSeconds != 90 || cfg.ImageScan.Scanners != "vuln,secret" {
		t.Errorf("image_scan fields: %+v", cfg.ImageScan)
	}
	if cfg.ImageScan.MaxLayerBytes != 1048576 {
		t.Errorf("max_layer_bytes = %d", cfg.ImageScan.MaxLayerBytes)
	}
}

// loadTTLConfig writes yaml to a temp file and loads it.
func loadTTLConfig(t *testing.T, yaml string) (*config.Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(yaml), 0o600))
	return config.Load(p)
}

// ttlBaseYAML is the smallest config that passes Validate.
const ttlBaseYAML = `
database:
  path: "/tmp/joei.db"
`

func TestRevalidationTTLDefaults(t *testing.T) {
	// No revalidation section at all → both TTLs default to 1440.
	cfg, err := loadTTLConfig(t, ttlBaseYAML)
	require.NoError(t, err)
	assert.Equal(t, 1440, cfg.Cache.Revalidation.CVETTLMinutes)
	assert.Equal(t, 1440, cfg.Cache.Revalidation.MalwareTTLMinutes)
}

func TestRevalidationTTLExplicitZeroDisables(t *testing.T) {
	cfg, err := loadTTLConfig(t, ttlBaseYAML+`
cache:
  revalidation:
    cve_ttl_minutes: 0
    malware_ttl_minutes: 90
`)
	require.NoError(t, err)
	assert.Equal(t, 0, cfg.Cache.Revalidation.CVETTLMinutes)
	assert.Equal(t, 90, cfg.Cache.Revalidation.MalwareTTLMinutes)
}

func TestRevalidationTTLNegativeRejected(t *testing.T) {
	_, err := loadTTLConfig(t, ttlBaseYAML+`
cache:
  revalidation:
    cve_ttl_minutes: -1
`)
	require.ErrorContains(t, err, "cve_ttl_minutes")
}

func TestRevalidationTTLNegativeMalwareRejected(t *testing.T) {
	_, err := loadTTLConfig(t, ttlBaseYAML+`
cache:
  revalidation:
    malware_ttl_minutes: -1
`)
	require.ErrorContains(t, err, "malware_ttl_minutes")
}

func TestValidate_RejectsNegativeStaleAfterDays(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c.Cache.Local.StaleAfterDays = -1
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stale_after_days")
}

func TestLoad_EnvOverridesFileValues(t *testing.T) {
	yaml := `
server:
  listen: ":8080"
supply_chain:
  min_age_hours: 24
  mode: "enforce"
cve:
  enabled: true
  block_on: "HIGH"
logging:
  level: "info"
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`
	f := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(f, []byte(yaml), 0o644))

	// Env var name = key path, dots replaced by underscores, JOEI_ prefix.
	t.Setenv("JOEI_LOGGING_LEVEL", "debug")
	t.Setenv("JOEI_CVE_BLOCK_ON", "CRITICAL")
	t.Setenv("JOEI_SUPPLY_CHAIN_MIN_AGE_HOURS", "48")

	cfg, err := config.Load(f)
	require.NoError(t, err)
	assert.Equal(t, "debug", cfg.Logging.Level)
	assert.Equal(t, "CRITICAL", cfg.CVE.BlockOn)
	assert.Equal(t, 48, cfg.SupplyChain.MinAgeHours)
}

func TestLoad_TLSCAFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `
database:
  path: ./jo-ei.db
tls:
  ca_files:
    - /etc/jo-ei/ca/corp-root.pem
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.TLS.CAFiles) != 1 || cfg.TLS.CAFiles[0] != "/etc/jo-ei/ca/corp-root.pem" {
		t.Fatalf("TLS.CAFiles = %v, want the single configured path", cfg.TLS.CAFiles)
	}
}

func TestValidateRejectsShortJWTSecret(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c.Console.Auth.JWTSecret = "short"

	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "console.auth.jwt_secret")
}

func TestValidateAcceptsA32ByteJWTSecret(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c.Server.Listen = ":8080"
	c.Console.Auth.JWTSecret = "0123456789abcdef0123456789abcdef"
	require.NoError(t, c.Validate())
}

func TestValidateRejectsNegativeTTLs(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c.Console.Auth.AccessTTLMinutes = -1
	assert.Error(t, c.Validate())

	c2 := &config.Config{}
	c2.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c2.Console.Auth.RefreshTTLHours = -1
	assert.Error(t, c2.Validate())
}

func TestAuthTTLsParseFromYAML(t *testing.T) {
	cfg, err := loadTTLConfig(t, ttlBaseYAML+`
console:
  auth:
    access_ttl_minutes: 5
    refresh_ttl_hours: 24
`)
	require.NoError(t, err)
	assert.Equal(t, 5, cfg.Console.Auth.AccessTTLMinutes)
	assert.Equal(t, 24, cfg.Console.Auth.RefreshTTLHours)
}

func TestLoad_TLSSectionIsOptional(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("database:\n  path: ./jo-ei.db\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.TLS.CAFiles) != 0 {
		t.Fatalf("TLS.CAFiles = %v, want empty when the section is absent", cfg.TLS.CAFiles)
	}
}

func TestLoad_MetadataFilterMaxMB_DefaultsTo256(t *testing.T) {
	path := writeTempConfig(t, `server:
  listen: ":8080"
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, 256, cfg.Server.MetadataFilterMaxMB)
}

func TestLoad_MetadataFilterMaxMB_ZeroMeansNoCap(t *testing.T) {
	path := writeTempConfig(t, `server:
  listen: ":8080"
  metadata_filter_max_mb: 0
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, 0, cfg.Server.MetadataFilterMaxMB, "an explicit zero means no cap, not a request for the default")
}

func TestValidate_RejectsNegativeMetadataFilterMaxMB(t *testing.T) {
	c := &config.Config{}
	c.Server.MetadataFilterMaxMB = -1
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata_filter_max_mb")
}

func TestLoad_MetricsDefaults(t *testing.T) {
	path := writeTempConfig(t, `server:
  listen: ":8080"
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.True(t, cfg.Metrics.Enabled)
	assert.Equal(t, ":9464", cfg.Metrics.Listen)
	assert.Equal(t, "/metrics", cfg.Metrics.Path)
}

func TestLoad_MetricsEnvOverride(t *testing.T) {
	path := writeTempConfig(t, `server:
  listen: ":8080"
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`)
	t.Setenv("JOEI_METRICS_LISTEN", "127.0.0.1:9999")
	t.Setenv("JOEI_METRICS_ENABLED", "false")
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:9999", cfg.Metrics.Listen)
	assert.False(t, cfg.Metrics.Enabled)
}

func TestValidate_MetricsListenEqualsServer(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c.Server.Listen = ":8080"
	c.Metrics = config.MetricsConfig{Enabled: true, Listen: ":8080", Path: "/metrics"}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metrics.listen")
}

func TestValidate_MetricsPathMustStartWithSlash(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c.Server.Listen = ":8080"
	c.Metrics = config.MetricsConfig{Enabled: true, Listen: ":9464", Path: "metrics"}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metrics.path")
}

func TestValidate_MetricsDisabledSkipsChecks(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c.Server.Listen = ":8080"
	c.Metrics = config.MetricsConfig{Enabled: false, Listen: ":8080", Path: "metrics"}
	require.NoError(t, c.Validate())
}

func TestValidate_MetricsPathRejectsNonPlainPaths(t *testing.T) {
	for _, p := range []string{"GET /metrics", "/met rics", "/{x}", "/m?x=1", "/m#frag", "/a\tb"} {
		c := &config.Config{}
		c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
		c.Server.Listen = ":8080"
		c.Metrics = config.MetricsConfig{Enabled: true, Listen: ":9464", Path: p}
		err := c.Validate()
		require.Error(t, err, "path %q", p)
		assert.Contains(t, err.Error(), "metrics.path")
	}
}

func TestValidate_MetricsPathAcceptsPlainPath(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c.Server.Listen = ":8080"
	c.Metrics = config.MetricsConfig{Enabled: true, Listen: ":9464", Path: "/internal/metrics"}
	require.NoError(t, c.Validate())
}

func TestValidate_RejectsEmptyServerListen(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server.listen")
}

func TestLoad_ServerListenDefault(t *testing.T) {
	path := writeTempConfig(t, `database:
  path: "/var/lib/jo-ei/jo-ei.db"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, ":8080", cfg.Server.Listen)
}

func TestScannerConfig_DisplayName(t *testing.T) {
	cases := []struct {
		sc   config.ScannerConfig
		want string
	}{
		{config.ScannerConfig{Type: "clamav"}, "clamav"},
		{config.ScannerConfig{Type: "icap", Service: "avscan"}, "icap:avscan"},
		{config.ScannerConfig{Type: "icap", Service: "avscan", Name: "kaspersky"}, "kaspersky"},
		{config.ScannerConfig{Type: "clamav", Name: "  "}, "clamav"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.sc.DisplayName(), "%+v", tc.sc)
	}
}

func TestValidate_RejectsDuplicateScannerNames(t *testing.T) {
	c := &config.Config{Malware: config.MalwareConfig{Scanners: []config.ScannerConfig{
		{Type: "icap", Address: "tcp:a:1344", Service: "avscan"},
		{Type: "icap", Address: "tcp:b:1344", Service: "avscan"},
	}}}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c.Server.Listen = ":8080"
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malware.scanners[1]")
	assert.Contains(t, err.Error(), "icap:avscan")
}

func TestValidate_TrustedProxies(t *testing.T) {
	c := &config.Config{}
	c.Server.Listen = ":8080"
	c.Database.Path = "x.db"
	c.Server.TrustedProxies = []string{"10.0.0.0/8", "192.0.2.1"}
	assert.NoError(t, c.Validate())

	c.Server.TrustedProxies = []string{"10.0.0.0/33"}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server.trusted_proxies[0]")

	c = &config.Config{}
	c.Server.Listen = ":8080"
	c.Database.Path = "x.db"
	c.Server.ClientIPHeader = "X-Foo"
	err = c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server.client_ip_header")
}

func TestConfig_ShutdownTimeoutDefault(t *testing.T) {
	cfg, err := config.Load(writeTempConfig(t, "server:\n  listen: \":8080\"\ndatabase:\n  path: \"/tmp/x.db\"\n"))
	require.NoError(t, err)
	assert.Equal(t, 30, cfg.Server.ShutdownTimeoutSeconds)
}

// viper overrides only keys the file contains, so the shipped config must
// carry server.trusted_proxies for JOEI_SERVER_TRUSTED_PROXIES to work — the
// setting a reverse-proxy deployment needs.
func TestShippedConfig_HasTrustedProxiesKey(t *testing.T) {
	for _, env := range []string{"10.0.0.1 10.0.0.0/8", "10.0.0.1,10.0.0.0/8", " 10.0.0.1 , 10.0.0.0/8 "} {
		t.Setenv("JOEI_SERVER_TRUSTED_PROXIES", env)
		cfg, err := config.Load(filepath.Join("..", "..", "config.yaml"))
		require.NoError(t, err, env)
		assert.Equal(t, []string{"10.0.0.1", "10.0.0.0/8"}, cfg.Server.TrustedProxies, env)
	}
}

const minimalYAML = "server:\n  listen: \":8080\"\ndatabase:\n  path: \"/tmp/x.db\"\n"

// Every scalar or string-list key can be set from the environment, whether or
// not the file mentions it.
func TestLoad_EnvSetsKeysAbsentFromFile(t *testing.T) {
	t.Setenv("JOEI_CACHE_LOCAL_MAX_SIZE_GB", "7")
	t.Setenv("JOEI_SERVER_SHUTDOWN_TIMEOUT_SECONDS", "5")
	t.Setenv("JOEI_METRICS_ENABLED", "false")
	t.Setenv("JOEI_REGISTRIES_PYPI_UPSTREAMS", "https://a.example,https://b.example")
	t.Setenv("JOEI_REGISTRIES_PYPI_ENABLED", "true")
	t.Setenv("JOEI_CVE_BLOCK_ON", "CRITICAL")

	cfg, err := config.Load(writeTempConfig(t, minimalYAML))
	require.NoError(t, err)

	assert.Equal(t, 7, cfg.Cache.Local.MaxSizeGB)
	assert.Equal(t, 5, cfg.Server.ShutdownTimeoutSeconds)
	assert.False(t, cfg.Metrics.Enabled)
	assert.Equal(t, []string{"https://a.example", "https://b.example"}, cfg.Registries.PyPI.Upstreams)
	assert.True(t, cfg.Registries.PyPI.Enabled)
	assert.Equal(t, "CRITICAL", cfg.CVE.BlockOn)
}

// A misspelt variable is reported, not silently ignored. Load itself does
// not fail — the server refuses to start on it, the CLI tools only warn — so
// a stray variable cannot lock out reset-admin-password.
func TestLoad_UnknownEnvReported(t *testing.T) {
	t.Setenv("JOEI_CACHE_LOCAL_MAX_SIZE_G", "1")
	cfg, err := config.Load(writeTempConfig(t, minimalYAML))
	require.NoError(t, err)
	require.Len(t, cfg.UnknownEnv, 1)
	assert.Contains(t, cfg.UnknownEnv[0], "JOEI_CACHE_LOCAL_MAX_SIZE_G")
}

// A variable aimed at a list of objects or a map key the file does not have
// cannot be applied; say so.
func TestLoad_EnvForObjectListOrMapReported(t *testing.T) {
	for _, name := range []string{"JOEI_MALWARE_SCANNERS_0_TYPE", "JOEI_POLICY_PROFILES_PRODUCTION_CVE_BLOCK"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "x")
			cfg, err := config.Load(writeTempConfig(t, minimalYAML))
			require.NoError(t, err)
			require.Len(t, cfg.UnknownEnv, 1)
			assert.Contains(t, cfg.UnknownEnv[0], name)
			assert.Contains(t, cfg.UnknownEnv[0], "config file")
		})
	}
}

// Overriding a field of a profile the file defines worked before and must keep
// working: the key exists once the file is read.
func TestLoad_EnvOverridesExistingProfileField(t *testing.T) {
	yaml := minimalYAML + "policy:\n  active_profile: dev\n  profiles:\n    dev:\n      cve_block: true\n"
	t.Setenv("JOEI_POLICY_PROFILES_DEV_CVE_BLOCK", "false")
	cfg, err := config.Load(writeTempConfig(t, yaml))
	require.NoError(t, err)
	assert.Empty(t, cfg.UnknownEnv)
	assert.False(t, cfg.Policy.Profiles["dev"].CVEBlock)
}

// Compose .env templates leave variables empty; an empty value sets nothing
// and is not reported, as viper itself ignores it.
func TestLoad_EmptyUnknownEnvIgnored(t *testing.T) {
	t.Setenv("JOEI_NO_SUCH_SETTING", "")
	cfg, err := config.Load(writeTempConfig(t, minimalYAML))
	require.NoError(t, err)
	assert.Empty(t, cfg.UnknownEnv)
}

// Variables read directly by the code, and the service links Kubernetes
// injects for a Service named "joei", are not configuration keys.
func TestLoad_NonKeyEnvAllowed(t *testing.T) {
	for _, name := range []string{
		"JOEI_CONSOLE_JWT_SECRET",
		"JOEI_SERVICE_HOST", "JOEI_SERVICE_PORT", "JOEI_SERVICE_PORT_HTTP", "JOEI_PORT", "JOEI_PORT_8080_TCP_ADDR",
		// Services named joei-metrics, joei-trivy, or a release "joei" of chart "jo-ei".
		"JOEI_METRICS_SERVICE_HOST", "JOEI_METRICS_PORT", "JOEI_METRICS_PORT_9464_TCP", "JOEI_TRIVY_SERVICE_PORT",
		"JOEI_JO_EI_SERVICE_HOST", "JOEI_JO_EI_PORT_8080_TCP_PROTO",
	} {
		t.Setenv(name, "x")
	}
	cfg, err := config.Load(writeTempConfig(t, minimalYAML))
	require.NoError(t, err)
	assert.Empty(t, cfg.UnknownEnv)
}

func TestConfig_MaxArtifactDefault(t *testing.T) {
	cfg, err := config.Load(writeTempConfig(t, minimalYAML))
	require.NoError(t, err)
	assert.Equal(t, 2048, cfg.Server.MaxArtifactMB)
}

func TestConfig_MaxArtifactNegativeRejected(t *testing.T) {
	_, err := config.Load(writeTempConfig(t, "server:\n  listen: \":8080\"\n  max_artifact_mb: -1\ndatabase:\n  path: \"/tmp/x.db\"\n"))
	require.Error(t, err)
}

// The CVE engines report health under these names; an antivirus scanner
// sharing one would shadow that engine's row in the console and in
// jo_ei_scanner_up.
func TestValidate_RejectsScannerNamesOfCVEEngines(t *testing.T) {
	for _, name := range []string{"osv", "osv.dev", "trivy", " Trivy "} {
		c := &config.Config{Malware: config.MalwareConfig{Scanners: []config.ScannerConfig{
			{Type: "clamav", Address: "tcp:a:3310", Name: name},
		}}}
		c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
		c.Server.Listen = ":8080"
		err := c.Validate()
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "malware.scanners[0]", name)
	}
}

func TestLoad_PublicURLFromEnv(t *testing.T) {
	t.Setenv("JOEI_SERVER_PUBLIC_URL", "https://reg.example.com/joei")
	cfg, err := config.Load(writeTempConfig(t, minimalYAML))
	require.NoError(t, err)
	assert.Equal(t, "https://reg.example.com/joei", cfg.Server.PublicURL)
	assert.Empty(t, cfg.UnknownEnv)
}

func TestValidate_PublicURL(t *testing.T) {
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"", true},
		{"https://reg.example.com", true},
		{"http://x/y/", true},
		{"ftp://x", false},
		{"https://x?q=1", false},
		{"/relative", false},
	} {
		c := &config.Config{}
		c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
		c.Server.Listen = ":8080"
		c.Server.PublicURL = tc.url
		err := c.Validate()
		if tc.ok {
			assert.NoError(t, err, tc.url)
		} else {
			require.Error(t, err, tc.url)
			assert.Contains(t, err.Error(), "server.public_url", tc.url)
		}
	}
}

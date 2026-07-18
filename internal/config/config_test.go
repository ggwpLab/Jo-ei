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
	assert.NoError(t, c.Validate())
}

func TestLoadConsoleAuthUsers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
console:
  auth:
    users:
      - username: admin
        password_hash: "$2a$10$abcdefghijklmnopqrstuv"
      - username: alice
        password_hash: "$2a$10$zyxwvutsrqponmlkjihgfe"
database:
  path: "/var/lib/jo-ei/jo-ei.db"
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	require.NoError(t, err)
	require.Len(t, cfg.Console.Auth.Users, 2)
	assert.Equal(t, "admin", cfg.Console.Auth.Users[0].Username)
	assert.Equal(t, "$2a$10$abcdefghijklmnopqrstuv", cfg.Console.Auth.Users[0].PasswordHash)
	assert.Equal(t, "alice", cfg.Console.Auth.Users[1].Username)
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

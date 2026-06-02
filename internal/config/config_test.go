package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestLoad_DisabledRegistryWithoutUpstreamsOK(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  npm:
    enabled: false
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

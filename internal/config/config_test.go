package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ParsesYAML(t *testing.T) {
	yaml := `
server:
  listen: ":9090"
registries:
  pypi:
    upstream: "https://pypi.org"
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
	assert.Equal(t, "https://pypi.org", cfg.Registries.PyPI.Upstream)
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

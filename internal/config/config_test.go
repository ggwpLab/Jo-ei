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

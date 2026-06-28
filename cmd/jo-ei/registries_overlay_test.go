package main

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

func newOverlayStore(t *testing.T) *settings.Store {
	t.Helper()
	sdb, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sdb.Close() })
	st, err := settings.New(sdb)
	require.NoError(t, err)
	return st
}

func seedCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Registries.PyPI = config.RegistryConfig{Enabled: true, Upstreams: []string{"https://pypi.org/simple"}}
	cfg.Registries.NPM = config.RegistryConfig{Enabled: false, Upstreams: []string{}}
	cfg.Registries.Maven = config.RegistryConfig{Enabled: false, Upstreams: []string{}}
	cfg.Registries.RubyGems = config.RegistryConfig{Enabled: false, Upstreams: []string{}}
	cfg.Registries.Docker = config.RegistryConfig{Enabled: false, Upstreams: []string{}}
	return cfg
}

// (a) seed-on-empty: empty store → applyStoredRegistries writes the "registries"
// key seeded from cfg.
func TestApplyStoredRegistries_SeedsEmptyStore(t *testing.T) {
	st := newOverlayStore(t)
	cfg := seedCfg()

	err := applyStoredRegistries(cfg, st)
	require.NoError(t, err)

	_, ok, err := st.Get("registries")
	require.NoError(t, err)
	assert.True(t, ok, "applyStoredRegistries must write 'registries' key on first boot")
}

// (b) overlay: pre-Put all 5 ecos with distinct values → applyStoredRegistries
// mutates cfg to match every ecosystem field.
func TestApplyStoredRegistries_OverlaysAllFiveEcos(t *testing.T) {
	st := newOverlayStore(t)

	stored := []console.RegistryInfo{
		{Ecosystem: "pypi", Enabled: true, Upstreams: []string{"https://pypi.org/simple"}},
		{Ecosystem: "npm", Enabled: true, Upstreams: []string{"https://registry.npmjs.org"}},
		{Ecosystem: "maven", Enabled: true, Upstreams: []string{"https://repo1.maven.org/maven2"}},
		{Ecosystem: "rubygems", Enabled: true, Upstreams: []string{"https://rubygems.org"}},
		{Ecosystem: "docker", Enabled: true, Upstreams: []string{"https://registry-1.docker.io"}},
	}
	b, err := json.Marshal(stored)
	require.NoError(t, err)
	require.NoError(t, st.Put("registries", b))

	cfg := seedCfg() // starts with only PyPI enabled, rest disabled
	require.NoError(t, applyStoredRegistries(cfg, st))

	assert.True(t, cfg.Registries.PyPI.Enabled)
	assert.Equal(t, []string{"https://pypi.org/simple"}, cfg.Registries.PyPI.Upstreams)

	assert.True(t, cfg.Registries.NPM.Enabled)
	assert.Equal(t, []string{"https://registry.npmjs.org"}, cfg.Registries.NPM.Upstreams)

	assert.True(t, cfg.Registries.Maven.Enabled)
	assert.Equal(t, []string{"https://repo1.maven.org/maven2"}, cfg.Registries.Maven.Upstreams)

	assert.True(t, cfg.Registries.RubyGems.Enabled)
	assert.Equal(t, []string{"https://rubygems.org"}, cfg.Registries.RubyGems.Upstreams)

	assert.True(t, cfg.Registries.Docker.Enabled)
	assert.Equal(t, []string{"https://registry-1.docker.io"}, cfg.Registries.Docker.Upstreams)
}

// (c) corrupt value fails fast: Put "registries" = invalid JSON →
// applyStoredRegistries returns an error.
func TestApplyStoredRegistries_CorruptValueFailsFast(t *testing.T) {
	st := newOverlayStore(t)
	require.NoError(t, st.Put("registries", []byte("{not json")))

	cfg := seedCfg()
	err := applyStoredRegistries(cfg, st)
	assert.Error(t, err, "corrupt stored value must return an error")
}

// (d) unknown ecosystem in stored blob → applyStoredRegistries returns an error.
func TestApplyStoredRegistries_UnknownEcoFailsFast(t *testing.T) {
	st := newOverlayStore(t)

	unknown := []console.RegistryInfo{
		{Ecosystem: "cargo", Enabled: false, Upstreams: []string{}},
	}
	b, err := json.Marshal(unknown)
	require.NoError(t, err)
	require.NoError(t, st.Put("registries", b))

	cfg := seedCfg()
	err = applyStoredRegistries(cfg, st)
	assert.Error(t, err, "unknown ecosystem must return an error")
	assert.Contains(t, err.Error(), "cargo")
}

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
)

func TestBuildTelemetryStore_FailsOnUnopenablePath(t *testing.T) {
	// Parent of the db path is a regular file, so MkdirAll fails → fail fast.
	f := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o644))
	cfg := &config.Config{}
	cfg.Database.Path = filepath.Join(f, "sub", "jo-ei.db")
	_, err := buildTelemetryStore(cfg, zerolog.Nop())
	require.Error(t, err)
}

func TestBuildHandlers_YarnAliasesNPM(t *testing.T) {
	cfg := &config.Config{}
	cfg.Registries.NPM.Enabled = true
	cfg.Registries.NPM.Upstreams = []string{"https://registry.npmjs.org"}

	h := buildHandlers(cfg, sharedDeps{logger: zerolog.Nop()})

	assert.Contains(t, h, "npm")
	assert.Contains(t, h, "yarn")
	assert.Same(t, h["npm"], h["yarn"]) // same handler object
}

func TestBuildHandlers_RubyGemsRegisteredWhenEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Registries.RubyGems.Enabled = true
	cfg.Registries.RubyGems.Upstreams = []string{"https://rubygems.org"}

	h := buildHandlers(cfg, sharedDeps{logger: zerolog.Nop()})

	assert.Contains(t, h, "rubygems")
	assert.NotContains(t, h, "npm")
	assert.NotContains(t, h, "yarn")
}

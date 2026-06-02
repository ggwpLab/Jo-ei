package main

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/ggwpLab/Jo-ei/internal/config"
)

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

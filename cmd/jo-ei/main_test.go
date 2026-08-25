package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/storage/storagetest"
)

func TestBuildTelemetryStore_FailsOnUnopenablePath(t *testing.T) {
	// Parent of the db path is a regular file, so MkdirAll fails → fail fast.
	// storage.Open is now the entry point that rejects the bad path.
	f := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o644))
	badPath := filepath.Join(f, "sub", "jo-ei.db")
	_, err := storage.Open(badPath)
	require.Error(t, err)
}

func TestBuildTelemetryStore_SucceedsOnValidPath(t *testing.T) {
	dir := storagetest.TempDir(t)
	cfg := &config.Config{}
	cfg.Database.Path = filepath.Join(dir, "jo-ei.db")
	sdb, err := storage.Open(cfg.Database.Path)
	require.NoError(t, err)
	defer func() { _ = sdb.Close() }()
	store, err := buildTelemetryStore(sdb, cfg, zerolog.Nop())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()
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

// A CA file that cannot be parsed must stop startup with a message naming it,
// not surface later as an opaque x509 failure on the first artifact fetch.
func TestRunProxy_FailsFastOnUnusableCAFile(t *testing.T) {
	dir := t.TempDir()
	badCA := filepath.Join(dir, "not-a-cert.pem")
	if err := os.WriteFile(badCA, []byte("definitely not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}

	slash := filepath.ToSlash
	body := "" +
		"database:\n  path: " + slash(filepath.Join(dir, "jo-ei.db")) + "\n" +
		"cache:\n  backend: local\n  local:\n    path: " + slash(filepath.Join(dir, "cache")) + "\n" +
		"policy:\n  active_profile: default\n  profiles:\n    default:\n      cve_block: false\n" +
		"tls:\n  ca_files:\n    - " + slash(badCA) + "\n"
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	old := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = old })

	err := runProxy(nil, nil)
	if err == nil {
		t.Fatal("startup succeeded with an unusable CA file")
	}
	if !strings.Contains(err.Error(), "not-a-cert.pem") {
		t.Fatalf("err = %v, want it to name the offending CA file", err)
	}
}

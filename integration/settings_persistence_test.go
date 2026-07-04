//go:build integration

package integration_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

// policyStore mirrors cmd/jo-ei's policySettingsStore (unexported there).
type policyStore struct{ s *settings.Store }

func (p policyStore) LoadPolicy() (policy.RuntimeParams, bool, error) {
	b, ok, err := p.s.Get("policy")
	if err != nil || !ok {
		return policy.RuntimeParams{}, ok, err
	}
	rp, derr := policy.DecodeStored(b)
	return rp, true, derr
}

func (p policyStore) SavePolicy(rp policy.RuntimeParams) error {
	b, err := policy.EncodeStored(rp)
	if err != nil {
		return err
	}
	return p.s.Put("policy", b)
}

func scCfg() config.SupplyChainConfig {
	return config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24}
}
func cveCfg() config.CVEConfig { return config.CVEConfig{Enabled: true, BlockOn: "CRITICAL"} }

func TestPolicyPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jo-ei.db")

	// First process: seed from YAML, then apply an edit.
	{
		db, err := storage.Open(path)
		require.NoError(t, err)
		st, err := settings.New(db)
		require.NoError(t, err)
		r, err := policy.NewRuntimeWithStore(scCfg(), cveCfg(), config.PolicyProfile{CVEBlock: true}, nil, policyStore{st})
		require.NoError(t, err)

		p := r.Current()
		p.Mode = "dry_run"
		p.MinAgeHours = 0
		require.NoError(t, r.Apply(p))

		// Simulate a pre-split row: single "allowlist" key.
		require.NoError(t, st.Put("policy", []byte(`{"mode":"dry_run","min_age_hours":0,"cve_block_on":"CRITICAL","allowlist":["pypi/requests@2.31.0"],"denylist":[]}`)))
		require.NoError(t, db.Close())
	}

	// Second process: reopen — the edit (not the YAML default) is installed.
	db, err := storage.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	st, err := settings.New(db)
	require.NoError(t, err)
	r, err := policy.NewRuntimeWithStore(scCfg(), cveCfg(), config.PolicyProfile{CVEBlock: true}, nil, policyStore{st})
	require.NoError(t, err)

	assert.Equal(t, "dry_run", r.Current().Mode, "edited mode restored from DB, not YAML")
	assert.Equal(t, 0, r.Current().MinAgeHours)
	assert.Equal(t, []string{"pypi/requests@2.31.0"}, r.Current().AllowlistSupply, "legacy allowlist migrated to supply list")
	assert.Equal(t, []string{"pypi/requests@2.31.0"}, r.Current().AllowlistCVE, "legacy allowlist migrated to cve list")
}

func TestRegistriesPersistAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jo-ei.db")
	edited := []console.RegistryInfo{
		{Ecosystem: "pypi", Enabled: true, Upstreams: []string{"https://pypi.org/simple"}},
		{Ecosystem: "npm", Enabled: true, Upstreams: []string{"https://registry.npmjs.org"}},
		{Ecosystem: "maven", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "rubygems", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "docker", Enabled: false, Upstreams: []string{}},
	}

	// First process: persist an edited registry set.
	{
		db, err := storage.Open(path)
		require.NoError(t, err)
		st, err := settings.New(db)
		require.NoError(t, err)
		b, err := json.Marshal(edited)
		require.NoError(t, err)
		require.NoError(t, st.Put("registries", b))
		require.NoError(t, db.Close())
	}

	// Second process: reopen and overlay onto a fresh (npm-disabled) config.
	db, err := storage.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	st, err := settings.New(db)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.Registries.PyPI = config.RegistryConfig{Enabled: true, Upstreams: []string{"https://pypi.org/simple"}}
	b, ok, err := st.Get("registries")
	require.NoError(t, err)
	require.True(t, ok)
	var stored []console.RegistryInfo
	require.NoError(t, json.Unmarshal(b, &stored))
	for _, ri := range stored {
		if ri.Ecosystem == "npm" {
			cfg.Registries.NPM = config.RegistryConfig{Enabled: ri.Enabled, Upstreams: ri.Upstreams}
		}
	}
	assert.True(t, cfg.Registries.NPM.Enabled, "npm edit restored from DB")
	assert.Equal(t, []string{"https://registry.npmjs.org"}, cfg.Registries.NPM.Upstreams)
}

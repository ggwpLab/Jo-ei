package main

import (
	"encoding/json"
	"fmt"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/settings"
)

// policySettingsStore adapts *settings.Store to policy.SettingsStore, storing
// the runtime policy params as JSON under the "policy" key.
type policySettingsStore struct{ s *settings.Store }

func (p policySettingsStore) LoadPolicy() (policy.RuntimeParams, bool, error) {
	b, ok, err := p.s.Get("policy")
	if err != nil || !ok {
		return policy.RuntimeParams{}, ok, err
	}
	rp, err := policy.DecodeStored(b)
	if err != nil {
		return policy.RuntimeParams{}, false, fmt.Errorf("decoding stored policy: %w", err)
	}
	return rp, true, nil
}

func (p policySettingsStore) SavePolicy(rp policy.RuntimeParams) error {
	b, err := policy.EncodeStored(rp)
	if err != nil {
		return err
	}
	return p.s.Put("policy", b)
}

// registrySettingsStore adapts *settings.Store to console.RegistryStore, storing
// the registry set as JSON under the "registries" key.
type registrySettingsStore struct{ s *settings.Store }

func (r registrySettingsStore) LoadRegistries() ([]console.RegistryInfo, bool, error) {
	b, ok, err := r.s.Get("registries")
	if err != nil || !ok {
		return nil, ok, err
	}
	var regs []console.RegistryInfo
	if err := json.Unmarshal(b, &regs); err != nil {
		return nil, false, fmt.Errorf("decoding stored registries: %w", err)
	}
	return regs, true, nil
}

func (r registrySettingsStore) SaveRegistries(in []console.RegistryInfo) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return r.s.Put("registries", b)
}

// applyStoredRegistries overlays persisted registry settings onto cfg before the
// proxy mux is built (DB wins), or seeds the store from the YAML config on first
// boot. A corrupt stored value fails fast rather than silently using YAML.
func applyStoredRegistries(cfg *config.Config, st *settings.Store) error {
	stored, ok, err := registrySettingsStore{s: st}.LoadRegistries()
	if err != nil {
		return err
	}
	if !ok {
		seed, err := json.Marshal(registryInfo(cfg))
		if err != nil {
			return err
		}
		return st.Put("registries", seed)
	}
	for _, ri := range stored {
		rc := config.RegistryConfig{Enabled: ri.Enabled, Upstreams: ri.Upstreams}
		switch ri.Ecosystem {
		case "pypi":
			cfg.Registries.PyPI = rc
		case "npm":
			cfg.Registries.NPM = rc
		case "maven":
			cfg.Registries.Maven = rc
		case "rubygems":
			cfg.Registries.RubyGems = rc
		case "go":
			cfg.Registries.Go = rc
		case "docker":
			cfg.Registries.Docker = rc
		default:
			return fmt.Errorf("unknown ecosystem %q in stored registries", ri.Ecosystem)
		}
	}
	return nil
}

// registryInfo flattens the registry config for GET /api/registries.
func registryInfo(cfg *config.Config) []console.RegistryInfo {
	return []console.RegistryInfo{
		{Ecosystem: "pypi", Enabled: cfg.Registries.PyPI.Enabled, Upstreams: cfg.Registries.PyPI.Upstreams},
		{Ecosystem: "npm", Enabled: cfg.Registries.NPM.Enabled, Upstreams: cfg.Registries.NPM.Upstreams},
		{Ecosystem: "maven", Enabled: cfg.Registries.Maven.Enabled, Upstreams: cfg.Registries.Maven.Upstreams},
		{Ecosystem: "rubygems", Enabled: cfg.Registries.RubyGems.Enabled, Upstreams: cfg.Registries.RubyGems.Upstreams},
		{Ecosystem: "go", Enabled: cfg.Registries.Go.Enabled, Upstreams: cfg.Registries.Go.Upstreams},
		{Ecosystem: "docker", Enabled: cfg.Registries.Docker.Enabled, Upstreams: cfg.Registries.Docker.Upstreams},
	}
}

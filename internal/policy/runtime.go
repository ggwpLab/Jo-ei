package policy

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

// RuntimeParams are the console-editable policy knobs (PUT /api/policy).
// Allowlists are per-gate: supply entries bypass only the min-age hold, cve
// entries bypass only the CVE block. Nothing bypasses the malware gate.
type RuntimeParams struct {
	Mode            string   `json:"mode"`             // supply-chain mode: enforce | dry_run | off
	MinAgeHours     int      `json:"min_age_hours"`    // supply-chain minimum age, >= 0
	CVEBlockOn      string   `json:"cve_block_on"`     // CRITICAL | HIGH | MEDIUM | LOW
	AllowlistSupply []string `json:"allowlist_supply"` // "eco/name[@version]", bypasses the age hold
	AllowlistCVE    []string `json:"allowlist_cve"`    // "eco/name[@version]", bypasses the CVE block
	Denylist        []string `json:"denylist"`
}

// ValidationError names the parameter that failed validation.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type runtimeSnapshot struct {
	engine *Engine
	filter *supplychain.Filter
	params RuntimeParams
}

// Runtime holds the current policy Engine and supply-chain Filter behind an
// atomic pointer so the console can swap both without restart. It implements
// gate.PolicyDecider and gate.SCFilter. Edits are runtime-only: the YAML
// config wins again after a restart.
type Runtime struct {
	cur       atomic.Pointer[runtimeSnapshot]
	cveCfg    config.CVEConfig
	profile   config.PolicyProfile
	fileAllow []string      // supply_chain.allowlist_path entries, immutable
	store     SettingsStore // nil = runtime-only (no persistence)
}

// SettingsStore persists the runtime policy params. Implemented in cmd/jo-ei by
// an adapter over *settings.Store that marshals RuntimeParams to/from JSON.
type SettingsStore interface {
	LoadPolicy() (RuntimeParams, bool, error)
	SavePolicy(RuntimeParams) error
}

// PersistError wraps a failure to write the policy to the settings store. It is
// distinct from ValidationError so the console can map it to HTTP 500.
type PersistError struct{ Err error }

func (e *PersistError) Error() string { return "persisting policy: " + e.Err.Error() }
func (e *PersistError) Unwrap() error { return e.Err }

// NewRuntime builds the boot snapshot from config. fileAllow entries are
// always honored by the supply-chain filter regardless of runtime edits.
//
// The YAML profile allowlist historically bypassed CVE and age checks, so it
// seeds BOTH per-gate lists. Runtime edits manage the two lists independently.
func NewRuntime(sc config.SupplyChainConfig, cve config.CVEConfig, profile config.PolicyProfile, fileAllow []string) *Runtime {
	r, seed := newRuntimeSeed(sc, cve, profile, fileAllow)
	r.install(seed)
	return r
}

// NewRuntimeWithStore seeds the store from YAML on first boot (empty store) or
// installs the stored params otherwise (DB wins). A nil store behaves like
// NewRuntime.
func NewRuntimeWithStore(sc config.SupplyChainConfig, cve config.CVEConfig, profile config.PolicyProfile, fileAllow []string, store SettingsStore) (*Runtime, error) {
	r, seed := newRuntimeSeed(sc, cve, profile, fileAllow)
	r.store = store
	if store != nil {
		p, ok, err := store.LoadPolicy()
		if err != nil {
			return nil, fmt.Errorf("loading stored policy: %w", err)
		}
		if ok {
			r.install(p)
			return r, nil
		}
	}
	r.install(seed)
	if store != nil {
		if err := store.SavePolicy(seed); err != nil {
			return nil, fmt.Errorf("seeding policy store: %w", err)
		}
	}
	return r, nil
}

// newRuntimeSeed builds the Runtime shell and the boot params derived from the
// YAML config, without installing them.
func newRuntimeSeed(sc config.SupplyChainConfig, cve config.CVEConfig, profile config.PolicyProfile, fileAllow []string) (*Runtime, RuntimeParams) {
	blockOn := cve.BlockOn
	if profile.CVEMinSeverity != "" {
		blockOn = profile.CVEMinSeverity
	}
	if blockOn == "" {
		// Empty block_on historically blocked any finding with a known
		// severity (threshold Unknown). LOW matches that exact set while
		// keeping the params valid for PUT /api/policy round-trips.
		blockOn = "LOW"
	}
	r := &Runtime{cveCfg: cve, profile: profile, fileAllow: append([]string{}, fileAllow...)}
	seed := RuntimeParams{
		Mode:            sc.Mode,
		MinAgeHours:     sc.MinAgeHours,
		CVEBlockOn:      blockOn,
		AllowlistSupply: append([]string{}, profile.Allowlist...),
		AllowlistCVE:    append([]string{}, profile.Allowlist...),
		Denylist:        append([]string{}, profile.Denylist...),
	}
	return r, seed
}

// install builds a fresh Engine/Filter pair for p and swaps it in atomically;
// there is no partial application.
func (r *Runtime) install(p RuntimeParams) {
	p.AllowlistSupply = append([]string{}, p.AllowlistSupply...)
	p.AllowlistCVE = append([]string{}, p.AllowlistCVE...)
	p.Denylist = append([]string{}, p.Denylist...)
	merged := append(append([]string{}, r.fileAllow...), p.AllowlistSupply...)
	filter := supplychain.NewFilter(
		config.SupplyChainConfig{Mode: p.Mode, MinAgeHours: p.MinAgeHours},
		supplychain.NewAllowlist(merged),
	)
	prof := r.profile
	prof.CVEMinSeverity = p.CVEBlockOn
	prof.Allowlist = p.AllowlistCVE
	prof.Denylist = p.Denylist
	r.cur.Store(&runtimeSnapshot{
		engine: NewEngine(r.cveCfg, prof),
		filter: filter,
		params: p,
	})
}

var validModes = map[string]bool{"enforce": true, "dry_run": true, "off": true}
var validSeverities = map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}

// Apply validates p and atomically swaps the active policy. Concurrent calls
// are safe; last writer wins (no compare-and-swap). On error the current
// policy is unchanged.
func (r *Runtime) Apply(p RuntimeParams) error {
	if !validModes[p.Mode] {
		return &ValidationError{Field: "mode", Message: fmt.Sprintf("must be enforce, dry_run or off (got %q)", p.Mode)}
	}
	if p.MinAgeHours < 0 {
		return &ValidationError{Field: "min_age_hours", Message: "must be >= 0"}
	}
	if !validSeverities[p.CVEBlockOn] {
		return &ValidationError{Field: "cve_block_on", Message: fmt.Sprintf("must be CRITICAL, HIGH, MEDIUM or LOW (got %q)", p.CVEBlockOn)}
	}
	for i, e := range p.AllowlistSupply {
		if msg := validateListEntry(e); msg != "" {
			return &ValidationError{Field: fmt.Sprintf("allowlist_supply[%d]", i), Message: msg}
		}
	}
	for i, e := range p.AllowlistCVE {
		if msg := validateListEntry(e); msg != "" {
			return &ValidationError{Field: fmt.Sprintf("allowlist_cve[%d]", i), Message: msg}
		}
	}
	for i, e := range p.Denylist {
		if msg := validateListEntry(e); msg != "" {
			return &ValidationError{Field: fmt.Sprintf("denylist[%d]", i), Message: msg}
		}
	}
	if r.store != nil {
		if err := r.store.SavePolicy(p); err != nil {
			return &PersistError{Err: err}
		}
	}
	r.install(p)
	return nil
}

// validateListEntry checks the "ecosystem/name[@version]" shape; returns a
// message on failure, "" when valid.
func validateListEntry(e string) string {
	eco, rest, ok := strings.Cut(strings.TrimSpace(e), "/")
	if !ok || eco == "" || rest == "" {
		return fmt.Sprintf("entry %q must be ecosystem/name or ecosystem/name@version", e)
	}
	if strings.ContainsAny(eco+rest, " \t") {
		return fmt.Sprintf("entry %q must not contain whitespace", e)
	}
	return ""
}

// Persistent reports whether policy edits are saved to a settings store and
// therefore survive a restart (false = runtime-only, YAML wins after restart).
func (r *Runtime) Persistent() bool {
	return r.store != nil
}

// Current returns a copy of the active params.
func (r *Runtime) Current() RuntimeParams {
	p := r.cur.Load().params
	p.AllowlistSupply = append([]string{}, p.AllowlistSupply...)
	p.AllowlistCVE = append([]string{}, p.AllowlistCVE...)
	p.Denylist = append([]string{}, p.Denylist...)
	return p
}

// Evaluate implements gate.PolicyDecider against the current snapshot.
func (r *Runtime) Evaluate(ref *gate.PackageRef, result *gate.ScanResult) gate.PolicyDecision {
	return r.cur.Load().engine.Evaluate(ref, result)
}

// Check implements gate.SCFilter against the current snapshot.
func (r *Runtime) Check(ctx context.Context, ref *gate.PackageRef, meta *gate.PackageMetadata) gate.FilterResult {
	return r.cur.Load().filter.Check(ctx, ref, meta)
}

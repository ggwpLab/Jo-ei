package policy

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

// RuntimeParams are the console-editable policy knobs (PUT /api/policy).
type RuntimeParams struct {
	Mode        string   `json:"mode"`          // supply-chain mode: enforce | dry_run | off
	MinAgeHours int      `json:"min_age_hours"` // supply-chain minimum age, >= 0
	CVEBlockOn  string   `json:"cve_block_on"`  // CRITICAL | HIGH | MEDIUM | LOW
	Allowlist   []string `json:"allowlist"`     // "eco/name[@version]"
	Denylist    []string `json:"denylist"`
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
// proxy.PolicyDecider and proxy.SCFilter. Edits are runtime-only: the YAML
// config wins again after a restart.
type Runtime struct {
	cur       atomic.Pointer[runtimeSnapshot]
	cveCfg    config.CVEConfig
	profile   config.PolicyProfile
	fileAllow []string // supply_chain.allowlist_path entries, immutable
}

// NewRuntime builds the boot snapshot from config. fileAllow entries are
// always honored by the supply-chain filter regardless of runtime edits.
func NewRuntime(sc config.SupplyChainConfig, cve config.CVEConfig, profile config.PolicyProfile, fileAllow []string) *Runtime {
	blockOn := cve.BlockOn
	if profile.CVEMinSeverity != "" {
		blockOn = profile.CVEMinSeverity
	}
	r := &Runtime{cveCfg: cve, profile: profile, fileAllow: append([]string{}, fileAllow...)}
	r.install(RuntimeParams{
		Mode:        sc.Mode,
		MinAgeHours: sc.MinAgeHours,
		CVEBlockOn:  blockOn,
		Allowlist:   append([]string{}, profile.Allowlist...),
		Denylist:    append([]string{}, profile.Denylist...),
	})
	return r
}

// install builds a fresh Engine/Filter pair for p and swaps it in atomically;
// there is no partial application.
func (r *Runtime) install(p RuntimeParams) {
	p.Allowlist = append([]string{}, p.Allowlist...)
	p.Denylist = append([]string{}, p.Denylist...)
	merged := append(append([]string{}, r.fileAllow...), p.Allowlist...)
	filter := supplychain.NewFilter(
		config.SupplyChainConfig{Mode: p.Mode, MinAgeHours: p.MinAgeHours},
		supplychain.NewAllowlist(merged),
	)
	prof := r.profile
	prof.CVEMinSeverity = p.CVEBlockOn
	prof.Allowlist = p.Allowlist
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
	for i, e := range p.Allowlist {
		if msg := validateListEntry(e); msg != "" {
			return &ValidationError{Field: fmt.Sprintf("allowlist[%d]", i), Message: msg}
		}
	}
	for i, e := range p.Denylist {
		if msg := validateListEntry(e); msg != "" {
			return &ValidationError{Field: fmt.Sprintf("denylist[%d]", i), Message: msg}
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

// Current returns a copy of the active params.
func (r *Runtime) Current() RuntimeParams {
	p := r.cur.Load().params
	p.Allowlist = append([]string{}, p.Allowlist...)
	p.Denylist = append([]string{}, p.Denylist...)
	return p
}

// Evaluate implements proxy.PolicyDecider against the current snapshot.
func (r *Runtime) Evaluate(ref *proxy.PackageRef, result *proxy.ScanResult) proxy.PolicyDecision {
	return r.cur.Load().engine.Evaluate(ref, result)
}

// Check implements proxy.SCFilter against the current snapshot.
func (r *Runtime) Check(ctx context.Context, ref *proxy.PackageRef, meta *proxy.PackageMetadata) proxy.FilterResult {
	return r.cur.Load().filter.Check(ctx, ref, meta)
}

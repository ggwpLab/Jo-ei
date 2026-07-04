// Package policy evaluates packages against CVE/allow/deny policy profiles.
package policy

import (
	"strings"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// Engine evaluates packages against a policy profile.
// It implements gate.PolicyDecider.
type Engine struct {
	blockOn   gate.Severity
	cveBlock  bool
	allowlist map[string]bool // "ecosystem/name" or "ecosystem/name@version"
	denylist  map[string]bool
}

// NewEngine creates a PolicyEngine from the CVE config and the active profile.
// Profile's CVEMinSeverity overrides cfg.BlockOn when non-empty.
func NewEngine(cfg config.CVEConfig, profile config.PolicyProfile) *Engine {
	blockSeverityStr := cfg.BlockOn
	if profile.CVEMinSeverity != "" {
		blockSeverityStr = profile.CVEMinSeverity
	}

	return &Engine{
		blockOn:   gate.ParseSeverity(blockSeverityStr),
		cveBlock:  profile.CVEBlock,
		allowlist: buildIndex(profile.Allowlist),
		denylist:  buildIndex(profile.Denylist),
	}
}

// Evaluate implements gate.PolicyDecider.
func (e *Engine) Evaluate(ref *gate.PackageRef, result *gate.ScanResult) gate.PolicyDecision {
	// Denylist takes highest priority.
	if e.matchesIndex(e.denylist, ref) {
		return gate.PolicyDecision{Allowed: false, Reason: "denylisted"}
	}

	// Allowlist bypasses CVE checks.
	if e.matchesIndex(e.allowlist, ref) {
		return gate.PolicyDecision{Allowed: true, Reason: "allowlisted_bypass"}
	}

	// If CVE blocking is disabled, pass through.
	if !e.cveBlock {
		return gate.PolicyDecision{Allowed: true, Reason: "cve_block_disabled"}
	}

	// Check for findings at or above the block threshold.
	var blocked []gate.CVEFinding
	for _, f := range result.Findings {
		if f.Severity.AtLeast(e.blockOn) {
			blocked = append(blocked, f)
		}
	}
	if len(blocked) > 0 {
		return gate.PolicyDecision{Allowed: false, Reason: "cve_found", Findings: blocked}
	}

	return gate.PolicyDecision{Allowed: true, Reason: "ok"}
}

// buildIndex converts a slice of "ecosystem/name[@version]" entries to a lookup map.
func buildIndex(entries []string) map[string]bool {
	m := make(map[string]bool, len(entries))
	for _, e := range entries {
		m[strings.TrimSpace(e)] = true
	}
	return m
}

// matchesIndex checks whether ref matches any entry in the index.
// Matches "ecosystem/name" (all versions) or "ecosystem/name@version" (exact).
func (e *Engine) matchesIndex(idx map[string]bool, ref *gate.PackageRef) bool {
	byName := ref.Ecosystem + "/" + ref.Name
	byVersion := byName + "@" + ref.Version
	return idx[byName] || idx[byVersion]
}

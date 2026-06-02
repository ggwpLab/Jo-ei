// Package policy evaluates packages against CVE/allow/deny policy profiles.
package policy

import (
	"strings"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// Engine evaluates packages against a policy profile.
// It implements proxy.PolicyDecider.
type Engine struct {
	blockOn   proxy.Severity
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
		blockOn:   proxy.ParseSeverity(blockSeverityStr),
		cveBlock:  profile.CVEBlock,
		allowlist: buildIndex(profile.Allowlist),
		denylist:  buildIndex(profile.Denylist),
	}
}

// Evaluate implements proxy.PolicyDecider.
func (e *Engine) Evaluate(ref *proxy.PackageRef, result *proxy.ScanResult) proxy.PolicyDecision {
	// Denylist takes highest priority.
	if e.matchesIndex(e.denylist, ref) {
		return proxy.PolicyDecision{Allowed: false, Reason: "denylisted"}
	}

	// Allowlist bypasses CVE checks.
	if e.matchesIndex(e.allowlist, ref) {
		return proxy.PolicyDecision{Allowed: true, Reason: "allowlisted_bypass"}
	}

	// If CVE blocking is disabled, pass through.
	if !e.cveBlock {
		return proxy.PolicyDecision{Allowed: true, Reason: "cve_block_disabled"}
	}

	// Check for findings at or above the block threshold.
	var blocked []proxy.CVEFinding
	for _, f := range result.Findings {
		if f.Severity.AtLeast(e.blockOn) {
			blocked = append(blocked, f)
		}
	}
	if len(blocked) > 0 {
		return proxy.PolicyDecision{Allowed: false, Reason: "cve_found", Findings: blocked}
	}

	return proxy.PolicyDecision{Allowed: true, Reason: "ok"}
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
func (e *Engine) matchesIndex(idx map[string]bool, ref *proxy.PackageRef) bool {
	byName := ref.Ecosystem + "/" + ref.Name
	byVersion := byName + "@" + ref.Version
	return idx[byName] || idx[byVersion]
}

package supplychain

import (
	"context"
	"strings"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// FilterResult is an alias for proxy.FilterResult kept here for backward compatibility.
// New code should use proxy.FilterResult directly.
type FilterResult = proxy.FilterResult

// Allowlist holds explicitly approved packages that bypass the age check.
// Entry format: "ecosystem/name" (all versions) or "ecosystem/name@version" (specific).
type Allowlist struct {
	entries map[string]bool
}

// NewAllowlist creates an Allowlist from a slice of entry strings.
func NewAllowlist(entries []string) *Allowlist {
	m := make(map[string]bool, len(entries))
	for _, e := range entries {
		m[strings.TrimSpace(e)] = true
	}
	return &Allowlist{entries: m}
}

// Contains reports whether ref is covered by the allowlist.
func (a *Allowlist) Contains(ref *proxy.PackageRef) bool {
	if a == nil {
		return false
	}
	byName := ref.Ecosystem + "/" + ref.Name
	byVersion := byName + "@" + ref.Version
	return a.entries[byName] || a.entries[byVersion]
}

// Filter implements the supply chain package age check.
type Filter struct {
	cfg       config.SupplyChainConfig
	allowlist *Allowlist
}

// NewFilter creates a Filter with the given configuration and allowlist.
func NewFilter(cfg config.SupplyChainConfig, allowlist *Allowlist) *Filter {
	return &Filter{cfg: cfg, allowlist: allowlist}
}

// Check applies the supply chain filter. The caller must provide pre-fetched PackageMetadata.
// No network calls are made inside Check.
func (f *Filter) Check(_ context.Context, ref *proxy.PackageRef, meta *proxy.PackageMetadata) FilterResult {
	if f.cfg.Mode == "off" {
		return FilterResult{Allowed: true, Reason: "off", PublishedAt: meta.PublishedAt}
	}

	if f.allowlist.Contains(ref) {
		return FilterResult{Allowed: true, Reason: "allowlisted", PublishedAt: meta.PublishedAt}
	}

	minAge := time.Duration(f.cfg.MinAgeHours) * time.Hour
	age := time.Since(meta.PublishedAt)

	if age < minAge {
		blockUntil := meta.PublishedAt.Add(minAge)
		if f.cfg.Mode == "dry_run" {
			return FilterResult{
				Allowed:     true,
				Reason:      "dry_run",
				PublishedAt: meta.PublishedAt,
				BlockUntil:  blockUntil,
			}
		}
		return FilterResult{
			Allowed:     false,
			Reason:      "package_version_newer_than_24h",
			PublishedAt: meta.PublishedAt,
			BlockUntil:  blockUntil,
		}
	}

	return FilterResult{Allowed: true, Reason: "ok", PublishedAt: meta.PublishedAt}
}

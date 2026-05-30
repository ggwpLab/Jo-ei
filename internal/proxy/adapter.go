package proxy

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// PackageRef uniquely identifies a versioned package in an ecosystem.
type PackageRef struct {
	Ecosystem string // "pypi", "npm", "maven", "go"
	Name      string
	Version   string
}

// Key returns a stable cache/log key for this package reference.
func (r PackageRef) Key() string {
	return fmt.Sprintf("%s/%s@%s", r.Ecosystem, r.Name, r.Version)
}

// PackageMetadata contains resolved metadata from the upstream registry.
type PackageMetadata struct {
	PublishedAt time.Time
	Maintainer  string
	License     string
	Checksum    string // SHA256 hex
}

// RegistryAdapter abstracts a specific package registry.
type RegistryAdapter interface {
	// Name returns the ecosystem identifier, e.g. "pypi".
	Name() string

	// NormalizeRequest extracts a PackageRef from an incoming HTTP request.
	// Returns (ref, true) for download requests that should be intercepted.
	// Returns (nil, false) for metadata/simple-API requests (proxied as-is).
	NormalizeRequest(r *http.Request) (*PackageRef, bool)

	// FetchMetadata fetches version metadata from the upstream registry.
	FetchMetadata(ctx context.Context, ref *PackageRef) (*PackageMetadata, error)

	// UpstreamURL returns the upstream URL corresponding to a proxy request path.
	UpstreamURL(r *http.Request) string
}

// BlockedError is returned when a package is blocked by a policy.
type BlockedError struct {
	Package   PackageRef
	Reason    string
	BlockedBy []string
	Details   map[string]any
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("package %s blocked: %s (by %v)", e.Package.Key(), e.Reason, e.BlockedBy)
}

// FilterResult describes the outcome of a supply chain check.
// Defined here (in proxy) to avoid import cycles: supplychain imports proxy,
// so proxy cannot import supplychain.
type FilterResult struct {
	Allowed     bool
	Reason      string    // "ok" | "allowlisted" | "dry_run" | "off" | "package_version_newer_than_24h"
	PublishedAt time.Time
	BlockUntil  time.Time // non-zero when Allowed=false
}

// SCFilter is the interface the handler uses for supply chain checks.
// supplychain.Filter satisfies this interface.
type SCFilter interface {
	Check(ctx context.Context, ref *PackageRef, meta *PackageMetadata) FilterResult
}

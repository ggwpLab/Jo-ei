// Package gate holds Jōei's domain vocabulary: the types that describe
// packages, scan results, verdicts, and telemetry events, and the ports
// (interfaces) implemented by registry adapters, scanners, the policy engine,
// the artifact cache, and telemetry. It imports nothing but the standard
// library; every other package depends inward on it.
package gate

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// PackageRef uniquely identifies a versioned package in an ecosystem.
type PackageRef struct {
	Ecosystem string // "pypi", "npm", "maven", "go"
	Name      string
	Version   string
	// Classifier distinguishes secondary artifacts that share the same
	// coordinates (Maven "sources"/"javadoc" jars, etc.). Empty for the main
	// artifact and for ecosystems without classifiers. It participates in the
	// cache key but not in CVE/supply-chain lookups, which key on Name+Version.
	Classifier string
}

// Key returns a stable cache/log key for this package reference. The classifier
// is appended only when non-empty, so main artifacts and non-maven ecosystems
// keep their historical keys (and existing cache entries stay valid).
func (r PackageRef) Key() string {
	key := fmt.Sprintf("%s/%s@%s", r.Ecosystem, r.Name, r.Version)
	if r.Classifier != "" {
		key += "?classifier=" + r.Classifier
	}
	return key
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

	// UpstreamURLs returns one candidate upstream URL per configured upstream,
	// in priority order, for the given proxy request path.
	UpstreamURLs(r *http.Request) []string
}

// DownloadMetadataExtractor is an optional RegistryAdapter capability: deriving
// PackageMetadata (notably the publish date) from the artifact download
// response headers. When an adapter implements it, the handler obtains the
// supply-chain date from the download itself and runs the supply-chain check
// after fetching the artifact — avoiding a separate metadata request. Maven
// implements this (the artifact's Last-Modified is the publish-date proxy), so a
// pull is one GET instead of a HEAD + GET. Adapters whose publish date comes
// from a distinct metadata API (PyPI, npm) do not implement it and are checked
// before download via FetchMetadata as before.
type DownloadMetadataExtractor interface {
	MetadataFromHeader(h http.Header) *PackageMetadata
}

// ── CVE / scan types ────────────────────────────────────────────────────────

// Severity represents a CVE severity level.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// ParseSeverity converts an OSV/NVD severity string to Severity.
// "MODERATE" (OSV) is mapped to SeverityMedium.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM", "MODERATE":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// String returns the canonical string form of a Severity.
func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// AtLeast reports whether s is at least as severe as threshold.
// SeverityUnknown is never at least anything (returns false).
func (s Severity) AtLeast(threshold Severity) bool {
	if s == SeverityUnknown {
		return false
	}
	return s >= threshold
}

// CVEFinding represents a single vulnerability found in a package.
type CVEFinding struct {
	ID       string   // canonical ID (CVE-YYYY-NNNNN or advisory ID if no CVE alias)
	Aliases  []string // other IDs (GHSA-…, PYSEC-…, etc.)
	Severity Severity
	Summary  string
	Score    float64 // CVSS score, 0 if unavailable
}

// ScanResult records the outcome of a CVE scan for a package version.
type ScanResult struct {
	Clean    bool         // true iff Findings is empty
	Findings []CVEFinding // all findings regardless of threshold
	ScanJSON string       // raw JSON for storage in cache audit log
}

// CVEScanner scans a package for known vulnerabilities.
// Implementations must be safe for concurrent use.
type CVEScanner interface {
	Scan(ctx context.Context, ref *PackageRef) (*ScanResult, error)
}

// PolicyDecision is the result of evaluating a package against policy rules.
type PolicyDecision struct {
	Allowed  bool
	Reason   string       // "ok" | "cve_found" | "denylisted" | "allowlisted_bypass"
	Findings []CVEFinding // findings that caused a block (empty if Allowed)
}

// PolicyDecider evaluates a package against policy rules.
type PolicyDecider interface {
	Evaluate(ref *PackageRef, result *ScanResult) PolicyDecision
}

// FilterResult describes the outcome of a supply chain check.
type FilterResult struct {
	Allowed     bool
	Reason      string // "ok" | "allowlisted" | "dry_run" | "off" | "package_younger_than_min_age"
	PublishedAt time.Time
	BlockUntil  time.Time // non-zero when Allowed=false
}

// SCFilter is the interface the handler uses for supply chain checks.
// supplychain.Filter satisfies this interface.
type SCFilter interface {
	Check(ctx context.Context, ref *PackageRef, meta *PackageMetadata) FilterResult
}

// ── Antivirus / malware-scan types ───────────────────────────────────────────

// AVResult records the outcome of an antivirus scan of a single file.
type AVResult struct {
	Clean     bool   // true iff no malware signature matched
	Signature string // signature name when infected, "" otherwise
	Engine    string // engine that produced this verdict, e.g. "clamav" | "icap"
}

// AVScanner scans a file on disk for malware.
// Implementations must be safe for concurrent use.
type AVScanner interface {
	Scan(ctx context.Context, filePath string) (*AVResult, error)
}

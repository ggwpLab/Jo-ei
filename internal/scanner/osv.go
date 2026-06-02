package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// ecosystemMap maps our internal ecosystem names to OSV API ecosystem names.
var ecosystemMap = map[string]string{
	"pypi":     "PyPI",
	"npm":      "npm",
	"maven":    "Maven",
	"go":       "Go",
	"rubygems": "RubyGems",
}

// osvQueryRequest is the body sent to api.osv.dev/v1/query.
type osvQueryRequest struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvQueryResponse is the response from api.osv.dev/v1/query.
type osvQueryResponse struct {
	Vulns []osvVulnerability `json:"vulns"`
}

type osvVulnerability struct {
	ID              string   `json:"id"`
	Aliases         []string `json:"aliases"`
	Summary         string   `json:"summary"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// cveEntry wraps a cached ScanResult with its expiry time.
type cveEntry struct {
	result    *proxy.ScanResult
	expiresAt time.Time
}

// OSVScanner queries api.osv.dev for known vulnerabilities.
// It implements proxy.CVEScanner and caches results in memory.
type OSVScanner struct {
	baseURL string
	client  *http.Client
	ttl     time.Duration

	mu    sync.Mutex
	cache map[string]*cveEntry
}

// NewOSVScanner creates an OSVScanner with the given base URL and cache TTL.
// baseURL should be "https://api.osv.dev" (or a mock server URL in tests).
func NewOSVScanner(baseURL string, ttl time.Duration) *OSVScanner {
	return &OSVScanner{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 15 * time.Second},
		ttl:     ttl,
		cache:   make(map[string]*cveEntry),
	}
}

// Scan implements proxy.CVEScanner.
func (s *OSVScanner) Scan(ctx context.Context, ref *proxy.PackageRef) (*proxy.ScanResult, error) {
	key := ref.Key()

	// Check in-memory cache first.
	s.mu.Lock()
	if entry, ok := s.cache[key]; ok && time.Now().Before(entry.expiresAt) {
		s.mu.Unlock()
		return entry.result, nil
	}
	s.mu.Unlock()

	result, err := s.queryOSV(ctx, ref)
	if err != nil {
		return nil, err
	}

	// Store in cache.
	s.mu.Lock()
	s.cache[key] = &cveEntry{result: result, expiresAt: time.Now().Add(s.ttl)}
	s.mu.Unlock()

	return result, nil
}

// queryOSV performs the actual HTTP request to api.osv.dev.
func (s *OSVScanner) queryOSV(ctx context.Context, ref *proxy.PackageRef) (*proxy.ScanResult, error) {
	eco := strings.ToLower(ref.Ecosystem)
	ecosystem, ok := ecosystemMap[eco]
	if !ok {
		ecosystem = ref.Ecosystem // fall back to as-is
	}

	// RubyGems encodes the platform into the version (e.g. "1.15.0-x86_64-linux");
	// OSV is keyed by the bare gem version. Gem versions contain no hyphens.
	version := ref.Version
	if eco == "rubygems" {
		version = strings.SplitN(version, "-", 2)[0]
	}

	reqBody, err := json.Marshal(osvQueryRequest{
		Package: osvPackage{Name: ref.Name, Ecosystem: ecosystem},
		Version: version,
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling OSV request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.baseURL+"/v1/query", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("creating OSV request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OSV request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned HTTP %d for %s", resp.StatusCode, ref.Key())
	}

	var osvResp osvQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("decoding OSV response: %w", err)
	}

	return s.toScanResult(osvResp)
}

// toScanResult converts an OSV API response to a proxy.ScanResult.
func (s *OSVScanner) toScanResult(resp osvQueryResponse) (*proxy.ScanResult, error) {
	var findings []proxy.CVEFinding
	for _, v := range resp.Vulns {
		id := canonicalID(v.ID, v.Aliases)
		findings = append(findings, proxy.CVEFinding{
			ID:       id,
			Aliases:  aliasesWithout(v.ID, v.Aliases, id),
			Severity: proxy.ParseSeverity(v.DatabaseSpecific.Severity),
			Summary:  v.Summary,
		})
	}

	scanJSON, err := json.Marshal(findings)
	if err != nil {
		return nil, fmt.Errorf("marshalling scan findings: %w", err)
	}

	return &proxy.ScanResult{
		Clean:    len(findings) == 0,
		Findings: findings,
		ScanJSON: string(scanJSON),
	}, nil
}

// canonicalID returns the first CVE alias if available, otherwise the primary ID.
func canonicalID(primaryID string, aliases []string) string {
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return primaryID
}

// aliasesWithout returns all IDs (primary + aliases) except the canonical one.
func aliasesWithout(primaryID string, aliases []string, canonicalID string) []string {
	var out []string
	for _, a := range append([]string{primaryID}, aliases...) {
		if a != canonicalID {
			out = append(out, a)
		}
	}
	return out
}

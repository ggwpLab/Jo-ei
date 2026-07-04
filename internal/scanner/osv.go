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

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/health"
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
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases"`
	Summary          string   `json:"summary"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// cveEntry wraps a cached ScanResult with its expiry time.
type cveEntry struct {
	result    *gate.ScanResult
	expiresAt time.Time
}

// OSVScanner queries api.osv.dev for known vulnerabilities.
// It implements gate.CVEScanner and caches results in memory.
type OSVScanner struct {
	baseURL string
	client  *http.Client
	ttl     time.Duration

	mu    sync.Mutex
	cache map[string]*cveEntry

	healthMu      sync.Mutex
	healthLatency time.Duration
	healthOK      bool
	healthHasData bool

	stop      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewOSVScanner creates an OSVScanner with the given base URL and cache TTL.
// baseURL should be "https://api.osv.dev" (or a mock server URL in tests).
func NewOSVScanner(baseURL string, ttl time.Duration) *OSVScanner {
	s := &OSVScanner{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 15 * time.Second},
		ttl:     ttl,
		cache:   make(map[string]*cveEntry),
		stop:    make(chan struct{}),
	}
	s.wg.Add(1)
	go s.janitor()
	return s
}

// janitor periodically removes expired cache entries so the map does not grow
// unbounded across distinct package keys.
func (s *OSVScanner) janitor() {
	defer s.wg.Done()
	interval := s.ttl
	if interval <= 0 {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for k, e := range s.cache {
				if now.After(e.expiresAt) {
					delete(s.cache, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

// Close stops the janitor goroutine and waits for it to exit.
// Safe to call more than once.
func (s *OSVScanner) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		s.wg.Wait()
	})
	return nil
}

// Scan implements gate.CVEScanner.
func (s *OSVScanner) Scan(ctx context.Context, ref *gate.PackageRef) (*gate.ScanResult, error) {
	key := ref.Key()

	// Check in-memory cache first.
	s.mu.Lock()
	if entry, ok := s.cache[key]; ok && time.Now().Before(entry.expiresAt) {
		s.mu.Unlock()
		return entry.result, nil
	}
	s.mu.Unlock()

	start := time.Now()
	result, err := s.queryOSV(ctx, ref)
	s.recordHealth(time.Since(start), err)
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
func (s *OSVScanner) queryOSV(ctx context.Context, ref *gate.PackageRef) (*gate.ScanResult, error) {
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

// toScanResult converts an OSV API response to a gate.ScanResult.
func (s *OSVScanner) toScanResult(resp osvQueryResponse) (*gate.ScanResult, error) {
	var findings []gate.CVEFinding
	for _, v := range resp.Vulns {
		id := canonicalID(v.ID, v.Aliases)
		findings = append(findings, gate.CVEFinding{
			ID:       id,
			Aliases:  aliasesWithout(v.ID, v.Aliases, id),
			Severity: gate.ParseSeverity(v.DatabaseSpecific.Severity),
			Summary:  v.Summary,
		})
	}

	scanJSON, err := json.Marshal(findings)
	if err != nil {
		return nil, fmt.Errorf("marshalling scan findings: %w", err)
	}

	return &gate.ScanResult{
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

// recordHealth stores the outcome of the most recent live OSV query for the
// passive health probe. Cache hits do not call this, so health reflects the real
// reachability of api.osv.dev.
func (s *OSVScanner) recordHealth(latency time.Duration, err error) {
	s.healthMu.Lock()
	s.healthLatency = latency
	s.healthOK = err == nil
	s.healthHasData = true
	s.healthMu.Unlock()
}

// Health reports the result of the last live query as a passive health sample.
// Before any live query runs, HasData is false (status unknown). Cache hits do
// not update it.
func (s *OSVScanner) Health() health.Sample {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	return health.Sample{OK: s.healthOK, Latency: s.healthLatency, HasData: s.healthHasData}
}

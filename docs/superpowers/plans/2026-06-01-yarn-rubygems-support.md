# Yarn and RubyGems Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `/yarn/` route alias to the existing npm handler and a new RubyGems adapter, so both flow through the four-layer pipeline.

**Architecture:** Yarn speaks the npm protocol, so it reuses the npm handler under a second routing prefix (no new adapter). RubyGems is a new `RegistryAdapter` (`internal/proxy/adapters/rubygems.go`) intercepting `/gems/*.gem`, fetching metadata from `/api/v1/versions/<gem>.json`, with platform encoded into `PackageRef.Version`; the OSV scanner strips that platform suffix for the `rubygems` ecosystem. New adapters inherit multi-upstream sequential fallback by implementing `UpstreamURLs`/looping in `FetchMetadata`.

**Tech Stack:** Go, `spf13/viper` (config), `rs/zerolog`, `stretchr/testify`, `net/http/httptest`.

**Spec:** `docs/superpowers/specs/2026-06-01-yarn-rubygems-support-design.md`

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `internal/config/config.go` | Config types + validation | Add `RubyGems RegistryConfig`; add it to `Validate()` map |
| `internal/config/config_test.go` | Config tests | RubyGems parse + enabled-empty tests |
| `internal/proxy/adapters/rubygems.go` | RubyGems adapter | **New** — full `RegistryAdapter` |
| `internal/proxy/adapters/rubygems_test.go` | RubyGems adapter tests | **New** |
| `internal/scanner/osv.go` | CVE scanner | `rubygems→RubyGems` map entry + platform-suffix strip |
| `internal/scanner/osv_test.go` | OSV tests | RubyGems version-normalization test |
| `cmd/sca-proxy/main.go` | Wiring | Extract `buildHandlers`; register rubygems; yarn alias; error msg |
| `cmd/sca-proxy/main_test.go` | Wiring tests | **New** — prefix map / yarn alias |
| `integration/rubygems_test.go` | Integration | **New** — multi-upstream RubyGems end-to-end |
| `config.yaml` | Sample config | Add `rubygems` block |
| `README.md` | Docs | Yarn + RubyGems usage sections |

---

## Task 1: Config — add RubyGems registry

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `config.yaml`

- [ ] **Step 1: Write the failing config tests**

In `internal/config/config_test.go`, add:
```go
func TestLoad_ParsesRubyGemsUpstreams(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  rubygems:
    enabled: true
    upstreams:
      - "https://rubygems.org"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://rubygems.org"}, cfg.Registries.RubyGems.Upstreams)
	assert.True(t, cfg.Registries.RubyGems.Enabled)
}

func TestLoad_EnabledRubyGemsWithoutUpstreamsFails(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  rubygems:
    enabled: true
    upstreams: []
`)
	_, err := config.Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rubygems")
}
```

- [ ] **Step 2: Run config tests to verify they fail**

Run: `go test ./internal/config/ -run RubyGems`
Expected: compile failure — `cfg.Registries.RubyGems` undefined.

- [ ] **Step 3: Add the RubyGems field and validation entry**

In `internal/config/config.go`, change `RegistriesConfig`:
```go
type RegistriesConfig struct {
	PyPI     RegistryConfig `mapstructure:"pypi"`
	NPM      RegistryConfig `mapstructure:"npm"`
	Maven    RegistryConfig `mapstructure:"maven"`
	RubyGems RegistryConfig `mapstructure:"rubygems"`
}
```

In the same file, add the rubygems entry to the `Validate` map:
```go
	regs := map[string]RegistryConfig{
		"pypi":     c.Registries.PyPI,
		"npm":      c.Registries.NPM,
		"maven":    c.Registries.Maven,
		"rubygems": c.Registries.RubyGems,
	}
```

- [ ] **Step 4: Run config tests to verify they pass**

Run: `go test ./internal/config/...`
Expected: PASS.

- [ ] **Step 5: Add rubygems to config.yaml**

In `config.yaml`, add to the `registries:` block (after `maven:`):
```yaml
  rubygems:
    upstreams:
      - "https://rubygems.org"
    enabled: true
```

- [ ] **Step 6: Build and commit**

Run: `go build ./... && go test ./...`
Expected: PASS.
```bash
git add internal/config config.yaml
git commit -m "feat(config): add rubygems registry with upstreams + validation"
```

---

## Task 2: RubyGems adapter

**Files:**
- Create: `internal/proxy/adapters/rubygems.go`
- Create: `internal/proxy/adapters/rubygems_test.go`

- [ ] **Step 1: Write the failing NormalizeRequest + UpstreamURLs tests**

Create `internal/proxy/adapters/rubygems_test.go`:
```go
package adapters_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRubyGemsAdapter_NormalizeRequest_PlainGem(t *testing.T) {
	a := adapters.NewRubyGemsAdapter([]string{"https://rubygems.org"})
	r := httptest.NewRequest(http.MethodGet, "/gems/rails-7.0.4.gem", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "rubygems", ref.Ecosystem)
	assert.Equal(t, "rails", ref.Name)
	assert.Equal(t, "7.0.4", ref.Version)
}

func TestRubyGemsAdapter_NormalizeRequest_HyphenatedName(t *testing.T) {
	a := adapters.NewRubyGemsAdapter([]string{"https://rubygems.org"})
	r := httptest.NewRequest(http.MethodGet, "/gems/aws-sdk-s3-1.0.0.gem", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "aws-sdk-s3", ref.Name)
	assert.Equal(t, "1.0.0", ref.Version)
}

func TestRubyGemsAdapter_NormalizeRequest_PlatformGem(t *testing.T) {
	a := adapters.NewRubyGemsAdapter([]string{"https://rubygems.org"})
	r := httptest.NewRequest(http.MethodGet, "/gems/nokogiri-1.15.0-x86_64-linux.gem", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "nokogiri", ref.Name)
	assert.Equal(t, "1.15.0-x86_64-linux", ref.Version)
}

func TestRubyGemsAdapter_NormalizeRequest_NonGemNotIntercepted(t *testing.T) {
	a := adapters.NewRubyGemsAdapter([]string{"https://rubygems.org"})
	for _, p := range []string{"/api/v1/versions/rails.json", "/info/rails", "/versions", "/specs.4.8.gz"} {
		r := httptest.NewRequest(http.MethodGet, p, nil)
		_, ok := a.NormalizeRequest(r)
		assert.False(t, ok, "path %q must not be intercepted", p)
	}
}

func TestRubyGemsAdapter_UpstreamURLs_OnePerUpstream(t *testing.T) {
	a := adapters.NewRubyGemsAdapter([]string{"https://rubygems.org/", "https://mirror.example.org"})
	r := httptest.NewRequest(http.MethodGet, "/gems/rails-7.0.4.gem", nil)
	urls := a.UpstreamURLs(r)
	assert.Equal(t, []string{
		"https://rubygems.org/gems/rails-7.0.4.gem",
		"https://mirror.example.org/gems/rails-7.0.4.gem",
	}, urls)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/proxy/adapters/ -run RubyGems`
Expected: compile failure — `adapters.NewRubyGemsAdapter` undefined.

- [ ] **Step 3: Create the adapter (struct, ctor, Name, NormalizeRequest, parser, UpstreamURLs)**

Create `internal/proxy/adapters/rubygems.go`:
```go
package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// rubygemsVersion is one entry in the /api/v1/versions/<gem>.json array.
type rubygemsVersion struct {
	Number    string   `json:"number"`
	Platform  string   `json:"platform"`
	CreatedAt string   `json:"created_at"`
	Licenses  []string `json:"licenses"`
	SHA       string   `json:"sha"`
}

// RubyGemsAdapter implements proxy.RegistryAdapter for a RubyGems repository.
type RubyGemsAdapter struct {
	upstreams  []string
	httpClient *http.Client
}

// NewRubyGemsAdapter creates a RubyGems adapter over the given ordered upstream
// URLs (e.g. "https://rubygems.org"). Upstreams are tried in order.
func NewRubyGemsAdapter(upstreams []string) *RubyGemsAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &RubyGemsAdapter{
		upstreams:  trimmed,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *RubyGemsAdapter) Name() string { return "rubygems" }

// NormalizeRequest intercepts gem downloads: /gems/<name>-<version>[-<platform>].gem.
// API/index paths (/api/, /info/, /versions, /quick/, /specs*) are proxied transparently.
func (a *RubyGemsAdapter) NormalizeRequest(r *http.Request) (*proxy.PackageRef, bool) {
	path := r.URL.Path
	if !strings.HasSuffix(path, ".gem") {
		return nil, false
	}
	idx := strings.LastIndex(path, "/gems/")
	if idx == -1 {
		return nil, false
	}
	filename := path[idx+len("/gems/"):]
	if strings.Contains(filename, "/") {
		return nil, false
	}
	name, version, ok := parseGemFilename(filename)
	if !ok {
		return nil, false
	}
	return &proxy.PackageRef{Ecosystem: "rubygems", Name: name, Version: version}, true
}

// parseGemFilename parses "<name>-<version>[-<platform>].gem". The version is the
// first hyphen-separated segment beginning with a digit (gem versions contain no
// hyphens); everything before it is the name; any trailing segments are the
// platform. Returns the name and an encoded version: "<number>" for pure-ruby
// gems or "<number>-<platform>" for platform gems.
func parseGemFilename(filename string) (name, version string, ok bool) {
	base := strings.TrimSuffix(filename, ".gem")
	segs := strings.Split(base, "-")
	verIdx := -1
	for i, s := range segs {
		if s != "" && s[0] >= '0' && s[0] <= '9' {
			verIdx = i
			break
		}
	}
	if verIdx <= 0 { // no version segment, or an empty name
		return "", "", false
	}
	name = strings.Join(segs[:verIdx], "-")
	number := segs[verIdx]
	platform := strings.Join(segs[verIdx+1:], "-")
	if name == "" || number == "" {
		return "", "", false
	}
	if platform == "" {
		return name, number, true
	}
	return name, number + "-" + platform, true
}

// UpstreamURLs returns one candidate URL per configured upstream, in order.
func (a *RubyGemsAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}
```
NOTE: `FetchMetadata` is added in Step 5 (the type does not satisfy `proxy.RegistryAdapter` until then, but it is not yet assigned to that interface, so the package compiles).

- [ ] **Step 4: Run NormalizeRequest/UpstreamURLs tests to verify they pass**

Run: `go test ./internal/proxy/adapters/ -run RubyGems`
Expected: PASS.

- [ ] **Step 5: Write the failing FetchMetadata tests**

Append to `internal/proxy/adapters/rubygems_test.go`:
```go
func TestRubyGemsAdapter_FetchMetadata_RubyPlatform(t *testing.T) {
	created := time.Now().UTC().Add(-72 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/versions/rails.json", r.URL.Path)
		w.Write([]byte(`[
			{"number":"7.0.4","platform":"ruby","created_at":"` + created.Format(time.RFC3339) + `","licenses":["MIT"],"sha":"abc123"},
			{"number":"6.1.0","platform":"ruby","created_at":"2020-01-01T00:00:00Z","licenses":["MIT"],"sha":"old"}
		]`))
	}))
	defer srv.Close()

	a := adapters.NewRubyGemsAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "rubygems", Name: "rails", Version: "7.0.4"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, created, meta.PublishedAt, time.Second)
	assert.Equal(t, "MIT", meta.License)
	assert.Equal(t, "abc123", meta.Checksum)
}

func TestRubyGemsAdapter_FetchMetadata_MatchesPlatform(t *testing.T) {
	created := time.Now().UTC().Add(-100 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"number":"1.15.0","platform":"ruby","created_at":"2020-01-01T00:00:00Z","licenses":["MIT"],"sha":"rubysha"},
			{"number":"1.15.0","platform":"x86_64-linux","created_at":"` + created.Format(time.RFC3339) + `","licenses":["MIT"],"sha":"linuxsha"}
		]`))
	}))
	defer srv.Close()

	a := adapters.NewRubyGemsAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "rubygems", Name: "nokogiri", Version: "1.15.0-x86_64-linux"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "linuxsha", meta.Checksum)
	assert.WithinDuration(t, created, meta.PublishedAt, time.Second)
}

func TestRubyGemsAdapter_FetchMetadata_FallsBackToSecondUpstream(t *testing.T) {
	created := time.Now().UTC().Add(-72 * time.Hour)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"number":"7.0.4","platform":"ruby","created_at":"` + created.Format(time.RFC3339) + `","licenses":["MIT"],"sha":"abc123"}]`))
	}))
	defer up.Close()

	a := adapters.NewRubyGemsAdapter([]string{down.URL, up.URL})
	ref := &proxy.PackageRef{Ecosystem: "rubygems", Name: "rails", Version: "7.0.4"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "abc123", meta.Checksum)
}

func TestRubyGemsAdapter_FetchMetadata_VersionNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"number":"6.1.0","platform":"ruby","created_at":"2020-01-01T00:00:00Z","licenses":["MIT"],"sha":"x"}]`))
	}))
	defer srv.Close()

	a := adapters.NewRubyGemsAdapter([]string{srv.URL})
	ref := &proxy.PackageRef{Ecosystem: "rubygems", Name: "rails", Version: "7.0.4"}
	_, err := a.FetchMetadata(context.Background(), ref)
	require.Error(t, err)
}
```

- [ ] **Step 6: Run to verify it fails**

Run: `go test ./internal/proxy/adapters/ -run RubyGems_FetchMetadata`
Expected: compile failure — `FetchMetadata` not defined on `*RubyGemsAdapter`.

- [ ] **Step 7: Implement FetchMetadata + version decoder**

Append to `internal/proxy/adapters/rubygems.go`:
```go
// FetchMetadata walks the configured upstreams in order, returning the first
// success. If all upstreams fail, the last error is returned.
func (a *RubyGemsAdapter) FetchMetadata(ctx context.Context, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	lastErr := fmt.Errorf("no upstreams configured for rubygems")
	for _, base := range a.upstreams {
		meta, err := a.fetchMetadataFrom(ctx, base, ref)
		if err == nil {
			return meta, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (a *RubyGemsAdapter) fetchMetadataFrom(ctx context.Context, base string, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	number, platform := splitGemVersion(ref.Version)
	apiURL := fmt.Sprintf("%s/api/v1/versions/%s.json", base, ref.Name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building rubygems metadata request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching rubygems metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rubygems returned HTTP %d for %s", resp.StatusCode, ref.Name)
	}

	var versions []rubygemsVersion
	if err := json.NewDecoder(resp.Body).Decode(&versions); err != nil {
		return nil, fmt.Errorf("decoding rubygems response: %w", err)
	}

	for _, v := range versions {
		if v.Number == number && v.Platform == platform {
			publishedAt, err := time.Parse(time.RFC3339, v.CreatedAt)
			if err != nil {
				return nil, fmt.Errorf("parsing rubygems created_at %q: %w", v.CreatedAt, err)
			}
			return &proxy.PackageMetadata{
				PublishedAt: publishedAt.UTC(),
				License:     strings.Join(v.Licenses, ", "),
				Checksum:    v.SHA,
			}, nil
		}
	}
	return nil, fmt.Errorf("version %s (platform %s) not found for rubygems gem %s", number, platform, ref.Name)
}

// splitGemVersion decodes an encoded ref version into (number, platform).
// "1.15.0" → ("1.15.0", "ruby"); "1.15.0-x86_64-linux" → ("1.15.0", "x86_64-linux").
func splitGemVersion(version string) (number, platform string) {
	parts := strings.SplitN(version, "-", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return parts[0], "ruby"
}
```

- [ ] **Step 8: Run all RubyGems adapter tests to verify they pass**

Run: `go test ./internal/proxy/adapters/ -run RubyGems`
Expected: PASS.

- [ ] **Step 9: Build and commit**

Run: `go build ./... && go test ./...`
Expected: PASS.
```bash
git add internal/proxy/adapters/rubygems.go internal/proxy/adapters/rubygems_test.go
git commit -m "feat(adapters): RubyGems adapter with platform-aware version parsing + metadata fallback"
```

---

## Task 3: OSV — RubyGems ecosystem + platform-suffix strip

**Files:**
- Modify: `internal/scanner/osv.go`
- Modify: `internal/scanner/osv_test.go`

- [ ] **Step 1: Write the failing OSV test**

In `internal/scanner/osv_test.go`, add:
```go
func TestOSVScanner_RubyGemsStripsPlatformSuffix(t *testing.T) {
	srv := newMockOSV(t, map[string]string{
		"RubyGems/nokogiri@1.15.0": `{
			"vulns": [{
				"id": "GHSA-xxxx",
				"aliases": ["CVE-2023-0001"],
				"summary": "vuln in nokogiri",
				"database_specific": {"severity": "HIGH"}
			}]
		}`,
	})
	defer srv.Close()

	sc := scanner.NewOSVScanner(srv.URL, time.Minute)
	result, err := sc.Scan(context.Background(), &proxy.PackageRef{
		Ecosystem: "rubygems", Name: "nokogiri", Version: "1.15.0-x86_64-linux",
	})
	require.NoError(t, err)
	require.False(t, result.Clean)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "CVE-2023-0001", result.Findings[0].ID)
}
```
This passes only if the OSV query maps the ecosystem to `RubyGems` AND queries version `1.15.0` (platform stripped); otherwise the mock returns `{"vulns":[]}` (the key would not match) and the result would be clean.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/scanner/ -run RubyGems`
Expected: FAIL — result is Clean (the query key `RubyGems/nokogiri@1.15.0-x86_64-linux` does not match the mock entry; no ecosystem mapping + no strip).

- [ ] **Step 3: Add the ecosystem mapping and version normalization**

In `internal/scanner/osv.go`, add the map entry:
```go
var ecosystemMap = map[string]string{
	"pypi":     "PyPI",
	"npm":      "npm",
	"maven":    "Maven",
	"go":       "Go",
	"rubygems": "RubyGems",
}
```

In `queryOSV`, after the `ecosystem` lookup and before marshalling the request, normalize the version:
```go
	ecosystem, ok := ecosystemMap[strings.ToLower(ref.Ecosystem)]
	if !ok {
		ecosystem = ref.Ecosystem // fall back to as-is
	}

	// RubyGems encodes the platform into the version (e.g. "1.15.0-x86_64-linux");
	// OSV is keyed by the bare gem version. Gem versions contain no hyphens.
	version := ref.Version
	if strings.ToLower(ref.Ecosystem) == "rubygems" {
		version = strings.SplitN(version, "-", 2)[0]
	}

	reqBody, err := json.Marshal(osvQueryRequest{
		Package: osvPackage{Name: ref.Name, Ecosystem: ecosystem},
		Version: version,
	})
```
(Replace the existing `Version: ref.Version` with `Version: version`.)

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/scanner/...`
Expected: PASS.

- [ ] **Step 5: Build and commit**

Run: `go build ./... && go test ./...`
Expected: PASS.
```bash
git add internal/scanner/osv.go internal/scanner/osv_test.go
git commit -m "feat(scanner): map rubygems→RubyGems and strip platform suffix for OSV queries"
```

---

## Task 4: Wire into main — RubyGems registration + Yarn alias

**Files:**
- Modify: `cmd/sca-proxy/main.go`
- Create: `cmd/sca-proxy/main_test.go`

- [ ] **Step 1: Write the failing wiring tests**

Create `cmd/sca-proxy/main_test.go`:
```go
package main

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestBuildHandlers_YarnAliasesNPM(t *testing.T) {
	cfg := &config.Config{}
	cfg.Registries.NPM.Enabled = true
	cfg.Registries.NPM.Upstreams = []string{"https://registry.npmjs.org"}

	h := buildHandlers(cfg, sharedDeps{logger: zerolog.Nop()})

	assert.Contains(t, h, "npm")
	assert.Contains(t, h, "yarn")
	assert.Same(t, h["npm"], h["yarn"]) // same handler object
}

func TestBuildHandlers_RubyGemsRegisteredWhenEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Registries.RubyGems.Enabled = true
	cfg.Registries.RubyGems.Upstreams = []string{"https://rubygems.org"}

	h := buildHandlers(cfg, sharedDeps{logger: zerolog.Nop()})

	assert.Contains(t, h, "rubygems")
	_, hasNPM := h["npm"]
	assert.False(t, hasNPM)
	_, hasYarn := h["yarn"]
	assert.False(t, hasYarn)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/sca-proxy/ -run BuildHandlers`
Expected: compile failure — `buildHandlers` undefined.

- [ ] **Step 3: Extract `buildHandlers` and add rubygems + yarn alias**

In `cmd/sca-proxy/main.go`, replace the inline handler-map construction in `runProxy`:
```go
	// Build one handler per enabled registry, keyed by routing prefix.
	handlers := map[string]*proxy.Handler{}
	if cfg.Registries.PyPI.Enabled {
		handlers["pypi"] = buildHandler(adapters.NewPyPIAdapter(cfg.Registries.PyPI.Upstreams), shared)
	}
	if cfg.Registries.NPM.Enabled {
		handlers["npm"] = buildHandler(adapters.NewNPMAdapter(cfg.Registries.NPM.Upstreams), shared)
	}
	if cfg.Registries.Maven.Enabled {
		handlers["maven"] = buildHandler(adapters.NewMavenAdapter(cfg.Registries.Maven.Upstreams), shared)
	}

	if len(handlers) == 0 {
		return fmt.Errorf("no registries enabled; set at least one of registries.{pypi,npm,maven}.enabled: true")
	}
```
with:
```go
	// Build the prefix→handler routing map from config.
	handlers := buildHandlers(cfg, shared)

	if len(handlers) == 0 {
		return fmt.Errorf("no registries enabled; set at least one of registries.{pypi,npm,maven,rubygems}.enabled: true")
	}
```

Then add this function to `cmd/sca-proxy/main.go` (next to `buildHandler`):
```go
// buildHandlers constructs the routing map of prefix→handler from config.
// The "yarn" prefix is an alias for the npm handler, since yarn speaks the npm
// registry protocol.
func buildHandlers(cfg *config.Config, shared sharedDeps) map[string]*proxy.Handler {
	handlers := map[string]*proxy.Handler{}
	if cfg.Registries.PyPI.Enabled {
		handlers["pypi"] = buildHandler(adapters.NewPyPIAdapter(cfg.Registries.PyPI.Upstreams), shared)
	}
	if cfg.Registries.NPM.Enabled {
		npmHandler := buildHandler(adapters.NewNPMAdapter(cfg.Registries.NPM.Upstreams), shared)
		handlers["npm"] = npmHandler
		handlers["yarn"] = npmHandler
	}
	if cfg.Registries.Maven.Enabled {
		handlers["maven"] = buildHandler(adapters.NewMavenAdapter(cfg.Registries.Maven.Upstreams), shared)
	}
	if cfg.Registries.RubyGems.Enabled {
		handlers["rubygems"] = buildHandler(adapters.NewRubyGemsAdapter(cfg.Registries.RubyGems.Upstreams), shared)
	}
	return handlers
}
```
(`cfg` in `runProxy` is already a `*config.Config` returned by `config.Load`, so `buildHandlers(cfg, shared)` type-checks.)

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./cmd/sca-proxy/...`
Expected: PASS.

- [ ] **Step 5: Update the startup log line (optional consistency)**

If `runProxy` logs an `Int("registries", len(handlers))` line, leave it as-is — the count now includes the yarn alias, which is acceptable. No change required.

- [ ] **Step 6: Build and commit**

Run: `go build ./... && go test ./...`
Expected: PASS.
```bash
git add cmd/sca-proxy
git commit -m "feat(main): register rubygems handler and alias /yarn/ to npm"
```

---

## Task 5: RubyGems integration test + docs

**Files:**
- Create: `integration/rubygems_test.go`
- Modify: `README.md`

- [ ] **Step 1: Write the integration test**

Create `integration/rubygems_test.go`. It reuses the package's existing `localCacheAdapter` (defined in `integration/phase1_test.go`). The first upstream 404s; the second serves `versions.json` (old `created_at`) and the `.gem`:
```go
//go:build integration

package integration_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sca-proxy/sca-proxy/internal/cache"
	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_RubyGemsFallsBackToSecondUpstream(t *testing.T) {
	createdAt := time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/versions/") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"number":"7.0.4","platform":"ruby","created_at":"` + createdAt + `","licenses":["MIT"],"sha":"abc123"}]`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("gem-bytes"))
	}))
	defer up.Close()

	dir := t.TempDir()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)

	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewRubyGemsAdapter([]string{down.URL, up.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   &localCacheAdapter{lc: lc},
		Logger:  zerolog.Nop(),
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/gems/rails-7.0.4.gem")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
```
Before writing, confirm the `localCacheAdapter` type name and `cache.LocalCacheConfig` fields by reading `integration/phase1_test.go` (they are: `localCacheAdapter{lc: *cache.LocalCache}` and `LocalCacheConfig{RootPath, MaxSizeGB, TTL}`).

- [ ] **Step 2: Run the integration test**

Run: `go test -tags integration ./integration/ -run RubyGemsFallsBack -v`
Expected: PASS. If it fails to compile, align the cache wiring with `phase1_test.go`.

- [ ] **Step 3: Update README — Yarn and RubyGems sections**

In `README.md`, add usage subsections matching the existing pip/npm style.

Yarn (under the package-manager configuration area):
```markdown
**yarn** (uses the npm registry protocol via the `/yarn/` alias):
\`\`\`bash
# Yarn Berry (v2+)
yarn config set npmRegistryServer http://localhost:8080/yarn/
# Yarn Classic (v1)
yarn config set registry http://localhost:8080/yarn/
\`\`\`
```

RubyGems:
```markdown
**RubyGems / Bundler:**
\`\`\`bash
# bundler
bundle config mirror.https://rubygems.org http://localhost:8080/rubygems
# or set the source in a Gemfile:
#   source "http://localhost:8080/rubygems"
\`\`\`
```

Also add `rubygems` to any config example listing the registries block, mirroring:
```yaml
  rubygems:
    upstreams:
      - "https://rubygems.org"
    enabled: true
```

- [ ] **Step 4: Run the full suite**

Run: `go build ./... && go test ./... && go test -tags integration ./integration/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add integration/rubygems_test.go README.md
git commit -m "test: RubyGems multi-upstream integration; docs: Yarn + RubyGems usage"
```

---

## Self-Review Notes

- **Spec coverage:** config `rubygems` + validation (Task 1); RubyGems adapter — NormalizeRequest parse incl. hyphenated names + platform suffix, FetchMetadata via `/api/v1/versions/<gem>.json` with `number`+`platform` match, multi-upstream fallback, `UpstreamURLs` (Task 2); OSV `rubygems→RubyGems` map + platform-strip (Task 3); Yarn `/yarn/`→npm alias + rubygems registration via testable `buildHandlers` (Task 4); integration + README Yarn/RubyGems docs (Task 5). Out-of-scope items (tarball rewriting, compact-index merge, Go) intentionally absent.
- **Type consistency:** `RubyGemsAdapter`, `NewRubyGemsAdapter([]string)`, `parseGemFilename`, `splitGemVersion`, `rubygemsVersion{Number,Platform,CreatedAt,Licenses,SHA}`, `buildHandlers(*config.Config, sharedDeps) map[string]*proxy.Handler` used consistently. `PackageRef.Version` carries the encoded `<number>[-<platform>]` everywhere; OSV strips it; FetchMetadata decodes it via `splitGemVersion`.
- **Green checkpoints:** full `go build ./... && go test ./...` at the end of every task; integration suite verified in Task 5.
- **Parsing limitation (accepted per spec):** a gem whose name has a hyphen-separated segment starting with a digit (e.g. `foo-2bar-1.0.0`) would mis-split; this is the documented "first digit-led segment = version" heuristic and is acceptable for this phase.

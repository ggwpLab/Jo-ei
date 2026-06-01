# Multi-Upstream Registries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let each registry provider (`pypi`, `npm`, `maven`) point at an ordered list of upstream repositories, trying them in order (sequential fallback) for metadata, downloads, and transparent proxying.

**Architecture:** Replace the single `upstream` string with an ordered `upstreams` list throughout config and adapters. Each operation walks the list per-request (Nexus-style): first success wins, any failure (404/410/5xx/timeout/conn-refused) advances to the next. Adapters own URL construction and metadata parsing; the handler owns the fallback walk and the failure→HTTP-status mapping.

**Tech Stack:** Go, `spf13/viper` (config), `rs/zerolog` (logging), `stretchr/testify` (tests), `net/http/httptest` (test servers).

**Spec:** `docs/superpowers/specs/2026-06-01-multi-upstream-registries-design.md`

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `internal/config/config.go` | Config types + load + validation | `Upstream string` → `Upstreams []string`; add `Validate()` |
| `internal/config/config_test.go` | Config tests | Update YAML to `upstreams:`; add validation tests |
| `internal/proxy/adapter.go` | `RegistryAdapter` interface + shared types | `UpstreamURL` → `UpstreamURLs` |
| `internal/proxy/adapters/{pypi,npm,maven}.go` | Per-ecosystem URL build + metadata parse | Slice field, slice ctor, `UpstreamURLs`, `FetchMetadata` fallback |
| `internal/proxy/adapters/{pypi,npm,maven}_test.go` | Adapter tests | Slice ctors; metadata-fallback tests |
| `internal/proxy/handler.go` | Fallback walk + HTTP mapping | Download fallback; transparent-proxy fallback; drop `HandlerConfig.Upstream` |
| `internal/proxy/handler_test.go` | Handler tests | Slice ctors; download/transparent fallback tests |
| `internal/proxy/mux_test.go` | Mux tests | Slice ctors; drop `Upstream:` |
| `cmd/sca-proxy/main.go` | Wiring | Pass `cfg.Registries.X.Upstreams`; drop `Upstream:` |
| `integration/phase{1,2,3}_test.go` | Integration tests | Slice ctors; drop `Upstream:`; new multi-upstream test |
| `config.yaml` | Sample config | `upstream:` → `upstreams:` lists |
| `README.md` | Docs | Document `upstreams` list + fallback |

---

## Task 1: Slice plumbing + adapter metadata fallback

Converts config + adapters + interface + main to the `upstreams` list and gives
`FetchMetadata` sequential fallback. Handler gets a minimal compile-fix only
(behaviour unchanged — uses the first candidate); real download fallback is Task 2.

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `internal/proxy/adapter.go`
- Modify: `internal/proxy/adapters/pypi.go`, `internal/proxy/adapters/npm.go`, `internal/proxy/adapters/maven.go`
- Modify: `internal/proxy/adapters/pypi_test.go`, `internal/proxy/adapters/npm_test.go`, `internal/proxy/adapters/maven_test.go`
- Modify: `internal/proxy/handler.go`
- Modify: `internal/proxy/handler_test.go`, `internal/proxy/mux_test.go`
- Modify: `integration/phase1_test.go`, `integration/phase2_test.go`, `integration/phase3_test.go`
- Modify: `cmd/sca-proxy/main.go`
- Modify: `config.yaml`

- [ ] **Step 1: Write the failing config tests**

In `internal/config/config_test.go`, change the `TestLoad_ParsesYAML` registry
block and assertion to use the list form, and add two new tests at the end of the file:

Replace inside `TestLoad_ParsesYAML` the `registries:` block:
```go
registries:
  pypi:
    upstreams:
      - "https://pypi.org"
      - "https://mirror.example.org/pypi"
    enabled: true
```
and replace its assertion:
```go
	assert.Equal(t, []string{"https://pypi.org", "https://mirror.example.org/pypi"}, cfg.Registries.PyPI.Upstreams)
```

Add new tests:
```go
func TestLoad_ParsesMavenUpstreamsList(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  maven:
    enabled: true
    upstreams:
      - "https://repo1.maven.org/maven2"
      - "https://repo.spring.io/release"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"https://repo1.maven.org/maven2",
		"https://repo.spring.io/release",
	}, cfg.Registries.Maven.Upstreams)
}

func TestLoad_EnabledRegistryWithoutUpstreamsFails(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  npm:
    enabled: true
    upstreams: []
`)
	_, err := config.Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "npm")
}

func TestLoad_DisabledRegistryWithoutUpstreamsOK(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
registries:
  npm:
    enabled: false
`)
	_, err := config.Load(path)
	require.NoError(t, err)
}
```

- [ ] **Step 2: Run config tests to verify they fail**

Run: `go test ./internal/config/...`
Expected: compile failure — `cfg.Registries.PyPI.Upstreams` undefined (field is still `Upstream`).

- [ ] **Step 3: Change the config struct and add validation**

In `internal/config/config.go`, change `RegistryConfig`:
```go
type RegistryConfig struct {
	Upstreams []string `mapstructure:"upstreams"`
	Enabled   bool     `mapstructure:"enabled"`
}
```

Add a `Validate` method (place it just below the `Config` type):
```go
// Validate checks cross-field invariants after loading.
func (c *Config) Validate() error {
	regs := map[string]RegistryConfig{
		"pypi":  c.Registries.PyPI,
		"npm":   c.Registries.NPM,
		"maven": c.Registries.Maven,
	}
	for name, rc := range regs {
		if rc.Enabled && len(rc.Upstreams) == 0 {
			return fmt.Errorf("registry %q is enabled but has no upstreams", name)
		}
	}
	return nil
}
```

Call it at the end of `Load`, replacing `return &cfg, nil`:
```go
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
```

- [ ] **Step 4: Run config tests to verify they pass**

Run: `go test ./internal/config/...`
Expected: PASS. (Repo-wide build is temporarily broken; fixed by later steps in this task.)

- [ ] **Step 5: Rename the interface method**

In `internal/proxy/adapter.go`, replace the `UpstreamURL` line in `RegistryAdapter`:
```go
	// UpstreamURLs returns one candidate upstream URL per configured upstream,
	// in priority order, for the given proxy request path.
	UpstreamURLs(r *http.Request) []string
```

- [ ] **Step 6: Write the failing Maven metadata-fallback test**

In `internal/proxy/adapters/maven_test.go`, add:
```go
func TestMavenAdapter_FetchMetadata_FallsBackToSecondUpstream(t *testing.T) {
	lastModified := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	a := adapters.NewMavenAdapter([]string{down.URL, up.URL})
	ref := &proxy.PackageRef{Ecosystem: "maven", Name: "com.google.guava:guava", Version: "31.0.1-jre"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, lastModified, meta.PublishedAt, time.Second)
}

func TestMavenAdapter_FetchMetadata_AllUpstreamsFail(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()

	a := adapters.NewMavenAdapter([]string{down.URL, down.URL})
	ref := &proxy.PackageRef{Ecosystem: "maven", Name: "com.google.guava:guava", Version: "31.0.1-jre"}
	_, err := a.FetchMetadata(context.Background(), ref)
	require.Error(t, err)
}

func TestMavenAdapter_UpstreamURLs_OnePerUpstream(t *testing.T) {
	a := adapters.NewMavenAdapter([]string{
		"https://repo1.maven.org/maven2/",
		"https://repo.spring.io/release",
	})
	r := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar", nil)
	urls := a.UpstreamURLs(r)
	assert.Equal(t, []string{
		"https://repo1.maven.org/maven2/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar",
		"https://repo.spring.io/release/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar",
	}, urls)
}
```

Also update every existing `adapters.NewMavenAdapter("...")` call in this file to
the slice form, e.g. `adapters.NewMavenAdapter([]string{"https://repo1.maven.org/maven2"})`
and `adapters.NewMavenAdapter([]string{srv.URL})`.

- [ ] **Step 7: Run Maven adapter tests to verify they fail**

Run: `go test ./internal/proxy/adapters/ -run Maven`
Expected: compile failure — `NewMavenAdapter` wants `string`, and `UpstreamURLs` undefined.

- [ ] **Step 8: Convert the Maven adapter to slice upstreams + fallback**

In `internal/proxy/adapters/maven.go`:

Change the struct field:
```go
type MavenAdapter struct {
	upstreams  []string
	httpClient *http.Client
}
```

Change the constructor:
```go
// NewMavenAdapter creates a Maven adapter over the given ordered upstream URLs
// (e.g. "https://repo1.maven.org/maven2"). Upstreams are tried in order.
func NewMavenAdapter(upstreams []string) *MavenAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &MavenAdapter{
		upstreams:  trimmed,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}
```

Replace `FetchMetadata` with a fallback wrapper + per-upstream helper:
```go
// FetchMetadata walks the configured upstreams in order, returning the first
// success. The current body is parameterised by a single base URL.
func (a *MavenAdapter) FetchMetadata(ctx context.Context, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	lastErr := fmt.Errorf("no upstreams configured for maven")
	for _, base := range a.upstreams {
		meta, err := a.fetchMetadataFrom(ctx, base, ref)
		if err == nil {
			return meta, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (a *MavenAdapter) fetchMetadataFrom(ctx context.Context, base string, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	parts := strings.SplitN(ref.Name, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid maven name %q (want group:artifact)", ref.Name)
	}
	group, artifact := parts[0], parts[1]
	groupPath := strings.ReplaceAll(group, ".", "/")
	pomURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom",
		base, groupPath, artifact, ref.Version, artifact, ref.Version)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, pomURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building maven HEAD request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching maven artifact head: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("maven returned HTTP %d for %s", resp.StatusCode, ref.Key())
	}

	meta := &proxy.PackageMetadata{}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			meta.PublishedAt = t.UTC()
		}
	}
	return meta, nil
}
```

Replace `UpstreamURL` with `UpstreamURLs`:
```go
// UpstreamURLs returns one candidate URL per configured upstream, in order.
func (a *MavenAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}
```

- [ ] **Step 9: Run Maven adapter tests to verify they pass**

Run: `go test ./internal/proxy/adapters/ -run Maven`
Expected: PASS.

- [ ] **Step 10: Write failing PyPI + npm adapter tests**

In `internal/proxy/adapters/pypi_test.go`, update every `adapters.NewPyPIAdapter("...")`
and `adapters.NewPyPIAdapter(srv.URL)` to the slice form (`[]string{...}`), then add:
```go
func TestPyPIAdapter_FetchMetadata_FallsBackToSecondUpstream(t *testing.T) {
	published := time.Now().UTC().Add(-72 * time.Hour)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"info": map[string]any{"name": "requests", "version": "2.31.0", "license": "MIT", "author": "x"},
			"urls": []map[string]any{{
				"upload_time_iso_8601": published.Format(time.RFC3339),
				"url":                  "https://example.com/requests.whl",
				"digests":              map[string]any{"sha256": "abc"},
			}},
		})
	}))
	defer up.Close()

	a := adapters.NewPyPIAdapter([]string{down.URL, up.URL})
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, published, meta.PublishedAt, time.Second)
}

func TestPyPIAdapter_UpstreamURLs_OnePerUpstream(t *testing.T) {
	a := adapters.NewPyPIAdapter([]string{"https://pypi.org/", "https://mirror.example.org"})
	r := httptest.NewRequest(http.MethodGet, "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl", nil)
	urls := a.UpstreamURLs(r)
	assert.Equal(t, []string{
		"https://pypi.org/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl",
		"https://mirror.example.org/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl",
	}, urls)
}
```
Ensure `encoding/json`, `net/http/httptest`, and `time` are imported in this test file.

In `internal/proxy/adapters/npm_test.go`, update every `adapters.NewNPMAdapter(...)`
call to the slice form, then add:
```go
func TestNPMAdapter_FetchMetadata_FallsBackToSecondUpstream(t *testing.T) {
	published := time.Now().UTC().Add(-72 * time.Hour)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"time": map[string]string{"1.0.0": published.Format(time.RFC3339)},
			"versions": map[string]any{
				"1.0.0": map[string]any{"license": "MIT", "dist": map[string]any{"shasum": "abc"}},
			},
		})
	}))
	defer up.Close()

	a := adapters.NewNPMAdapter([]string{down.URL, up.URL})
	ref := &proxy.PackageRef{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, published, meta.PublishedAt, time.Second)
}

func TestNPMAdapter_UpstreamURLs_OnePerUpstream(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org/", "https://mirror.example.org"})
	r := httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-1.0.0.tgz", nil)
	urls := a.UpstreamURLs(r)
	assert.Equal(t, []string{
		"https://registry.npmjs.org/lodash/-/lodash-1.0.0.tgz",
		"https://mirror.example.org/lodash/-/lodash-1.0.0.tgz",
	}, urls)
}
```
Ensure `encoding/json`, `net/http/httptest`, and `time` are imported.

- [ ] **Step 11: Run PyPI + npm adapter tests to verify they fail**

Run: `go test ./internal/proxy/adapters/ -run 'PyPI|NPM'`
Expected: compile failure — slice ctors / `UpstreamURLs` not yet implemented.

- [ ] **Step 12: Convert the PyPI adapter**

In `internal/proxy/adapters/pypi.go`:

Struct field → `upstreams []string`. Constructor:
```go
func NewPyPIAdapter(upstreams []string) *PyPIAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &PyPIAdapter{
		upstreams:  trimmed,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}
```

Replace `FetchMetadata` with wrapper + helper:
```go
func (a *PyPIAdapter) FetchMetadata(ctx context.Context, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	lastErr := fmt.Errorf("no upstreams configured for pypi")
	for _, base := range a.upstreams {
		meta, err := a.fetchMetadataFrom(ctx, base, ref)
		if err == nil {
			return meta, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (a *PyPIAdapter) fetchMetadataFrom(ctx context.Context, base string, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	apiURL := fmt.Sprintf("%s/pypi/%s/%s/json", base, ref.Name, ref.Version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building metadata request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching pypi metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %s@%s not found on PyPI", ref.Name, ref.Version)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi returned HTTP %d", resp.StatusCode)
	}

	var info pypiJSONResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding pypi response: %w", err)
	}
	if len(info.URLs) == 0 {
		return nil, fmt.Errorf("no download URLs in pypi response for %s@%s", ref.Name, ref.Version)
	}

	publishedAt, err := time.Parse(time.RFC3339, info.URLs[0].UploadTimeISO)
	if err != nil {
		publishedAt, err = time.Parse("2006-01-02T15:04:05.999999Z07:00", info.URLs[0].UploadTimeISO)
		if err != nil {
			return nil, fmt.Errorf("parsing upload_time_iso_8601 %q: %w", info.URLs[0].UploadTimeISO, err)
		}
	}
	return &proxy.PackageMetadata{
		PublishedAt: publishedAt.UTC(),
		Maintainer:  info.Info.Author,
		License:     info.Info.License,
		Checksum:    info.URLs[0].Digests.SHA256,
	}, nil
}
```

Replace `UpstreamURL`:
```go
func (a *PyPIAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}
```

- [ ] **Step 13: Convert the npm adapter**

In `internal/proxy/adapters/npm.go`:

Struct field → `upstreams []string`. Constructor:
```go
func NewNPMAdapter(upstreams []string) *NPMAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &NPMAdapter{
		upstreams:  trimmed,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}
```

Replace `FetchMetadata`:
```go
func (a *NPMAdapter) FetchMetadata(ctx context.Context, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	lastErr := fmt.Errorf("no upstreams configured for npm")
	for _, base := range a.upstreams {
		meta, err := a.fetchMetadataFrom(ctx, base, ref)
		if err == nil {
			return meta, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (a *NPMAdapter) fetchMetadataFrom(ctx context.Context, base string, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	apiURL := base + "/" + ref.Name

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building npm metadata request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching npm metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm returned HTTP %d for %s", resp.StatusCode, ref.Name)
	}

	var doc npmMetadata
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding npm response: %w", err)
	}
	publishedStr, ok := doc.Time[ref.Version]
	if !ok {
		return nil, fmt.Errorf("version %s not found in npm metadata for %s", ref.Version, ref.Name)
	}
	publishedAt, err := time.Parse(time.RFC3339, publishedStr)
	if err != nil {
		return nil, fmt.Errorf("parsing npm publish time %q: %w", publishedStr, err)
	}
	versionInfo, ok := doc.Versions[ref.Version]
	if !ok {
		return nil, fmt.Errorf("version %s missing from npm versions map for %s", ref.Version, ref.Name)
	}
	return &proxy.PackageMetadata{
		PublishedAt: publishedAt.UTC(),
		License:     versionInfo.License,
		Checksum:    versionInfo.Dist.Shasum,
	}, nil
}
```

Replace `UpstreamURL`:
```go
func (a *NPMAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}
```

- [ ] **Step 14: Run all adapter tests to verify they pass**

Run: `go test ./internal/proxy/adapters/...`
Expected: PASS.

- [ ] **Step 15: Minimal handler compile-fix**

In `internal/proxy/handler.go`, replace the download line:
```go
	upstreamURL := h.cfg.Adapter.UpstreamURL(r)
```
with (uses the first candidate — behaviour unchanged; real fallback in Task 2):
```go
	upstreamURL := h.cfg.Adapter.UpstreamURLs(r)[0]
```

- [ ] **Step 16: Update handler/mux/integration adapter constructor call sites**

These files construct adapters with a string and must switch to the slice form
(leave any `Upstream:` HandlerConfig fields untouched for now — removed in Task 3):

- `internal/proxy/handler_test.go`: every `adapters.NewPyPIAdapter(upstream.URL)` → `adapters.NewPyPIAdapter([]string{upstream.URL})`.
- `internal/proxy/mux_test.go`: every `adapters.New*Adapter(upstream.URL)` → slice form.
- `integration/phase1_test.go`, `integration/phase2_test.go`, `integration/phase3_test.go`: every `adapters.New*Adapter(<x>.URL)` → slice form.

- [ ] **Step 17: Update main.go wiring**

In `cmd/sca-proxy/main.go`, update the three handler-build calls to pass slices:
```go
	if cfg.Registries.PyPI.Enabled {
		handlers["pypi"] = buildHandler(adapters.NewPyPIAdapter(cfg.Registries.PyPI.Upstreams),
			cfg.Registries.PyPI.Upstreams, shared)
	}
	if cfg.Registries.NPM.Enabled {
		handlers["npm"] = buildHandler(adapters.NewNPMAdapter(cfg.Registries.NPM.Upstreams),
			cfg.Registries.NPM.Upstreams, shared)
	}
	if cfg.Registries.Maven.Enabled {
		handlers["maven"] = buildHandler(adapters.NewMavenAdapter(cfg.Registries.Maven.Upstreams),
			cfg.Registries.Maven.Upstreams, shared)
	}
```

Change `buildHandler`'s second parameter type from `string` to `[]string` and the
`HandlerConfig.Upstream` field it sets — since `Upstream` is still a `string` in
this task, set it to the first element:
```go
func buildHandler(adapter proxy.RegistryAdapter, upstreams []string, shared sharedDeps) *proxy.Handler {
	upstream := ""
	if len(upstreams) > 0 {
		upstream = upstreams[0]
	}
	return proxy.NewHandler(proxy.HandlerConfig{
		Adapter:    adapter,
		Filter:     shared.filter,
		Cache:      shared.cache,
		Logger:     shared.logger,
		Upstream:   upstream,
		CVEScanner: shared.cveScanner,
		Policy:     shared.policy,
		AVScanner:  shared.avScanner,
	})
}
```

- [ ] **Step 18: Update config.yaml**

In `config.yaml`, replace the `registries:` block:
```yaml
registries:
  pypi:
    upstreams:
      - "https://pypi.org"
    enabled: true
  npm:
    upstreams:
      - "https://registry.npmjs.org"
    enabled: true
  maven:
    upstreams:
      - "https://repo1.maven.org/maven2"
      - "https://repo.spring.io/release"
    enabled: true
```

- [ ] **Step 19: Run full build and test suite**

Run: `go build ./... && go test ./...`
Expected: PASS (all packages compile; behaviour for single-element lists is unchanged from before).

- [ ] **Step 20: Commit**

```bash
git add internal config.yaml cmd
git commit -m "feat: configure registries with an ordered upstreams list + metadata fallback"
```

---

## Task 2: Handler artifact-download fallback

Walk all download candidates; map exhaustion to 404 (all 404/410) or 502 (any other failure).

**Files:**
- Modify: `internal/proxy/handler.go`
- Test: `internal/proxy/handler_test.go`

- [ ] **Step 1: Write the failing download-fallback tests**

In `internal/proxy/handler_test.go`, add a helper and tests. The helper builds a
PyPI-backed handler over two upstreams; `metaSrv` serves the JSON metadata (so the
age check passes) and 404s the artifact, `artifactSrv` serves the artifact:
```go
// setupTwoUpstreamProxy builds a PyPI handler over [first, second].
func setupTwoUpstreamProxy(t *testing.T, first, second *httptest.Server) *httptest.Server {
	t.Helper()
	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewPyPIAdapter([]string{first.URL, second.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   newFakeCache(),
		Logger:  zerolog.Nop(),
	})
	return httptest.NewServer(handler)
}

func TestHandler_DownloadFallsBackToSecondUpstream(t *testing.T) {
	published := time.Now().UTC().Add(-48 * time.Hour)
	metaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/pypi/") {
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{"name": "requests", "version": "2.31.0", "license": "MIT", "author": "x"},
				"urls": []map[string]any{{
					"upload_time_iso_8601": published.Format(time.RFC3339),
					"url":                  "https://example.com/requests.whl",
					"digests":              map[string]any{"sha256": "abc"},
				}},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound) // artifact missing here
	}))
	defer metaSrv.Close()
	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("wheel-bytes"))
	}))
	defer artifactSrv.Close()

	srv := setupTwoUpstreamProxy(t, metaSrv, artifactSrv)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "wheel-bytes", string(body))
}

func TestHandler_DownloadAllNotFoundReturns404(t *testing.T) {
	published := time.Now().UTC().Add(-48 * time.Hour)
	meta := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/pypi/") {
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{"name": "requests", "version": "2.31.0", "license": "MIT", "author": "x"},
				"urls": []map[string]any{{
					"upload_time_iso_8601": published.Format(time.RFC3339),
					"url":                  "https://example.com/requests.whl",
					"digests":              map[string]any{"sha256": "abc"},
				}},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
	a := httptest.NewServer(http.HandlerFunc(meta))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(meta))
	defer b.Close()

	srv := setupTwoUpstreamProxy(t, a, b)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandler_DownloadServerErrorReturns502(t *testing.T) {
	published := time.Now().UTC().Add(-48 * time.Hour)
	meta := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/pypi/") {
			json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{"name": "requests", "version": "2.31.0", "license": "MIT", "author": "x"},
				"urls": []map[string]any{{
					"upload_time_iso_8601": published.Format(time.RFC3339),
					"url":                  "https://example.com/requests.whl",
					"digests":              map[string]any{"sha256": "abc"},
				}},
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError) // not a 404
	}
	a := httptest.NewServer(http.HandlerFunc(meta))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(meta))
	defer b.Close()

	srv := setupTwoUpstreamProxy(t, a, b)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
}
```

- [ ] **Step 2: Run download-fallback tests to verify they fail**

Run: `go test ./internal/proxy/ -run 'Handler_Download'`
Expected: FAIL — `TestHandler_DownloadFallsBackToSecondUpstream` gets 502 (only first candidate used), and the 404 test gets 502.

- [ ] **Step 3: Replace downloadToTemp with a status-aware variant**

In `internal/proxy/handler.go`, replace the `downloadToTemp` method with:
```go
// tryDownload downloads url to a temp file. Returns the temp path on HTTP 200.
// statusCode is the upstream HTTP status (0 on transport error). The caller
// removes the file.
func (h *Handler) tryDownload(ctx context.Context, url string) (tmpPath string, statusCode int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, fmt.Errorf("upstream returned HTTP %d for %s", resp.StatusCode, url)
	}

	tmp, err := os.CreateTemp("", "sca-proxy-artifact-*")
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("creating temp file: %w", err)
	}
	defer tmp.Close()
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		os.Remove(tmp.Name())
		return "", resp.StatusCode, fmt.Errorf("writing temp file: %w", err)
	}
	return tmp.Name(), resp.StatusCode, nil
}

// downloadFromUpstreams tries each candidate URL in order, returning the first
// HTTP 200. allNotFound is true iff every attempt returned 404/410 (no other
// failure occurred), which the caller maps to a 404 instead of 502.
func (h *Handler) downloadFromUpstreams(ctx context.Context, urls []string) (tmpPath string, allNotFound bool, err error) {
	allNotFound = true
	for _, u := range urls {
		path, status, derr := h.tryDownload(ctx, u)
		if derr == nil {
			return path, false, nil
		}
		if status != http.StatusNotFound && status != http.StatusGone {
			allNotFound = false
		}
		err = derr
	}
	return "", allNotFound, err
}
```

- [ ] **Step 4: Use the fallback walk in ServeHTTP**

In `internal/proxy/handler.go`, replace the download block:
```go
	// Download artifact from upstream to a temp file
	upstreamURL := h.cfg.Adapter.UpstreamURLs(r)[0]
	tmpPath, err := h.downloadToTemp(ctx, upstreamURL)
	if err != nil {
		log.Error().Err(err).Str("upstream_url", upstreamURL).Msg("failed to download artifact")
		h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer os.Remove(tmpPath)
```
with:
```go
	// Download artifact, trying each configured upstream in order.
	upstreamURLs := h.cfg.Adapter.UpstreamURLs(r)
	tmpPath, allNotFound, err := h.downloadFromUpstreams(ctx, upstreamURLs)
	if err != nil {
		if allNotFound {
			log.Warn().Strs("upstream_urls", upstreamURLs).Msg("artifact not found on any upstream")
			h.writeError(w, requestID, ref, http.StatusNotFound, "artifact_not_found")
			return
		}
		log.Error().Err(err).Strs("upstream_urls", upstreamURLs).Msg("failed to download artifact")
		h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer os.Remove(tmpPath)
```

- [ ] **Step 5: Run handler tests to verify they pass**

Run: `go test ./internal/proxy/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/proxy
git commit -m "feat: sequential fallback for artifact downloads (404 vs 502 mapping)"
```

---

## Task 3: Transparent-proxy fallback + drop HandlerConfig.Upstream

Make metadata/listing requests walk all upstreams; remove the now-unused single `Upstream` field.

**Files:**
- Modify: `internal/proxy/handler.go`
- Test: `internal/proxy/handler_test.go`
- Modify: `internal/proxy/mux_test.go`, `cmd/sca-proxy/main.go`
- Modify: `integration/phase1_test.go`, `integration/phase2_test.go`, `integration/phase3_test.go`

- [ ] **Step 1: Write the failing transparent-proxy fallback test**

In `internal/proxy/handler_test.go`, add:
```go
func TestHandler_TransparentProxyFallsBackToSecondUpstream(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("simple-index-html"))
	}))
	defer up.Close()

	srv := setupTwoUpstreamProxy(t, down, up)
	defer srv.Close()

	// /simple/ is a metadata path (not intercepted) → transparent proxy.
	resp, err := http.Get(srv.URL + "/simple/requests/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "simple-index-html", string(body))
}

func TestHandler_TransparentProxyAllNotFoundReturns404(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()

	srv := setupTwoUpstreamProxy(t, down, down)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/simple/nonexistent/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/proxy/ -run 'Handler_TransparentProxy'`
Expected: compile failure first if `setupTwoUpstreamProxy` still passes `Upstream:` after its removal — but at this step the field still exists, so the failure is behavioural: the fallback test sees the first upstream's 404 (single-upstream transparent proxy), not the second upstream's body.

- [ ] **Step 3: Rewrite proxyTransparent to walk upstreams**

In `internal/proxy/handler.go`, replace the whole `proxyTransparent` method with:
```go
// proxyTransparent forwards a non-intercepted request to each configured
// upstream in order, streaming back the first response with status < 400.
// If all fail, returns 404 (all were 404/410) or 502.
func (h *Handler) proxyTransparent(w http.ResponseWriter, r *http.Request) {
	urls := h.cfg.Adapter.UpstreamURLs(r)

	// Buffer the request body once so it can be replayed across attempts.
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		r.Body.Close()
	}

	allNotFound := true
	for _, url := range urls {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, url, bytes.NewReader(body))
		if err != nil {
			allNotFound = false
			continue
		}
		for key, vals := range r.Header {
			for _, v := range vals {
				req.Header.Add(key, v)
			}
		}
		for _, hop := range hopByHopHeaders {
			req.Header.Del(hop)
		}

		resp, err := h.httpClient.Do(req)
		if err != nil {
			allNotFound = false
			continue
		}
		if resp.StatusCode < 400 {
			for key, vals := range resp.Header {
				for _, v := range vals {
					w.Header().Add(key, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			if _, err := io.Copy(w, resp.Body); err != nil {
				h.cfg.Logger.Error().Err(err).Msg("error streaming proxy response")
			}
			resp.Body.Close()
			return
		}
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusGone {
			allNotFound = false
		}
		resp.Body.Close()
	}

	if allNotFound {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	http.Error(w, "upstream unavailable", http.StatusBadGateway)
}
```
Add `"bytes"` to the import block in `internal/proxy/handler.go`.

- [ ] **Step 4: Remove the unused HandlerConfig.Upstream field**

In `internal/proxy/handler.go`, delete the `Upstream string` line from `HandlerConfig`.

- [ ] **Step 5: Drop Upstream from all HandlerConfig literals**

Remove the `Upstream:` line from every `proxy.HandlerConfig{...}` literal in:
- `internal/proxy/handler_test.go` (in `setupTestProxy`, `setupTestProxyCVE`, `setupTestProxyAV`)
- `internal/proxy/mux_test.go` (its `buildHandlerFor` helper)
- `integration/phase1_test.go`, `integration/phase2_test.go`, `integration/phase3_test.go`
- `cmd/sca-proxy/main.go` (`buildHandler`): remove the `upstream` local, the `Upstream:` field, and the now-unused second parameter. Update its signature to `buildHandler(adapter proxy.RegistryAdapter, shared sharedDeps)` and the three call sites to drop the upstreams argument:
```go
	if cfg.Registries.PyPI.Enabled {
		handlers["pypi"] = buildHandler(adapters.NewPyPIAdapter(cfg.Registries.PyPI.Upstreams), shared)
	}
	if cfg.Registries.NPM.Enabled {
		handlers["npm"] = buildHandler(adapters.NewNPMAdapter(cfg.Registries.NPM.Upstreams), shared)
	}
	if cfg.Registries.Maven.Enabled {
		handlers["maven"] = buildHandler(adapters.NewMavenAdapter(cfg.Registries.Maven.Upstreams), shared)
	}
```
```go
func buildHandler(adapter proxy.RegistryAdapter, shared sharedDeps) *proxy.Handler {
	return proxy.NewHandler(proxy.HandlerConfig{
		Adapter:    adapter,
		Filter:     shared.filter,
		Cache:      shared.cache,
		Logger:     shared.logger,
		CVEScanner: shared.cveScanner,
		Policy:     shared.policy,
		AVScanner:  shared.avScanner,
	})
}
```

- [ ] **Step 6: Run full build and test suite**

Run: `go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal cmd integration
git commit -m "feat: sequential fallback for transparent proxy; drop single-upstream field"
```

---

## Task 4: Integration test + docs

End-to-end multi-upstream coverage and updated docs.

**Files:**
- Modify: `integration/phase3_test.go` (or a new `integration/multiupstream_test.go`)
- Modify: `README.md`

- [ ] **Step 1: Write the failing integration test**

Create `integration/multiupstream_test.go`. It points a Maven handler at two
upstreams: the first 404s everything, the second serves both the `.pom` HEAD
(metadata) and the `.jar` (artifact). Match the existing integration style
(see `integration/phase3_test.go` for the Maven setup, the supply-chain filter,
the fake cache, and how the handler is wrapped in `httptest.NewServer`). The test
asserts the request succeeds and the body comes from the second upstream:
```go
package integration

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_MavenFallsBackToSecondUpstream(t *testing.T) {
	lastModified := time.Now().UTC().Add(-72 * time.Hour)

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".pom") {
			w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("jar-bytes"))
	}))
	defer up.Close()

	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewMavenAdapter([]string{down.URL, up.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   newIntegrationCache(t),
		Logger:  zerolog.Nop(),
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
```
If `integration` has no shared cache helper, reuse the cache construction already
used in `integration/phase3_test.go` (copy that handler's `Cache:` value) instead
of `newIntegrationCache(t)`, and drop the helper reference. Confirm the actual
helper/cache name by reading `integration/phase3_test.go` before writing this.

- [ ] **Step 2: Run the integration test to verify it fails, then passes**

Run: `go test ./integration/ -run MavenFallsBack`
Expected: PASS (the fallback is already implemented in Tasks 1–2). If it fails to
compile, align the cache construction with `phase3_test.go` as noted above.

- [ ] **Step 3: Update README**

In `README.md`, update any `upstream:` config snippet to the `upstreams:` list
form, and add a short subsection under "How it Works" describing sequential
fallback:
```markdown
### Multiple upstreams per provider

Each provider accepts an ordered list of `upstreams`. For every request the proxy
tries them in order and uses the first that serves the artifact (Nexus-style
sequential fallback). Any failure — 404/410, 5xx, timeout, or connection refused —
advances to the next upstream. If every upstream returns 404/410 the client gets a
404; any other failure mix yields a 502.

\`\`\`yaml
registries:
  maven:
    enabled: true
    upstreams:
      - "https://repo1.maven.org/maven2"
      - "https://repo.spring.io/release"
\`\`\`
```

- [ ] **Step 4: Run full suite**

Run: `go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add integration README.md
git commit -m "test: multi-upstream integration coverage; docs: document upstreams fallback"
```

---

## Self-Review Notes

- **Spec coverage:** `upstreams` list + validation (Task 1, Task 1 config tests); per-request sequential fallback for metadata (Task 1), download (Task 2), transparent proxy (Task 3); 404-vs-502 mapping (Task 2 download, Task 3 transparent); interface rename `UpstreamURL`→`UpstreamURLs` (Task 1); breaking config (Task 1, no legacy field); ordering = sequential in config order (loops preserve slice order); integration + docs (Task 4). Out-of-scope items (listing merge, negative cache, auth, parallel) intentionally absent.
- **Type consistency:** `Upstreams []string`, `UpstreamURLs(r) []string`, `tryDownload(ctx,url) (string,int,error)`, `downloadFromUpstreams(ctx,urls) (string,bool,error)`, `fetchMetadataFrom(ctx,base,ref)` used consistently across tasks. `HandlerConfig.Upstream` exists through Tasks 1–2 (first-element bridge) and is removed in Task 3 along with all literals.
- **Green checkpoints:** full `go build ./... && go test ./...` at end of Tasks 1, 3, 4; package-scoped green within Task 2.

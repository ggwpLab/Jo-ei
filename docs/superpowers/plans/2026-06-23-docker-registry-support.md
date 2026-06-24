# Docker Registry Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pull-through Docker Registry V2 proxy that gates public images on Trivy (CVE/secrets) and ClamAV (signature malware) before serving them, reusing Jōei's existing telemetry, policy, supply-chain, cache, and health subsystems.

**Architecture:** A dedicated, isolated package `internal/proxy/dockerproxy` implements the Docker Registry V2 flow with a single gate on the manifest. The existing `proxy.Handler` is untouched. The gate reuses the existing `proxy.SCFilter`, `proxy.PolicyDecider`, and `proxy.AVScanner` interfaces (all satisfied by `policy.Runtime` / the ClamAV `MultiScanner`); only one new interface — `ImageScanner` (Trivy) — is introduced. Verdicts are cached by image-digest and layer blobs by blob-digest via a thin digest→`PackageRef` wrapper over the existing `cache.Cache`.

**Tech Stack:** Go, Docker Registry HTTP API V2, Trivy (client/server via the `trivy` CLI), ClamAV (existing `internal/scanner`), `httptest` for integration, `cobra`/`viper` config.

## Global Constraints

- Module path: `github.com/ggwpLab/Jo-ei` — all imports use this prefix.
- Lint gate is **golangci-lint** (ineffassign/staticcheck/unused/errcheck/…), not just `go vet`. Run `golangci-lint run ./...` before every commit; fix all findings.
- Tests are standard `go test`. Run `go test ./...` (and `go build ./...`) green before each commit.
- **Fail-closed everywhere:** any scanner/resolve/download error blocks the request — never serve on error.
- Docker error responses use the registry envelope: `{"errors":[{"code":"<CODE>","message":"<msg>"}]}` with codes `DENIED` (block), `MANIFEST_UNKNOWN`/`BLOB_UNKNOWN` (404), `UNAVAILABLE` (502).
- Telemetry: one `proxy.Event` per gate, `Ecosystem:"docker"`. Never block or fail the data path on telemetry.
- Match surrounding code style: package-doc comments, zerolog logging, table-driven tests, no new third-party deps unless unavoidable.
- New CLI behaviour must not change the default (no-docker) config's behaviour: `registries.docker.enabled` defaults to `false`.

---

## File Structure

**New package `internal/proxy/dockerproxy`:**
- `path.go` / `path_test.go` — parse V2 request paths into kind+repo+reference (pure functions).
- `adapter.go` / `adapter_test.go` — upstream selection, Docker Hub token auth, digest resolution, manifest/blob fetch, multi-arch platform selection.
- `trivy.go` / `trivy_test.go` — `TrivyScanner` (`ImageScanner` impl) via `os/exec`, JSON parsing, health probe.
- `blobcache.go` / `blobcache_test.go` — digest-keyed wrapper over `cache.Cache`.
- `gate.go` / `gate_test.go` — `manifestGate`: orchestrate supply-chain + Trivy + ClamAV + policy; verdict cache by digest.
- `handler.go` / `handler_test.go` — `Handler` implementing the HTTP V2 flow + Docker error envelope + telemetry.
- `doc.go` — package doc + the `ImageScanner` interface and shared types.

**Modified:**
- `internal/config/config.go` — add `Docker` registry + `ImageScan` config + validation.
- `internal/proxy/recorder.go` — add `GateImageScan` constant.
- `cmd/jo-ei/main.go` — build the Trivy scanner, the docker handler, register prefix `v2`, add health probe.
- `config.yaml`, `docker-compose.yaml`, `Dockerfile`, `README.md`, `.env.example` (if needed) — wiring + docs.
- `integration/docker_test.go` — end-to-end pull flow.

---

## Task 1: Config — docker registry + image_scan

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.RegistriesConfig.Docker config.RegistryConfig`; `config.Config.ImageScan config.ImageScanConfig` with fields `Enabled bool`, `TrivyServer string`, `TimeoutSeconds int`, `Scanners string`, `MaxLayerBytes int64`.

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go` (create a `config.yaml`-shaped fixture inline via a temp file, following the existing test pattern in this file):

```go
func TestLoadDockerAndImageScan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	const body = `
server: { listen: ":8080" }
registries:
  docker:
    upstreams: ["https://registry-1.docker.io"]
    enabled: true
image_scan:
  enabled: true
  trivy_server: "http://trivy:4954"
  timeout_seconds: 90
  scanners: "vuln,secret"
  max_layer_bytes: 1048576
database: { path: "/tmp/x.db" }
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Registries.Docker.Enabled {
		t.Error("docker registry should be enabled")
	}
	if cfg.Registries.Docker.Upstreams[0] != "https://registry-1.docker.io" {
		t.Errorf("docker upstream = %q", cfg.Registries.Docker.Upstreams[0])
	}
	if !cfg.ImageScan.Enabled || cfg.ImageScan.TrivyServer != "http://trivy:4954" {
		t.Errorf("image_scan not parsed: %+v", cfg.ImageScan)
	}
	if cfg.ImageScan.TimeoutSeconds != 90 || cfg.ImageScan.Scanners != "vuln,secret" {
		t.Errorf("image_scan fields: %+v", cfg.ImageScan)
	}
	if cfg.ImageScan.MaxLayerBytes != 1048576 {
		t.Errorf("max_layer_bytes = %d", cfg.ImageScan.MaxLayerBytes)
	}
}
```

Ensure `path/filepath` and `os` are imported in the test file (they likely already are).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestLoadDockerAndImageScan -v`
Expected: FAIL — `cfg.Registries.Docker` / `cfg.ImageScan` undefined (compile error).

- [ ] **Step 3: Write minimal implementation**

In `internal/config/config.go`, add `Docker` to `RegistriesConfig`:

```go
type RegistriesConfig struct {
	PyPI     RegistryConfig `mapstructure:"pypi"`
	NPM      RegistryConfig `mapstructure:"npm"`
	Maven    RegistryConfig `mapstructure:"maven"`
	RubyGems RegistryConfig `mapstructure:"rubygems"`
	Docker   RegistryConfig `mapstructure:"docker"`
}
```

Add `ImageScan` to `Config` (after `CVE`):

```go
	ImageScan   ImageScanConfig   `mapstructure:"image_scan"`
```

Add the type (near `CVEConfig`):

```go
// ImageScanConfig configures container-image vulnerability scanning (Trivy).
// It is separate from CVEConfig (osv.dev): a different engine and model.
type ImageScanConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	TrivyServer   string `mapstructure:"trivy_server"`   // e.g. "http://trivy:4954"
	TimeoutSeconds int   `mapstructure:"timeout_seconds"` // default 120
	Scanners      string `mapstructure:"scanners"`        // trivy --scanners value, default "vuln,secret"
	MaxLayerBytes int64  `mapstructure:"max_layer_bytes"` // layer larger than this → fail-closed
}
```

Extend `Validate()` to include docker in the enabled-without-upstreams check:

```go
	regs := map[string]RegistryConfig{
		"pypi":     c.Registries.PyPI,
		"npm":      c.Registries.NPM,
		"maven":    c.Registries.Maven,
		"rubygems": c.Registries.RubyGems,
		"docker":   c.Registries.Docker,
	}
```

And add, after the registries loop:

```go
	if c.ImageScan.Enabled && c.ImageScan.TrivyServer == "" {
		return fmt.Errorf("image_scan.enabled is true but trivy_server is empty")
	}
	if c.ImageScan.MaxLayerBytes < 0 {
		return fmt.Errorf("image_scan.max_layer_bytes must not be negative")
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/ -run TestLoadDockerAndImageScan -v`
Expected: PASS.

- [ ] **Step 5: Lint, build, full test, commit**

```bash
golangci-lint run ./internal/config/...
go build ./... && go test ./internal/config/...
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): docker registry and image_scan (Trivy) settings"
```

---

## Task 2: V2 path parsing

**Files:**
- Create: `internal/proxy/dockerproxy/path.go`
- Create: `internal/proxy/dockerproxy/doc.go`
- Test: `internal/proxy/dockerproxy/path_test.go`

**Interfaces:**
- Produces:
  - `type RequestKind int` with `KindUnknown, KindPing, KindManifest, KindBlob, KindTagList`.
  - `type ParsedPath struct { Kind RequestKind; Repo string; Reference string }` — `Reference` is a tag or `sha256:...` for manifests, a `sha256:...` digest for blobs.
  - `func ParsePath(p string) ParsedPath` — `p` is the path **after** the `/v2` prefix has been stripped by the mux (e.g. `/library/nginx/manifests/latest`). Repo may contain slashes.

- [ ] **Step 1: Write the failing test**

`internal/proxy/dockerproxy/path_test.go`:

```go
package dockerproxy

import "testing"

func TestParsePath(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  ParsedPath
	}{
		{"ping root", "/", ParsedPath{Kind: KindPing}},
		{"ping empty", "", ParsedPath{Kind: KindPing}},
		{"manifest by tag", "/library/nginx/manifests/latest",
			ParsedPath{Kind: KindManifest, Repo: "library/nginx", Reference: "latest"}},
		{"manifest by digest", "/library/nginx/manifests/sha256:abc",
			ParsedPath{Kind: KindManifest, Repo: "library/nginx", Reference: "sha256:abc"}},
		{"nested repo manifest", "/a/b/c/manifests/v1",
			ParsedPath{Kind: KindManifest, Repo: "a/b/c", Reference: "v1"}},
		{"blob", "/library/nginx/blobs/sha256:def",
			ParsedPath{Kind: KindBlob, Repo: "library/nginx", Reference: "sha256:def"}},
		{"tag list", "/library/nginx/tags/list",
			ParsedPath{Kind: KindTagList, Repo: "library/nginx"}},
		{"unknown", "/library/nginx/whatever", ParsedPath{Kind: KindUnknown}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParsePath(tt.in)
			if got != tt.want {
				t.Errorf("ParsePath(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/dockerproxy/ -run TestParsePath -v`
Expected: FAIL — package/types undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/proxy/dockerproxy/doc.go`:

```go
// Package dockerproxy implements a pull-through Docker Registry V2 proxy that
// gates images on Trivy (CVE/secrets) and ClamAV (signature malware) before
// serving them. It is isolated from proxy.Handler and reuses Jōei's existing
// policy, supply-chain, cache, and telemetry subsystems via their interfaces.
package dockerproxy
```

`internal/proxy/dockerproxy/path.go`:

```go
package dockerproxy

import "strings"

// RequestKind classifies a Docker Registry V2 request.
type RequestKind int

const (
	KindUnknown RequestKind = iota
	KindPing                // GET /v2/
	KindManifest            // GET|HEAD /v2/<repo>/manifests/<ref>
	KindBlob                // GET /v2/<repo>/blobs/<digest>
	KindTagList             // GET /v2/<repo>/tags/list
)

// ParsedPath is the result of classifying a V2 path (with the /v2 mux prefix
// already stripped). Repo may contain slashes; Reference is a tag or digest.
type ParsedPath struct {
	Kind      RequestKind
	Repo      string
	Reference string
}

// ParsePath classifies a Docker Registry V2 path. The input is the path after
// the mux has stripped the "/v2" prefix (e.g. "/library/nginx/manifests/latest"
// or "/" for the ping endpoint).
func ParsePath(p string) ParsedPath {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return ParsedPath{Kind: KindPing}
	}
	// Split off the trailing "<verb>/<ref>" (manifests/blobs) or "tags/list".
	if repo, ref, ok := splitRepoVerb(trimmed, "manifests"); ok {
		return ParsedPath{Kind: KindManifest, Repo: repo, Reference: ref}
	}
	if repo, ref, ok := splitRepoVerb(trimmed, "blobs"); ok {
		return ParsedPath{Kind: KindBlob, Repo: repo, Reference: ref}
	}
	if strings.HasSuffix(trimmed, "/tags/list") {
		repo := strings.TrimSuffix(trimmed, "/tags/list")
		return ParsedPath{Kind: KindTagList, Repo: repo}
	}
	return ParsedPath{Kind: KindUnknown}
}

// splitRepoVerb finds the LAST "/<verb>/" separator so multi-segment repos
// (e.g. "a/b/c") are preserved. Returns (repo, reference, true) on match.
func splitRepoVerb(path, verb string) (string, string, bool) {
	sep := "/" + verb + "/"
	idx := strings.LastIndex(path, sep)
	if idx < 0 {
		return "", "", false
	}
	repo := path[:idx]
	ref := path[idx+len(sep):]
	if repo == "" || ref == "" || strings.Contains(ref, "/") {
		return "", "", false
	}
	return repo, ref, true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/dockerproxy/ -run TestParsePath -v`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

```bash
golangci-lint run ./internal/proxy/dockerproxy/...
git add internal/proxy/dockerproxy/doc.go internal/proxy/dockerproxy/path.go internal/proxy/dockerproxy/path_test.go
git commit -m "feat(dockerproxy): parse Docker Registry V2 request paths"
```

---

## Task 3: Adapter — upstream, Docker Hub token auth, digest resolution, multi-arch

**Files:**
- Create: `internal/proxy/dockerproxy/adapter.go`
- Test: `internal/proxy/dockerproxy/adapter_test.go`

**Interfaces:**
- Consumes: `ParsedPath` (Task 2).
- Produces:
  - `type Adapter struct { ... }` with `func NewAdapter(upstreams []string) *Adapter`.
  - `func (a *Adapter) ResolveDigest(ctx context.Context, repo, ref string) (digest string, err error)` — HEAD `manifests/<ref>`, return `Docker-Content-Digest`.
  - `func (a *Adapter) FetchManifest(ctx context.Context, repo, ref, platform string) (body []byte, contentType string, digest string, err error)` — fetches the manifest; if it is a multi-arch index, selects the manifest for `platform` (e.g. "linux/amd64"; empty → "linux/amd64") and returns that child manifest.
  - `func (a *Adapter) FetchBlob(ctx context.Context, repo, digest string) (io.ReadCloser, int64, error)` — opens a blob stream (config or layer). Caller closes.
  - `func (a *Adapter) ImageConfig(ctx context.Context, repo string, manifestBody []byte) (created time.Time, layerDigests []string, err error)` — parse a schema2/OCI manifest, fetch the config blob, return its `created` time and the layer digests.

The Adapter handles Docker Hub bearer-token auth transparently (on 401 with `Www-Authenticate: Bearer realm=...`, fetch a token and retry). All requests send `Accept` for both schema2 and OCI manifest + index media types.

- [ ] **Step 1: Write the failing test**

`internal/proxy/dockerproxy/adapter_test.go` — drive against an `httptest` fake registry. Include the media-type constants the implementation will define.

```go
package dockerproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestResolveDigest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/v2/library/nginx/manifests/latest" {
			w.Header().Set("Docker-Content-Digest", "sha256:deadbeef")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	a := NewAdapter([]string{srv.URL})
	dg, err := a.ResolveDigest(context.Background(), "library/nginx", "latest")
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if dg != "sha256:deadbeef" {
		t.Errorf("digest = %q", dg)
	}
}

func TestFetchManifestSelectsPlatformFromIndex(t *testing.T) {
	amd64Manifest := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`
	index := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mediaTypeOCIIndex,
		"manifests": []map[string]any{
			{"digest": "sha256:arm", "mediaType": mediaTypeOCIManifest,
				"platform": map[string]string{"os": "linux", "architecture": "arm64"}},
			{"digest": "sha256:amd", "mediaType": mediaTypeOCIManifest,
				"platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		},
	}
	indexBody, _ := json.Marshal(index)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/library/nginx/manifests/latest":
			w.Header().Set("Content-Type", mediaTypeOCIIndex)
			w.Header().Set("Docker-Content-Digest", "sha256:index")
			_, _ = w.Write(indexBody)
		case "/v2/library/nginx/manifests/sha256:amd":
			w.Header().Set("Content-Type", mediaTypeOCIManifest)
			w.Header().Set("Docker-Content-Digest", "sha256:amd")
			_, _ = w.Write([]byte(amd64Manifest))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	a := NewAdapter([]string{srv.URL})
	body, ct, dg, err := a.FetchManifest(context.Background(), "library/nginx", "latest", "linux/amd64")
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if dg != "sha256:amd" {
		t.Errorf("selected digest = %q, want sha256:amd", dg)
	}
	if ct != mediaTypeOCIManifest {
		t.Errorf("content-type = %q", ct)
	}
	if string(body) != amd64Manifest {
		t.Errorf("body = %q", body)
	}
}

func TestImageConfigCreatedAndLayers(t *testing.T) {
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	configBlob, _ := json.Marshal(map[string]any{"created": created.Format(time.RFC3339)})
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mediaTypeOCIManifest,
		"config":        map[string]any{"digest": "sha256:cfg"},
		"layers": []map[string]any{
			{"digest": "sha256:l1"}, {"digest": "sha256:l2"},
		},
	}
	manifestBody, _ := json.Marshal(manifest)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/library/nginx/blobs/sha256:cfg" {
			_, _ = w.Write(configBlob)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	a := NewAdapter([]string{srv.URL})
	gotCreated, layers, err := a.ImageConfig(context.Background(), "library/nginx", manifestBody)
	if err != nil {
		t.Fatalf("ImageConfig: %v", err)
	}
	if !gotCreated.Equal(created) {
		t.Errorf("created = %v, want %v", gotCreated, created)
	}
	if len(layers) != 2 || layers[0] != "sha256:l1" || layers[1] != "sha256:l2" {
		t.Errorf("layers = %v", layers)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/dockerproxy/ -run 'TestResolveDigest|TestFetchManifest|TestImageConfig' -v`
Expected: FAIL — `NewAdapter`/media-type constants undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/proxy/dockerproxy/adapter.go`:

```go
package dockerproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Manifest / index media types we accept and recognise.
const (
	mediaTypeSchema2Manifest = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeSchema2List     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeOCIManifest     = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeOCIIndex        = "application/vnd.oci.image.index.v1+json"
)

var manifestAccept = strings.Join([]string{
	mediaTypeSchema2Manifest, mediaTypeSchema2List,
	mediaTypeOCIManifest, mediaTypeOCIIndex,
}, ", ")

const defaultPlatform = "linux/amd64"

// Adapter talks to upstream Docker registries, handling bearer-token auth and
// multi-arch index resolution. It is safe for concurrent use.
type Adapter struct {
	upstreams []string
	client    *http.Client
}

// NewAdapter creates an Adapter over the given ordered upstream base URLs
// (e.g. "https://registry-1.docker.io"). Trailing slashes are trimmed.
func NewAdapter(upstreams []string) *Adapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &Adapter{upstreams: trimmed, client: &http.Client{Timeout: 120 * time.Second}}
}

// do issues a request to base+path with bearer-token auth retry. accept sets the
// Accept header (empty → none). Returns the response; caller closes the body.
func (a *Adapter) do(ctx context.Context, method, base, path, accept string) (*http.Response, error) {
	build := func(token string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return a.client.Do(req)
	}
	resp, err := build("")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	// Token auth: parse Www-Authenticate, fetch a token, retry once.
	challenge := resp.Header.Get("Www-Authenticate")
	resp.Body.Close()
	token, terr := a.fetchToken(ctx, challenge)
	if terr != nil {
		return nil, terr
	}
	return build(token)
}

// fetchToken resolves a Bearer challenge of the form
// `Bearer realm="https://auth.docker.io/token",service="...",scope="..."`.
func (a *Adapter) fetchToken(ctx context.Context, challenge string) (string, error) {
	if !strings.HasPrefix(challenge, "Bearer ") {
		return "", fmt.Errorf("unsupported auth challenge %q", challenge)
	}
	params := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(challenge, "Bearer "), ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			params[kv[0]] = strings.Trim(kv[1], `"`)
		}
	}
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("auth challenge missing realm")
	}
	u := realm + "?service=" + params["service"] + "&scope=" + params["scope"]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.Token != "" {
		return tok.Token, nil
	}
	return tok.AccessToken, nil
}

// ResolveDigest HEADs the manifest and returns the canonical content digest.
func (a *Adapter) ResolveDigest(ctx context.Context, repo, ref string) (string, error) {
	var lastErr error
	for _, base := range a.upstreams {
		resp, err := a.do(ctx, http.MethodHead, base, "/v2/"+repo+"/manifests/"+ref, manifestAccept)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if dg := resp.Header.Get("Docker-Content-Digest"); dg != "" {
				return dg, nil
			}
			lastErr = fmt.Errorf("upstream omitted Docker-Content-Digest for %s/%s", repo, ref)
			continue
		}
		lastErr = fmt.Errorf("HEAD manifest %s/%s: HTTP %d", repo, ref, resp.StatusCode)
	}
	return "", lastErr
}

// FetchManifest fetches the manifest for ref. If it is a multi-arch index, the
// child manifest matching platform (default linux/amd64) is fetched and returned.
func (a *Adapter) FetchManifest(ctx context.Context, repo, ref, platform string) ([]byte, string, string, error) {
	if platform == "" {
		platform = defaultPlatform
	}
	body, ct, dg, err := a.getManifest(ctx, repo, ref)
	if err != nil {
		return nil, "", "", err
	}
	if ct != mediaTypeOCIIndex && ct != mediaTypeSchema2List {
		return body, ct, dg, nil
	}
	childDigest, err := selectPlatform(body, platform)
	if err != nil {
		return nil, "", "", err
	}
	return a.getManifest(ctx, repo, childDigest)
}

// getManifest GETs a manifest by ref/digest from the first working upstream.
func (a *Adapter) getManifest(ctx context.Context, repo, ref string) ([]byte, string, string, error) {
	var lastErr error
	for _, base := range a.upstreams {
		resp, err := a.do(ctx, http.MethodGet, base, "/v2/"+repo+"/manifests/"+ref, manifestAccept)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("GET manifest %s/%s: HTTP %d", repo, ref, resp.StatusCode)
			continue
		}
		b, rerr := io.ReadAll(resp.Body)
		dg := resp.Header.Get("Docker-Content-Digest")
		ct := resp.Header.Get("Content-Type")
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if dg == "" {
			dg = ref
		}
		return b, ct, dg, nil
	}
	return nil, "", "", lastErr
}

// selectPlatform returns the child manifest digest for "os/arch" from an index.
func selectPlatform(indexBody []byte, platform string) (string, error) {
	parts := strings.SplitN(platform, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid platform %q", platform)
	}
	wantOS, wantArch := parts[0], parts[1]
	var idx struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS   string `json:"os"`
				Arch string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexBody, &idx); err != nil {
		return "", fmt.Errorf("decoding manifest index: %w", err)
	}
	for _, m := range idx.Manifests {
		if m.Platform.OS == wantOS && m.Platform.Arch == wantArch {
			return m.Digest, nil
		}
	}
	return "", fmt.Errorf("platform %q not present in manifest index", platform)
}

// FetchBlob opens a blob (config or layer) stream from the first working
// upstream. The caller must close the returned ReadCloser.
func (a *Adapter) FetchBlob(ctx context.Context, repo, digest string) (io.ReadCloser, int64, error) {
	var lastErr error
	for _, base := range a.upstreams {
		resp, err := a.do(ctx, http.MethodGet, base, "/v2/"+repo+"/blobs/"+digest, "")
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("GET blob %s/%s: HTTP %d", repo, digest, resp.StatusCode)
			continue
		}
		return resp.Body, resp.ContentLength, nil
	}
	return nil, 0, lastErr
}

// ImageConfig parses a schema2/OCI manifest, fetches its config blob, and
// returns the image's created time and the ordered layer digests.
func (a *Adapter) ImageConfig(ctx context.Context, repo string, manifestBody []byte) (time.Time, []string, error) {
	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestBody, &m); err != nil {
		return time.Time{}, nil, fmt.Errorf("decoding manifest: %w", err)
	}
	layers := make([]string, len(m.Layers))
	for i, l := range m.Layers {
		layers[i] = l.Digest
	}

	var created time.Time
	if m.Config.Digest != "" {
		rc, _, err := a.FetchBlob(ctx, repo, m.Config.Digest)
		if err != nil {
			return time.Time{}, nil, fmt.Errorf("fetching config blob: %w", err)
		}
		defer rc.Close()
		var cfg struct {
			Created string `json:"created"`
		}
		if err := json.NewDecoder(rc).Decode(&cfg); err != nil {
			return time.Time{}, nil, fmt.Errorf("decoding config blob: %w", err)
		}
		if cfg.Created != "" {
			t, perr := time.Parse(time.RFC3339, cfg.Created)
			if perr != nil {
				return time.Time{}, nil, fmt.Errorf("parsing config.created %q: %w", cfg.Created, perr)
			}
			created = t.UTC()
		}
	}
	return created, layers, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/dockerproxy/ -run 'TestResolveDigest|TestFetchManifest|TestImageConfig' -v`
Expected: PASS.

- [ ] **Step 5: Lint, build, commit**

```bash
golangci-lint run ./internal/proxy/dockerproxy/...
go build ./... && go test ./internal/proxy/dockerproxy/...
git add internal/proxy/dockerproxy/adapter.go internal/proxy/dockerproxy/adapter_test.go
git commit -m "feat(dockerproxy): upstream adapter with token auth and multi-arch resolve"
```

---

## Task 4: TrivyScanner (ImageScanner)

**Files:**
- Create: `internal/proxy/dockerproxy/trivy.go`
- Test: `internal/proxy/dockerproxy/trivy_test.go`
- Modify: `internal/proxy/dockerproxy/doc.go` (add the `ImageScanner` interface + `ImageScanResult`)

**Interfaces:**
- Produces:
  - In `doc.go`: `type ImageScanResult struct { Findings []proxy.CVEFinding }` and
    `type ImageScanner interface { ScanImage(ctx context.Context, imageRef string) (*ImageScanResult, error); Health() health.Sample }`.
  - In `trivy.go`: `func NewTrivyScanner(serverURL, scanners string, timeout time.Duration) *TrivyScanner` and `func NewTrivyScannerWithRunner(serverURL, scanners string, timeout time.Duration, run commandRunner) *TrivyScanner`.
  - `type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)` — injection seam for tests (default wraps `exec.CommandContext(...).Output()`).
  - `imageRef` is `<host>/<repo>@<digest>` (the gate builds it).

- [ ] **Step 1: Write the failing test**

`internal/proxy/dockerproxy/trivy_test.go`:

```go
package dockerproxy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

const trivyJSONFixture = `{
  "Results": [
    {"Target":"alpine","Vulnerabilities":[
      {"VulnerabilityID":"CVE-2021-1","PkgName":"openssl","Severity":"HIGH","Title":"bad"},
      {"VulnerabilityID":"CVE-2021-2","PkgName":"musl","Severity":"MEDIUM","Title":"meh"}
    ]},
    {"Target":"node-pkgs","Vulnerabilities":null}
  ]
}`

func TestTrivyScannerParsesFindings(t *testing.T) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name != "trivy" {
			t.Fatalf("expected trivy, got %q", name)
		}
		return []byte(trivyJSONFixture), nil
	}
	s := NewTrivyScannerWithRunner("http://trivy:4954", "vuln,secret", 30*time.Second, run)
	res, err := s.ScanImage(context.Background(), "registry-1.docker.io/library/alpine@sha256:x")
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(res.Findings))
	}
	if res.Findings[0].ID != "CVE-2021-1" || res.Findings[0].Severity != proxy.SeverityHigh {
		t.Errorf("finding[0] = %+v", res.Findings[0])
	}
	if !s.Health().OK || !s.Health().HasData {
		t.Errorf("health after success = %+v", s.Health())
	}
}

func TestTrivyScannerFailClosedOnError(t *testing.T) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("trivy boom")
	}
	s := NewTrivyScannerWithRunner("http://trivy:4954", "vuln", time.Second, run)
	if _, err := s.ScanImage(context.Background(), "x@sha256:y"); err == nil {
		t.Fatal("expected error from failing trivy run")
	}
	if s.Health().OK {
		t.Error("health should be not-OK after failure")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/dockerproxy/ -run TestTrivyScanner -v`
Expected: FAIL — `NewTrivyScannerWithRunner`/`ImageScanner` undefined.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/proxy/dockerproxy/doc.go`:

```go
import (
	"context"

	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// ImageScanResult holds the vulnerability findings for a scanned image.
type ImageScanResult struct {
	Findings []proxy.CVEFinding
}

// ImageScanner scans a container image for vulnerabilities/secrets. imageRef is
// "<host>/<repo>@<digest>". Implementations must be safe for concurrent use and
// expose a passive health sample for the console.
type ImageScanner interface {
	ScanImage(ctx context.Context, imageRef string) (*ImageScanResult, error)
	Health() health.Sample
}
```

`internal/proxy/dockerproxy/trivy.go`:

```go
package dockerproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// commandRunner runs an external command and returns its stdout. Injectable for
// tests; the default wraps exec.CommandContext.
type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// TrivyScanner runs the `trivy` CLI in client/server mode against a sidecar
// `trivy server` that holds the vulnerability DB. It implements ImageScanner.
type TrivyScanner struct {
	serverURL string
	scanners  string
	timeout   time.Duration
	run       commandRunner

	healthMu      sync.Mutex
	healthOK      bool
	healthHasData bool
	healthLatency time.Duration
}

// NewTrivyScanner creates a scanner that shells out to the real trivy binary.
func NewTrivyScanner(serverURL, scanners string, timeout time.Duration) *TrivyScanner {
	return NewTrivyScannerWithRunner(serverURL, scanners, timeout, execRunner)
}

// NewTrivyScannerWithRunner is NewTrivyScanner with an injectable command runner.
func NewTrivyScannerWithRunner(serverURL, scanners string, timeout time.Duration, run commandRunner) *TrivyScanner {
	if scanners == "" {
		scanners = "vuln,secret"
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &TrivyScanner{serverURL: serverURL, scanners: scanners, timeout: timeout, run: run}
}

// trivyReport is the subset of `trivy image --format json` output we consume.
type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			Severity        string `json:"Severity"`
			Title           string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ScanImage runs trivy against imageRef and maps findings to proxy.CVEFinding.
func (s *TrivyScanner) ScanImage(ctx context.Context, imageRef string) (*ImageScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	args := []string{
		"image", "--server", s.serverURL,
		"--format", "json", "--quiet",
		"--scanners", s.scanners,
		imageRef,
	}
	start := time.Now()
	out, err := s.run(ctx, "trivy", args...)
	s.recordHealth(time.Since(start), err)
	if err != nil {
		return nil, fmt.Errorf("running trivy for %s: %w", imageRef, err)
	}

	var report trivyReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("decoding trivy output: %w", err)
	}
	var findings []proxy.CVEFinding
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			findings = append(findings, proxy.CVEFinding{
				ID:       v.VulnerabilityID,
				Severity: proxy.ParseSeverity(v.Severity),
				Summary:  v.Title,
			})
		}
	}
	return &ImageScanResult{Findings: findings}, nil
}

func (s *TrivyScanner) recordHealth(latency time.Duration, err error) {
	s.healthMu.Lock()
	s.healthLatency = latency
	s.healthOK = err == nil
	s.healthHasData = true
	s.healthMu.Unlock()
}

// Health reports the outcome of the last scan as a passive sample.
func (s *TrivyScanner) Health() health.Sample {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	return health.Sample{OK: s.healthOK, Latency: s.healthLatency, HasData: s.healthHasData}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/dockerproxy/ -run TestTrivyScanner -v`
Expected: PASS.

- [ ] **Step 5: Lint, build, commit**

```bash
golangci-lint run ./internal/proxy/dockerproxy/...
go build ./... && go test ./internal/proxy/dockerproxy/...
git add internal/proxy/dockerproxy/doc.go internal/proxy/dockerproxy/trivy.go internal/proxy/dockerproxy/trivy_test.go
git commit -m "feat(dockerproxy): Trivy image scanner (client/server) with health"
```

---

## Task 5: blobCache — digest-keyed wrapper over cache.Cache

**Files:**
- Create: `internal/proxy/dockerproxy/blobcache.go`
- Test: `internal/proxy/dockerproxy/blobcache_test.go`

**Interfaces:**
- Consumes: the existing `cache.Cache` interface (`Get/Put/Invalidate(*proxy.PackageRef)`).
- Produces:
  - `type verdictStore struct { ... }` with `func newVerdictStore(c cache.Cache) *verdictStore`.
  - `func (v *verdictStore) GetBlob(digest string) (path string, clean bool, found bool)` — blob key.
  - `func (v *verdictStore) PutBlob(digest, tmpPath string, clean bool) error`.
  - `func (v *verdictStore) GetImageVerdict(repo, digest string) (clean bool, reason string, found bool)` — manifest-verdict key, reason stored in ScanJSON.
  - `func (v *verdictStore) PutImageVerdict(repo, digest, manifestTmpPath string, clean bool, reason string) error`.
  - `func (v *verdictStore) GetManifestBody(repo, digest string) (path string, found bool)` — for serving the cached manifest body.
- Mapping: blob → `PackageRef{Ecosystem:"docker", Name:"blobs", Version:digest}`; image verdict/manifest → `PackageRef{Ecosystem:"docker", Name:repo, Version:digest}`.

- [ ] **Step 1: Write the failing test**

`internal/proxy/dockerproxy/blobcache_test.go` — use a small in-memory fake of `cache.Cache`:

```go
package dockerproxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// fakeCache is a minimal in-memory cache.Cache for tests.
type fakeCache struct {
	entries map[string]*cache.CacheEntry
}

func newFakeCache() *fakeCache { return &fakeCache{entries: map[string]*cache.CacheEntry{}} }

func (f *fakeCache) Get(ref *proxy.PackageRef) (*cache.CacheEntry, bool) {
	e, ok := f.entries[ref.Key()]
	return e, ok
}
func (f *fakeCache) Put(ref *proxy.PackageRef, tmpPath string, clean bool, scanJSON string) error {
	f.entries[ref.Key()] = &cache.CacheEntry{ArtifactPath: tmpPath, ScanClean: clean, ScanJSON: scanJSON}
	return nil
}
func (f *fakeCache) Invalidate(ref *proxy.PackageRef) error { delete(f.entries, ref.Key()); return nil }
func (f *fakeCache) Stats() (cache.CacheStats, error)       { return cache.CacheStats{}, nil }
func (f *fakeCache) Close() error                           { return nil }

func TestVerdictStoreBlobRoundTrip(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "layer")
	if err := os.WriteFile(tmp, []byte("layerdata"), 0o600); err != nil {
		t.Fatal(err)
	}
	vs := newVerdictStore(newFakeCache())

	if _, _, found := vs.GetBlob("sha256:l1"); found {
		t.Fatal("blob should be absent initially")
	}
	if err := vs.PutBlob("sha256:l1", tmp, true); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	_, clean, found := vs.GetBlob("sha256:l1")
	if !found || !clean {
		t.Errorf("GetBlob = found:%v clean:%v", found, clean)
	}
}

func TestVerdictStoreImageVerdict(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "manifest")
	if err := os.WriteFile(tmp, []byte(`{"x":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	vs := newVerdictStore(newFakeCache())
	if err := vs.PutImageVerdict("library/nginx", "sha256:img", tmp, false, "cve_found"); err != nil {
		t.Fatalf("PutImageVerdict: %v", err)
	}
	clean, reason, found := vs.GetImageVerdict("library/nginx", "sha256:img")
	if !found || clean || reason != "cve_found" {
		t.Errorf("verdict = clean:%v reason:%q found:%v", clean, reason, found)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/dockerproxy/ -run TestVerdictStore -v`
Expected: FAIL — `newVerdictStore` undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/proxy/dockerproxy/blobcache.go`:

```go
package dockerproxy

import (
	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// verdictStore is a thin digest-keyed facade over the shared cache.Cache. Blob
// bodies, manifest bodies, and gate verdicts are all stored as cache entries
// under docker-shaped PackageRefs, reusing the cache's disk store, size
// accounting, and LRU eviction.
type verdictStore struct {
	c cache.Cache
}

func newVerdictStore(c cache.Cache) *verdictStore { return &verdictStore{c: c} }

func blobRef(digest string) *proxy.PackageRef {
	return &proxy.PackageRef{Ecosystem: "docker", Name: "blobs", Version: digest}
}

func imageRefKey(repo, digest string) *proxy.PackageRef {
	return &proxy.PackageRef{Ecosystem: "docker", Name: repo, Version: digest}
}

// GetBlob returns the cached path and clean flag for a layer/config blob.
func (v *verdictStore) GetBlob(digest string) (string, bool, bool) {
	e, ok := v.c.Get(blobRef(digest))
	if !ok {
		return "", false, false
	}
	return e.ArtifactPath, e.ScanClean, true
}

// PutBlob stores a blob body with its ClamAV clean verdict.
func (v *verdictStore) PutBlob(digest, tmpPath string, clean bool) error {
	return v.c.Put(blobRef(digest), tmpPath, clean, "")
}

// GetImageVerdict returns the cached gate verdict for an image digest. The block
// reason is stored in the entry's ScanJSON field.
func (v *verdictStore) GetImageVerdict(repo, digest string) (bool, string, bool) {
	e, ok := v.c.Get(imageRefKey(repo, digest))
	if !ok {
		return false, "", false
	}
	return e.ScanClean, e.ScanJSON, true
}

// PutImageVerdict caches the gate verdict together with the manifest body.
func (v *verdictStore) PutImageVerdict(repo, digest, manifestTmpPath string, clean bool, reason string) error {
	return v.c.Put(imageRefKey(repo, digest), manifestTmpPath, clean, reason)
}

// GetManifestBody returns the cached manifest file path for an approved image.
func (v *verdictStore) GetManifestBody(repo, digest string) (string, bool) {
	e, ok := v.c.Get(imageRefKey(repo, digest))
	if !ok {
		return "", false
	}
	return e.ArtifactPath, true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/dockerproxy/ -run TestVerdictStore -v`
Expected: PASS.

- [ ] **Step 5: Lint, build, commit**

```bash
golangci-lint run ./internal/proxy/dockerproxy/...
go build ./... && go test ./internal/proxy/dockerproxy/...
git add internal/proxy/dockerproxy/blobcache.go internal/proxy/dockerproxy/blobcache_test.go
git commit -m "feat(dockerproxy): digest-keyed verdict/blob store over cache.Cache"
```

---

## Task 6: manifestGate — orchestrate the checks

**Files:**
- Create: `internal/proxy/dockerproxy/gate.go`
- Test: `internal/proxy/dockerproxy/gate_test.go`

**Interfaces:**
- Consumes: `Adapter` (Task 3), `ImageScanner` (Task 4), `verdictStore` (Task 5), and the existing `proxy.SCFilter`, `proxy.PolicyDecider`, `proxy.AVScanner`.
- Produces:
  - `type gateDeps struct { adapter *Adapter; scanner ImageScanner; av proxy.AVScanner; filter proxy.SCFilter; policy proxy.PolicyDecider; store *verdictStore; maxLayerBytes int64; logger zerolog.Logger }`.
  - `type manifestGate struct { gateDeps }` with `func newManifestGate(d gateDeps) *manifestGate`.
  - `type GateVerdict struct { Allowed bool; Reason string; BlockedBy string; Findings []proxy.CVEFinding; ManifestPath string; ContentType string; PublishedAt time.Time }`.
  - `func (g *manifestGate) Evaluate(ctx context.Context, repo, ref, platform string) (digest string, v GateVerdict, err error)` — the full gate; returns the resolved digest and the verdict. On any infrastructure error returns err (handler maps to 502/503, fail-closed).

**Gate order** (matches the existing pipeline): supply-chain (`config.created`) → Trivy vs policy (severity threshold + denylist) → ClamAV over layers. The first block wins; the verdict is cached by image-digest. Reuses `policy.Runtime` via `proxy.SCFilter.Check` and `proxy.PolicyDecider.Evaluate` by constructing a docker `PackageRef` and a `proxy.ScanResult` from Trivy findings.

- [ ] **Step 1: Write the failing test**

`internal/proxy/dockerproxy/gate_test.go` — stub the collaborators. Reuse `fakeCache` from Task 5's test (same package).

```go
package dockerproxy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/rs/zerolog"
)

// --- stubs ---

type stubScanner struct{ findings []proxy.CVEFinding; err error }

func (s stubScanner) ScanImage(context.Context, string) (*ImageScanResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &ImageScanResult{Findings: s.findings}, nil
}
func (s stubScanner) Health() health.Sample { return health.Sample{} } // import health

type stubAV struct{ infected bool }

func (s stubAV) Scan(context.Context, string) (*proxy.AVResult, error) {
	if s.infected {
		return &proxy.AVResult{Clean: false, Signature: "EICAR", Engine: "clamav"}, nil
	}
	return &proxy.AVResult{Clean: true}, nil
}

// allowFilter and policy that allow everything / block on findings.
type allowFilter struct{}

func (allowFilter) Check(context.Context, *proxy.PackageRef, *proxy.PackageMetadata) proxy.FilterResult {
	return proxy.FilterResult{Allowed: true, Reason: "ok"}
}

type findingPolicy struct{}

func (findingPolicy) Evaluate(_ *proxy.PackageRef, r *proxy.ScanResult) proxy.PolicyDecision {
	if r != nil && len(r.Findings) > 0 {
		return proxy.PolicyDecision{Allowed: false, Reason: "cve_found", Findings: r.Findings}
	}
	return proxy.PolicyDecision{Allowed: true, Reason: "ok"}
}
```

Then the behavioural tests. They need an `Adapter` pointed at an `httptest` upstream serving a manifest + config + layers. Build a small helper `newGateTestServer(t)` returning the server URL and the manifest body, then assert:

```go
func TestGateBlocksOnCVE(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t) // serves index-free manifest + config + 1 layer
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}),
		scanner: stubScanner{findings: []proxy.CVEFinding{{ID: "CVE-1", Severity: proxy.SeverityHigh}}},
		av:      stubAV{},
		filter:  allowFilter{},
		policy:  findingPolicy{},
		store:   newVerdictStore(newFakeCache()),
		logger:  zerolog.Nop(),
	}
	g := newManifestGate(d)
	_, v, err := g.Evaluate(context.Background(), repo, ref, "linux/amd64")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed || v.Reason != "cve_found" || v.BlockedBy != "cve" {
		t.Errorf("verdict = %+v, want blocked cve_found", v)
	}
}

func TestGateBlocksOnMalware(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t)
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}),
		scanner: stubScanner{}, av: stubAV{infected: true},
		filter: allowFilter{}, policy: findingPolicy{},
		store: newVerdictStore(newFakeCache()), logger: zerolog.Nop(),
	}
	_, v, err := newManifestGate(d).Evaluate(context.Background(), repo, ref, "linux/amd64")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed || v.BlockedBy != "malware" {
		t.Errorf("verdict = %+v, want blocked malware", v)
	}
}

func TestGateAllowsCleanImageAndCachesVerdict(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t)
	store := newVerdictStore(newFakeCache())
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}),
		scanner: stubScanner{}, av: stubAV{},
		filter: allowFilter{}, policy: findingPolicy{},
		store: store, logger: zerolog.Nop(),
	}
	g := newManifestGate(d)
	digest, v, err := g.Evaluate(context.Background(), repo, ref, "linux/amd64")
	if err != nil || !v.Allowed {
		t.Fatalf("Evaluate clean: v=%+v err=%v", v, err)
	}
	if _, _, found := store.GetImageVerdict(repo, digest); !found {
		t.Error("clean verdict should be cached by digest")
	}
}

func TestGateFailClosedOnOversizedLayer(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t) // layer body is 9 bytes
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}),
		scanner: stubScanner{}, av: stubAV{},
		filter: allowFilter{}, policy: findingPolicy{},
		store: newVerdictStore(newFakeCache()), logger: zerolog.Nop(),
		maxLayerBytes: 1, // smaller than the layer → block
	}
	_, v, err := newManifestGate(d).Evaluate(context.Background(), repo, ref, "linux/amd64")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed || v.BlockedBy != "malware" {
		t.Errorf("oversized layer should fail-closed as malware block, got %+v", v)
	}
}
```

Add the `newGateTestServer(t)` helper in the test file: serve `GET/HEAD /v2/<repo>/manifests/<ref>` (schema2/OCI manifest with `config` digest + one `layers` entry, `Docker-Content-Digest: sha256:img`), `GET /v2/<repo>/blobs/sha256:cfg` (config JSON `{"created":"2020-01-01T00:00:00Z"}`), and `GET /v2/<repo>/blobs/sha256:layer1` (9-byte body). Add the missing `health` import to the stub.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/dockerproxy/ -run TestGate -v`
Expected: FAIL — `newManifestGate`/`gateDeps` undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/proxy/dockerproxy/gate.go`:

```go
package dockerproxy

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/rs/zerolog"
)

// GateVerdict is the per-image decision produced by the manifest gate.
type GateVerdict struct {
	Allowed      bool
	Reason       string // "ok" | "cve_found" | "denylisted" | "malware_found" | supply-chain reason
	BlockedBy    string // "supply_chain" | "cve" | "denylist" | "malware" (empty when allowed)
	Findings     []proxy.CVEFinding
	ManifestPath string // cached manifest body (allowed only)
	ContentType  string
	PublishedAt  time.Time
}

type gateDeps struct {
	adapter       *Adapter
	scanner       ImageScanner
	av            proxy.AVScanner
	filter        proxy.SCFilter
	policy        proxy.PolicyDecider
	store         *verdictStore
	maxLayerBytes int64
	logger        zerolog.Logger
}

type manifestGate struct{ gateDeps }

func newManifestGate(d gateDeps) *manifestGate { return &manifestGate{d} }

// Evaluate runs the full gate for repo:ref on the given platform. It returns the
// resolved image digest and the verdict. Infrastructure failures (resolve,
// fetch, scan errors) return a non-nil error so the handler fails closed.
func (g *manifestGate) Evaluate(ctx context.Context, repo, ref, platform string) (string, GateVerdict, error) {
	// Resolve the requested ref to a canonical digest for the selected platform
	// by fetching the (possibly index) manifest.
	manifestBody, contentType, digest, err := g.adapter.FetchManifest(ctx, repo, ref, platform)
	if err != nil {
		return "", GateVerdict{}, fmt.Errorf("resolving manifest %s:%s: %w", repo, ref, err)
	}

	// Cached verdict?
	if clean, reason, found := g.store.GetImageVerdict(repo, digest); found {
		v := GateVerdict{Allowed: clean, Reason: reason}
		if !clean {
			v.BlockedBy = blockedByForReason(reason)
		} else if path, ok := g.store.GetManifestBody(repo, digest); ok {
			v.ManifestPath, v.ContentType = path, contentType
		}
		return digest, v, nil
	}

	pkgRef := &proxy.PackageRef{Ecosystem: "docker", Name: repo, Version: ref}

	// Parse manifest → config.created + layer digests.
	created, layers, err := g.adapter.ImageConfig(ctx, repo, manifestBody)
	if err != nil {
		return "", GateVerdict{}, err
	}

	// 1. Supply-chain (config.created as the publish proxy).
	fr := g.filter.Check(ctx, pkgRef, &proxy.PackageMetadata{PublishedAt: created})
	if !fr.Allowed {
		v := GateVerdict{Allowed: false, Reason: fr.Reason, BlockedBy: "supply_chain", PublishedAt: created}
		_ = g.cacheVerdict(ctx, repo, digest, manifestBody, v)
		return digest, v, nil
	}

	// 2. Trivy → policy (severity threshold + denylist).
	scan, err := g.scanner.ScanImage(ctx, g.imageRef(repo, digest))
	if err != nil {
		return "", GateVerdict{}, err
	}
	if g.policy != nil {
		decision := g.policy.Evaluate(pkgRef, &proxy.ScanResult{
			Clean:    len(scan.Findings) == 0,
			Findings: scan.Findings,
		})
		if !decision.Allowed {
			by := "cve"
			if decision.Reason == proxy.ReasonDenylisted {
				by = "denylist"
			}
			v := GateVerdict{Allowed: false, Reason: decision.Reason, BlockedBy: by, Findings: decision.Findings}
			_ = g.cacheVerdict(ctx, repo, digest, manifestBody, v)
			return digest, v, nil
		}
	}

	// 3. ClamAV over each layer (fail-closed on oversize / infection / error).
	if g.av != nil {
		for _, layer := range layers {
			infected, scanErr := g.scanLayer(ctx, repo, layer)
			if scanErr != nil {
				return "", GateVerdict{}, scanErr
			}
			if infected {
				v := GateVerdict{Allowed: false, Reason: "malware_found", BlockedBy: "malware"}
				_ = g.cacheVerdict(ctx, repo, digest, manifestBody, v)
				return digest, v, nil
			}
		}
	}

	// Clean.
	v := GateVerdict{Allowed: true, Reason: "ok", PublishedAt: created, ContentType: contentType}
	if err := g.cacheVerdict(ctx, repo, digest, manifestBody, v); err != nil {
		return "", GateVerdict{}, err
	}
	if path, ok := g.store.GetManifestBody(repo, digest); ok {
		v.ManifestPath = path
	}
	return digest, v, nil
}

// scanLayer downloads a layer (unless cached clean), enforces the size limit,
// runs the AV scanner, and caches the per-blob verdict. Returns infected=true on
// a malware hit or an oversized layer (fail-closed). An error means the layer
// could not be checked (handler fails closed with 5xx).
func (g *manifestGate) scanLayer(ctx context.Context, repo, digest string) (bool, error) {
	if _, clean, found := g.store.GetBlob(digest); found {
		return !clean, nil
	}
	rc, size, err := g.adapter.FetchBlob(ctx, repo, digest)
	if err != nil {
		return false, fmt.Errorf("fetching layer %s: %w", digest, err)
	}
	defer rc.Close()

	if g.maxLayerBytes > 0 && size > g.maxLayerBytes {
		// Oversized: fail-closed, cache as not-clean so repeats stay blocked.
		_ = g.store.PutBlob(digest, os.DevNull, false)
		return true, nil
	}

	tmp, err := os.CreateTemp("", "jo-ei-layer-*")
	if err != nil {
		return false, fmt.Errorf("creating temp layer file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	limit := g.maxLayerBytes
	var written int64
	if limit > 0 {
		written, err = io.Copy(tmp, io.LimitReader(rc, limit+1))
	} else {
		written, err = io.Copy(tmp, rc)
	}
	tmp.Close()
	if err != nil {
		return false, fmt.Errorf("buffering layer %s: %w", digest, err)
	}
	if limit > 0 && written > limit {
		_ = g.store.PutBlob(digest, os.DevNull, false)
		return true, nil
	}

	res, err := g.av.Scan(ctx, tmpPath)
	if err != nil {
		return false, fmt.Errorf("AV scanning layer %s: %w", digest, err)
	}
	if err := g.store.PutBlob(digest, tmpPath, res.Clean); err != nil {
		return false, fmt.Errorf("caching layer %s: %w", digest, err)
	}
	return !res.Clean, nil
}

// cacheVerdict writes the manifest body + verdict to the store under the digest.
func (g *manifestGate) cacheVerdict(_ context.Context, repo, digest string, manifestBody []byte, v GateVerdict) error {
	tmp, err := os.CreateTemp("", "jo-ei-manifest-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(manifestBody); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	tmp.Close()
	defer os.Remove(tmpPath)
	return g.store.PutImageVerdict(repo, digest, tmpPath, v.Allowed, v.Reason)
}

// imageRef builds the "<host>/<repo>@<digest>" string Trivy scans. The host is
// taken from the first upstream (scheme stripped).
func (g *manifestGate) imageRef(repo, digest string) string {
	host := hostFromUpstream(g.adapter.upstreams)
	return host + "/" + repo + "@" + digest
}

func blockedByForReason(reason string) string {
	switch reason {
	case "malware_found":
		return "malware"
	case proxy.ReasonDenylisted:
		return "denylist"
	case "cve_found":
		return "cve"
	default:
		return "supply_chain"
	}
}
```

Add `hostFromUpstream` to `adapter.go`:

```go
// hostFromUpstream returns the host[:port] of the first upstream, scheme
// stripped, for building the image reference Trivy scans. Empty list → "".
func hostFromUpstream(upstreams []string) string {
	if len(upstreams) == 0 {
		return ""
	}
	h := upstreams[0]
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	return strings.TrimRight(h, "/")
}
```

Note on caching the manifest body: `verdictStore.PutImageVerdict` copies the temp file into the cache via `cache.Put`, so removing the temp afterwards is safe (the real `LocalCache.Put` copies; the test `fakeCache` stores the path but the test does not read the body back).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/dockerproxy/ -run TestGate -v`
Expected: PASS (all four gate tests).

- [ ] **Step 5: Lint, build, full package test, commit**

```bash
golangci-lint run ./internal/proxy/dockerproxy/...
go build ./... && go test ./internal/proxy/dockerproxy/...
git add internal/proxy/dockerproxy/gate.go internal/proxy/dockerproxy/gate_test.go internal/proxy/dockerproxy/adapter.go
git commit -m "feat(dockerproxy): manifest gate (supply-chain + Trivy + ClamAV)"
```

---

## Task 7: Handler — HTTP V2 flow, error envelope, telemetry

**Files:**
- Create: `internal/proxy/dockerproxy/handler.go`
- Test: `internal/proxy/dockerproxy/handler_test.go`
- Modify: `internal/proxy/recorder.go` (add `GateImageScan`)

**Interfaces:**
- Consumes: `manifestGate` (Task 6), `Adapter` (Task 3), `verdictStore` (Task 5), `proxy.Recorder`.
- Produces:
  - `type Config struct { Adapter *Adapter; Gate *manifestGate; Store *verdictStore; Recorder proxy.Recorder; Logger zerolog.Logger }`.
  - `func NewHandler(cfg Config) *Handler`; `func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request)`.
  - The mux strips `/v2`, so `r.URL.Path` here is e.g. `/library/nginx/manifests/latest`.

**Behaviour:**
- `KindPing` → 200 + `Docker-Distribution-API-Version: registry/2.0`.
- `KindManifest` (GET/HEAD) → run the gate; on block emit a `BLOCK` event + `403` `DENIED`; on allow serve the cached manifest body with its content type (HEAD: headers only) + `PASS` event (`Gate: GateImageScan`).
- `KindBlob` (GET) → only serve if the blob is in the store (clean); else `404 BLOB_UNKNOWN`. (Layers enter the store during the manifest gate, so a normal pull populates them first.)
- Errors from the gate → `502 UNAVAILABLE` + `ERROR` event.
- Platform from the request `Accept`/default `linux/amd64` (MVP: use default; a future task may read a client hint).

- [ ] **Step 1: Write the failing test**

Add `GateImageScan` usage test indirectly via handler. `internal/proxy/dockerproxy/handler_test.go` reuses the stubs/`newGateTestServer`/`fakeCache` from earlier tests (same package):

```go
package dockerproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/rs/zerolog"
)

type recspy struct{ events []proxy.Event }

func (r *recspy) Record(e proxy.Event) { r.events = append(r.events, e) }

func newTestHandler(t *testing.T, sc ImageScanner, av proxy.AVScanner, rec proxy.Recorder) (*Handler, string, string) {
	srvURL, repo, ref := newGateTestServer(t)
	adapter := NewAdapter([]string{srvURL})
	store := newVerdictStore(newFakeCache())
	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: sc, av: av,
		filter: allowFilter{}, policy: findingPolicy{},
		store: store, logger: zerolog.Nop(),
	})
	h := NewHandler(Config{Adapter: adapter, Gate: gate, Store: store, Recorder: rec, Logger: zerolog.Nop()})
	return h, repo, ref
}

func TestHandlerPing(t *testing.T) {
	h, _, _ := newTestHandler(t, stubScanner{}, stubAV{}, &recspy{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ping status = %d", w.Code)
	}
	if w.Header().Get("Docker-Distribution-API-Version") != "registry/2.0" {
		t.Error("missing API version header")
	}
}

func TestHandlerManifestCleanServes(t *testing.T) {
	rec := &recspy{}
	h, repo, ref := newTestHandler(t, stubScanner{}, stubAV{}, rec)
	req := httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+ref, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("manifest status = %d, body=%s", w.Code, w.Body.String())
	}
	if len(rec.events) != 1 || rec.events[0].Verdict != proxy.VerdictPass {
		t.Errorf("events = %+v", rec.events)
	}
}

func TestHandlerManifestCVEBlocked403(t *testing.T) {
	rec := &recspy{}
	h, repo, ref := newTestHandler(t,
		stubScanner{findings: []proxy.CVEFinding{{ID: "CVE-1", Severity: proxy.SeverityHigh}}},
		stubAV{}, rec)
	req := httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+ref, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d", w.Code)
	}
	if !contains(w.Body.String(), "DENIED") {
		t.Errorf("body = %s", w.Body.String())
	}
	if len(rec.events) != 1 || rec.events[0].Verdict != proxy.VerdictBlock {
		t.Errorf("events = %+v", rec.events)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || stringIndex(s, sub) >= 0) }
func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

(Use `strings.Contains` directly instead of the `contains` helper if preferred — just add the import.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/dockerproxy/ -run TestHandler -v`
Expected: FAIL — `NewHandler`/`Config` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/proxy/recorder.go` gate constants block:

```go
	GateImageScan = "image_scan"
```

`internal/proxy/dockerproxy/handler.go`:

```go
package dockerproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Config groups the Docker proxy handler dependencies.
type Config struct {
	Adapter  *Adapter
	Gate     *manifestGate
	Store    *verdictStore
	Recorder proxy.Recorder
	Logger   zerolog.Logger
}

// Handler implements the Docker Registry V2 pull-through flow.
type Handler struct {
	cfg Config
}

// NewHandler creates a Docker proxy handler.
func NewHandler(cfg Config) *Handler { return &Handler{cfg: cfg} }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pp := ParsePath(r.URL.Path)
	switch pp.Kind {
	case KindPing:
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
	case KindManifest:
		h.serveManifest(w, r, pp)
	case KindBlob:
		h.serveBlob(w, r, pp)
	default:
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "unsupported registry path")
	}
}

func (h *Handler) serveManifest(w http.ResponseWriter, r *http.Request, pp ParsedPath) {
	requestID := uuid.New().String()
	start := time.Now()
	log := h.cfg.Logger.With().Str("request_id", requestID).Str("repo", pp.Repo).Str("ref", pp.Reference).Logger()

	digest, v, err := h.cfg.Gate.Evaluate(r.Context(), pp.Repo, pp.Reference, defaultPlatform)
	if err != nil {
		log.Error().Err(err).Msg("docker gate error")
		h.record(requestID, pp, proxy.VerdictError, proxy.GateImageScan, "gate_error", http.StatusBadGateway, start, nil)
		h.writeError(w, http.StatusBadGateway, "UNAVAILABLE", "upstream or scan failure")
		return
	}

	if !v.Allowed {
		log.Warn().Str("reason", v.Reason).Str("blocked_by", v.BlockedBy).Msg("docker image blocked")
		h.record(requestID, pp, proxy.VerdictBlock, gateForBlockedBy(v.BlockedBy), v.Reason, http.StatusForbidden, start, func(ev *proxy.Event) {
			ev.BlockedBy = []string{v.BlockedBy}
			ev.CVEs = v.Findings
			ev.Version = digest
		})
		h.writeError(w, http.StatusForbidden, "DENIED", "image blocked by policy: "+v.Reason)
		return
	}

	w.Header().Set("Docker-Content-Digest", digest)
	if v.ContentType != "" {
		w.Header().Set("Content-Type", v.ContentType)
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		h.record(requestID, pp, proxy.VerdictPass, proxy.GateImageScan, "ok", http.StatusOK, start, func(ev *proxy.Event) { ev.Version = digest })
		return
	}
	if err := streamFile(w, v.ManifestPath); err != nil {
		log.Error().Err(err).Msg("serving cached manifest")
		return
	}
	h.record(requestID, pp, proxy.VerdictPass, proxy.GateImageScan, "ok", http.StatusOK, start, func(ev *proxy.Event) { ev.Version = digest })
}

func (h *Handler) serveBlob(w http.ResponseWriter, r *http.Request, pp ParsedPath) {
	path, clean, found := h.cfg.Store.GetBlob(pp.Reference)
	if !found || !clean {
		h.writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not available")
		return
	}
	w.Header().Set("Docker-Content-Digest", pp.Reference)
	w.Header().Set("Content-Type", "application/octet-stream")
	if err := streamFile(w, path); err != nil {
		h.cfg.Logger.Error().Err(err).Str("digest", pp.Reference).Msg("serving cached blob")
	}
}

func streamFile(w http.ResponseWriter, path string) error {
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "cache read error", http.StatusInternalServerError)
		return err
	}
	defer f.Close()
	w.WriteHeader(http.StatusOK)
	_, err = io.Copy(w, f)
	return err
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{{"code": code, "message": msg}},
	})
}

func (h *Handler) record(requestID string, pp ParsedPath, verdict, gate, reason string, status int, start time.Time, mod func(*proxy.Event)) {
	if h.cfg.Recorder == nil {
		return
	}
	ev := proxy.Event{
		RequestID: requestID, Time: time.Now(),
		Ecosystem: "docker", Package: pp.Repo, Version: pp.Reference,
		Verdict: verdict, Gate: gate, Reason: reason,
		HTTPStatus: status, LatencyMS: time.Since(start).Milliseconds(),
	}
	if mod != nil {
		mod(&ev)
	}
	h.cfg.Recorder.Record(ev)
}

func gateForBlockedBy(by string) string {
	switch by {
	case "malware":
		return proxy.GateMalware
	case "supply_chain":
		return proxy.GateSupply
	default:
		return proxy.GateImageScan
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/dockerproxy/ -run TestHandler -v`
Expected: PASS.

- [ ] **Step 5: Lint, build, full package test, commit**

```bash
golangci-lint run ./internal/proxy/... && go build ./... && go test ./internal/proxy/...
git add internal/proxy/dockerproxy/handler.go internal/proxy/dockerproxy/handler_test.go internal/proxy/recorder.go
git commit -m "feat(dockerproxy): V2 HTTP handler with Docker error envelope and telemetry"
```

---

## Task 8: Wire into the mux and main.go

**Files:**
- Modify: `cmd/jo-ei/main.go`
- Test: `cmd/jo-ei/main_test.go` (add a wiring assertion) or `cmd/jo-ei/serve_test.go` — follow whichever already tests `buildHandlers`.

**Interfaces:**
- Consumes: everything above; `dockerproxy.NewHandler`, `dockerproxy.NewAdapter`, `dockerproxy.NewTrivyScanner`, `dockerproxy.newManifestGate` is unexported → expose a constructor.
- Produces: a wired `v2` route. Add an exported `dockerproxy.New(cfg dockerproxy.HandlerDeps) http.Handler` so `main` does not touch unexported types.

First add the exported assembler to `dockerproxy` so main stays clean.

- [ ] **Step 1: Write the failing test**

Add to `internal/proxy/dockerproxy/handler_test.go`:

```go
func TestNewAssemblesHandler(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t)
	h := New(HandlerDeps{
		Upstreams:     []string{srvURL},
		Scanner:       stubScanner{},
		AV:            stubAV{},
		Filter:        allowFilter{},
		Policy:        findingPolicy{},
		Cache:         newFakeCache(),
		MaxLayerBytes: 0,
		Recorder:      &recspy{},
		Logger:        zerolog.Nop(),
	})
	req := httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+ref, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("assembled handler status = %d", w.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/dockerproxy/ -run TestNewAssembles -v`
Expected: FAIL — `New`/`HandlerDeps` undefined.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/proxy/dockerproxy/handler.go`:

```go
// HandlerDeps is the public assembly input for the Docker proxy handler.
type HandlerDeps struct {
	Upstreams     []string
	Scanner       ImageScanner
	AV            proxy.AVScanner
	Filter        proxy.SCFilter
	Policy        proxy.PolicyDecider
	Cache         cache.Cache
	MaxLayerBytes int64
	Recorder      proxy.Recorder
	Logger        zerolog.Logger
}

// New assembles a ready-to-serve Docker Registry V2 proxy handler.
func New(d HandlerDeps) http.Handler {
	adapter := NewAdapter(d.Upstreams)
	store := newVerdictStore(d.Cache)
	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: d.Scanner, av: d.AV,
		filter: d.Filter, policy: d.Policy, store: store,
		maxLayerBytes: d.MaxLayerBytes, logger: d.Logger,
	})
	return NewHandler(Config{Adapter: adapter, Gate: gate, Store: store, Recorder: d.Recorder, Logger: d.Logger})
}
```

Add the `cache` import to `handler.go`: `"github.com/ggwpLab/Jo-ei/internal/cache"`.

Now wire `main.go`. In `runProxy`, after the malware scanners block and before building handlers, construct the Trivy scanner:

```go
	// Image scanner (Trivy) for the Docker registry (optional).
	var trivyScanner *dockerproxy.TrivyScanner
	if cfg.ImageScan.Enabled {
		timeout := time.Duration(cfg.ImageScan.TimeoutSeconds) * time.Second
		trivyScanner = dockerproxy.NewTrivyScanner(cfg.ImageScan.TrivyServer, cfg.ImageScan.Scanners, timeout)
	}
```

In `buildHandlers`, the Docker handler is not a `*proxy.Handler`, so register it on the mux separately. Change the routing assembly: have `buildHandlers` keep returning `map[string]*proxy.Handler` for the package registries, and register the docker `http.Handler` in `NewMux`. Update `proxy.NewMux` to accept an optional extra handler map `map[string]http.Handler`, OR (simpler, lower-risk) add a dedicated field. Implement the simple route in the mux:

In `internal/proxy/mux.go`, extend `Mux`:

```go
type Mux struct {
	handlers map[string]*Handler
	raw      map[string]http.Handler // prefix → handler for non-package registries (docker)
	logger   zerolog.Logger
}

// NewMux creates a Mux. raw may be nil; it holds prefixes served by a plain
// http.Handler (e.g. the Docker V2 proxy).
func NewMux(handlers map[string]*Handler, raw map[string]http.Handler, logger zerolog.Logger) *Mux {
	return &Mux{handlers: handlers, raw: raw, logger: logger}
}
```

In `Mux.ServeHTTP`, after computing `prefix, rest` and before the `m.handlers` lookup, check `raw`:

```go
	if rh, ok := m.raw[prefix]; ok {
		r.URL.Path = rest
		r.URL.RawPath = ""
		rh.ServeHTTP(w, r)
		return
	}
```

Update the existing `proxy.NewMux` call sites (search: `NewMux(`) — there is the one in `main.go` and any in tests. In `main.go`:

```go
	rawHandlers := map[string]http.Handler{}
	if cfg.Registries.Docker.Enabled && trivyScanner != nil {
		rawHandlers["v2"] = dockerproxy.New(dockerproxy.HandlerDeps{
			Upstreams:     cfg.Registries.Docker.Upstreams,
			Scanner:       trivyScanner,
			AV:            shared.avScanner,
			Filter:        shared.filter,
			Policy:        shared.policy,
			Cache:         artifactCache,
			MaxLayerBytes: cfg.ImageScan.MaxLayerBytes,
			Recorder:      shared.recorder,
			Logger:        logger,
		})
	}
	mux := proxy.NewMux(handlers, rawHandlers, logger)
```

(Note: `shared.policy` is nil unless `cfg.CVE.Enabled`. The Docker denylist/severity policy comes from the same `policyRuntime`; set `shared.policy = policyRuntime` unconditionally is wrong for the existing osv path. Instead pass `policyRuntime` directly here: replace `Policy: shared.policy` with `Policy: policyRuntime`, and `Filter: policyRuntime`.)

Add the import `"github.com/ggwpLab/Jo-ei/internal/proxy/dockerproxy"` to `main.go`.

Health probe for Trivy (active probe via `trivy version --server`). Add to `dockerproxy` a probe method and register it:

In `trivy.go`:

```go
// Probe checks Trivy server reachability (trivy version --server <url>).
func (s *TrivyScanner) Probe(ctx context.Context) error {
	_, err := s.run(ctx, "trivy", "version", "--server", s.serverURL, "--format", "json")
	return err
}
```

In `main.go` health section, after the malware scanner loop:

```go
	if cfg.ImageScan.Enabled && trivyScanner != nil {
		healthMon.AddActive("trivy", cfg.ImageScan.TrivyServer, true, trivyScanner.Probe)
	}
```

Adjust the `registryCount` log line / `buildHandlers` empty-check: docker is enabled via `rawHandlers`, so the "no registries enabled" guard must also accept a docker-only setup:

```go
	if len(handlers) == 0 && len(rawHandlers) == 0 {
		return fmt.Errorf("no registries enabled; set at least one of registries.{pypi,npm,maven,rubygems,docker}.enabled: true")
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go build ./... && go test ./internal/proxy/... ./cmd/... -v`
Expected: PASS (including the existing mux tests after the signature update — fix any `NewMux(` call in `mux_test.go` to pass `nil` for `raw`).

- [ ] **Step 5: Lint and commit**

```bash
golangci-lint run ./... && go test ./...
git add internal/proxy/mux.go internal/proxy/mux_test.go internal/proxy/dockerproxy/handler.go internal/proxy/dockerproxy/trivy.go cmd/jo-ei/main.go cmd/jo-ei/*_test.go
git commit -m "feat: wire Docker V2 proxy into mux, main, and health monitor"
```

---

## Task 9: Deployment + config + docs

**Files:**
- Modify: `config.yaml`, `docker-compose.yaml`, `Dockerfile`, `README.md`

**Interfaces:** none (operational wiring + docs).

- [ ] **Step 1: Add config keys to `config.yaml`**

Under `registries:` add:

```yaml
  docker:
    upstreams:
      - "https://registry-1.docker.io"
    enabled: false   # opt-in; flip to true to enable the Docker pull-through proxy
```

After the `cve:` block add:

```yaml
# Container-image vulnerability scanning (Trivy). Separate from the osv.dev CVE
# scanner above: a different engine and model. Severity threshold and denylist
# come from the active policy profile (cve_min_severity / denylist).
image_scan:
  enabled: false
  trivy_server: "http://trivy:4954"
  timeout_seconds: 120
  scanners: "vuln,secret"
  max_layer_bytes: 2147483648   # 2 GB; a larger layer fails closed (blocks the image)
```

- [ ] **Step 2: Add the Trivy sidecar to `docker-compose.yaml`**

Add a `trivy` service running `trivy server`, a volume for its DB cache, and ensure `jo-ei` can reach it on `trivy:4954`:

```yaml
  trivy:
    image: aquasec/trivy:latest
    command: ["server", "--listen", "0.0.0.0:4954"]
    volumes:
      - trivy-cache:/root/.cache/trivy
    restart: unless-stopped
```

Add `trivy-cache:` under the top-level `volumes:` map. (Match the existing compose file's indentation and the clamav service style.)

- [ ] **Step 3: Install the `trivy` binary in the Jōei `Dockerfile`**

In the final runtime stage, install the trivy CLI (the gate shells out to it in client/server mode). Add, matching the base image's package manager (Alpine example):

```dockerfile
# Trivy CLI for the Docker registry image scanner (client/server mode).
RUN apk add --no-cache curl ca-certificates \
 && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin
```

If the base is Debian/distroless, adapt accordingly (the engineer should match the existing `Dockerfile` base — read it first and follow its conventions).

- [ ] **Step 4: Document in `README.md`**

Add a Docker section near the other registries: how to point the Docker daemon at Jōei as a `registry-mirror` (`/etc/docker/daemon.json`: `{"registry-mirrors":["http://localhost:8080"]}`), the Docker Hub-only caveat, that images are gated by Trivy + ClamAV, and that blocking happens on the manifest before any layer downloads. Update the architecture diagram's protection list to mention image scanning.

- [ ] **Step 5: Verify config still loads and commit**

```bash
go test ./internal/config/... && go build ./...
git add config.yaml docker-compose.yaml Dockerfile README.md
git commit -m "feat(docker): compose Trivy sidecar, config keys, and docs"
```

---

## Task 10: Integration test — full pull flow

**Files:**
- Create: `integration/docker_test.go`

**Interfaces:** Consumes `dockerproxy.New`, a fake upstream registry, and a real `cache.LocalCache` (temp dir). Models `integration/phase*_test.go`.

- [ ] **Step 1: Write the failing test**

`integration/docker_test.go` — stand up a fake upstream Docker registry serving ping, an OCI manifest (config + two layers), and the blobs; wire `dockerproxy.New` behind a mux that strips `/v2`; then drive the pull sequence.

```go
package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/dockerproxy"
	"github.com/rs/zerolog"
)

// fakeUpstream serves a minimal Docker Registry V2 for one image.
func fakeUpstream(t *testing.T) *httptest.Server {
	config, _ := json.Marshal(map[string]any{"created": "2020-01-01T00:00:00Z"})
	manifest, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]any{"digest": "sha256:cfg"},
		"layers": []map[string]any{
			{"digest": "sha256:layer1"}, {"digest": "sha256:layer2"},
		},
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/" :
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/manifests/latest"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Docker-Content-Digest", "sha256:img")
			_, _ = w.Write(manifest)
		case strings.HasSuffix(r.URL.Path, "/blobs/sha256:cfg"):
			_, _ = w.Write(config)
		case strings.HasSuffix(r.URL.Path, "/blobs/sha256:layer1"):
			_, _ = w.Write([]byte("layer-one"))
		case strings.HasSuffix(r.URL.Path, "/blobs/sha256:layer2"):
			_, _ = w.Write([]byte("layer-two"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// stubs local to the integration package.
type okScanner struct{}
func (okScanner) ScanImage(context.Context, string) (*dockerproxy.ImageScanResult, error) {
	return &dockerproxy.ImageScanResult{}, nil
}
func (okScanner) Health() health.Sample { return health.Sample{} } // add import

type cleanAV struct{}
func (cleanAV) Scan(context.Context, string) (*proxy.AVResult, error) {
	return &proxy.AVResult{Clean: true}, nil
}
type allowAll struct{}
func (allowAll) Check(context.Context, *proxy.PackageRef, *proxy.PackageMetadata) proxy.FilterResult {
	return proxy.FilterResult{Allowed: true, Reason: "ok"}
}
func (allowAll) Evaluate(*proxy.PackageRef, *proxy.ScanResult) proxy.PolicyDecision {
	return proxy.PolicyDecision{Allowed: true, Reason: "ok"}
}

func TestDockerPullFlow(t *testing.T) {
	up := fakeUpstream(t)
	defer up.Close()

	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()

	dh := dockerproxy.New(dockerproxy.HandlerDeps{
		Upstreams: []string{up.URL},
		Scanner:   okScanner{}, AV: cleanAV{},
		Filter: allowAll{}, Policy: allowAll{},
		Cache: lc, Logger: zerolog.Nop(),
	})
	// Mimic the mux stripping the /v2 prefix.
	front := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/v2")
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		dh.ServeHTTP(w, r)
	})
	ts := httptest.NewServer(front)
	defer ts.Close()

	// 1. Manifest pull → gate runs, image approved, manifest served.
	resp, err := http.Get(ts.URL + "/v2/library/nginx/manifests/latest")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("manifest pull status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 2. Layer blob now served from cache (populated during the gate).
	resp2, err := http.Get(ts.URL + "/v2/library/nginx/blobs/sha256:layer1")
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("blob status = %d", resp2.StatusCode)
	}
	resp2.Body.Close()
}
```

Add the `internal/health` import for the `okScanner.Health` stub.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./integration/ -run TestDockerPullFlow -v`
Expected: FAIL until all prior tasks are merged (it exercises the whole chain). If prior tasks are complete, this should drive out any remaining wiring gap.

- [ ] **Step 3: Make it pass**

No new production code beyond Tasks 1–8 should be required. If the blob is not served in step 2, confirm the gate populates the blob store for every layer (Task 6 `scanLayer` caches each layer). Fix any gap discovered here in the relevant package, then re-run.

- [ ] **Step 4: Run the full suite**

Run: `golangci-lint run ./... && go build ./... && go test ./...`
Expected: PASS across the repo.

- [ ] **Step 5: Commit**

```bash
git add integration/docker_test.go
git commit -m "test(integration): end-to-end Docker pull-through flow"
```

---

## Self-Review (completed against the spec)

**Spec coverage:**
- Pull-through public images / Docker Hub mirror → Tasks 3, 8, 9. ✓
- CVE via Trivy (client/server, sidecar, CLI in image) → Tasks 4, 9. ✓
- ClamAV over layers, dedup by blob-digest, oversize fail-closed → Tasks 5, 6. ✓
- 24h rule via `config.created` → Task 6 (`ImageConfig` + `filter.Check`). ✓
- Single gate on manifest, block before layer download → Tasks 6, 7. ✓
- multi-arch: requested platform only → Task 3 (`selectPlatform`, default `linux/amd64`). ✓
- Verdict cache by image-digest; tag mutability handled by digest binding → Tasks 5, 6. ✓
- Reuse policy (severity + denylist) and supply-chain via existing interfaces → Task 6. ✓
- Docker error envelope, fail-closed status codes → Task 7. ✓
- Telemetry `Ecosystem:"docker"`, `GateImageScan` → Task 7. ✓
- Health probe for Trivy → Task 8. ✓
- Config `registries.docker` + `image_scan` → Task 1, 9. ✓
- Tests: unit (paths/adapter/trivy/blobcache/gate/handler) + integration → Tasks 2–7, 10. ✓
- Out of scope (push, GHCR/Quay mirror, all-platform scan, registry-specific dates) → not implemented, documented in spec. ✓

**Placeholder scan:** Real code/tests in every step. The only "match the existing file" instruction is Task 9 step 3 (Dockerfile base) — unavoidable, since the base image dictates the package manager; the engineer reads the existing `Dockerfile` first.

**Type consistency:** `GateVerdict`, `gateDeps`, `verdictStore` methods (`GetBlob/PutBlob/GetImageVerdict/PutImageVerdict/GetManifestBody`), `ImageScanner.ScanImage`, `HandlerDeps`, and `Config` names are used consistently across Tasks 5–10. `proxy.GateImageScan` defined in Task 7, used in Tasks 7–8. `NewMux` signature change propagated in Task 8.

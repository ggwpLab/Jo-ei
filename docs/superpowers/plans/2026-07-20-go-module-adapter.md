# Go module registry adapter — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a GOPROXY-protocol `RegistryAdapter` under `/go/` so `go` clients pull modules through Jo-ei and have module zips run the supply-chain / CVE / malware gates.

**Architecture:** A new `GoAdapter` (mirrors `npm.go`) intercepts `…/@v/<version>.zip` downloads and proxies `list`/`.info`/`.mod`/`@latest` transparently. Publish date comes from the `.info` endpoint via `FetchMetadata`. Go case-encoding (`!x`↔`X`) is decoded to canonical coordinates for OSV/allowlist and re-encoded for upstream requests. Then `"go"` is wired through config, main, console validation, and the console UI.

**Tech Stack:** Go 1.x, `net/http`, `encoding/json`, testify; existing Jo-ei `gate.RegistryAdapter` interface; esbuild-based console build via `go generate`.

## Global Constraints

- Ecosystem identifier is the exact string `"go"` everywhere (config key, `PackageRef.Ecosystem`, `knownEcos`, `REG_ECOS`, OSV map key — already present).
- Default upstream: `https://proxy.golang.org`. New `registries.go` block ships `enabled: false`.
- Follow the `npm.go` adapter pattern: shared `httpClient` via `resolveClient(opts)`, upstreams trimmed of trailing `/`, walk upstreams in order returning first success.
- No metadata URL rewriting (GOPROXY embeds no URLs). No sumdb proxying, no VCS fallback (out of scope by decision).
- Lint gate is `golangci-lint` (unused/staticcheck/ineffassign). Unexported helpers must be referenced (production or same-package test) or they fail `unused`.
- `knownEcos` (Go, `internal/console/server.go`) and `REG_ECOS` (JS, `web/console/src/registries.jsx`) must change together; the console PUT validator requires the payload to list **all** ecosystems.
- Editing any `web/console/src/*.js|jsx` requires regenerating `web/console/app.bundle.js` via `go generate ./...` and committing the regenerated bundle.
- Commit after every task. End commit messages with the Co-Authored-By trailer already used on this branch.
- Work happens on the existing `feat/go-module-adapter` branch.

---

### Task 1: Go case-encoding decode/encode helpers

**Files:**
- Create: `internal/proxy/adapters/go.go`
- Create (whitebox test, `package adapters`): `internal/proxy/adapters/go_internal_test.go`

**Interfaces:**
- Produces: `decodeGoPath(s string) (string, bool)` — reverses case-encoding; invalid `!` sequences return `("", false)`. `encodeGoPath(s string) string` — inverse (uppercase → `!`+lowercase). Both unexported, in `package adapters`.

- [ ] **Step 1: Write the failing whitebox test**

Create `internal/proxy/adapters/go_internal_test.go`:

```go
package adapters

import "testing"

func TestDecodeGoPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"github.com/stretchr/testify", "github.com/stretchr/testify", true},
		{"github.com/!azure/azure-sdk-for-go", "github.com/Azure/azure-sdk-for-go", true},
		{"!cover", "Cover", true},
		{"v2.0.0+incompatible", "v2.0.0+incompatible", true},
		{"v0.0.0-20200101000000-abcdef123456", "v0.0.0-20200101000000-abcdef123456", true},
		{"bad!", "", false},   // trailing '!'
		{"bad!A", "", false},  // '!' + non-lowercase
		{"bad!1", "", false},  // '!' + digit
	}
	for _, c := range cases {
		got, ok := decodeGoPath(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("decodeGoPath(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestEncodeGoPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"github.com/stretchr/testify", "github.com/stretchr/testify"},
		{"github.com/Azure/azure-sdk-for-go", "github.com/!azure/azure-sdk-for-go"},
		{"Cover", "!cover"},
	}
	for _, c := range cases {
		if got := encodeGoPath(c.in); got != c.want {
			t.Errorf("encodeGoPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGoPathRoundTrip(t *testing.T) {
	for _, s := range []string{"github.com/Azure/Go-Foo", "example.com/ABC/def", "plain/path"} {
		enc := encodeGoPath(s)
		dec, ok := decodeGoPath(enc)
		if !ok || dec != s {
			t.Errorf("round-trip %q -> %q -> (%q, %v)", s, enc, dec, ok)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/adapters/ -run 'TestDecodeGoPath|TestEncodeGoPath|TestGoPathRoundTrip' -v`
Expected: FAIL — `undefined: decodeGoPath` / `undefined: encodeGoPath` (build error).

- [ ] **Step 3: Write the helpers**

Create `internal/proxy/adapters/go.go`:

```go
package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// decodeGoPath reverses Go module case-encoding: a '!' followed by a lowercase
// ASCII letter becomes that letter uppercased (e.g. "!azure" -> "Azure"). Input
// without '!' is returned unchanged. A '!' that is trailing, or followed by any
// byte other than [a-z], is invalid and yields ("", false) — reject, never guess.
func decodeGoPath(s string) (string, bool) {
	if !strings.Contains(s, "!") {
		return s, true
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '!' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(s) {
			return "", false
		}
		n := s[i+1]
		if n < 'a' || n > 'z' {
			return "", false
		}
		b.WriteByte(n - ('a' - 'A'))
		i++
	}
	return b.String(), true
}

// encodeGoPath applies Go module case-encoding: each uppercase ASCII letter
// becomes '!' followed by its lowercase form. It is the inverse of decodeGoPath.
func encodeGoPath(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			b.WriteByte(c + ('a' - 'A'))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
```

Note: the imports `context`, `json`, `fmt`, `http`, `time`, `gate` are used by later tasks in this same file. To keep this task compiling and lint-clean on its own, add a temporary blank reference is NOT needed — instead complete Task 2 and Task 3 which consume them. If running Task 1 in isolation, trim the import block to just `strings` and re-add the rest in Tasks 2–3. (Subagent-driven execution builds only at task end; keep the full import list if Tasks 2–3 follow immediately.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/adapters/ -run 'TestDecodeGoPath|TestEncodeGoPath|TestGoPathRoundTrip' -v`
Expected: PASS (3 tests). If `go.go` was written with the full import list but Tasks 2–3 not yet done, the package won't build (unused imports) — proceed directly to Task 2 before running the full package, or temporarily keep only `import "strings"`.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/adapters/go.go internal/proxy/adapters/go_internal_test.go
git commit -m "feat(go): case-encoding decode/encode helpers

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: GoAdapter core — Name, NormalizeRequest, UpstreamURLs

**Files:**
- Modify: `internal/proxy/adapters/go.go` (append to the file from Task 1)
- Create: `internal/proxy/adapters/go_test.go` (external, `package adapters_test`)

**Interfaces:**
- Consumes: `decodeGoPath` (Task 1); `Option`, `resolveClient` (`options.go`); `gate.PackageRef`, `gate.RegistryAdapter`.
- Produces: `NewGoAdapter(upstreams []string, opts ...Option) *GoAdapter`; methods `Name() string`, `NormalizeRequest(*http.Request) (*gate.PackageRef, bool)`, `UpstreamURLs(*http.Request) []string`.

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/adapters/go_test.go`:

```go
package adapters_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
)

func TestGoAdapter_NormalizeRequest_Zip(t *testing.T) {
	a := adapters.NewGoAdapter([]string{"https://proxy.golang.org"})
	r := httptest.NewRequest(http.MethodGet, "/github.com/stretchr/testify/@v/v1.9.0.zip", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "go", ref.Ecosystem)
	assert.Equal(t, "github.com/stretchr/testify", ref.Name)
	assert.Equal(t, "v1.9.0", ref.Version)
}

func TestGoAdapter_NormalizeRequest_CaseEncoded(t *testing.T) {
	a := adapters.NewGoAdapter([]string{"https://proxy.golang.org"})
	r := httptest.NewRequest(http.MethodGet, "/github.com/!azure/azure-sdk-for-go/@v/v68.0.0+incompatible.zip", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "github.com/Azure/azure-sdk-for-go", ref.Name)
	assert.Equal(t, "v68.0.0+incompatible", ref.Version)
}

func TestGoAdapter_NormalizeRequest_NotIntercepted(t *testing.T) {
	a := adapters.NewGoAdapter([]string{"https://proxy.golang.org"})
	for _, p := range []string{
		"/github.com/stretchr/testify/@v/list",
		"/github.com/stretchr/testify/@v/v1.9.0.info",
		"/github.com/stretchr/testify/@v/v1.9.0.mod",
		"/github.com/stretchr/testify/@latest",
		"/github.com/stretchr/testify/@v/.zip", // empty version
		"/no-atv-segment.zip",                  // missing /@v/
	} {
		r := httptest.NewRequest(http.MethodGet, p, nil)
		_, ok := a.NormalizeRequest(r)
		assert.False(t, ok, "path %q should not be intercepted", p)
	}
}

func TestGoAdapter_UpstreamURLs(t *testing.T) {
	a := adapters.NewGoAdapter([]string{"https://proxy.golang.org/", "https://mirror.example.org/go"})
	r := httptest.NewRequest(http.MethodGet, "/github.com/stretchr/testify/@v/list", nil)
	urls := a.UpstreamURLs(r)
	require.Len(t, urls, 2)
	assert.Equal(t, "https://proxy.golang.org/github.com/stretchr/testify/@v/list", urls[0])
	assert.Equal(t, "https://mirror.example.org/go/github.com/stretchr/testify/@v/list", urls[1])
}

func TestGoAdapter_Name(t *testing.T) {
	assert.Equal(t, "go", adapters.NewGoAdapter(nil).Name())
}

// keep imports used across Task 2 + Task 3
var _ = context.Background
var _ = json.NewEncoder
var _ = time.Now
```

Note: delete the three `var _ =` lines at the end of Task 3 once `FetchMetadata` tests use those imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/adapters/ -run TestGoAdapter -v`
Expected: FAIL — `undefined: adapters.NewGoAdapter`.

- [ ] **Step 3: Append the struct and methods to `go.go`**

Append to `internal/proxy/adapters/go.go`:

```go
// GoAdapter implements gate.RegistryAdapter for the Go module proxy protocol
// (GOPROXY). It intercepts module zip downloads for gating and proxies the rest
// of the protocol (list/.info/.mod/@latest) transparently.
type GoAdapter struct {
	upstreams  []string
	httpClient *http.Client
}

// NewGoAdapter creates a Go module adapter over the given ordered upstream URLs.
func NewGoAdapter(upstreams []string, opts ...Option) *GoAdapter {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return &GoAdapter{
		upstreams:  trimmed,
		httpClient: resolveClient(opts),
	}
}

func (a *GoAdapter) Name() string { return "go" }

// NormalizeRequest intercepts module zip downloads (path contains "/@v/" and
// ends ".zip"). list/.info/.mod/@latest requests are proxied transparently.
// The case-encoded module path and version are decoded to canonical coordinates
// for OSV / allowlist lookups.
func (a *GoAdapter) NormalizeRequest(r *http.Request) (*gate.PackageRef, bool) {
	path := r.URL.Path
	if !strings.HasSuffix(path, ".zip") {
		return nil, false
	}
	idx := strings.Index(path, "/@v/")
	if idx == -1 {
		return nil, false
	}
	encModule := strings.TrimPrefix(path[:idx], "/")
	encVersion := strings.TrimSuffix(path[idx+len("/@v/"):], ".zip")
	if encModule == "" || encVersion == "" {
		return nil, false
	}
	module, ok := decodeGoPath(encModule)
	if !ok {
		return nil, false
	}
	version, ok := decodeGoPath(encVersion)
	if !ok {
		return nil, false
	}
	return &gate.PackageRef{Ecosystem: "go", Name: module, Version: version}, true
}

// UpstreamURLs returns one candidate URL per configured upstream, in order.
// The client already sent case-encoded paths, so RequestURI() is forwarded
// verbatim.
func (a *GoAdapter) UpstreamURLs(r *http.Request) []string {
	urls := make([]string, len(a.upstreams))
	for i, base := range a.upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/adapters/ -run TestGoAdapter -v`
Expected: PASS. (Package still has unused `context`/`json`/`fmt`/`time` in `go.go` until Task 3; the `var _ =` lines in the test keep the *test* imports alive, but `go.go`'s `fmt`/`json`/`time`/`context` are consumed only in Task 3. If the build fails on unused imports in `go.go`, proceed to Task 3 before running the full package — or run only `-run TestGoAdapter` which still compiles the whole package. If blocked, temporarily comment the unused imports and restore in Task 3.)

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/adapters/go.go internal/proxy/adapters/go_test.go
git commit -m "feat(go): GoAdapter Name/NormalizeRequest/UpstreamURLs

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: FetchMetadata from the .info endpoint

**Files:**
- Modify: `internal/proxy/adapters/go.go` (append)
- Modify: `internal/proxy/adapters/go_test.go` (add FetchMetadata tests; remove the `var _ =` shims)

**Interfaces:**
- Consumes: `encodeGoPath` (Task 1); `gate.PackageMetadata`.
- Produces: `func (a *GoAdapter) FetchMetadata(ctx context.Context, ref *gate.PackageRef) (*gate.PackageMetadata, error)` — sets `PublishedAt` from the `.info` `Time`; leaves `License`/`Checksum`/`Maintainer` empty.

- [ ] **Step 1: Write the failing test**

In `internal/proxy/adapters/go_test.go`, remove the three `var _ =` shim lines and add:

```go
func TestGoAdapter_FetchMetadata(t *testing.T) {
	publishedAt := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/github.com/!azure/azure-sdk-for-go/@v/v68.0.0+incompatible.info", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Version": "v68.0.0+incompatible",
			"Time":    publishedAt.Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	a := adapters.NewGoAdapter([]string{srv.URL})
	ref := &gate.PackageRef{Ecosystem: "go", Name: "github.com/Azure/azure-sdk-for-go", Version: "v68.0.0+incompatible"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, publishedAt, meta.PublishedAt)
	assert.Empty(t, meta.License)
}

func TestGoAdapter_FetchMetadata_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	a := adapters.NewGoAdapter([]string{srv.URL})
	ref := &gate.PackageRef{Ecosystem: "go", Name: "example.com/x", Version: "v1.0.0"}
	_, err := a.FetchMetadata(context.Background(), ref)
	require.Error(t, err)
}

func TestGoAdapter_FetchMetadata_Failover(t *testing.T) {
	published := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"Version": "v1.0.0", "Time": published.Format(time.RFC3339)})
	}))
	defer up.Close()

	a := adapters.NewGoAdapter([]string{down.URL, up.URL})
	ref := &gate.PackageRef{Ecosystem: "go", Name: "example.com/x", Version: "v1.0.0"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, published, meta.PublishedAt)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/adapters/ -run TestGoAdapter_FetchMetadata -v`
Expected: FAIL — `a.FetchMetadata undefined`.

- [ ] **Step 3: Append `FetchMetadata` to `go.go`**

```go
// goInfo is the subset of the GOPROXY .info document we consume. encoding/json
// parses the RFC3339 Time string into time.Time automatically.
type goInfo struct {
	Version string
	Time    time.Time
}

// FetchMetadata fetches the module version's .info document from each upstream
// in order, returning the first success. The .info Time is the publish date;
// the Go protocol carries no license or (SHA256) checksum there, so those stay
// empty.
func (a *GoAdapter) FetchMetadata(ctx context.Context, ref *gate.PackageRef) (*gate.PackageMetadata, error) {
	lastErr := fmt.Errorf("no upstreams configured for go")
	encModule := encodeGoPath(ref.Name)
	encVersion := encodeGoPath(ref.Version)
	for _, base := range a.upstreams {
		meta, err := a.fetchInfoFrom(ctx, base, encModule, encVersion)
		if err == nil {
			return meta, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (a *GoAdapter) fetchInfoFrom(ctx context.Context, base, encModule, encVersion string) (*gate.PackageMetadata, error) {
	apiURL := base + "/" + encModule + "/@v/" + encVersion + ".info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building go info request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching go info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("go proxy returned HTTP %d for %s", resp.StatusCode, apiURL)
	}
	var info goInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding go info: %w", err)
	}
	if info.Time.IsZero() {
		return nil, fmt.Errorf("go info for %s has no Time", encVersion)
	}
	return &gate.PackageMetadata{PublishedAt: info.Time.UTC()}, nil
}
```

- [ ] **Step 4: Run the full adapter package**

Run: `go test ./internal/proxy/adapters/ -v`
Expected: PASS (all existing + new Go tests). All imports in `go.go` now used.

Then lint:
Run: `golangci-lint run ./internal/proxy/adapters/...`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/adapters/go.go internal/proxy/adapters/go_test.go
git commit -m "feat(go): FetchMetadata from GOPROXY .info endpoint

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Config wiring

**Files:**
- Modify: `internal/config/config.go` (`RegistriesConfig`, `Validate` map)
- Modify: `config.yaml`
- Modify: `internal/config/config_test.go` (add a parse test)

**Interfaces:**
- Consumes: nothing from prior tasks.
- Produces: `config.Config.Registries.Go` of type `RegistryConfig`, populated from the `registries.go` YAML key.

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
func TestLoad_ParsesGoUpstreams(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
registries:
  go:
    upstreams:
      - "https://proxy.golang.org"
    enabled: true
`), 0o600))

	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://proxy.golang.org"}, cfg.Registries.Go.Upstreams)
	assert.True(t, cfg.Registries.Go.Enabled)
}
```

(Match the existing test file's helper style — reuse whatever `Load`/temp-file pattern `TestLoad_ParsesRubyGemsUpstreams` uses; if that test constructs config differently, mirror it exactly.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestLoad_ParsesGoUpstreams -v`
Expected: FAIL — `cfg.Registries.Go undefined`.

- [ ] **Step 3: Add the `Go` field and validation entry**

In `internal/config/config.go`, `RegistriesConfig`:

```go
type RegistriesConfig struct {
	PyPI     RegistryConfig `mapstructure:"pypi"`
	NPM      RegistryConfig `mapstructure:"npm"`
	Maven    RegistryConfig `mapstructure:"maven"`
	RubyGems RegistryConfig `mapstructure:"rubygems"`
	Go       RegistryConfig `mapstructure:"go"`
	Docker   RegistryConfig `mapstructure:"docker"`
}
```

In `Validate`, add `"go"` to the `regs` map:

```go
	regs := map[string]RegistryConfig{
		"pypi":     c.Registries.PyPI,
		"npm":      c.Registries.NPM,
		"maven":    c.Registries.Maven,
		"rubygems": c.Registries.RubyGems,
		"go":       c.Registries.Go,
		"docker":   c.Registries.Docker,
	}
```

- [ ] **Step 4: Add the `config.yaml` block**

In `config.yaml`, after the `rubygems:` block and before `docker:` (or anywhere within `registries:`), add:

```yaml
  go:
    upstreams:
      - "https://proxy.golang.org"
    enabled: false   # opt-in; Go module pull-through proxy (GOPROXY=http://<jo-ei>/go)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS (new test + existing).

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go config.yaml
git commit -m "feat(go): registries.go config field and validation

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: main.go wiring

**Files:**
- Modify: `cmd/jo-ei/main.go` (`buildHandlers`, `applyStoredRegistries`, `registryInfo`, the "no registries enabled" error string)

**Interfaces:**
- Consumes: `adapters.NewGoAdapter` (Task 2); `config.Config.Registries.Go` (Task 4).
- Produces: `handlers["go"]` route when enabled; `go` in `registryInfo` output; `case "go"` in the stored-registry overlay.

- [ ] **Step 1: Add the handler registration**

In `buildHandlers` (`cmd/jo-ei/main.go`), after the RubyGems block:

```go
	if cfg.Registries.Go.Enabled {
		handlers["go"] = buildHandler(adapters.NewGoAdapter(cfg.Registries.Go.Upstreams, client), shared)
	}
```

- [ ] **Step 2: Add the stored-registry case**

In `applyStoredRegistries`, add before `case "docker":`:

```go
		case "go":
			cfg.Registries.Go = rc
```

- [ ] **Step 3: Add the registryInfo entry**

In `registryInfo`, add before the docker entry:

```go
		{Ecosystem: "go", Enabled: cfg.Registries.Go.Enabled, Upstreams: cfg.Registries.Go.Upstreams},
```

- [ ] **Step 4: Update the "no registries enabled" error string**

Find the error in `run`/startup (`"no registries enabled; set at least one of registries.{pypi,npm,maven,rubygems,docker}.enabled: true"`) and add `go`:

```go
	return fmt.Errorf("no registries enabled; set at least one of registries.{pypi,npm,maven,rubygems,go,docker}.enabled: true")
```

- [ ] **Step 5: Build and smoke-test**

Run: `go build ./... && go vet ./cmd/...`
Expected: no errors.

Run: `go test ./cmd/... ./internal/... -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/jo-ei/main.go
git commit -m "feat(go): wire GoAdapter into handler routing and registry info

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Console validation + UI

**Files:**
- Modify: `internal/console/server.go` (`knownEcos`)
- Modify: `web/console/src/api.js` (`ECO` map)
- Modify: `web/console/src/registries.jsx` (`REG_ECOS`)
- Regenerate: `web/console/app.bundle.js` (via `go generate`)
- Check: `internal/console/server_test.go` for a validator test asserting the ecosystem count/set — update if present.

**Interfaces:**
- Consumes: nothing new.
- Produces: `"go"` accepted by `validateRegistries`; `go` rendered in the console registries screen.

- [ ] **Step 1: Add `"go"` to `knownEcos`**

In `internal/console/server.go`:

```go
var knownEcos = []string{"pypi", "npm", "maven", "rubygems", "go", "docker"}
```

- [ ] **Step 2: Check and update console tests**

Run: `grep -n "knownEcos\|must list all\|rubygems\|len(knownEcos)" internal/console/server_test.go`

If a test enumerates the ecosystem set or asserts the count (e.g. builds a valid PUT payload listing all ecosystems, or asserts "must list all N"), add a `go` entry / bump the count so it lists all 6. Run:

Run: `go test ./internal/console/ -v`
Expected: PASS (after updating any count/enumeration test).

- [ ] **Step 3: Add the `go` ECO entry (frontend)**

In `web/console/src/api.js`, add to the `ECO` object:

```js
    go:       { id: "go",       label: "go",   name: "Go" },
```

- [ ] **Step 4: Add `go` to `REG_ECOS`**

In `web/console/src/registries.jsx`:

```js
const REG_ECOS = ["pypi", "npm", "maven", "rubygems", "go", "docker"];
```

- [ ] **Step 5: Regenerate the console bundle**

Run: `go generate ./...`
Expected: `uibuild: wrote console/app.bundle.js (...)`. Confirm `web/console/app.bundle.js` changed:

Run: `git status --short web/console/app.bundle.js`
Expected: the bundle shows as modified.

- [ ] **Step 6: Build to confirm embed still compiles**

Run: `go build ./...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/console/server.go internal/console/server_test.go web/console/src/api.js web/console/src/registries.jsx web/console/app.bundle.js
git commit -m "feat(go): accept and render the go ecosystem in the console

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Documentation

**Files:**
- Create: `examples/go/README.md`
- Modify: `CHANGELOG.md` (Unreleased section)

**Interfaces:** none.

- [ ] **Step 1: Write the example README**

Create `examples/go/README.md`:

```markdown
# Go modules through Jōei

Point the Go toolchain at the Jōei proxy so module downloads pass the
supply-chain, CVE, and malware gates.

## Setup

    export GOPROXY=http://localhost:8080/go
    # No ",direct": a proxy miss is a 404 instead of an unscanned VCS fetch.

    go mod download        # pulls modules through Jōei
    go build ./...

## Checksum database

Jōei proxies module content only (`.info`, `.mod`, `.zip`, `list`), not the
Go checksum database (`sum.golang.org`). In a closed environment where the
toolchain can't reach the sumdb directly, disable it:

    export GOSUMDB=off

(Or configure `GONOSUMCHECK` / `GONOSUMDB` / `GOFLAGS` per your policy.)

## What is gated

Jōei intercepts module **zip** downloads and runs them through every enabled
gate. Resolution manifests (`.info`, `.mod`, `@v/list`, `@latest`) are proxied
transparently — they carry no executable code, and any dependency that ends up
compiled is fetched as its own zip and gated independently. A blocked module's
zip returns a structured 423/403 and `go build` fails.
```

- [ ] **Step 2: Add the CHANGELOG entry**

In `CHANGELOG.md`, under the `## [Unreleased]` `Added` list (create the `### Added` subhead if the section shape requires it — match the file's existing style), add:

```markdown
- Go module registry adapter: pull Go modules through Jōei
  (`GOPROXY=http://<jo-ei>/go`) so module zips pass the supply-chain, CVE, and
  malware gates. Enable via `registries.go` (disabled by default).
```

- [ ] **Step 3: Verify the docs render / no broken references**

Run: `git diff --stat CHANGELOG.md examples/go/README.md`
Expected: both files listed.

- [ ] **Step 4: Commit**

```bash
git add examples/go/README.md CHANGELOG.md
git commit -m "docs(go): example GOPROXY setup and changelog entry

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Full verification

**Files:** none (verification only).

- [ ] **Step 1: Full test + lint sweep**

Run: `go build ./... && go test ./... -count=1`
Expected: PASS across all packages.

Run: `golangci-lint run ./...`
Expected: no findings. (CRLF can mask gofmt locally; if the lint host disagrees, run `gofmt -l internal/proxy/adapters/go.go`.)

- [ ] **Step 2: Confirm bundle is committed and clean tree**

Run: `git status --short`
Expected: clean (no uncommitted `app.bundle.js` or source).

- [ ] **Step 3: Manual protocol sanity (optional, if a build is available)**

Start the proxy with `registries.go.enabled: true`, then:

Run: `GOPROXY=http://localhost:8080/go GOSUMDB=off go mod download github.com/stretchr/testify@v1.9.0`
Expected: succeeds (module cached after passing gates). A known-blocked package returns a structured 4xx and `go` reports the download failure.

- [ ] **Step 4: Push and open PR**

```bash
git push -u origin feat/go-module-adapter
gh pr create --base main --title "feat: Go module registry adapter" --body "..."
```

---

## Self-Review

**Spec coverage:**
- GoAdapter under `/go/`, `.zip` interception, transparent list/.info/.mod/@latest → Tasks 1–3, 5. ✓
- Case-encoding decode/encode → Task 1. ✓
- Publish date from `.info` via FetchMetadata → Task 3. ✓
- No URL rewriting / not a DownloadMetadataExtractor → Task 3 (FetchMetadata up front; no MetadataFromHeader added). ✓
- Wiring: config, main, console validation, console UI, example, changelog → Tasks 4–7. ✓
- Stored-registry migration (validator only on PUT; overlay tolerates missing `go`) → Task 5 (`case "go"`) + Task 6 (knownEcos). ✓
- Out-of-scope items (sumdb, VCS) documented, not implemented → Task 7 README. ✓
- Edge cases (`+incompatible`, pseudo-versions, uppercase, missing `/@v/`, empty version) → Task 2 tests. ✓
- Threat-model rationale for transparent `.mod` → captured in spec; no code needed. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code. The only conditional instructions concern import-liveness across Tasks 1–3 (unavoidable for an incrementally built single Go file) and matching the existing test-file style in Tasks 4 & 6 — both give concrete fallback actions.

**Type consistency:** `decodeGoPath`/`encodeGoPath` signatures identical across Tasks 1–3. `NewGoAdapter`, `Name`, `NormalizeRequest`, `UpstreamURLs`, `FetchMetadata` names/signatures consistent Task 2↔3↔5. `Registries.Go` (Task 4) referenced identically in Task 5. `knownEcos`/`REG_ECOS`/`ECO` all gain the exact string `"go"`.

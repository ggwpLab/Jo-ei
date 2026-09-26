# npm Metadata Version Filtering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hide versions the supply-chain gate would block from npm metadata documents, so npm's own resolver picks an allowed version instead of failing the install on a `423`.

**Architecture:** A new optional `gate.MetadataFilterer` capability lets the npm adapter rewrite a packument; the proxy handler buffers the document, asks policy about each version, and serves the rewrite under its own synthetic `ETag` so clients cannot revalidate their way back into a stale filtered copy. Documents that cannot be filtered — oversized, unparseable, or entirely rejected — are served untouched, because the artifact gate stays the enforcement boundary.

**Tech Stack:** Go (stdlib only for the new code: `encoding/json`, `compress/gzip`, `crypto/sha256`), `golang.org/x/sync/singleflight` (already a dependency), testify, zerolog, viper.

**Spec:** `docs/superpowers/specs/2026-09-26-npm-metadata-version-filter-design.md`

## Global Constraints

- **No new module dependencies.** `go.mod` is deliberately lean. Everything new comes from the standard library or a module already required. In particular: no semver library — `dist-tags` are deliberately left untouched.
- **`gate.Event` gains no new verdict.** `aggregate.record` increments `requests` for every event (`internal/telemetry/aggregate.go:42`), so a filtering event would corrupt the KPI counters repaired in PR #80. Filtering is reported by log lines only.
- **The artifact gate remains the enforcement boundary.** Every path that cannot filter falls back to serving the document untouched and letting the tarball request answer `423`.
- **Comments in English**, matching the density and voice of the surrounding file: say why, not what.
- **Lint gate is `golangci-lint run`, not `go vet`.** Run `make lint` before every commit. A CRLF checkout can mask gofmt findings locally, so also run `make fmt` and check `git diff` is empty.
- Unit tests: `go test ./... -race`. Integration tests are behind a build tag: `go test -tags integration ./integration/ -v`.

---

### Task 1: The `MetadataFilterer` capability and npm request classification

**Files:**
- Modify: `internal/gate/gate.go` (append after the `DownloadMetadataExtractor` block, around line 75)
- Modify: `internal/proxy/adapters/npm.go`
- Test: `internal/proxy/adapters/npm_test.go`

**Interfaces:**
- Consumes: `gate.RegistryAdapter` (existing), `adapters.NPMAdapter` (existing).
- Produces: `gate.MetadataRef{Ecosystem, Name string}`, `gate.VersionDecider func(version string, publishedAt time.Time) bool`, `gate.FilteredDocument{Body []byte; Removed []string; AllRejected bool}`, `gate.MetadataFilterer` with `NormalizeMetadataRequest(*http.Request) (*gate.MetadataRef, bool)` and `FilterVersions([]byte, gate.VersionDecider) (gate.FilteredDocument, error)`. `(*NPMAdapter).NormalizeMetadataRequest` is implemented here; `FilterVersions` lands in Task 2.

> **Note on the spec.** The spec's §1 sketch returns `([]byte, []string, error)` and leaves the "every version rejected" rule to the handler. This plan moves that rule into the adapter and returns a named `FilteredDocument` instead, because the rule is about the document's byte identity — the same concern as "return the input slice when nothing changed" — and keeping both in one place is what makes the byte-identity test in Task 2 meaningful. Observable behaviour is identical to the spec.

- [ ] **Step 1: Write the failing test**

Append to `internal/proxy/adapters/npm_test.go`:

```go
func TestNPMAdapter_NormalizeMetadataRequest(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	tests := []struct {
		name     string
		method   string
		path     string
		wantOK   bool
		wantName string
	}{
		{name: "bare package", method: http.MethodGet, path: "/left-pad", wantOK: true, wantName: "left-pad"},
		{name: "scoped encoded", method: http.MethodGet, path: "/@types%2fnode", wantOK: true, wantName: "@types/node"},
		{name: "scoped plain", method: http.MethodGet, path: "/@types/node", wantOK: true, wantName: "@types/node"},

		// A single-version manifest has no version list to rewrite.
		{name: "version manifest", method: http.MethodGet, path: "/left-pad/1.3.0"},
		{name: "scoped version manifest", method: http.MethodGet, path: "/@types/node/20.0.0"},

		// Tarballs belong to NormalizeRequest, service endpoints to nobody.
		{name: "tarball", method: http.MethodGet, path: "/left-pad/-/left-pad-1.3.0.tgz"},
		{name: "search", method: http.MethodGet, path: "/-/v1/search"},
		{name: "npm api", method: http.MethodGet, path: "/-/npm/v1/user"},
		{name: "whoami", method: http.MethodGet, path: "/-/whoami"},

		// Publishes must never be rewritten.
		{name: "publish put", method: http.MethodPut, path: "/left-pad"},
		{name: "publish post", method: http.MethodPost, path: "/left-pad"},

		{name: "root", method: http.MethodGet, path: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.path, nil)
			ref, ok := a.NormalizeMetadataRequest(r)
			require.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				assert.Nil(t, ref)
				return
			}
			require.NotNil(t, ref)
			assert.Equal(t, "npm", ref.Ecosystem)
			assert.Equal(t, tt.wantName, ref.Name)
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/adapters/ -run TestNPMAdapter_NormalizeMetadataRequest -v`
Expected: FAIL to compile — `a.NormalizeMetadataRequest undefined` and `gate.MetadataRef` undefined.

- [ ] **Step 3: Declare the capability in `internal/gate/gate.go`**

Insert after the `DownloadMetadataExtractor` interface block (the comment block ends around line 75):

```go
// MetadataRef names the package a metadata document describes. It is a
// PackageRef without a version, because the document covers every version.
type MetadataRef struct {
	Ecosystem string
	Name      string
}

// VersionDecider reports whether one version of a package may be served.
// publishedAt is the zero time when the document carries no publish date for
// that version, which leaves any age-based rule mute.
type VersionDecider func(version string, publishedAt time.Time) bool

// FilteredDocument is the result of rewriting a metadata document.
type FilteredDocument struct {
	// Body is the document to serve. It is the input document itself, byte for
	// byte, when nothing was removed — which lets the caller forward the
	// upstream validators along with it.
	Body []byte
	// Removed lists the versions hidden from Body, sorted.
	Removed []string
	// AllRejected reports that policy rejected every version in the document.
	// Body is then the original: an empty version list would turn every install
	// of that package into a resolution error instead of a gate verdict, so the
	// artifact gate is left to state the real reason at download time.
	AllRejected bool
}

// MetadataFilterer is an optional RegistryAdapter capability: rewriting a
// metadata document so that versions policy will not serve are absent from it,
// letting the client's own resolver pick an allowed version instead of failing
// on a blocked download. npm implements it; adapters whose clients resolve
// server-side do not.
type MetadataFilterer interface {
	// NormalizeMetadataRequest reports whether r asks for a filterable metadata
	// document, and names the package it describes.
	NormalizeMetadataRequest(r *http.Request) (*MetadataRef, bool)

	// FilterVersions rewrites doc, dropping every version decide rejects.
	FilterVersions(doc []byte, decide VersionDecider) (FilteredDocument, error)
}
```

- [ ] **Step 4: Implement `NormalizeMetadataRequest` in `internal/proxy/adapters/npm.go`**

Append to the file:

```go
// NormalizeMetadataRequest reports whether r asks for an npm packument — the
// per-package document npm resolves version ranges from. Only a bare package
// name qualifies: registry service endpoints live under "/-/", and a
// single-version manifest ("/left-pad/1.3.0") carries no version list to
// rewrite, so both are proxied untouched and blocked at download time instead.
func (a *NPMAdapter) NormalizeMetadataRequest(r *http.Request) (*gate.MetadataRef, bool) {
	if r.Method != http.MethodGet {
		return nil, false
	}
	// URL.Path arrives percent-decoded, so npm's two spellings of a scoped name
	// — "/@types%2fnode" and "/@types/node" — are the same string here.
	name := strings.TrimPrefix(r.URL.Path, "/")
	if !isNPMPackageName(name) {
		return nil, false
	}
	return &gate.MetadataRef{Ecosystem: "npm", Name: name}, true
}

// isNPMPackageName reports whether s is a bare package name: "left-pad" or
// "@types/node". A leading "-" segment is a registry service endpoint, and any
// extra segment means a tarball or a single-version manifest.
func isNPMPackageName(s string) bool {
	if s == "" {
		return false
	}
	parts := strings.Split(s, "/")
	if parts[0] == "-" {
		return false
	}
	if strings.HasPrefix(s, "@") {
		return len(parts) == 2 && len(parts[0]) > 1 && parts[1] != ""
	}
	return len(parts) == 1
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/proxy/adapters/ -run TestNPMAdapter_NormalizeMetadataRequest -v`
Expected: PASS, all 12 subtests.

- [ ] **Step 6: Verify nothing else broke, then lint**

Run: `go test ./... -race`
Expected: PASS.
Run: `make fmt && make lint && git diff --stat`
Expected: no lint findings; `git diff` shows only the files you edited.

- [ ] **Step 7: Commit**

```bash
git add internal/gate/gate.go internal/proxy/adapters/npm.go internal/proxy/adapters/npm_test.go
git commit -m "feat(gate): add MetadataFilterer capability and npm packument routing

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: `FilterVersions` on the npm adapter

**Files:**
- Modify: `internal/proxy/adapters/npm.go`
- Test: `internal/proxy/adapters/npm_test.go`

**Interfaces:**
- Consumes: `gate.VersionDecider`, `gate.FilteredDocument` (Task 1).
- Produces: `(*NPMAdapter).FilterVersions(doc []byte, decide gate.VersionDecider) (gate.FilteredDocument, error)`. After this task `*NPMAdapter` satisfies `gate.MetadataFilterer` in full.

- [ ] **Step 1: Write the failing tests**

Append to `internal/proxy/adapters/npm_test.go`:

```go
// fullPackument is a miniature of the real thing: unknown top-level fields that
// must survive, a time map that includes the non-version "created"/"modified"
// keys, and a dist-tags entry pointing at the newest version.
const fullPackument = `{
  "_id": "left-pad",
  "name": "left-pad",
  "readme": "# left-pad",
  "dist-tags": {"latest": "1.3.0"},
  "time": {
    "created": "2014-01-01T00:00:00.000Z",
    "modified": "2018-01-01T00:00:00.000Z",
    "1.2.0": "2017-01-01T00:00:00.000Z",
    "1.3.0": "2018-01-01T00:00:00.000Z"
  },
  "versions": {
    "1.2.0": {"name": "left-pad", "version": "1.2.0", "dist": {"shasum": "aaa"}},
    "1.3.0": {"name": "left-pad", "version": "1.3.0", "dist": {"shasum": "bbb"}}
  }
}`

// abbreviatedPackument is what Accept: application/vnd.npm.install-v1+json
// returns: no "time" map anywhere, so no age rule can speak.
const abbreviatedPackument = `{
  "name": "left-pad",
  "dist-tags": {"latest": "1.3.0"},
  "modified": "2018-01-01T00:00:00.000Z",
  "versions": {
    "1.2.0": {"name": "left-pad", "version": "1.2.0", "dist": {"shasum": "aaa"}},
    "1.3.0": {"name": "left-pad", "version": "1.3.0", "dist": {"shasum": "bbb"}}
  }
}`

// rejectVersions builds a decider that hides exactly the named versions.
func rejectVersions(names ...string) gate.VersionDecider {
	bad := make(map[string]bool, len(names))
	for _, n := range names {
		bad[n] = true
	}
	return func(version string, _ time.Time) bool { return !bad[version] }
}

func TestNPMAdapter_FilterVersions_RemovesVersionAndItsTimeEntry(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	got, err := a.FilterVersions([]byte(fullPackument), rejectVersions("1.3.0"))
	require.NoError(t, err)
	assert.Equal(t, []string{"1.3.0"}, got.Removed)
	assert.False(t, got.AllRejected)

	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
		Time     map[string]string          `json:"time"`
		DistTags map[string]string          `json:"dist-tags"`
		Readme   string                     `json:"readme"`
	}
	require.NoError(t, json.Unmarshal(got.Body, &doc))

	assert.NotContains(t, doc.Versions, "1.3.0")
	assert.Contains(t, doc.Versions, "1.2.0")
	assert.NotContains(t, doc.Time, "1.3.0", "the removed version's publish date must go with it")
	assert.Contains(t, doc.Time, "created", "non-version time keys must survive")
	assert.Equal(t, "# left-pad", doc.Readme, "unknown top-level fields must survive")

	// npm tolerates a tag naming a version that is no longer listed and falls
	// back to the highest one that is. Leaving tags alone is what spares this
	// project a semver comparator; do not "fix" this assertion.
	assert.Equal(t, "1.3.0", doc.DistTags["latest"])
}

func TestNPMAdapter_FilterVersions_NothingRemovedReturnsOriginalBytes(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})
	doc := []byte(fullPackument)

	got, err := a.FilterVersions(doc, rejectVersions())
	require.NoError(t, err)
	assert.Empty(t, got.Removed)
	assert.False(t, got.AllRejected)
	// Byte identity, not just equality: the caller forwards the upstream ETag
	// with this body, and Go marshals maps with sorted keys, so a re-marshal
	// would silently reorder the document the ETag describes.
	assert.Same(t, &doc[0], &got.Body[0])
	assert.Equal(t, doc, got.Body)
}

func TestNPMAdapter_FilterVersions_AllRejectedKeepsOriginal(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})
	doc := []byte(fullPackument)

	got, err := a.FilterVersions(doc, rejectVersions("1.2.0", "1.3.0"))
	require.NoError(t, err)
	assert.True(t, got.AllRejected)
	assert.Equal(t, []string{"1.2.0", "1.3.0"}, got.Removed)
	assert.Equal(t, doc, got.Body, "an empty version list would break every install of this package")
}

func TestNPMAdapter_FilterVersions_AbbreviatedHasNoDates(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	var seen map[string]time.Time
	decide := func(version string, publishedAt time.Time) bool {
		if seen == nil {
			seen = map[string]time.Time{}
		}
		seen[version] = publishedAt
		return true
	}

	got, err := a.FilterVersions([]byte(abbreviatedPackument), decide)
	require.NoError(t, err)
	assert.Empty(t, got.Removed)
	assert.True(t, seen["1.2.0"].IsZero(), "no time map means no publish date to judge")
	assert.True(t, seen["1.3.0"].IsZero())
}

func TestNPMAdapter_FilterVersions_PassesPublishDates(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	seen := map[string]time.Time{}
	decide := func(version string, publishedAt time.Time) bool {
		seen[version] = publishedAt
		return true
	}

	_, err := a.FilterVersions([]byte(fullPackument), decide)
	require.NoError(t, err)
	assert.Equal(t, "2018-01-01T00:00:00Z", seen["1.3.0"].Format(time.RFC3339))
	assert.Equal(t, "2017-01-01T00:00:00Z", seen["1.2.0"].Format(time.RFC3339))
}

func TestNPMAdapter_FilterVersions_MalformedDocument(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})

	_, err := a.FilterVersions([]byte(`{"versions": [`), rejectVersions("1.0.0"))
	require.Error(t, err)
}

func TestNPMAdapter_FilterVersions_DocumentWithoutVersions(t *testing.T) {
	a := adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"})
	doc := []byte(`{"name": "left-pad"}`)

	got, err := a.FilterVersions(doc, rejectVersions("1.3.0"))
	require.NoError(t, err)
	assert.Equal(t, doc, got.Body)
	assert.Empty(t, got.Removed)
}
```

`internal/proxy/adapters/npm_test.go` will need `encoding/json` and `sort` is not needed in the test; confirm the import block contains `encoding/json`, `net/http`, `net/http/httptest`, `testing`, `time`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/adapters/ -run TestNPMAdapter_FilterVersions -v`
Expected: FAIL to compile — `a.FilterVersions undefined`.

- [ ] **Step 3: Implement `FilterVersions`**

Append to `internal/proxy/adapters/npm.go`:

```go
// FilterVersions implements gate.MetadataFilterer. It rewrites an npm packument,
// dropping every version decide rejects along with that version's "time" entry.
// Unknown fields survive because the document is decoded one level deep, as raw
// JSON. dist-tags are deliberately left alone: npm tolerates a tag naming a
// version that is no longer listed and falls back to the highest one that is,
// which spares this project a semver comparator.
func (a *NPMAdapter) FilterVersions(doc []byte, decide gate.VersionDecider) (gate.FilteredDocument, error) {
	unchanged := gate.FilteredDocument{Body: doc}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		return gate.FilteredDocument{}, fmt.Errorf("decoding npm packument: %w", err)
	}
	rawVersions, ok := top["versions"]
	if !ok {
		return unchanged, nil
	}
	var versions map[string]json.RawMessage
	if err := json.Unmarshal(rawVersions, &versions); err != nil {
		return gate.FilteredDocument{}, fmt.Errorf("decoding npm packument versions: %w", err)
	}

	published := npmPublishDates(top["time"])

	var removed []string
	for version := range versions {
		if !decide(version, published[version]) {
			removed = append(removed, version)
		}
	}
	if len(removed) == 0 {
		return unchanged, nil
	}
	sort.Strings(removed)
	if len(removed) == len(versions) {
		// Serving an empty version list would turn every install of this
		// package into a resolution error. Hand back the original and let the
		// artifact gate state the real reason at download time.
		return gate.FilteredDocument{Body: doc, Removed: removed, AllRejected: true}, nil
	}

	for _, v := range removed {
		delete(versions, v)
	}
	encodedVersions, err := json.Marshal(versions)
	if err != nil {
		return gate.FilteredDocument{}, fmt.Errorf("encoding npm packument versions: %w", err)
	}
	top["versions"] = encodedVersions

	if raw, ok := top["time"]; ok {
		var times map[string]json.RawMessage
		if err := json.Unmarshal(raw, &times); err == nil {
			for _, v := range removed {
				delete(times, v)
			}
			if encoded, err := json.Marshal(times); err == nil {
				top["time"] = encoded
			}
		}
	}

	body, err := json.Marshal(top)
	if err != nil {
		return gate.FilteredDocument{}, fmt.Errorf("encoding npm packument: %w", err)
	}
	return gate.FilteredDocument{Body: body, Removed: removed}, nil
}

// npmPublishDates decodes a packument's "time" map. It is absent from the
// abbreviated document, and a version missing from it yields the zero time,
// which mutes any age-based rule for that version. The map also holds the
// non-version keys "created" and "modified"; they are harmless here because
// only version names are ever looked up.
func npmPublishDates(raw json.RawMessage) map[string]time.Time {
	if len(raw) == 0 {
		return nil
	}
	var times map[string]string
	if err := json.Unmarshal(raw, &times); err != nil {
		return nil
	}
	out := make(map[string]time.Time, len(times))
	for version, s := range times {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			out[version] = t.UTC()
		}
	}
	return out
}
```

Add `"sort"` to the import block in `internal/proxy/adapters/npm.go`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/adapters/ -run TestNPMAdapter_FilterVersions -v`
Expected: PASS, all 7 tests.

- [ ] **Step 5: Assert the interface is satisfied**

Add to `internal/proxy/adapters/npm.go`, just below the `NPMAdapter` struct declaration:

```go
// Compile-time proof that npm supports metadata filtering; the handler
// type-asserts this capability rather than requiring it of every adapter.
var _ gate.MetadataFilterer = (*NPMAdapter)(nil)
```

Run: `go build ./... && go test ./... -race`
Expected: builds; all tests PASS.

- [ ] **Step 6: Lint and commit**

Run: `make fmt && make lint`
Expected: no findings.

```bash
git add internal/proxy/adapters/npm.go internal/proxy/adapters/npm_test.go
git commit -m "feat(npm): filter blocked versions out of a packument

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Synthetic ETag helpers

**Files:**
- Create: `internal/proxy/metadata.go`
- Test: `internal/proxy/metadata_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `syntheticETagPrefix` constant, `syntheticETag(body []byte) string`, `holdsSyntheticETag(ifNoneMatch string) bool`. All package-private in `package proxy`; Tasks 5 and 6 call them.

Note: `internal/proxy/metadata_test.go` is an **internal** test file (`package proxy`, not `proxy_test`) because these helpers are unexported. The other proxy tests are external; this one has to differ.

- [ ] **Step 1: Write the failing tests**

Create `internal/proxy/metadata_test.go`:

```go
package proxy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSyntheticETag_IsStableAndBodyDependent(t *testing.T) {
	a := syntheticETag([]byte(`{"versions":{"1.2.0":{}}}`))
	b := syntheticETag([]byte(`{"versions":{"1.2.0":{}}}`))
	c := syntheticETag([]byte(`{"versions":{"1.2.0":{},"1.3.0":{}}}`))

	assert.Equal(t, a, b, "identical filtering must revalidate as 304")
	assert.NotEqual(t, a, c, "different filtering must not")

	assert.True(t, strings.HasPrefix(a, syntheticETagPrefix), "must be recognisable as ours: %s", a)
	assert.True(t, strings.HasSuffix(a, `"`), "must be a quoted ETag: %s", a)
}

func TestHoldsSyntheticETag(t *testing.T) {
	ours := syntheticETag([]byte(`{}`))

	tests := []struct {
		name  string
		inm   string
		want  bool
	}{
		{name: "empty", inm: ""},
		{name: "upstream tag", inm: `"e83879f942df342315ccdeff2139a89a"`},
		{name: "ours", inm: ours, want: true},
		{name: "ours second in a list", inm: `"e83879f9", ` + ours, want: true},
		{name: "ours first in a list", inm: ours + `, "e83879f9"`, want: true},
		{name: "wildcard is not ours", inm: "*"},
		{name: "garbage", inm: "not-a-tag"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, holdsSyntheticETag(tt.inm))
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/ -run 'TestSyntheticETag|TestHoldsSyntheticETag' -v`
Expected: FAIL to compile — `undefined: syntheticETag`.

- [ ] **Step 3: Implement the helpers**

Create `internal/proxy/metadata.go`:

```go
package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// syntheticETagPrefix marks an ETag this proxy minted for a rewritten metadata
// document. A client revalidating with such a tag must be served from a freshly
// filtered document: forwarding its If-None-Match upstream would earn a 304 with
// no body to filter, pinning the client to a stale rewrite forever.
const syntheticETagPrefix = `"joei.`

// syntheticETag mints a strong validator for a rewritten document. The value
// hashes the rewritten body, so a client whose filtering has not changed
// revalidates as 304 and the slow path still costs the client hop nothing.
func syntheticETag(body []byte) string {
	sum := sha256.Sum256(body)
	return syntheticETagPrefix + hex.EncodeToString(sum[:8]) + `"`
}

// holdsSyntheticETag reports whether an If-None-Match header carries a tag this
// proxy minted. The header is a list, and one of ours anywhere in it means the
// client is holding a rewritten document. "*" is not ours: it asks about any
// representation at all, which upstream can answer.
func holdsSyntheticETag(ifNoneMatch string) bool {
	for _, tag := range strings.Split(ifNoneMatch, ",") {
		if strings.HasPrefix(strings.TrimSpace(tag), syntheticETagPrefix) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -run 'TestSyntheticETag|TestHoldsSyntheticETag' -v`
Expected: PASS, 2 tests / 7 subtests.

- [ ] **Step 5: Lint and commit**

Run: `make fmt && make lint`

```bash
git add internal/proxy/metadata.go internal/proxy/metadata_test.go
git commit -m "feat(proxy): mint a synthetic ETag for rewritten metadata

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: Extract `forwardUpstream` from `proxyTransparent`

A pure refactor with no behaviour change, committed on its own so a reviewer can check exactly that.

**Files:**
- Modify: `internal/proxy/handler.go:417-491` (`proxyTransparent`)

**Interfaces:**
- Consumes: `upstream.Attempts` (existing).
- Produces, all package-private:
  - `errNoUpstreams`, `errUnreadableRequestBody` sentinel errors
  - `(h *Handler) forwardUpstream(r *http.Request) (*http.Response, upstream.Attempts, error)`
  - `(h *Handler) writeForwardError(w http.ResponseWriter, r *http.Request, atts upstream.Attempts, err error)`
  - `copyProxyHeaders(dst http.Header, src http.Header)`

- [ ] **Step 1: Establish the baseline**

Run: `go test ./internal/proxy/... -race && go test -tags integration ./integration/ -run TestIntegration_MultiUpstream -v`
Expected: PASS. Write down the test names that ran — they are the safety net for this refactor, and they must still pass unchanged at the end.

- [ ] **Step 2: Add the extracted helpers to `internal/proxy/handler.go`**

Add above `proxyTransparent`:

```go
// errNoUpstreams and errUnreadableRequestBody are local failures — nothing was
// attempted upstream — so callers answer them directly instead of reporting an
// upstream outage.
var (
	errNoUpstreams           = errors.New("no upstream configured")
	errUnreadableRequestBody = errors.New("unreadable request body")
)

// forwardUpstream replays r against each configured upstream in priority order
// and returns the first response with status < 400; the caller closes its body.
// A nil response with a nil error means every upstream failed and atts carries
// each mirror's own outcome.
func (h *Handler) forwardUpstream(r *http.Request) (*http.Response, upstream.Attempts, error) {
	urls := h.cfg.Adapter.UpstreamURLs(r)
	if len(urls) == 0 {
		return nil, nil, errNoUpstreams
	}

	// Buffer the request body once so it can be replayed across attempts.
	var body []byte
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, nil, errUnreadableRequestBody
		}
		body = b
	}

	var atts upstream.Attempts
	for _, url := range urls {
		start := time.Now()
		req, err := http.NewRequestWithContext(r.Context(), r.Method, url, bytes.NewReader(body))
		if err != nil {
			atts.Add(url, 0, fmt.Errorf("building request: %w", err), time.Since(start))
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

		resp, err := h.httpClient.Do(req) // #nosec G704 -- fetching configured upstream registries is the proxy's purpose
		if err != nil {
			atts.Add(url, 0, err, time.Since(start))
			continue
		}
		if resp.StatusCode < 400 {
			return resp, atts, nil
		}
		atts.Add(url, resp.StatusCode, fmt.Errorf("upstream returned HTTP %d", resp.StatusCode), time.Since(start))
		resp.Body.Close()
	}
	return nil, atts, nil
}

// writeForwardError answers a request that never got a usable upstream
// response: 404 when every mirror said so, 502 otherwise.
func (h *Handler) writeForwardError(w http.ResponseWriter, r *http.Request, atts upstream.Attempts, err error) {
	switch {
	case errors.Is(err, errNoUpstreams):
		h.cfg.Logger.Error().Msg("adapter returned no upstream URLs for transparent request")
		http.Error(w, "no upstream configured", http.StatusInternalServerError)
	case errors.Is(err, errUnreadableRequestBody):
		http.Error(w, "bad request", http.StatusBadRequest)
	case atts.AllNotFound():
		h.cfg.Logger.Warn().Array("upstream_attempts", atts).
			Str("path", r.URL.Path).Msg("transparent proxy: not found on any upstream")
		http.Error(w, "not found", http.StatusNotFound)
	default:
		h.cfg.Logger.Error().Array("upstream_attempts", atts).
			Str("path", r.URL.Path).Msg("transparent proxy: no upstream available")
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
}

// copyProxyHeaders copies src onto dst minus the hop-by-hop headers, which are
// connection-specific and must not cross a proxy.
func copyProxyHeaders(dst http.Header, src http.Header) {
	for key, vals := range src {
		for _, v := range vals {
			dst.Add(key, v)
		}
	}
	for _, hop := range hopByHopHeaders {
		dst.Del(hop)
	}
}
```

Confirm `errors` is in the import block of `internal/proxy/handler.go`; add it if not.

- [ ] **Step 3: Replace the body of `proxyTransparent` with a call to them**

`proxyTransparent` becomes, keeping its existing doc comment:

```go
func (h *Handler) proxyTransparent(w http.ResponseWriter, r *http.Request) {
	resp, atts, err := h.forwardUpstream(r)
	if resp == nil {
		h.writeForwardError(w, r, atts, err)
		return
	}
	defer resp.Body.Close()

	copyProxyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		h.cfg.Logger.Error().Err(err).Msg("error streaming proxy response")
	}
}
```

Delete the old loop, the old body buffering, and the old 404/502 tail — they now live in the helpers.

- [ ] **Step 4: Prove the refactor changed nothing**

Run: `go test ./... -race`
Expected: PASS — the same tests as in Step 1, none skipped.
Run: `go test -tags integration ./integration/ -v`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Run: `make fmt && make lint`

```bash
git add internal/proxy/handler.go
git commit -m "refactor(proxy): extract forwardUpstream from proxyTransparent

No behaviour change. The metadata filter needs the same ordered-upstream
failover, and duplicating the loop is worse than naming it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: `proxyMetadata` — filter, cap, gzip, serve

This task always fetches a body, ignoring conditional requests. Task 6 adds the fast path. Correct first, fast second.

**Files:**
- Modify: `internal/proxy/handler.go` (`HandlerConfig`, `ServeHTTP:74-79`)
- Modify: `internal/proxy/metadata.go`
- Create: `integration/npm_metadata_filter_test.go`

**Interfaces:**
- Consumes: `gate.MetadataFilterer`, `gate.FilteredDocument`, `gate.VersionDecider` (Task 1); `(*NPMAdapter).FilterVersions` (Task 2); `syntheticETag` (Task 3); `forwardUpstream`, `writeForwardError`, `copyProxyHeaders` (Task 4).
- Produces: `HandlerConfig.MetadataFilterMaxMB int`; `(h *Handler) proxyMetadata(w, r, *gate.MetadataRef)`; `(h *Handler) metadataFilterRef(r) (*gate.MetadataRef, bool)`; `(h *Handler) versionDecider(ctx, *gate.MetadataRef, undated *int) gate.VersionDecider`; `readMetadataDocument(*http.Response, int64) ([]byte, io.Reader, error)`; `writeMetadataDocument(w, r, *http.Response, []byte, bool)`.

- [ ] **Step 1: Write the failing integration test**

Create `integration/npm_metadata_filter_test.go`:

```go
//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

// npmRegistry is a mock npm registry serving one package with an old and a
// fresh version. It records what it was asked and what it answered, because
// several assertions are about the request it received rather than the body.
type npmRegistry struct {
	*httptest.Server
	etag string

	mu                sync.Mutex
	packumentRequests []http.Header
	bodiesServed      int
}

// newNPMRegistry serves "left-pad" with 1.2.0 published oldHours ago and 1.3.0
// published freshHours ago, so a min_age_hours between the two blocks exactly
// one version.
func newNPMRegistry(t *testing.T, oldHours, freshHours int) *npmRegistry {
	t.Helper()
	reg := &npmRegistry{etag: `"upstream-v1"`}

	packument := func() []byte {
		old := time.Now().UTC().Add(-time.Duration(oldHours) * time.Hour)
		fresh := time.Now().UTC().Add(-time.Duration(freshHours) * time.Hour)
		doc := map[string]any{
			"name":      "left-pad",
			"dist-tags": map[string]string{"latest": "1.3.0"},
			"time": map[string]string{
				"created": old.Format(time.RFC3339),
				"1.2.0":   old.Format(time.RFC3339),
				"1.3.0":   fresh.Format(time.RFC3339),
			},
			"versions": map[string]any{
				"1.2.0": map[string]any{"name": "left-pad", "version": "1.2.0", "dist": map[string]string{"shasum": "aaa"}},
				"1.3.0": map[string]any{"name": "left-pad", "version": "1.3.0", "dist": map[string]string{"shasum": "bbb"}},
			},
		}
		b, err := json.Marshal(doc)
		require.NoError(t, err)
		return b
	}

	reg.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".tgz") {
			w.Write([]byte("fake-tarball"))
			return
		}
		if r.URL.Path == "/left-pad" {
			reg.mu.Lock()
			reg.packumentRequests = append(reg.packumentRequests, r.Header.Clone())
			reg.mu.Unlock()

			w.Header().Set("ETag", reg.etag)
			w.Header().Set("Last-Modified", "Tue, 16 Apr 2024 05:01:58 GMT")
			w.Header().Set("Cache-Control", "public, max-age=300")
			w.Header().Set("Vary", "accept-encoding, accept")
			w.Header().Set("Content-Type", "application/json")

			reg.mu.Lock()
			reg.bodiesServed++
			reg.mu.Unlock()
			w.Write(packument())
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(reg.Close)
	return reg
}

func (reg *npmRegistry) lastPackumentRequest(t *testing.T) http.Header {
	t.Helper()
	reg.mu.Lock()
	defer reg.mu.Unlock()
	require.NotEmpty(t, reg.packumentRequests, "upstream saw no packument request")
	return reg.packumentRequests[len(reg.packumentRequests)-1]
}

// newNPMProxy wires a proxy in front of reg. minAgeHours and mode drive the
// supply-chain filter; capMB is HandlerConfig.MetadataFilterMaxMB, where 0
// disables metadata filtering entirely.
func newNPMProxy(t *testing.T, reg *npmRegistry, minAgeHours int, mode string, capMB int) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:   dir,
		MaxSizeGB:  1,
		StaleAfter: 24 * time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = localCache.Close() })

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewNPMAdapter([]string{reg.URL}),
		Filter: supplychain.NewFilter(config.SupplyChainConfig{
			MinAgeHours: minAgeHours,
			Mode:        mode,
		}, nil),
		Cache:               cache.AsArtifactCache(localCache),
		Logger:              zerolog.Nop(),
		MetadataFilterMaxMB: capMB,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// getPackument fetches the packument through the proxy with the given headers.
func getPackument(t *testing.T, srv *httptest.Server, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/left-pad", nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// The default client would follow redirects and transparently gzip; neither
	// is wanted while asserting on headers.
	resp, err := (&http.Client{}).Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	return resp, body
}

func versionsOf(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	require.NoError(t, json.Unmarshal(body, &doc))
	return doc.Versions
}

// Scenario A: the fresh version is hidden, and the response carries our own
// validator instead of upstream's.
func TestIntegration_NPMMetadataFilter_HidesFreshVersion(t *testing.T) {
	reg := newNPMRegistry(t, 240, 1)
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	versions := versionsOf(t, body)
	assert.NotContains(t, versions, "1.3.0", "a version younger than min_age must not be offered")
	assert.Contains(t, versions, "1.2.0")

	assert.True(t, strings.HasPrefix(resp.Header.Get("ETag"), `"joei.`), "got %q", resp.Header.Get("ETag"))
	assert.Empty(t, resp.Header.Get("Last-Modified"), "a date validator would let the client revalidate around us")
	assert.Equal(t, "public, max-age=300", resp.Header.Get("Cache-Control"))
	assert.Equal(t, fmt.Sprint(len(body)), resp.Header.Get("Content-Length"))
}

// Scenario G: hiding every version would break every install of the package, so
// the original document is served and the tarball still answers 423.
func TestIntegration_NPMMetadataFilter_AllVersionsBlockedServesOriginal(t *testing.T) {
	reg := newNPMRegistry(t, 2, 1)
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	versions := versionsOf(t, body)
	assert.Contains(t, versions, "1.2.0")
	assert.Contains(t, versions, "1.3.0")
	assert.Equal(t, `"upstream-v1"`, resp.Header.Get("ETag"), "an untouched document keeps upstream's validator")

	tarball, err := http.Get(srv.URL + "/left-pad/-/left-pad-1.3.0.tgz")
	require.NoError(t, err)
	defer tarball.Body.Close()
	assert.Equal(t, http.StatusLocked, tarball.StatusCode, "the artifact gate is still the enforcement boundary")
}

// Scenario I: the cap doubles as a kill switch.
func TestIntegration_NPMMetadataFilter_ZeroCapDisablesFiltering(t *testing.T) {
	reg := newNPMRegistry(t, 240, 1)
	srv := newNPMProxy(t, reg, 24, "enforce", 0)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, versionsOf(t, body), "1.3.0", "filtering is off, so nothing is hidden")
	assert.Equal(t, `"upstream-v1"`, resp.Header.Get("ETag"))
}

// Scenario H: upstream may answer gzipped, and the client must still get a
// document it can parse.
func TestIntegration_NPMMetadataFilter_GzippedUpstream(t *testing.T) {
	reg := newNPMRegistry(t, 240, 1)
	reg.gzip = true
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, body := getPackument(t, srv, map[string]string{"Accept-Encoding": "gzip"})

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	reader := io.Reader(bytes.NewReader(body))
	if resp.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(reader)
		require.NoError(t, err)
		defer zr.Close()
		reader = zr
	}
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.NotContains(t, versionsOf(t, plain), "1.3.0")
}
```

The mock needs two more fields for the gzip case. Add to `npmRegistry`: `gzip bool`, and in the packument branch, before writing:

```go
		if reg.gzip {
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			defer zw.Close()
			zw.Write(packument())
			return
		}
```

Imports for the test file also need `bytes`, `compress/gzip` and `sync`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -tags integration ./integration/ -run TestIntegration_NPMMetadataFilter -v`
Expected: FAIL to compile — `unknown field MetadataFilterMaxMB in struct literal of type proxy.HandlerConfig`.

- [ ] **Step 3: Add the config field and the routing branch in `internal/proxy/handler.go`**

Add to `HandlerConfig`, after `MalwareRecheckTTL`:

```go
	// MetadataFilterMaxMB caps the decompressed size of a metadata document the
	// handler will buffer in order to hide versions policy would block at
	// download time. A larger document is streamed through unfiltered, and the
	// artifact gate blocks it at download time instead. Zero disables metadata
	// filtering entirely.
	MetadataFilterMaxMB int
```

Change the head of `ServeHTTP` (currently lines 74-79):

```go
	ref, isDownload := h.cfg.Adapter.NormalizeRequest(r)
	if !isDownload {
		if mref, ok := h.metadataFilterRef(r); ok {
			h.proxyMetadata(w, r, mref)
			return
		}
		// Metadata / simple API — proxy transparently, no interception
		h.proxyTransparent(w, r)
		return
	}
```

- [ ] **Step 4: Implement `proxyMetadata` in `internal/proxy/metadata.go`**

Replace the import block and append to the file:

```go
import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// metadataFilterRef reports the package a filterable metadata request describes.
// It is false unless filtering is enabled and this registry's adapter can
// rewrite documents at all, which keeps the cost off every other ecosystem.
func (h *Handler) metadataFilterRef(r *http.Request) (*gate.MetadataRef, bool) {
	if h.cfg.MetadataFilterMaxMB <= 0 {
		return nil, false
	}
	filterer, ok := h.cfg.Adapter.(gate.MetadataFilterer)
	if !ok {
		return nil, false
	}
	return filterer.NormalizeMetadataRequest(r)
}

// proxyMetadata serves a metadata document with the versions policy would block
// at download time hidden from it, so the client's own resolver never picks one.
// Every path that cannot filter — an oversized document, an unparseable one, a
// policy that rejects everything — serves the document untouched, because the
// artifact gate remains the enforcement boundary.
func (h *Handler) proxyMetadata(w http.ResponseWriter, r *http.Request, mref *gate.MetadataRef) {
	filterer, ok := h.cfg.Adapter.(gate.MetadataFilterer)
	if !ok { // unreachable: metadataFilterRef already asserted the capability
		h.proxyTransparent(w, r)
		return
	}

	log := h.cfg.Logger.With().Str("ecosystem", mref.Ecosystem).Str("package", mref.Name).Logger()

	resp, atts, err := h.forwardUpstream(r)
	if resp == nil {
		h.writeForwardError(w, r, atts, err)
		return
	}
	defer resp.Body.Close()

	doc, rest, err := readMetadataDocument(resp, int64(h.cfg.MetadataFilterMaxMB)<<20)
	if err != nil {
		log.Error().Err(err).Msg("metadata filter: reading upstream document")
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	if rest != nil {
		// Over the cap. Stream it through untouched rather than fail: the
		// artifact gate still blocks the download, which is today's behaviour.
		log.Warn().Int("cap_mb", h.cfg.MetadataFilterMaxMB).
			Msg("metadata filter: document over cap, serving unfiltered")
		copyProxyHeaders(w.Header(), resp.Header)
		w.Header().Del("Content-Length") // length is unknown once decompressed
		w.Header().Del("Content-Encoding")
		w.WriteHeader(resp.StatusCode)
		if _, err := w.Write(doc); err != nil {
			log.Error().Err(err).Msg("metadata filter: writing oversized document")
			return
		}
		if _, err := io.Copy(w, rest); err != nil {
			log.Error().Err(err).Msg("metadata filter: streaming oversized document")
		}
		return
	}

	var undated int
	filtered, err := filterer.FilterVersions(doc, h.versionDecider(r.Context(), mref, &undated))
	if err != nil {
		log.Warn().Err(err).Msg("metadata filter: unparseable document, serving unfiltered")
		filtered = gate.FilteredDocument{Body: doc}
	}
	if undated > 0 {
		// The abbreviated packument has no publish dates at all, so min-age
		// cannot speak for it. Say so once, or "why does pnpm still get 423"
		// has no answer outside the source.
		log.Debug().Int("versions", undated).
			Msg("metadata filter: document carries no publish dates, so the age rule is mute here")
	}

	switch {
	case filtered.AllRejected:
		log.Info().Strs("versions", filtered.Removed).
			Msg("metadata filter: every version is blocked, serving the document unchanged")
	case len(filtered.Removed) > 0:
		log.Info().Strs("versions", filtered.Removed).Int("count", len(filtered.Removed)).
			Msg("metadata filter: hid blocked versions")
	}

	rewritten := len(filtered.Removed) > 0 && !filtered.AllRejected
	writeMetadataDocument(w, r, resp, filtered.Body, rewritten)
}

// versionDecider builds the per-version predicate the filter asks. It mirrors
// what the artifact gate would decide at download time, limited to the rules
// that need no network call: the denylist and the age check. undated counts the
// versions the document gave no publish date for, so the caller can say once
// that the age rule had nothing to judge.
func (h *Handler) versionDecider(ctx context.Context, mref *gate.MetadataRef, undated *int) gate.VersionDecider {
	return func(version string, publishedAt time.Time) bool {
		ref := &gate.PackageRef{Ecosystem: mref.Ecosystem, Name: mref.Name, Version: version}

		// An empty ScanResult means "not scanned", not "clean": only the
		// denylist verdict is trustworthy here, so no other reason may hide a
		// version.
		if h.cfg.Policy != nil {
			if d := h.cfg.Policy.Evaluate(ref, &gate.ScanResult{}); !d.Allowed && d.Reason == gate.ReasonDenylisted {
				return false
			}
		}
		// Document shapes without per-version publish dates leave the age check
		// mute; the artifact gate still applies it at download time.
		if publishedAt.IsZero() {
			*undated++
			return true
		}
		return h.cfg.Filter.Check(ctx, ref, &gate.PackageMetadata{PublishedAt: publishedAt}).Allowed
	}
}

// readMetadataDocument reads a decompressed metadata document, at most limit
// bytes of it. A non-nil rest means the document is larger than the limit and is
// positioned at the remainder, so the caller can stream what it did not buffer
// instead of failing.
func readMetadataDocument(resp *http.Response, limit int64) (doc []byte, rest io.Reader, err error) {
	src := io.Reader(resp.Body)
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("decompressing metadata document: %w", err)
		}
		src = zr
	}
	buf, err := io.ReadAll(io.LimitReader(src, limit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("reading metadata document: %w", err)
	}
	if int64(len(buf)) <= limit {
		return buf, nil, nil
	}
	return buf, src, nil
}

// writeMetadataDocument serves a buffered document. A rewritten body gets this
// proxy's own validator and loses upstream's, so no client can revalidate its
// way back into a stale rewrite; an untouched body keeps upstream's validators
// and with them the cheap 304 that follows. The body is re-compressed when the
// client asked for gzip, so rewriting costs the client hop nothing.
func writeMetadataDocument(w http.ResponseWriter, r *http.Request, resp *http.Response, body []byte, rewritten bool) {
	copyProxyHeaders(w.Header(), resp.Header)
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Encoding")
	if rewritten {
		w.Header().Del("Last-Modified")
		w.Header().Set("ETag", syntheticETag(body))
	}

	payload := body
	if clientAcceptsGzip(r) {
		if gzipped, err := gzipBytes(body); err == nil {
			payload = gzipped
			w.Header().Set("Content-Encoding", "gzip")
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(payload); err != nil {
		return
	}
}

// clientAcceptsGzip reports whether the client listed gzip in Accept-Encoding.
// A "gzip;q=0" is a refusal, so the encoding must not be offered then.
func clientAcceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(fields[0]), "gzip") {
			continue
		}
		for _, param := range fields[1:] {
			if strings.EqualFold(strings.ReplaceAll(strings.TrimSpace(param), " ", ""), "q=0") {
				return false
			}
		}
		return true
	}
	return false
}

// gzipBytes compresses b at the default level.
func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
```

Add `"bytes"` to the import block.

- [ ] **Step 5: Unit-test the decider**

`versionDecider` is where a wrong verdict would silently hide a version nobody
asked to hide, so it gets its own tests rather than only integration coverage.
Append to `internal/proxy/metadata_test.go`:

```go
// denylistPolicy denies the named versions the way the real policy engine does.
type denylistPolicy struct{ denied map[string]bool }

func (p denylistPolicy) Evaluate(ref *gate.PackageRef, _ *gate.ScanResult) gate.PolicyDecision {
	if p.denied[ref.Version] {
		return gate.PolicyDecision{Allowed: false, Reason: gate.ReasonDenylisted}
	}
	return gate.PolicyDecision{Allowed: true, Reason: "ok"}
}

// cvePolicy rejects everything for a non-denylist reason. The decider must
// ignore it: it passes an empty ScanResult, which means "not scanned", not
// "dirty", so a CVE verdict here would be an invention.
type cvePolicy struct{}

func (cvePolicy) Evaluate(*gate.PackageRef, *gate.ScanResult) gate.PolicyDecision {
	return gate.PolicyDecision{Allowed: false, Reason: "cve_found"}
}

func newDeciderHandler(t *testing.T, mode string, policy gate.PolicyDecider) *Handler {
	t.Helper()
	return NewHandler(HandlerConfig{
		Adapter: adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"}),
		Filter: supplychain.NewFilter(config.SupplyChainConfig{
			MinAgeHours: 24,
			Mode:        mode,
		}, nil),
		Logger:              zerolog.Nop(),
		Policy:              policy,
		MetadataFilterMaxMB: 32,
	})
}

func TestHandler_VersionDecider(t *testing.T) {
	mref := &gate.MetadataRef{Ecosystem: "npm", Name: "left-pad"}
	old := time.Now().Add(-240 * time.Hour)
	fresh := time.Now().Add(-1 * time.Hour)

	tests := []struct {
		name        string
		mode        string
		policy      gate.PolicyDecider
		version     string
		publishedAt time.Time
		want        bool
	}{
		{name: "old version allowed", mode: "enforce", version: "1.2.0", publishedAt: old, want: true},
		{name: "fresh version hidden", mode: "enforce", version: "1.3.0", publishedAt: fresh},
		{name: "dry_run hides nothing", mode: "dry_run", version: "1.3.0", publishedAt: fresh, want: true},
		{name: "off hides nothing", mode: "off", version: "1.3.0", publishedAt: fresh, want: true},
		{
			name: "denylisted version hidden", mode: "enforce", version: "1.2.0", publishedAt: old,
			policy: denylistPolicy{denied: map[string]bool{"1.2.0": true}},
		},
		{
			name: "other denylist entries do not spread", mode: "enforce", version: "1.2.0", publishedAt: old,
			policy: denylistPolicy{denied: map[string]bool{"9.9.9": true}}, want: true,
		},
		{
			name: "a CVE verdict on an unscanned package is ignored", mode: "enforce",
			version: "1.2.0", publishedAt: old, policy: cvePolicy{}, want: true,
		},
		{name: "no publish date leaves the age rule mute", mode: "enforce", version: "1.3.0", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newDeciderHandler(t, tt.mode, tt.policy)
			var undated int
			decide := h.versionDecider(context.Background(), mref, &undated)
			assert.Equal(t, tt.want, decide(tt.version, tt.publishedAt))
			if tt.publishedAt.IsZero() {
				assert.Equal(t, 1, undated, "an undated version must be counted so it can be logged")
			} else {
				assert.Zero(t, undated)
			}
		})
	}
}
```

This file is `package proxy`, so it needs these imports added: `context`, `time`,
`github.com/rs/zerolog`, `github.com/stretchr/testify/require` is already there
via the earlier tests, plus `github.com/ggwpLab/Jo-ei/internal/config`,
`internal/gate`, `internal/proxy/adapters` and `internal/supplychain`. None of
those import `internal/proxy`, so there is no cycle.

Run: `go test ./internal/proxy/ -run TestHandler_VersionDecider -v`
Expected: PASS, 8 subtests.

- [ ] **Step 6: Run the integration tests to verify they pass**

Run: `go test -tags integration ./integration/ -run TestIntegration_NPMMetadataFilter -v`
Expected: PASS — 4 tests (HidesFreshVersion, AllVersionsBlockedServesOriginal, ZeroCapDisablesFiltering, GzippedUpstream).

- [ ] **Step 7: Verify the rest of the suite and lint**

Run: `go test ./... -race && go test -tags integration ./integration/ -v`
Expected: PASS. Every pre-existing integration test must still pass: they construct `HandlerConfig` without `MetadataFilterMaxMB`, so filtering is off for them and nothing changes.
Run: `make fmt && make lint`

- [ ] **Step 8: Commit**

```bash
git add internal/proxy/handler.go internal/proxy/metadata.go internal/proxy/metadata_test.go integration/npm_metadata_filter_test.go
git commit -m "feat(proxy): hide blocked versions from npm metadata documents

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: Conditional requests — relay, clean, and our own 304

**Files:**
- Modify: `internal/proxy/metadata.go` (`proxyMetadata`)
- Modify: `integration/npm_metadata_filter_test.go`

**Interfaces:**
- Consumes: `holdsSyntheticETag`, `syntheticETag` (Task 3); `proxyMetadata` (Task 5).
- Produces: no new exported or package-level names. `proxyMetadata` gains the three-path behaviour.

- [ ] **Step 1: Write the failing tests**

Append to `integration/npm_metadata_filter_test.go`:

```go
// Scenario B: a client revalidating with our tag gets a 304, and its
// If-None-Match must not reach upstream — a 304 from upstream would leave us
// with no body to filter.
func TestIntegration_NPMMetadataFilter_RevalidateWithOurTag(t *testing.T) {
	reg := newNPMRegistry(t, 240, 1)
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	first, _ := getPackument(t, srv, nil)
	ourTag := first.Header.Get("ETag")
	require.True(t, strings.HasPrefix(ourTag, `"joei.`))

	second, body := getPackument(t, srv, map[string]string{"If-None-Match": ourTag})

	assert.Equal(t, http.StatusNotModified, second.StatusCode)
	assert.Empty(t, body)
	assert.Equal(t, ourTag, second.Header.Get("ETag"))
	assert.Empty(t, reg.lastPackumentRequest(t).Get("If-None-Match"),
		"our own tag must never be forwarded upstream")
}

// Scenario C: once nothing needs hiding, the client is handed upstream's own
// validator and the untouched bytes, which puts it back on the fast path.
func TestIntegration_NPMMetadataFilter_RecoversToUpstreamTag(t *testing.T) {
	reg := newNPMRegistry(t, 240, 1)
	blocking := newNPMProxy(t, reg, 24, "enforce", 32)

	first, _ := getPackument(t, blocking, nil)
	ourTag := first.Header.Get("ETag")
	require.True(t, strings.HasPrefix(ourTag, `"joei.`))

	// min_age_hours lowered below the fresh version's age: nothing is blocked.
	allowing := newNPMProxy(t, reg, 0, "enforce", 32)
	second, body := getPackument(t, allowing, map[string]string{"If-None-Match": ourTag})

	assert.Equal(t, http.StatusOK, second.StatusCode)
	assert.Contains(t, versionsOf(t, body), "1.3.0")
	assert.Equal(t, `"upstream-v1"`, second.Header.Get("ETag"))
	assert.NotEmpty(t, second.Header.Get("Last-Modified"), "an untouched document keeps upstream's date too")
}

// Scenario D: a client holding an upstream tag is revalidated against upstream,
// and an upstream 304 is relayed without a body being read at all.
func TestIntegration_NPMMetadataFilter_RelaysUpstream304(t *testing.T) {
	reg := newNPMRegistry(t, 240, 1)
	reg.honourConditional = true
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	before := reg.bodyCount()
	resp, body := getPackument(t, srv, map[string]string{"If-None-Match": `"upstream-v1"`})

	assert.Equal(t, http.StatusNotModified, resp.StatusCode)
	assert.Empty(t, body)
	assert.Equal(t, `"upstream-v1"`, reg.lastPackumentRequest(t).Get("If-None-Match"),
		"an upstream tag must be forwarded so upstream can answer 304")
	assert.Equal(t, before, reg.bodyCount(), "no document body should have been served or parsed")
}

// Scenario F: dry_run reports but never blocks, so it must never hide either.
func TestIntegration_NPMMetadataFilter_DryRunHidesNothing(t *testing.T) {
	reg := newNPMRegistry(t, 240, 1)
	srv := newNPMProxy(t, reg, 24, "dry_run", 32)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, versionsOf(t, body), "1.3.0")
	assert.Equal(t, `"upstream-v1"`, resp.Header.Get("ETag"))
}
```

Add to `npmRegistry` the two members these tests use:

```go
	// honourConditional makes the mock answer 304 to a matching If-None-Match,
	// the way a real registry does.
	honourConditional bool
```

and a helper plus the conditional branch:

```go
func (reg *npmRegistry) bodyCount() int {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return reg.bodiesServed
}
```

In the `/left-pad` branch, after recording the request headers and before writing any body:

```go
			if reg.honourConditional && r.Header.Get("If-None-Match") == reg.etag {
				w.Header().Set("ETag", reg.etag)
				w.WriteHeader(http.StatusNotModified)
				return
			}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -tags integration ./integration/ -run TestIntegration_NPMMetadataFilter -v`
Expected: `RevalidateWithOurTag` FAILs with `200` instead of `304`; `RelaysUpstream304` FAILs because Task 5 strips nothing yet and therefore never forwards the upstream tag — it asserts `If-None-Match` reached upstream and finds it empty. `RecoversToUpstreamTag` and `DryRunHidesNothing` should already PASS.

- [ ] **Step 3: Add the request-side branch to `proxyMetadata`**

In `internal/proxy/metadata.go`, replace the `h.forwardUpstream(r)` call in `proxyMetadata` with:

```go
	// The whole cost model rests on this branch, and it is decided from the
	// request alone: a client holding one of our tags needs a fresh body to
	// filter, so its validators must not reach upstream. Everyone else keeps
	// their conditional request, and with it the chance of a cheap 304.
	clientTag := r.Header.Get("If-None-Match")
	ourTag := holdsSyntheticETag(clientTag)

	outbound := r
	if ourTag {
		outbound = r.Clone(r.Context())
		outbound.Header.Del("If-None-Match")
		outbound.Header.Del("If-Modified-Since")
	}

	resp, atts, err := h.forwardUpstream(outbound)
	if resp == nil {
		h.writeForwardError(w, r, atts, err)
		return
	}
	defer resp.Body.Close()

	// Upstream says the document is unchanged, and the client is holding an
	// upstream tag for it. There is no body to filter and none is needed.
	if resp.StatusCode == http.StatusNotModified {
		copyProxyHeaders(w.Header(), resp.Header)
		w.WriteHeader(http.StatusNotModified)
		return
	}
```

- [ ] **Step 4: Add our own 304 to the filtered path**

Replace the final two lines of `proxyMetadata` (`rewritten := ...` and the `writeMetadataDocument` call) with:

```go
	rewritten := len(filtered.Removed) > 0 && !filtered.AllRejected
	if rewritten {
		tag := syntheticETag(filtered.Body)
		if ourTag && etagMatches(clientTag, tag) {
			// Same document, same policy, same rewrite: the copy the client
			// already has is current.
			w.Header().Set("ETag", tag)
			w.Header().Set("Cache-Control", resp.Header.Get("Cache-Control"))
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	writeMetadataDocument(w, r, resp, filtered.Body, rewritten)
```

And add the comparison helper next to `holdsSyntheticETag`:

```go
// etagMatches reports whether an If-None-Match list contains tag exactly. The
// tags this proxy mints are strong validators, so a weak comparison would be
// wrong here.
func etagMatches(ifNoneMatch, tag string) bool {
	for _, candidate := range strings.Split(ifNoneMatch, ",") {
		if strings.TrimSpace(candidate) == tag {
			return true
		}
	}
	return false
}
```

`writeMetadataDocument` already computes the tag itself; leave that as is — computing it twice on the filtered path costs one hash of an in-memory buffer and keeps each function readable on its own.

- [ ] **Step 5: Add a unit test for the comparison helper**

Append to `internal/proxy/metadata_test.go`:

```go
func TestETagMatches(t *testing.T) {
	ours := syntheticETag([]byte(`{}`))

	assert.True(t, etagMatches(ours, ours))
	assert.True(t, etagMatches(`"other", `+ours, ours))
	assert.False(t, etagMatches(`"other"`, ours))
	assert.False(t, etagMatches("", ours))
	assert.False(t, etagMatches(`W/`+ours, ours), "a weak tag is not a match for a strong one")
}
```

Run: `go test ./internal/proxy/ -run TestETagMatches -v`
Expected: PASS.

- [ ] **Step 6: Run the integration tests to verify they pass**

Run: `go test -tags integration ./integration/ -run TestIntegration_NPMMetadataFilter -v`
Expected: PASS — all 8 tests.

- [ ] **Step 7: Full suite, lint, commit**

Run: `go test ./... -race && go test -tags integration ./integration/ -v`
Expected: PASS.
Run: `make fmt && make lint`

```bash
git add internal/proxy/metadata.go internal/proxy/metadata_test.go integration/npm_metadata_filter_test.go
git commit -m "feat(proxy): keep 304 economics for unfiltered metadata

Only a client holding one of our synthetic tags pays for a fresh body:
its validators are stripped so upstream cannot answer 304 with nothing to
filter. Everyone else revalidates upstream as before.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7: Guard tests for the fallback paths

No new production code is expected here. These lock in the enforcement invariant from the spec's §7 — every path that cannot filter degrades into the artifact gate, not into an error. If one fails, the fix belongs in `proxyMetadata`.

**Files:**
- Modify: `integration/npm_metadata_filter_test.go`

**Interfaces:**
- Consumes: `newNPMRegistry`, `newNPMProxy`, `getPackument`, `versionsOf` (Task 5).
- Produces: nothing.

- [ ] **Step 1: Write the tests**

Append to `integration/npm_metadata_filter_test.go`:

```go
// Scenario E: a document over the cap is served unfiltered, and the gate takes
// over at download time.
func TestIntegration_NPMMetadataFilter_OverCapFallsBackToTheGate(t *testing.T) {
	reg := newNPMRegistry(t, 240, 1)
	// The mock packument is a few hundred bytes; a 1 MB cap would never trip, so
	// the handler needs a cap expressed in whole MB that the document exceeds.
	// Use the smallest enabling value and a padded document instead.
	reg.padBytes = 2 << 20
	srv := newNPMProxy(t, reg, 24, "enforce", 1)

	resp, body := getPackument(t, srv, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, versionsOf(t, body), "1.3.0", "an oversized document is not rewritten")
	assert.Empty(t, resp.Header.Get("Content-Length"), "the length is unknown once streamed")

	tarball, err := http.Get(srv.URL + "/left-pad/-/left-pad-1.3.0.tgz")
	require.NoError(t, err)
	defer tarball.Body.Close()
	assert.Equal(t, http.StatusLocked, tarball.StatusCode)
}

// Scenario J: a single-version manifest has no version list to rewrite, so it is
// proxied untouched and the download is what gets blocked.
func TestIntegration_NPMMetadataFilter_VersionManifestUntouched(t *testing.T) {
	reg := newNPMRegistry(t, 240, 1)
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	resp, err := http.Get(srv.URL + "/left-pad/1.3.0")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "1.3.0")
	assert.Equal(t, `"manifest-v1"`, resp.Header.Get("ETag"), "a manifest keeps upstream's validator")

	tarball, err := http.Get(srv.URL + "/left-pad/-/left-pad-1.3.0.tgz")
	require.NoError(t, err)
	defer tarball.Body.Close()
	assert.Equal(t, http.StatusLocked, tarball.StatusCode)
}
```

The mock needs two additions. Add `padBytes int` to `npmRegistry`, and in the packument builder, before marshalling, add a field whose only job is bulk:

```go
		if reg.padBytes > 0 {
			doc["_padding"] = strings.Repeat("x", reg.padBytes)
		}
```

Add a `/left-pad/1.3.0` branch to the mock handler, before the `/left-pad` branch:

```go
		if r.URL.Path == "/left-pad/1.3.0" {
			w.Header().Set("ETag", `"manifest-v1"`)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name":"left-pad","version":"1.3.0","dist":{"shasum":"bbb"}}`))
			return
		}
```

- [ ] **Step 2: Run the tests**

Run: `go test -tags integration ./integration/ -run TestIntegration_NPMMetadataFilter -v`
Expected: PASS — 10 tests. If `OverCapFallsBackToTheGate` or `VersionManifestUntouched` fails, fix `proxyMetadata` (over-cap path) or `isNPMPackageName` (manifest path) rather than relaxing the assertion.

- [ ] **Step 3: Lint and commit**

Run: `make fmt && make lint`

```bash
git add integration/npm_metadata_filter_test.go
git commit -m "test(proxy): pin the metadata filter's fallbacks to the artifact gate

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 8: Coalesce concurrent packument fetches

**Files:**
- Modify: `internal/proxy/handler.go` (`Handler` struct, around line 56)
- Modify: `internal/proxy/metadata.go` (`proxyMetadata`)
- Modify: `integration/npm_metadata_filter_test.go`

**Interfaces:**
- Consumes: `singleflight.Group` (already imported in `handler.go`), `readMetadataDocument` (Task 5).
- Produces: `Handler.metadataGroup singleflight.Group`; `(h *Handler) fetchMetadataDocument(...)`.

Only the upstream fetch and decompression are coalesced. Filtering is *not*: two clients can hold different tags and need different answers, and the decision is cheap once the body is in hand.

- [ ] **Step 1: Write the failing test**

Append to `integration/npm_metadata_filter_test.go`:

```go
// Concurrent clients asking for one packument must cost one upstream fetch.
func TestIntegration_NPMMetadataFilter_CoalescesConcurrentFetches(t *testing.T) {
	reg := newNPMRegistry(t, 240, 1)
	reg.delay = 150 * time.Millisecond
	srv := newNPMProxy(t, reg, 24, "enforce", 32)

	const clients = 8
	var wg sync.WaitGroup
	wg.Add(clients)
	for i := 0; i < clients; i++ {
		go func() {
			defer wg.Done()
			resp, body := getPackument(t, srv, nil)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.NotContains(t, versionsOf(t, body), "1.3.0")
		}()
	}
	wg.Wait()

	assert.Less(t, reg.bodyCount(), clients,
		"8 simultaneous clients should not each fetch the document")
}
```

Add `delay time.Duration` to `npmRegistry`, and at the top of the `/left-pad` branch, after recording the headers:

```go
			if reg.delay > 0 {
				time.Sleep(reg.delay) // widen the window so coalescing is observable
			}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -tags integration ./integration/ -run TestIntegration_NPMMetadataFilter_CoalescesConcurrentFetches -v`
Expected: FAIL — `8 is not less than 8`.

- [ ] **Step 3: Add the group to the `Handler` struct**

In `internal/proxy/handler.go`, alongside `recheckGroup`:

```go
	// metadataGroup coalesces concurrent fetches of one metadata document, so a
	// CI fleet resolving the same dependency tree costs one upstream request
	// rather than one per worker.
	metadataGroup singleflight.Group
```

- [ ] **Step 4: Route the fetch through it**

Add to `internal/proxy/metadata.go`:

```go
// metadataFetch is one coalesced upstream document: the bytes, and the response
// header they came with. A document over the cap is not shareable — its
// remainder is a live reader belonging to one request — so oversized fetches
// are reported and the caller retries alone.
type metadataFetch struct {
	doc    []byte
	header http.Header
	status int
}

// fetchMetadataDocument fetches and decompresses a metadata document, collapsing
// concurrent callers for the same package onto one upstream request. oversized
// is true when the document exceeded the cap, in which case the caller must
// fetch it itself and stream it.
func (h *Handler) fetchMetadataDocument(r *http.Request, key string, limit int64) (f *metadataFetch, oversized bool, atts upstream.Attempts, err error) {
	type result struct {
		fetch     *metadataFetch
		oversized bool
		atts      upstream.Attempts
		err       error
	}
	v, _, _ := h.metadataGroup.Do(key, func() (any, error) {
		resp, atts, err := h.forwardUpstream(r)
		if resp == nil {
			return result{atts: atts, err: err}, nil
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotModified {
			return result{fetch: &metadataFetch{header: resp.Header.Clone(), status: resp.StatusCode}}, nil
		}

		doc, rest, err := readMetadataDocument(resp, limit)
		if err != nil {
			return result{err: err}, nil
		}
		if rest != nil {
			return result{oversized: true}, nil
		}
		return result{fetch: &metadataFetch{doc: doc, header: resp.Header.Clone(), status: resp.StatusCode}}, nil
	})
	res := v.(result)
	return res.fetch, res.oversized, res.atts, res.err
}
```

Move the over-cap block out of `proxyMetadata` into its own method, so the shared path and the solo path can both use it:

```go
// streamOversizedMetadata serves a document too large to buffer: the artifact
// gate blocks the download instead, which is the behaviour that predates
// metadata filtering.
func (h *Handler) streamOversizedMetadata(w http.ResponseWriter, r *http.Request, outbound *http.Request, log *zerolog.Logger) {
	log.Warn().Int("cap_mb", h.cfg.MetadataFilterMaxMB).
		Msg("metadata filter: document over cap, serving unfiltered")

	resp, atts, err := h.forwardUpstream(outbound)
	if resp == nil {
		h.writeForwardError(w, r, atts, err)
		return
	}
	defer resp.Body.Close()

	copyProxyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Error().Err(err).Msg("metadata filter: streaming oversized document")
	}
}
```

Note this version streams the upstream body verbatim, compression and all, so `Content-Encoding` and the absent `Content-Length` are upstream's own — which is why Task 7's over-cap test asserts an empty `Content-Length`.

`writeMetadataDocument` no longer has a `*http.Response` to read from, so change its signature and first line to take the two things it actually used:

```go
func writeMetadataDocument(w http.ResponseWriter, r *http.Request, header http.Header, status int, body []byte, rewritten bool) {
	copyProxyHeaders(w.Header(), header)
```

and its final write to `w.WriteHeader(status)`. The rest of the function is unchanged.

`proxyMetadata` in full after this task — this replaces the version from Tasks 5 and 6 entirely:

```go
func (h *Handler) proxyMetadata(w http.ResponseWriter, r *http.Request, mref *gate.MetadataRef) {
	filterer, ok := h.cfg.Adapter.(gate.MetadataFilterer)
	if !ok { // unreachable: metadataFilterRef already asserted the capability
		h.proxyTransparent(w, r)
		return
	}

	log := h.cfg.Logger.With().Str("ecosystem", mref.Ecosystem).Str("package", mref.Name).Logger()

	// The whole cost model rests on this branch, and it is decided from the
	// request alone: a client holding one of our tags needs a fresh body to
	// filter, so its validators must not reach upstream. Everyone else keeps
	// their conditional request, and with it the chance of a cheap 304.
	clientTag := r.Header.Get("If-None-Match")
	ourTag := holdsSyntheticETag(clientTag)

	outbound := r
	if ourTag {
		outbound = r.Clone(r.Context())
		outbound.Header.Del("If-None-Match")
		outbound.Header.Del("If-Modified-Since")
	}

	// Requests that would get different answers must not be coalesced: the path
	// picks the package, Accept picks the document shape, and a client holding
	// one of our tags needs a body while others may be given a 304.
	key := fmt.Sprintf("%s\x00%s\x00%t", r.URL.Path, r.Header.Get("Accept"), ourTag)

	fetch, oversized, atts, err := h.fetchMetadataDocument(outbound, key, int64(h.cfg.MetadataFilterMaxMB)<<20)
	switch {
	case oversized:
		// Not shareable across callers: its remainder is a live reader that
		// belongs to one request, so this caller fetches it alone.
		h.streamOversizedMetadata(w, r, outbound, &log)
		return
	case err != nil:
		log.Error().Err(err).Msg("metadata filter: reading upstream document")
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	case fetch == nil:
		h.writeForwardError(w, r, atts, err)
		return
	}

	// Upstream says the document is unchanged, and the client is holding an
	// upstream tag for it. There is no body to filter and none is needed.
	if fetch.status == http.StatusNotModified {
		copyProxyHeaders(w.Header(), fetch.header)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	var undated int
	filtered, err := filterer.FilterVersions(fetch.doc, h.versionDecider(r.Context(), mref, &undated))
	if err != nil {
		log.Warn().Err(err).Msg("metadata filter: unparseable document, serving unfiltered")
		filtered = gate.FilteredDocument{Body: fetch.doc}
	}
	if undated > 0 {
		// The abbreviated packument has no publish dates at all, so min-age
		// cannot speak for it. Say so once, or "why does pnpm still get 423"
		// has no answer outside the source.
		log.Debug().Int("versions", undated).
			Msg("metadata filter: document carries no publish dates, so the age rule is mute here")
	}

	switch {
	case filtered.AllRejected:
		log.Info().Strs("versions", filtered.Removed).
			Msg("metadata filter: every version is blocked, serving the document unchanged")
	case len(filtered.Removed) > 0:
		log.Info().Strs("versions", filtered.Removed).Int("count", len(filtered.Removed)).
			Msg("metadata filter: hid blocked versions")
	}

	rewritten := len(filtered.Removed) > 0 && !filtered.AllRejected
	if rewritten {
		tag := syntheticETag(filtered.Body)
		if ourTag && etagMatches(clientTag, tag) {
			// Same document, same policy, same rewrite: the copy the client
			// already has is current.
			w.Header().Set("ETag", tag)
			w.Header().Set("Cache-Control", fetch.header.Get("Cache-Control"))
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	writeMetadataDocument(w, r, fetch.header, fetch.status, filtered.Body, rewritten)
}
```

Add `"github.com/ggwpLab/Jo-ei/internal/upstream"` and `"github.com/rs/zerolog"` to the imports of `internal/proxy/metadata.go`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test -tags integration ./integration/ -run TestIntegration_NPMMetadataFilter -v`
Expected: PASS — 11 tests, including `CoalescesConcurrentFetches`.

- [ ] **Step 6: Full suite with the race detector, lint, commit**

Run: `go test ./... -race && go test -tags integration ./integration/ -race -v`
Expected: PASS, no race reports. The mock registry's counters are mutex-guarded; if the detector complains about test state, fix the mock, not the handler.
Run: `make fmt && make lint`

```bash
git add internal/proxy/handler.go internal/proxy/metadata.go integration/npm_metadata_filter_test.go
git commit -m "perf(proxy): coalesce concurrent metadata fetches

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 9: Configuration, wiring, and documentation

**Files:**
- Modify: `internal/config/config.go` (`ServerConfig` ~line 103, `Validate` ~line 28, `Load` ~line 303)
- Modify: `cmd/jo-ei/main.go` (`sharedDeps` ~line 84, `sharedDeps{...}` ~line 230, `buildHandler` ~line 494)
- Modify: `docs/configuration.md`
- Modify: `CHANGELOG.md`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: `HandlerConfig.MetadataFilterMaxMB` (Task 5).
- Produces: `config.ServerConfig.MetadataFilterMaxMB`, YAML key `server.metadata_filter_max_mb`, env override `JOEI_SERVER_METADATA_FILTER_MAX_MB`.

- [ ] **Step 1: Write the failing config tests**

Append to `internal/config/config_test.go`. The file already has the helper these tests need — `writeTempConfig(t, content) string` at line 74 — and its negative-validation tests call `Validate()` on a bare `&config.Config{}` instead of going through `Load`; follow both conventions:

```go
func TestLoad_MetadataFilterMaxMB_DefaultsTo32(t *testing.T) {
	path := writeTempConfig(t, `server:
  listen: ":8080"
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, 32, cfg.Server.MetadataFilterMaxMB)
}

func TestLoad_MetadataFilterMaxMB_ZeroDisables(t *testing.T) {
	path := writeTempConfig(t, `server:
  listen: ":8080"
  metadata_filter_max_mb: 0
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, 0, cfg.Server.MetadataFilterMaxMB, "an explicit zero is the kill switch, not a request for the default")
}

func TestValidate_RejectsNegativeMetadataFilterMaxMB(t *testing.T) {
	c := &config.Config{}
	c.Server.MetadataFilterMaxMB = -1
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata_filter_max_mb")
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/config/ -run MetadataFilterMaxMB -v`
Expected: FAIL to compile — `cfg.Server.MetadataFilterMaxMB` undefined.

- [ ] **Step 3: Add the field, the default, and the validation**

In `ServerConfig` (`internal/config/config.go`):

```go
	// MetadataFilterMaxMB caps the decompressed size of a registry metadata
	// document the proxy will buffer in order to hide versions policy blocks, so
	// a client's own resolver picks an allowed version instead of failing on a
	// blocked download. A document over the cap is streamed through unfiltered
	// and the artifact gate blocks it at download time instead. Zero disables
	// metadata filtering entirely; the default (32) comes from Load, so an
	// explicit zero stays a zero.
	MetadataFilterMaxMB int `mapstructure:"metadata_filter_max_mb"`
```

In `Load`, alongside the existing defaults:

```go
	v.SetDefault("server.metadata_filter_max_mb", 32)
```

In `Validate`, next to the other numeric guards:

```go
	if c.Server.MetadataFilterMaxMB < 0 {
		return fmt.Errorf("server.metadata_filter_max_mb must not be negative")
	}
```

- [ ] **Step 4: Run the config tests to verify they pass**

Run: `go test ./internal/config/ -run MetadataFilterMaxMB -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Wire it through `cmd/jo-ei/main.go`**

Add to `sharedDeps`, below `malwareRecheckTTL`:

```go
	metadataFilterMaxMB int
```

Add to the `sharedDeps{...}` literal, next to the TTLs:

```go
		metadataFilterMaxMB: cfg.Server.MetadataFilterMaxMB,
```

Add to the `proxy.HandlerConfig{...}` literal in `buildHandler`:

```go
		MetadataFilterMaxMB: shared.metadataFilterMaxMB,
```

Run: `go build ./... && go test ./... -race`
Expected: builds; PASS.

- [ ] **Step 6: Document the knob**

Add to `docs/configuration.md`, in the `server` section, matching the surrounding format:

```markdown
### `server.metadata_filter_max_mb`

Default: `32`. Caps the decompressed size of a registry metadata document the
proxy buffers in order to hide versions the supply-chain gate would block.

npm resolves a version range from the package's metadata document before it ever
requests a tarball, so a blocked version makes the whole install fail with no
fallback. Hiding those versions from the document instead lets npm resolve to the
newest version your policy allows. Only rules that need no network call take
part: the minimum-age check and the denylist. CVE and malware verdicts still
block at download time.

Set to `0` to disable metadata filtering entirely; documents are then proxied
untouched and a blocked version fails the download with `423`, as it did before
this option existed. A document larger than the cap is also streamed through
untouched.

Applies to npm. Other registries proxy metadata untouched regardless of this
setting.
```

- [ ] **Step 7: Add the CHANGELOG entry**

Under `## [Unreleased]` in `CHANGELOG.md`, in the `### Added` section (create it above `### Fixed` if this is the first Added entry of the cycle), matching the prose style of the surrounding entries:

```markdown
- **npm installs now fall back to an allowed version instead of failing.**
  npm resolves a version range from a package's metadata document before it
  requests any tarball, so a version blocked by the minimum-age rule or the
  denylist used to kill the whole install: it had already committed to that
  version, and `423` gave it nowhere to go. The proxy now hides blocked
  versions from the metadata document itself, so `^1.0.0` resolves to the
  newest version your policy allows and the install simply succeeds. Rewritten
  documents carry the proxy's own `ETag`, so a client cannot revalidate its way
  back into a stale copy once a version matures; documents that were not
  rewritten keep the registry's own validators and the cheap `304` that follows.
  A lockfile-pinned install (`npm ci`) still fails with `423` — there is no
  range left to resolve — and so does a document larger than
  `server.metadata_filter_max_mb` (default 32). Set that to `0` to switch
  filtering off.
```

- [ ] **Step 8: Full verification**

Run: `go test ./... -race`
Expected: PASS.
Run: `go test -tags integration ./integration/ -race -v`
Expected: PASS.
Run: `make fmt && make lint && git diff --stat`
Expected: no lint findings; only intended files changed.

- [ ] **Step 9: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go cmd/jo-ei/main.go docs/configuration.md CHANGELOG.md
git commit -m "feat(config): expose server.metadata_filter_max_mb

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

- [ ] **Step 10: Run the manual verification recipe from the spec**

CI has no npm, so this is the only check that exercises a real client. Point a local npm at the proxy with `min_age_hours` high enough to block the newest version of a package, then walk the four steps in the spec's "Manual verification recipe": filtered install, `304` on revalidation with no forwarded `If-None-Match`, recovery to upstream's tag once the version matures, and a relayed upstream `304` afterwards.

Record the outcome in the PR description. If any step disagrees with the spec's Evidence table, stop and report rather than adjusting the tests.

---

## Open the PR

```bash
git push -u origin feat/npm-metadata-version-filter
gh pr create --base main --title "feat(npm): resolve around blocked versions instead of failing the install" --body "$(cat <<'BODY'
## Summary

A supply-chain block answered the tarball request with `423`, which npm treats
as terminal: it resolved the version range from the packument long before the
download, so the install failed instead of falling back to a version policy
allows. No status code changes that.

This hides blocked versions from the metadata document instead, so npm's own
resolver lands on an allowed version. The artifact gate stays the enforcement
boundary: every path that cannot filter — an oversized document, `npm ci`, a
version manifest, a policy that rejects everything — degrades to today's `423`.

Design: `docs/superpowers/specs/2026-09-26-npm-metadata-version-filter-design.md`
Plan: `docs/superpowers/plans/2026-09-26-npm-metadata-version-filter.md`

## Verification

- `go test ./... -race`
- `go test -tags integration ./integration/ -race`
- `golangci-lint run`
- Manual four-step lifecycle against registry.npmjs.org with a real npm client
  (see the spec's manual recipe) — paste the outcome here.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
BODY
)"
```

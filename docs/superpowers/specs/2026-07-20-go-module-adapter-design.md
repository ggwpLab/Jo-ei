# Go module registry adapter — design

**Date:** 2026-07-20
**Status:** Approved, ready for implementation plan
**Ecosystem:** Go modules (GOPROXY protocol)

## Goal

Add a `RegistryAdapter` for the Go module proxy protocol so `go` clients can pull
modules through Jo-ei and have module zips run the same supply-chain / CVE /
malware gates as the existing npm, PyPI, Maven, and RubyGems adapters.

Clients configure `GOPROXY=http://<jo-ei>/go`. The adapter intercepts module
zip downloads (the scannable artifact) and proxies the rest of the protocol
transparently.

## Scope

**In scope (v1):**
- `GoAdapter` implementing `gate.RegistryAdapter` under the `/go/` prefix.
- Interception of `…/@v/<version>.zip` downloads for gating.
- Transparent proxying of `@v/list`, `.info`, `.mod`, `@latest`.

### Why `.mod` / `.info` / `list` are proxied without gating

Jo-ei's model gates the installable/executable artifact, not the resolution
manifests. `.mod` is the module's `go.mod` — text, non-executable, carrying no
code; a signature/CVE scan of it is meaningless. A CVE or malware payload only
materializes when code is compiled/run, and that code lives **only in the
`.zip`**, which is gated. A blocked module's `.zip` returns 423/403, so `go
build` fails — the fact that its `.mod` passed grants no code. Transitive
`require`s do not bypass gating either: each dependency is fetched as its own
proxy request and its own `.zip` is gated independently. This mirrors the npm
adapter, which proxies the metadata document (including `scripts`/`postinstall`)
transparently while gating the `.tgz`. (Policy over `go.mod` *contents* — e.g.
forbidding a specific `require`/`replace` — would be a separate dependency-graph
policy feature, not a malware/CVE scan, and is out of scope.)
- Case-encoding decode (`!x` → `X`) for module path and version, so OSV and the
  allowlist see canonical coordinates.
- Publish date from `.info` via `FetchMetadata` (supply-chain gate input).
- Full wiring: config, main, console validation, console UI, example, changelog.
- Unit tests mirroring `npm_test.go`.

**Explicitly out of scope (YAGNI):**
- Proxying the checksum database (`sum.golang.org` / `/sumdb/`). Documented:
  users set `GOSUMDB=off` (or `GONOSUMCHECK` / `GOFLAGS`) for closed
  environments. Confirmed decision.
- VCS / `direct` fallback for modules absent from the upstream proxy. A miss is
  a 404; the README shows `GOPROXY` without `,direct` so clients cannot bypass
  Jo-ei to git. Confirmed decision.
- Storing/using the Go dirhash `h1:` checksum in policy (no policy reads
  `Checksum`; the field is SHA256-hex, a different scheme). Left empty.
- Any special `@latest` handling beyond transparent proxying.

## Background: what's already wired

- `gate.PackageRef` doc comment already enumerates `"go"` as an ecosystem.
- `internal/scanner/osv.go` `ecosystemMap` already maps `"go" → "Go"`, so the
  CVE path needs no change — the adapter just emits `Ecosystem: "go"`.
- Unlike npm's `dist.tarball`, the GOPROXY protocol embeds **no** URLs in its
  responses. The `go` command derives every path (`@v/list`, `.info`, `.mod`,
  `.zip`) by convention from the base URL. Therefore **no metadata URL
  rewriting is required** — the "tarball URL rewriting" roadmap note does not
  apply to Go.

## Architecture

New file `internal/proxy/adapters/go.go` (+ `go_test.go`), same shape as
`npm.go`.

```
type GoAdapter struct {
    upstreams  []string     // trimmed of trailing "/"; default proxy.golang.org
    httpClient *http.Client // shared, per-host concurrency-capped (options.go)
}

func NewGoAdapter(upstreams []string, opts ...Option) *GoAdapter
func (a *GoAdapter) Name() string { return "go" }
```

### `NormalizeRequest(r) (*PackageRef, bool)`

Intercept **only** zip downloads:

1. If path does not end in `.zip` → `(nil, false)`.
2. Find `/@v/`; if absent → `(nil, false)`.
3. `encModule = TrimPrefix(path[:idx], "/")`; `encVersion = TrimSuffix(rest,
   ".zip")`. If `encVersion == ""` → `(nil, false)`.
4. `module, ok := decodeGoPath(encModule)`; `version, ok := decodeGoPath(encVersion)`.
   If either fails → `(nil, false)` (transparent proxy; upstream returns the
   appropriate error).
5. Return `&PackageRef{Ecosystem: "go", Name: module, Version: version}`
   (no classifier).

`list`, `.info`, `.mod`, `@latest` never match (not `.zip`) → transparent proxy.

### `decodeGoPath(s) (string, bool)`

Reverses Go module case-encoding: a `!` followed by a lowercase ASCII letter
becomes that letter uppercased. A `!` that is trailing, or followed by any
non-`[a-z]` byte, is invalid → `("", false)` (reject, never guess). Input with
no `!` returns unchanged, `true`.

Used for both module path and version. Version rarely contains `!`, but the
protocol case-encodes both, so decode both uniformly.

### `FetchMetadata(ctx, ref) (*PackageMetadata, error)`

Walk `upstreams` in order, first success wins, last error otherwise (npm
pattern). Per upstream:

- `GET <base>/<encModule>/@v/<encVersion>.info` — `ref.Name`/`ref.Version` are
  canonical (already decoded), so re-encode them to the on-wire case-encoded
  form for the request path. Encoding is the inverse of `decodeGoPath`: an
  uppercase letter → `!` + its lowercase. Implement `encodeGoPath(s) string`
  alongside the decoder.
- Non-200 → error (advance to next upstream).
- Decode JSON `{ "Version": "...", "Time": "RFC3339" }`.
- `PublishedAt = Time.UTC()`. `License` and `Checksum` empty.

Not a `DownloadMetadataExtractor`: the zip download carries no reliable
publish-date header, so metadata is fetched up front (like npm/PyPI), and the
supply-chain check runs before the CVE scan and download.

### `UpstreamURLs(r) []string`

`base + r.URL.RequestURI()` per upstream, in order (npm pattern). Serves both
the intercepted `.zip` download and transparent proxying of
`list`/`.info`/`.mod`/`@latest`. The client already sent case-encoded paths, so
forwarding `RequestURI()` verbatim is correct — no re-encoding here.

## Protocol edge cases the adapter must survive

| Case | Handling |
|------|----------|
| `+incompatible` (e.g. `v2.0.0+incompatible`) | Valid version; decoder/`.info` pass it through unchanged. |
| Pseudo-versions (`v0.0.0-2020…-abcdef`) | Valid; request is well-formed (OSV may return nothing, which is fine). |
| Uppercase in path (`github.com/!azure/…`) | Decoded to `Azure` for OSV/allowlist. |
| Nested major versions (`/v2`, `/v3`) | Part of the module path; not special-cased. |
| `.zip` without `/@v/`, or empty version | `(nil, false)` → transparent proxy → upstream 404. |

## Wiring (add `"go"`, symmetric with rubygems)

1. `internal/config/config.go`: `RegistriesConfig.Go RegistryConfig`; add `"go"`
   to the `Registries()` map.
2. viper defaults + `config.yaml`: `registries.go` block, `enabled: false`,
   `upstreams: [https://proxy.golang.org]`.
3. `cmd/jo-ei/main.go`:
   - `buildHandlers`: register `handlers["go"] = buildHandler(adapters.NewGoAdapter(cfg.Registries.Go.Upstreams, client), shared)` when enabled.
   - `applyStoredRegistries`: `case "go"`.
   - `registryInfo`: append the `go` entry.
   - "no registries enabled" error string: add `go`.
4. `internal/console/server.go`: add `"go"` to `knownEcos` (the "must list all N
   ecosystems" count becomes N+1 automatically).
5. `web/console/src/registries.jsx`: add `"go"` to `REG_ECOS`; add a `JOEI.ECO.go`
   icon (or rely on the existing fallback to `pypi`).
6. `examples/go/README.md`: `GOPROXY` setup, `GOSUMDB=off` note, `GOPROXY`
   without `,direct`.
7. `CHANGELOG` Unreleased: "Go module registry adapter".

### Stored-registry migration

`validateRegistries` (console/server.go) runs **only** on the UI's `PUT`
payload, not on load-from-DB (`applyStoredRegistries` overlays by switch and
ignores unknown/missing ecosystems). So an existing install whose stored
registry set predates `go` will not fail on boot: the missing `go` simply keeps
its YAML default (disabled).

The console `GET /api/registries` returns `registryInfo(cfg)`, which now
includes `go`, so the UI receives all ecosystems; the frontend normalizes to the
full set before `PUT`, keeping `PUT` payloads in sync with the enlarged
`knownEcos`. `knownEcos` (Go) and `REG_ECOS` (JS) must change together.

## Testing

`internal/proxy/adapters/go_test.go`, mirroring `npm_test.go`:

- `NormalizeRequest` table: zip vs. non-zip (list/info/mod), case-encoded path,
  `+incompatible`, pseudo-version, missing `/@v/`, empty version, junk.
- `decodeGoPath` / `encodeGoPath` round-trip: canonical ↔ encoded; invalid
  trailing `!`, `!` + non-lowercase → reject.
- `FetchMetadata` against `httptest.Server`: valid `.info`, 404, malformed JSON,
  multi-upstream failover (first fails, second succeeds).
- `UpstreamURLs`: one URL per upstream, `RequestURI()` appended verbatim.

## Success criteria

- `GOPROXY=http://<jo-ei>/go go mod download <module>` pulls a real module,
  running it through supply-chain + CVE + malware gates; a blocked module
  returns the structured block response and is not cached clean.
- Transparent `@v/list` / `.info` / `.mod` requests pass through to the upstream.
- A module with an uppercase path element (e.g. `github.com/Azure/...`) resolves
  and is CVE-queried under its canonical module path.
- Existing installs boot unchanged with `go` disabled by default.
- `golangci-lint` clean; new unit tests pass; CI `-race` job green.

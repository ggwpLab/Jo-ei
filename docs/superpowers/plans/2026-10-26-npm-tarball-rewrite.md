# npm Tarball URL Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every npm metadata document Jō-ei serves points each `dist.tarball` at Jō-ei itself, under the address the client used, and fails closed (502) when it cannot.

**Architecture:** A new `httpx.PublicBaseResolver` derives the client-facing base URL (config override → forwarding headers from trusted proxies → `Host`/TLS). The mux puts the stripped route prefix (`npm`/`yarn`) in the request context. The npm adapter's `FilterVersions` gains a link base and rewrites every `dist.tarball` to the canonical path while filtering; `proxyMetadata` always rewrites, always strips client validators, and turns every "cannot rewrite" case into 502.

**Tech Stack:** Go 1.26 stdlib (`net/http`, `net/netip`, `net/url`, `encoding/json`), zerolog, viper.

**Spec:** `docs/superpowers/specs/2026-10-26-npm-tarball-rewrite-design.md`

## Global Constraints

- ALL Go tests run in Docker, never natively:
  `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/src" -w /src -v joei-gomod:/go/pkg/mod -v joei-gocache:/root/.cache/go-build golang:1.26.10 sh -c '<go test ...>'`.
  Focused: `go test ./internal/<pkg>/ -race -run '<Regex>'`. Full: `go test ./... -race && go test -tags integration ./integration/... -race`.
- `gofmt -l .` and `golangci-lint run` locally; both clean before each commit.
- Docs and comments in present tense: no "no longer", "used to", "now" contrasts outside CHANGELOG.
- Branch `feat/npm-tarball-rewrite` (exists, holds the spec). One commit per task, Conventional Commits, ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Rewritten tarball URL: `<base>/<route-prefix>/<name>/-/<unscoped-name>-<version>.tgz`, built from the version key, never from the original URL.
- Fail-closed status is 502 with body `{"error":"metadata_rewrite_failed"}`; malformed forwarding header or `Host` is 400 `{"error":"bad_forwarded_header"}`.
- `server.metadata_filter_max_mb: 0` = no size cap. No switch disables filtering/rewriting.
- Forwarding headers are read only when the TCP peer is in `server.trusted_proxies`.
- Error reasons are logged only; no new Prometheus metric.

## Review Focus

1. IPv6 host in `Host`/`X-Forwarded-Host` (`[::1]:8080`) must survive into the link with brackets → test in Task 1.
2. `X-Forwarded-Host` carrying a comma list (`a.example, b.internal`, chained proxies) → use the first (client-facing) entry → test in Task 1.
3. Scoped package via `/yarn/` route with `%2f` spelling (`/yarn/@types%2fnode`) → link `/yarn/@types/node/-/node-<v>.tgz` → test in Task 5.
4. Client sends `Accept-Encoding: br` only → upstream still asked for gzip, client gets identity, not 502 → test in Task 5.
5. Packument with `versions: {}` (unpublished package) → served (rewritten, unchanged versions), not 502 → test in Task 4.

---

### Task 1: Public base address resolver

**Files:**
- Create: `internal/httpx/trusted.go`, `internal/httpx/publicbase.go`, `internal/httpx/publicbase_test.go`
- Modify: `internal/httpx/clientip.go` (use `TrustedPeers` instead of its own `[]netip.Prefix` + `parseTrusted` + `isTrusted`)

**Interfaces:**
- Produces:
  - `type TrustedPeers []netip.Prefix`; `func ParseTrustedPeers(entries []string) (TrustedPeers, error)` (move `parseTrusted` here; error text keeps `trusted proxy [%d]: ...`); `func (t TrustedPeers) Contains(a netip.Addr) bool`; `func (t TrustedPeers) PeerTrusted(r *http.Request) bool` (parses `r.RemoteAddr`, unmaps).
  - `func NewClientIPResolver(trusted TrustedPeers, header string, log zerolog.Logger) (*ClientIPResolver, error)` — signature change; update `cmd/jo-ei/console.go` and existing tests.
  - `var ErrBadForwardedHeader = errors.New(...)`.
  - `type PublicBaseResolver struct{...}`; `func NewPublicBaseResolver(publicURL string, trusted TrustedPeers) (*PublicBaseResolver, error)`; `func (p *PublicBaseResolver) Base(r *http.Request) (*url.URL, error)` — returns scheme+host+path with no trailing slash, query/fragment empty. A nil `*PublicBaseResolver` behaves as `NewPublicBaseResolver("", nil)`.

- [ ] **Step 1: Write failing tests** in `publicbase_test.go`, table-driven `TestPublicBaseResolver_Base`, each row: publicURL, trusted, RemoteAddr, TLS (bool), headers, want string or wantErr `ErrBadForwardedHeader`:
  - direct: RemoteAddr `10.0.0.5:1234`, Host `joei:8080` → `http://joei:8080`
  - direct TLS → `https://joei:8080`
  - untrusted peer with `X-Forwarded-Host: evil.example`, `X-Forwarded-Proto: https` → `http://joei:8080` (ignored)
  - trusted peer `172.18.0.1`, `X-Forwarded-Proto: https`, `X-Forwarded-Host: registry.example.com` → `https://registry.example.com`
  - trusted + `X-Forwarded-Port: 8443` and host without port → `https://registry.example.com:8443`
  - trusted + `X-Forwarded-Prefix: /joei/` → `https://registry.example.com/joei`
  - trusted + `X-Forwarded-Host: a.example, b.internal` → host `a.example`
  - trusted + only `Forwarded: for=1.2.3.4;proto=https;host=reg.example` → `https://reg.example`
  - trusted + `X-Forwarded-Proto` only → proto from header, host from `Host`
  - Host `[::1]:8080` direct → `http://[::1]:8080`
  - publicURL `https://reg.example.com/joei/` with trusted headers present → `https://reg.example.com/joei`
  - trusted + `X-Forwarded-Proto: gopher` → `ErrBadForwardedHeader`
  - trusted + `X-Forwarded-Host: a.example/evil` → `ErrBadForwardedHeader`
  - direct Host `bad host` → `ErrBadForwardedHeader`
  - `NewPublicBaseResolver("ftp://x", nil)` and `("not a url", nil)` → error; nil resolver `Base` works as direct.
- [ ] **Step 2: Run** `go test ./internal/httpx/ -race -run 'PublicBase'` in Docker. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `TrustedPeers` (refactor `ClientIPResolver` onto it; existing clientip tests pass unchanged apart from constructor arg) and `PublicBaseResolver`. Host validation: after first comma-split entry trimmed, `url.Parse("http://"+host)` must yield `u.Host == host` and empty path/user; proto must be `http` or `https` case-insensitive. `X-Forwarded-Prefix` must start with `/` (else error); trailing `/` trimmed.
- [ ] **Step 4: Run** `go test ./internal/httpx/ -race` in Docker. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpx): resolve the client-facing base URL from trusted forwarding headers`.

### Task 2: Config `server.public_url`; `metadata_filter_max_mb: 0` means unlimited

**Files:**
- Modify: `internal/config/config.go` (Server struct near line 182–195, validation near line 51, defaults near line 410), `internal/config/config_test.go`

**Interfaces:**
- Produces: `Server.PublicURL string` (`mapstructure:"public_url"`); default `""` registered with `v.SetDefault` so `JOEI_SERVER_PUBLIC_URL` binds.

- [ ] **Step 1: Write failing tests:** `TestLoad_PublicURL_FromEnv` (`JOEI_SERVER_PUBLIC_URL=https://reg.example.com/joei` → field set); `TestValidate_PublicURL` rows: `""` ok, `https://reg.example.com` ok, `http://x/y/` ok, `ftp://x` error containing `server.public_url`, `https://x?q=1` error, `/relative` error.
- [ ] **Step 2: Run** `go test ./internal/config/ -race -run 'PublicURL'`. Expected: FAIL.
- [ ] **Step 3: Implement** field, default, validation (absolute, scheme http/https, non-empty host, no query/fragment/userinfo). Update the `MetadataFilterMaxMB` comment: zero = no size cap.
- [ ] **Step 4: Run** `go test ./internal/config/ -race`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(config): server.public_url overrides the derived base URL`.

### Task 3: Route prefix in request context

**Files:**
- Modify: `internal/proxy/mux.go`, `internal/proxy/mux_test.go`

**Interfaces:**
- Produces: `func RoutePrefix(ctx context.Context) string` (empty when unset); the mux stores the stripped prefix before `h.ServeHTTP` for package handlers (raw handlers too, harmless).

- [ ] **Step 1: Write failing test** `TestMux_SetsRoutePrefix`: handler registered under `npm` and `yarn` records `RoutePrefix(r.Context())`; requests to `/yarn/lodash` and `/npm/lodash` record `yarn` and `npm`.
- [ ] **Step 2: Run** `go test ./internal/proxy/ -race -run 'RoutePrefix'`. Expected: FAIL.
- [ ] **Step 3: Implement** unexported context key, `r = r.WithContext(context.WithValue(...))` before path strip.
- [ ] **Step 4: Run** same. Expected: PASS.
- [ ] **Step 5: Commit** `feat(proxy): carry the route prefix in the request context`.

### Task 4: npm adapter rewrites tarball links (packument and single-version manifest)

**Files:**
- Modify: `internal/gate/gate.go:77-116`, `internal/proxy/adapters/npm.go:176-319`, `internal/proxy/adapters/npm_test.go`; any other `MetadataFilterer` implementer/fake (grep `FilterVersions(`) — fakes in `internal/proxy/*_test.go` get the new signature.

**Interfaces:**
- Produces:
  - `MetadataRef` gains `Version string` — empty for a packument, the requested version or dist-tag for a single-version manifest (`/<name>/<version-or-tag>`).
  - `MetadataFilterer.FilterVersions(doc []byte, ref *MetadataRef, decide VersionDecider, linkBase string) (FilteredDocument, error)`. `linkBase` is `<base>/<route-prefix>` with no trailing slash. Contract comment: every download link in the result points under `linkBase`; an error means the document cannot be served.
  - `FilteredDocument` gains `Unmappable []string` (versions dropped because their link cannot round-trip). `Body` is always the re-encoded, rewritten document (drop the "input bytes when nothing removed" sentence).
  - `var ErrNoServableVersions = errors.New("no version left with a rewritable tarball link")` in `gate`.
- Tarball link algorithm (adapter-private `npmTarballURL(linkBase, name, version string) (string, bool)`): build `linkBase + "/" + name + "/-/" + unscoped + "-" + version + ".tgz"`; ok only if `version` matches `^[0-9A-Za-z.+_-]+$` and `parseNPMVersion(name, unscoped+"-"+version+".tgz")` returns `version`.

- [ ] **Step 1: Write failing tests** in `npm_test.go` (base `https://reg.example/npm`):
  - `TestNPMAdapter_FilterVersions_RewritesEveryTarball`: two versions with `dist.tarball` on `https://registry.npmjs.org/...` → both become `https://reg.example/npm/left-pad/-/left-pad-1.3.0.tgz` etc.; `dist.integrity`/`shasum` untouched; unknown top-level field survives.
  - `..._ScopedName`: `@babel/core` 7.26.0 from `https://nexus.example/repository/npm-proxy/@babel/core/-/core-7.26.0.tgz` → `https://reg.example/npm/@babel/core/-/core-7.26.0.tgz`.
  - `..._ArtifactoryStyleFilenameIgnored`: original `.../@scope/name/-/@scope/name-1.0.0.tgz` → canonical `.../@scope/name/-/name-1.0.0.tgz`.
  - `..._UnmappableVersionDropped`: version key `1.0.0/../x` → absent from `versions` and `time`, listed in `Unmappable`; other version present.
  - `..._AllUnmappable`: → `errors.Is(err, gate.ErrNoServableVersions)`.
  - `..._AllRejectedStillRewritten`: decide rejects all → `AllRejected`, every version present, links rewritten.
  - `..._VersionWithoutDistLeftAlone`: version object with no `dist` → kept, unchanged.
  - `..._EmptyVersions`: `"versions":{}` → no error, body still valid JSON with empty versions.
  - `..._AbbreviatedDoc`: corgi doc (no `time`) rewritten.
  - `..._SingleVersionManifest`: ref `{Name:"left-pad", Version:"latest"}`, doc `{"name":"left-pad","version":"1.3.0","dist":{"tarball":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}` → tarball rewritten; `decide` never called (pass one that `t.Fatal`s).
  - `..._SingleVersionManifestUnmappable`: manifest `version` `bad/v` → `ErrNoServableVersions`.
  - Update `TestNPMAdapter_NormalizeMetadataRequest` rows: `/left-pad/1.3.0` → ok, `Version:"1.3.0"`; `/left-pad/latest` → ok, `Version:"latest"`; `/@types/node/20.1.0` and `/@types%2fnode/20.1.0` → ok, name `@types/node`; `/left-pad/-/left-pad-1.3.0.tgz`, `/-/v1/search`, `/left-pad/1.3.0/extra`, `?write=true` → not ok.
  - Replace `TestNPMAdapter_FilterVersions_NothingRemovedReturnsOriginalBytes` with an assertion that links are rewritten when nothing is removed; update the other existing FilterVersions tests to the new signature.
- [ ] **Step 2: Run** `go test ./internal/proxy/adapters/ -race -run 'NPMAdapter'`. Expected: compile FAIL / test FAIL.
- [ ] **Step 3: Implement** gate contract changes and the adapter. Keep one-level raw-JSON decoding; for each version decode the version object as `map[string]json.RawMessage`, then `dist` the same way, replace only `tarball`. Unmappable versions are removed from `versions` and `time` like rejected ones, and do not count toward `AllRejected`. Update the `NormalizeMetadataRequest` / `isNPMPackageName` comments (manifests are now rewritten).
- [ ] **Step 4: Run** `go test ./internal/proxy/adapters/ ./internal/gate/ -race`. Expected: PASS. (`internal/proxy` may not compile yet; fixed in Task 5 — if the executor prefers green-per-commit, fold the one-line call-site update in `metadata.go` into this task passing `mref, decide, ""` temporarily.)
- [ ] **Step 5: Commit** `feat(npm): point every tarball link at the proxy`.

### Task 5: proxyMetadata always rewrites and fails closed

**Files:**
- Modify: `internal/proxy/handler.go` (HandlerConfig, `MetadataFilterMaxMB` comment), `internal/proxy/metadata.go`, `internal/proxy/metadata_test.go`, `integration/npm_metadata_filter_test.go`, `internal/proxy/handler_test.go` (any npm metadata fixture)

**Interfaces:**
- Consumes: `httpx.PublicBaseResolver.Base`, `httpx.ErrBadForwardedHeader` (Task 1); `RoutePrefix` (Task 3); new `FilterVersions` signature, `gate.ErrNoServableVersions`, `FilteredDocument.Unmappable` (Task 4).
- Produces: `HandlerConfig.PublicBase *httpx.PublicBaseResolver` (nil = direct-only).

Behaviour (replaces today's fallbacks):
- `metadataFilterRef` no longer checks `MetadataFilterMaxMB`.
- Link base = `Base(r)` + `"/" + RoutePrefix(ctx)`; `Base` error → 400 `bad_forwarded_header` before any upstream call. Empty `RoutePrefix` (handler used without the mux, e.g. unit tests) → link base is just `Base(r)`.
- Outbound: always delete `If-None-Match`, `If-Modified-Since`, `Range`, `If-Range`; set `Accept-Encoding: gzip`. Coalescing key = `RequestURI \x00 Accept`.
- Size limit: `MetadataFilterMaxMB == 0` → unlimited (no `LimitReader`; avoid `limit+1` overflow).
- Upstream status: 200 → rewrite; 3xx (incl. 304) and 2xx other than 200/204 → 502; 204 → relay.
- Oversized, unsupported encoding, read error, parse error, `ErrNoServableVersions` → 502 `metadata_rewrite_failed`, one Error log naming the reason. `streamOversizedMetadata` and the relay reasons it served are deleted; keep a small relay for 204.
- `Unmappable` non-empty → Warn with count and up to `maxLoggedDrops` versions.
- Every 200 goes through `writeMetadataDocument` with a synthetic ETag; client holding the matching synthetic tag → 304 (existing logic). Drop the `rewritten` parameter (always true). `proxyIndex` call site updated.
- Update the `proxyMetadata` doc comment: fail closed, tarball links rewritten.

- [ ] **Step 1: Write failing integration tests** in `integration/npm_metadata_filter_test.go` (reuse the file's fake upstream helpers; base via mux `/npm/`):
  - `..._RewritesTarballLinksToTheProxy`: direct request with `Host: joei.test:8080` → every `dist.tarball` starts `http://joei.test:8080/npm/`.
  - `..._YarnRouteLinksUnderYarn`: `/yarn/@types%2fnode` → links `http://joei.test:8080/yarn/@types/node/-/node-<v>.tgz`.
  - `..._TrustedProxyHeaders`: handler with `PublicBase` trusting the test client's loopback, `X-Forwarded-Proto: https`, `X-Forwarded-Host: reg.example` → links `https://reg.example/npm/...`; same headers with empty trust → `http://<Host>/npm/...`.
  - `..._BadForwardedHeaderIs400`: trusted + `X-Forwarded-Host: a/b` → 400, upstream hit count 0.
  - `..._ETagDiffersPerBase`: same doc requested with two `Host`s → different `ETag`s.
  - `..._ClientValidatorsNeverForwarded`: client sends upstream-style `If-None-Match: "abc"` and `If-Modified-Since` → upstream sees neither, client gets 200 rewritten.
  - `..._OverCapIs502` (replaces both OverCap*FallsBackToTheGate), `..._UnsupportedEncodingIs502` (upstream forced `Content-Encoding: br`), `..._UnparseableIs502`, `..._UpstreamRedirectIs502`, `..._AllUnmappableIs502`.
  - `..._ZeroCapMeansUnlimited` (replaces `ZeroCapDisablesFiltering`): cap 0, fresh version hidden and links rewritten.
  - `..._BrOnlyClientGetsIdentity`: client `Accept-Encoding: br` → upstream saw `gzip`, response 200 without `Content-Encoding`.
  - `..._VersionManifestRewritten` (replaces `VersionManifestUntouched`).
  - Delete `RecoversToUpstreamTag`, `RelaysUpstream304`, `MixedValidatorsDoNotShareAFlight`, `RepeatedValidatorLinesDoNotShareAFlight` (their premise — forwarding client validators — is gone; `ClientValidatorsNeverForwarded` covers it). Keep and adapt `HidesFreshVersion`, `AllVersionsBlockedServesOriginal` (assert links rewritten too; rename `...ServesAllVersionsRewritten`), `GzippedUpstream`, `RevalidateWithOurTag`, `DryRunHidesNothing`, `CoalescesConcurrentFetches`.
- [ ] **Step 2: Run** `go test -tags integration ./integration/ -race -run 'NPMMetadataFilter'`. Expected: FAIL.
- [ ] **Step 3: Implement** the behaviour above in `metadata.go`/`handler.go`; update unit tests in `metadata_test.go` that reference removed helpers.
- [ ] **Step 4: Run full suite** in Docker: `go test ./... -race && go test -tags integration ./integration/... -race`. Expected: PASS. `golangci-lint run`: 0 issues.
- [ ] **Step 5: Commit** `feat(proxy): serve npm metadata only with tarball links rewritten`.

### Task 6: Wire the resolver in `cmd/jo-ei`

**Files:**
- Modify: `cmd/jo-ei/main.go` (~line 95, `sharedDeps`), `cmd/jo-ei/routes.go:162-178`, `cmd/jo-ei/console.go:61`; test in `cmd/jo-ei/*_test.go` if a wiring test file exists for routes.

**Interfaces:**
- Consumes: `httpx.ParseTrustedPeers`, `httpx.NewPublicBaseResolver`, `HandlerConfig.PublicBase`.

- [ ] **Step 1: Write failing test** (if `cmd/jo-ei` has route tests): building handlers from a config with `server.public_url: https://reg.example` and requesting `/npm/<pkg>` against a fake upstream yields links under `https://reg.example/npm/`. If no harness exists, skip the test and rely on Task 8 E2E — say so in the commit body.
- [ ] **Step 2: Run** it. Expected: FAIL.
- [ ] **Step 3: Implement:** parse `TrustedProxies` once into `httpx.TrustedPeers` in `main`, pass it to both `NewClientIPResolver` and `NewPublicBaseResolver(cfg.Server.PublicURL, peers)`; add `publicBase` to `sharedDeps` and `PublicBase` to `buildHandler`.
- [ ] **Step 4: Run** full suite in Docker + lint. Expected: PASS, 0 issues.
- [ ] **Step 5: Commit** `feat(cmd): wire the public base resolver into the registry handlers`.

### Task 7: Docs and CHANGELOG

**Files:**
- Modify: `README.md` (replace the "Known limitation — tarballs can bypass the gates" block), `docs/configuration.md` (server table: `public_url`, `metadata_filter_max_mb` meaning of 0; reverse-proxy section: headers read from trusted proxies — `X-Forwarded-Proto/Host/Port/Prefix`, `Forwarded`; npm section: links rewritten, fail-closed 502 cases, lockfile caveat, GitHub Packages unsupported, `?write=true` passes untouched), `CHANGELOG.md` Unreleased, `config.example.yaml` / `.env.example` if they list server keys (grep `metadata_filter_max_mb`).

- [ ] **Step 1: Write the docs.** Lockfile text: lockfiles created before Jō-ei (`yarn.lock` `resolved`, `package-lock.json` `resolved` for clients other than npm) pin tarball URLs the client fetches without asking Jō-ei; regenerate them, and block direct egress to `registry.npmjs.org` so a missed one fails instead of bypassing. CHANGELOG: Security — tarball links rewritten, pnpm/Yarn no longer bypass the gates; Changed — npm metadata fails closed (502) instead of being relayed unfiltered, `metadata_filter_max_mb: 0` means no cap (previously disabled filtering), client validators are not forwarded upstream for npm metadata; Added — `server.public_url`, forwarding headers for the base URL.
- [ ] **Step 2: Check** `grep -rn "Known limitation\|bypass the gates\|disables metadata filtering" README.md docs/` → only intended hits; present-tense rule holds outside CHANGELOG.
- [ ] **Step 3: Commit** `docs: npm tarball links route through the proxy`.

### Task 8: E2E verification (manual, no commit unless docs change)

Harness: scratchpad `e2e` dir from PR #115 (linux `jo-ei` binary built from this branch, `config.yaml`, fake upstream JS, self-signed cert for `registry.npmjs.org`), `--internal` Docker network, tools image with npm 10, pnpm 9, Yarn 1, Yarn Berry (corepack).

- [ ] **Step 1:** Default npmjs upstream (fake, TLS, aliased `registry.npmjs.org`): `npm install`, `pnpm install`, `yarn install` (v1), `yarn install` (Berry) of a test package. Expected: install succeeds; fake upstream log shows every tarball request coming from the proxy IP, none from the client IP.
- [ ] **Step 2:** Verdaccio as upstream (and Nexus if the image runs in reasonable time): same four clients, same expectation.
- [ ] **Step 3:** Behind an nginx container in `trusted_proxies` with `X-Forwarded-Proto/Host` → links carry the nginx host; install via nginx succeeds.
- [ ] **Step 4:** Inspect generated lockfiles: pnpm v9 and Yarn Berry must not contain `registry.npmjs.org`; Yarn 1 `resolved` points at the proxy. If the pnpm/Berry assumption fails, correct the lockfile paragraph from Task 7 and commit `docs: ...`.
- [ ] **Step 5:** Clean up containers, network and image. Report results with the client/proxy IP evidence.

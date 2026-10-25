# PyPI Index Link Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every pip/uv/poetry download through the proxy reaches `/pypi/packages/...` and therefore the gates; no index document the proxy serves points a client at a file host directly.

**Architecture:** A new optional adapter capability `gate.IndexRewriter` (PyPI implements it) rewrites download links in index documents — PEP 503 HTML, PEP 691 JSON, and the legacy JSON API — to relative `…/packages/…` links. `proxy.Handler` routes index requests to a fail-closed path: fetch with validators stripped and `Accept-Encoding: gzip`, decode, rewrite, serve with a synthetic ETag; anything that cannot be rewritten answers 502.

**Tech Stack:** Go (toolchain go1.26.10), stdlib only (`regexp`, `encoding/json`, `net/url`).

**Spec:** `docs/superpowers/specs/2026-10-25-production-readiness-audit.md` — P0 #0. Owner decisions (2026-10-25): relative links; fail-closed 502; unmappable absolute links dropped with a warning; JSON API rewritten too; e2e with real pip on a network that reaches only the proxy.

## Global Constraints

- Link mapping: an **absolute** URL (has scheme and host) whose path starts with `/packages/` → `strings.Repeat("../", depth) + "packages/…"` keeping query and `#fragment`, where `depth` = number of path segments in the directory of the (prefix-stripped) request path (`/simple/torch/` → 2, `/simple/torch` → 1, `/pypi/requests/json` → 2, `/pypi/requests/2.31.0/json` → 3).
- Any other absolute URL → the file entry/anchor is **removed**; count and log at warn with up to 5 example URLs (credentials stripped via `upstream.SanitizeURL`).
- Relative and absolute-path hrefs are left untouched (they resolve against the proxy). A `<base …>` element is removed.
- Index requests (PyPI): path starts with `/simple/`, or matches `^/pypi/[^/]+(/[^/]+)?/json$`.
- Fail-closed: upstream 200 that is oversized (> `HandlerConfig.IndexMaxMB`, default **64** when 0), in an undecodable encoding, or unparseable → `502` with JSON `{"error":"index_rewrite_failed"}`; error logged. Non-200 upstream responses are relayed unchanged (no document to rewrite). Index rewriting does **not** depend on `metadata_filter_max_mb` (that knob only controls npm version filtering).
- Validators: client `If-None-Match`/`If-Modified-Since` are never forwarded upstream; the response carries `syntheticETag(body)` (existing helper) and no `Last-Modified`; a client `If-None-Match` equal to that tag gets `304`.
- No new dependencies, no new config keys.
- OWNER RULE: Go tests only in a container: `MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD":/src -v jo-ei-gomod:/go/pkg/mod -v jo-ei-gobuild:/root/.cache/go-build -w /src golang:1.26.10 go test -race <pkgs>`; `golangci-lint run ./...` → `0 issues.` before every commit.
- Branch `fix/pypi-index-rewrite`, stacked on `fix/large-artifacts-and-cache-writes` (PR #106).

## Review Focus

1. **Stale client caches** — pip caches simple pages; after upgrade a client revalidating with upstream's ETag must get a rewritten body, never an upstream 304 for an unrewritten copy; pinned by Task 2 `TestIndex_ClientValidatorsNotForwarded`.
2. **gzip from upstream** — pypi.org compresses; the rewrite must see decoded bytes; pinned by Task 2 `TestIndex_GzipUpstreamIsRewritten`.
3. **Foreign absolute links** — a mirror linking another host must not leak a bypass; pinned by Task 1 `TestRewriteIndex_HTMLDropsForeignAbsolute` / `_JSONDropsForeignAbsolute`.
4. **Hash fragments** — `#sha256=` must survive or pip refuses `--require-hashes` installs; pinned by Task 1 `TestRewriteIndex_HTMLRewritesAbsolutePackageLinks`.
5. **Oversized index** — must 502, not stream through; pinned by Task 2 `TestIndex_OversizedFailsClosed`.

---

### Task 1: `gate.IndexRewriter` and the PyPI implementation

**Files:**
- Modify: `internal/gate/gate.go` (interface + result type)
- Create: `internal/proxy/adapters/pypi_index.go`, `internal/proxy/adapters/pypi_index_test.go`

**Interfaces:**
- Produces:
  ```go
  // gate.IndexRewriter: optional RegistryAdapter capability for registries whose
  // index documents link downloads by absolute URL.
  type IndexRewriter interface {
      IsIndexRequest(r *http.Request) bool
      // RewriteIndex rewrites doc served for requestPath (prefix-stripped) with
      // the given Content-Type. An error means the document cannot be made safe.
      RewriteIndex(doc []byte, contentType, requestPath string) (IndexRewrite, error)
  }
  type IndexRewrite struct {
      Body      []byte
      Rewritten int      // links pointed at the proxy
      Dropped   []string // absolute links removed (unmappable)
  }
  ```
  Dispatch: path matches the JSON API pattern → JSON API; Content-Type contains `application/vnd.pypi.simple.v1+json` → PEP 691; anything else → HTML.

- [ ] **Step 1: Failing tests** (`pypi_index_test.go`, package `adapters`):
  - `TestIsIndexRequest`: `/simple/`, `/simple/torch/`, `/pypi/torch/json`, `/pypi/torch/2.5.1/json` → true; `/packages/ab/x.whl`, `/pypi/torch` → false.
  - `TestRewriteIndex_HTMLRewritesAbsolutePackageLinks`: `<a href="https://files.pythonhosted.org/packages/8b/5c/x-1.0-py3-none-any.whl#sha256=ab" data-requires-python="&gt;=3.8">x</a>` at `/simple/x/` → href `../../packages/8b/5c/x-1.0-py3-none-any.whl#sha256=ab`, other attributes intact, `Rewritten == 1`.
  - `TestRewriteIndex_HTMLKeepsRelativeLinks`: `href="../../packages/a/b.whl"` unchanged, `Rewritten == 0`, no drops.
  - `TestRewriteIndex_HTMLDropsForeignAbsolute`: `href="https://evil.example/x-1.0.tar.gz"` → anchor gone from body, `Dropped == ["https://evil.example/x-1.0.tar.gz"]`.
  - `TestRewriteIndex_HTMLRemovesBase`: `<base href="https://files.pythonhosted.org/">` removed.
  - `TestRewriteIndex_DepthFollowsRequestPath`: `/simple/x` (no slash) → `../packages/…`.
  - `TestRewriteIndex_JSONSimple`: PEP 691 doc with two files (one pythonhosted, one foreign) → first `url` = `../../packages/…#sha256=…` preserved fields (`hashes`, `filename`), second removed; other top-level keys (`meta`, `name`, `versions`) preserved.
  - `TestRewriteIndex_JSONSimpleDropsForeignAbsolute`: covered by the case above (assert `Dropped`).
  - `TestRewriteIndex_JSONAPI`: `/pypi/x/json` doc with `urls[0].url` and `releases["1.0"][0].url` → both `../../packages/…`; `/pypi/x/1.0/json` → `../../../packages/…`.
  - `TestRewriteIndex_MalformedJSONErrors`: PEP 691 content type with body `{` → error.
- [ ] **Step 2:** Container `go test -race ./internal/proxy/adapters/` → FAIL (`undefined`).
- [ ] **Step 3:** Implement. HTML: regexp over `<a\b[^>]*>.*?</a>` (case-insensitive, dot matches newline) extracting `href` (double or single quoted); `<base\b[^>]*>` removed. JSON: decode into `map[string]json.RawMessage`, rewrite `files[].url` (PEP 691) or `urls[].url` and every `releases[*][].url` (JSON API) via `[]map[string]json.RawMessage`; re-marshal.
- [ ] **Step 4:** Container tests PASS; lint `0 issues.`
- [ ] **Step 5: Commit** — `fix(pypi): rewrite index download links to route through the proxy`.

### Task 2: Fail-closed index path in `proxy.Handler`

**Files:**
- Create: `internal/proxy/index.go`, `internal/proxy/index_test.go`
- Modify: `internal/proxy/handler.go` (`HandlerConfig.IndexMaxMB`; `ServeHTTP` routes `IsIndexRequest` before the metadata-filter check)

**Interfaces:**
- Consumes: `gate.IndexRewriter`, `readMetadataDocument`, `writeMetadataDocument`, `syntheticETag`, `forwardUpstream`.
- Produces: `func (h *Handler) proxyIndex(w http.ResponseWriter, r *http.Request, rw gate.IndexRewriter)`; `HandlerConfig.IndexMaxMB int` (0 → 64).

- [ ] **Step 1: Failing tests** (package `proxy_test`, real `proxy.NewHandler` with `adapters.NewPyPIAdapter` over an httptest upstream):
  - `TestIndex_HTMLLinksPointAtProxy`: upstream simple page with an absolute pythonhosted link → response 200, body contains `href="../../packages/`, not `files.pythonhosted.org`.
  - `TestIndex_GzipUpstreamIsRewritten`: upstream answers gzip-encoded (when request has `Accept-Encoding: gzip`) → client (no gzip) gets rewritten plain body.
  - `TestIndex_ClientValidatorsNotForwarded`: client sends `If-None-Match: "upstream-tag"` and `If-Modified-Since` → upstream sees neither; response has `ETag` with the `"joei.` prefix and no `Last-Modified`.
  - `TestIndex_OurETagRevalidates`: second request with the first response's ETag → `304`.
  - `TestIndex_OversizedFailsClosed`: `IndexMaxMB: 1`, upstream 2 MiB page → `502`, body `{"error":"index_rewrite_failed"}`.
  - `TestIndex_UnparseableFailsClosed`: PEP 691 content type with invalid JSON → `502`.
  - `TestIndex_Non200Relayed`: upstream 404 → client 404 (via existing `writeForwardError` path).
- [ ] **Step 2:** Container `go test -race ./internal/proxy/` → FAIL.
- [ ] **Step 3:** Implement: clone request, delete `If-None-Match`/`If-Modified-Since`, set `Accept-Encoding: gzip`; `forwardUpstream`; nil response → `writeForwardError`; status ≠ 200 → relay headers+body via `CopyWithWriteDeadline`; read with limit; `rest != nil` or unsupported encoding or rewrite error → log + 502; `etagMatches(clientINM, syntheticETag(body))` → 304 with ETag; else `writeMetadataDocument(..., rewritten=true)`. Log debug `index rewritten` (rewritten count), warn `dropped unmappable index links` (count + up to 5 sanitized URLs).
- [ ] **Step 4:** Container tests for `./internal/proxy/...` PASS; lint `0 issues.`
- [ ] **Step 5: Commit** — `fix(proxy): serve PyPI indexes only with proxied download links`.

### Task 3: End-to-end with real clients, docs, PR

**Files:**
- Modify: `CHANGELOG.md` (`### Security` under Unreleased), `README.md` (PyPI section: note links are rewritten), audit doc (mark P0 #0 fixed; record npm/yarn/pnpm findings)

- [ ] **Step 1: e2e pip** — build image; `docker network create --internal joei-e2e`; run proxy (pypi only, scanners off) on the default bridge, then `docker network connect joei-e2e`; run `python:3.12-slim` **only** on `joei-e2e`: `pip download --no-deps --index-url http://jo-ei:8080/pypi/simple/ --trusted-host jo-ei six==1.16.0 -d /tmp/d` → exit 0, wheel present; proxy log has a `request gated` PASS for `six 1.16.0`. Repeat with `PIP_` default JSON negotiation (pip ≥ 22 asks for PEP 691 JSON) — the same command covers it; also `pip install --no-deps --require-hashes` with `six==1.16.0 --hash=sha256:<from index>` → exit 0.
- [ ] **Step 2: e2e npm/yarn/pnpm (verification only)** — `node:22-slim` on `joei-e2e` only: `npm pack left-pad@1.3.0 --registry http://jo-ei:8080/npm/` → exit 0 means tarballs route through the proxy. Same for `corepack pnpm` / `yarn` if available offline; record results in the audit doc. A failure is documented as a new finding, not fixed here.
- [ ] **Step 3:** CHANGELOG `### Security`: **pip downloads now go through the proxy's gates.** …(absolute links, relative rewrite, fail-closed 502, dropped foreign links). README PyPI note. Audit doc updated.
- [ ] **Step 4:** Full suite in container + lint.
- [ ] **Step 5: Commit** — `docs: changelog and audit for PyPI index rewrite`; push; `gh pr create --base fix/large-artifacts-and-cache-writes`.

# Upstream failure visibility and CA trust — design

Date: 2026-08-24
Status: approved, ready for planning

## Problem

Two operational blind spots when a proxied artifact cannot be fetched.

**1. Mirror errors collapse to the last one.** Every upstream loop in the
codebase keeps a single `lastErr` variable and overwrites it on each failed
mirror. When mirror A fails TLS verification and mirror B answers 404, only the
404 survives into the log. The operator sees "artifact not found on any
upstream" and has no way to learn that a mirror was unreachable for an entirely
different reason. The `allNotFound` flag in `downloadFromUpstreams`
(`internal/proxy/handler.go:518`) decides 404-versus-502 correctly, but the
evidence behind that decision is thrown away.

Affected sites:

- `internal/proxy/handler.go:531` — `err = derr` in `downloadFromUpstreams`
- `internal/proxy/handler.go:436-476` — `proxyTransparent` drops errors entirely
  (`continue` with no logging at all)
- `internal/proxy/adapters/{npm,pypi,maven,rubygems,go}.go` — `FetchMetadata`
- `internal/proxy/dockerproxy/adapter.go:126,206,237` — `ResolveDigest`,
  `getManifest`, `FetchBlob`

**2. No way to trust a private mirror's CA.** Every upstream client is built on
`http.DefaultTransport` at `cmd/jo-ei/main.go:204`, which trusts only the system
root store. A mirror presenting a certificate signed by a corporate or
self-signed CA fails verification, and the artifact cannot be fetched. There is
no configuration knob for additional roots.

## Scope

In scope: additional trusted CA certificates for upstream registry traffic, and
per-attempt error visibility in the logs across all upstream paths.

Out of scope, decided explicitly:

- `insecure_skip_verify` — not wanted
- client certificates / mTLS — not wanted
- hot reload of CA material — not wanted
- per-registry or per-host trust — one global pool is enough
- surfacing attempts in the HTTP response body, response headers, or the admin
  console — logs only
- the OSV (`internal/scanner/osv.go`) and Trivy clients — internal services with
  their own clients, not mirrors

## Part 1 — upstream attempt aggregation

### New package `internal/upstream`

```go
type Attempt struct {
	URL      string        // userinfo stripped: https://user:pass@mirror → https://mirror
	Status   int           // 0 = transport error (TLS, DNS, timeout, circuit breaker)
	Err      error
	Duration time.Duration
}

type Attempts []Attempt

func (a *Attempts) Add(url string, status int, err error, d time.Duration)
func (a Attempts) Error() string                      // "all 2 upstreams failed: https://mirror-a: tls: …; https://mirror-b: HTTP 404"
func (a Attempts) Unwrap() []error                    // errors.Is/errors.As reach the individual errors
func (a Attempts) AllNotFound() bool                  // len > 0 and every Status is 404 or 410
func (a Attempts) MarshalZerologArray(*zerolog.Array) // {url, status, error, ms}
func AttemptsFrom(err error) (Attempts, bool)         // errors.As helper for log sites
```

`Status: 0` is the load-bearing distinction: it separates "the mirror answered
404" from "we never reached the mirror". That difference is what is missing
today.

`Attempts` implements `error`, so adapter signatures keep returning plain
`error` — only the concrete type behind it becomes richer. Log sites recover the
detail with `AttemptsFrom`.

URL sanitization strips userinfo before an attempt is recorded, so credentials
embedded in a configured upstream never reach the log.

### Call-site changes

| File | Change |
|---|---|
| `internal/proxy/handler.go:518` | `downloadFromUpstreams` returns `Attempts` instead of `(bool, error)`; the `allNotFound` return is removed and the caller uses `atts.AllNotFound()`, so the 404-versus-502 rule lives in one place |
| `internal/proxy/handler.go:436` | `proxyTransparent` accumulates attempts instead of a bare `continue`; one `Warn` before writing 404/502 |
| `internal/proxy/adapters/npm.go:113` and the pypi, maven, rubygems, go equivalents | `FetchMetadata`: `lastErr` → `Attempts` |
| `internal/proxy/dockerproxy/adapter.go:126,206,237` | `ResolveDigest`, `getManifest`, `FetchBlob`: same |
| `internal/proxy/handler.go:164,215,220` | log sites attach `.Array("upstream_attempts", atts)` |

Existing behaviour that must not change: the HTTP status the client receives
(404 when every mirror said 404/410, 502 otherwise), the gate verdict recorded,
and the order in which upstreams are tried.

### Resulting log line

```
WARN artifact not found on any upstream package=npm/left-pad@1.3.0 upstream_attempts=[
  {"url":"https://mirror.corp","status":0,"error":"x509: certificate signed by unknown authority","ms":11},
  {"url":"https://registry.npmjs.org","status":404,"error":"upstream returned HTTP 404","ms":92}]
```

## Part 2 — trusted CA certificates

### Configuration

```yaml
tls:
  ca_files:
    - /etc/jo-ei/ca/corp-root.pem
```

`internal/config` gains a top-level `TLS TLSConfig` field with a single member,
`CAFiles []string` (`mapstructure:"ca_files"`). The section is optional; an
absent or empty list means today's behaviour — system roots only.

### Loading

`internal/httpx/tls.go` (httpx already owns transport construction, so no new
package):

```go
func RootPool(caFiles []string) (pool *x509.CertPool, added int, err error)
func NewTransport(pool *x509.CertPool) *http.Transport // DefaultTransport.Clone() + TLSClientConfig{RootCAs: pool}
```

`RootPool` clones `x509.SystemCertPool()` and appends the configured PEM files.
Configured CAs are *added* to the public roots, never a replacement, so a
corporate mirror and registry.npmjs.org work at the same time.

Startup fails — not warns — on any of:

- a file in `ca_files` cannot be read
- a PEM file yields zero certificates (the common mistake: a private key, or DER
  content in a `.pem`-named file)
- `x509.SystemCertPool()` returns an error; silently dropping the public roots
  is not acceptable

On success: `INFO tls: added 2 CA certificates to the upstream trust pool
sources=1`.

### Wiring

`cmd/jo-ei/main.go:204` is the single wiring point: the base of the transport
chain changes from `http.DefaultTransport` to `httpx.NewTransport(pool)`. All
four clients (metadata, download, docker, transparent) inherit the trust pool
through the shared circuit-breaker → rate-limiter → concurrency-limiter chain.
The limiter configuration is untouched.

## Part 3 — testing

Test-driven: each test below is written failing first.

| Level | Check |
|---|---|
| `internal/upstream` unit | `AllNotFound()` over a mix of 404 and status 0; `Error()` mentions every attempt; `errors.Is` reaches a wrapped sentinel through `Unwrap`; zerolog array marshalled into a buffer and compared as JSON |
| `internal/httpx` unit | `RootPool` with a valid PEM reports `added=1`; a malformed PEM is an error; a missing file is an error; an empty list yields the system pool |
| `internal/httpx` TLS end-to-end | `httptest.NewTLSServer` (self-signed): a request through `NewTransport` with the system pool fails with an x509 error; the same server succeeds once `srv.Certificate()` is written to a PEM file and loaded through `RootPool`. This is the direct proof of the feature |
| `internal/httpx` | HTTP/2 to an upstream still negotiates through the cloned transport (`ForceAttemptHTTP2` survives `Clone()` with a custom `TLSClientConfig`) |
| `internal/proxy` handler | Mirror A fails at the transport layer, mirror B answers 404 → client gets 502 and the log carries both attempts, one with `status:0` and one with `status:404` |
| `internal/proxy` handler | Both mirrors answer 404 → client gets 404 (regression guard on `AllNotFound`) |
| `internal/config` | The `tls` section parses; an absent section leaves the zero value |

## Documentation

- `config.yaml`: commented `tls` section
- `docs/`: a section on private mirrors with a self-signed or corporate CA,
  including how to obtain the PEM
- `CHANGELOG.md`: entries under Unreleased (this refills the section toward
  v0.4.0)

## Risks

- Adapter tests that assert on error text are likely to break; they are updated
  as the change lands.
- `DefaultTransport.Clone()` keeps `ForceAttemptHTTP2: true`, so HTTP/2 to
  upstreams is not lost when a custom `TLSClientConfig` is set — pinned by a
  test rather than assumed.
- The CI gate is golangci-lint, not only `go vet`; it is run locally before
  pushing.

## Delivery

Feature branch `feat/upstream-errors-and-ca-trust`, pull request into `main`.

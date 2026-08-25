# Upstream Failure Visibility and CA Trust — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Log every upstream mirror's own failure instead of only the last one, and let operators add trusted CA certificates so mirrors with a corporate or self-signed certificate can be fetched.

**Architecture:** A new `internal/upstream` package holds an `Attempts` slice that doubles as an `error` and as a zerolog array marshaler; every upstream retry loop (artifact download, transparent proxy, four metadata adapters, three Docker adapter methods) accumulates attempts into it instead of overwriting a `lastErr`. Separately, `internal/httpx` gains a CA-pool loader and a transport constructor; `cmd/jo-ei/main.go` builds the shared upstream transport on that pool instead of `http.DefaultTransport`, so all four HTTP clients inherit the added trust.

**Tech Stack:** Go 1.25, zerolog (structured logging), viper (config), `crypto/x509` + `encoding/pem`, `net/http/httptest` for TLS end-to-end tests.

**Spec:** `docs/superpowers/specs/2026-08-24-upstream-errors-and-ca-trust-design.md`

## Global Constraints

- Go 1.25.0, toolchain go1.26.5 (`go.mod`). No new third-party dependencies — everything here is stdlib plus the already-vendored zerolog and viper.
- The CI lint gate is `golangci-lint run` (`make lint`), which includes staticcheck/unused/ineffassign — **not** just `go vet`. Run `make lint` before every commit. Deprecated APIs (e.g. `x509.CertPool.Subjects()`) fail the gate.
- Run tests locally without `-race` (`go test ./internal/...`); CI runs `make test`, which adds `-race`.
- Client-visible behaviour must not change: 404 when every mirror answered 404/410, 502 otherwise; same upstream ordering; same gate verdicts.
- Logs only. No attempt data in HTTP response bodies, headers, or the admin console.
- TLS scope is exactly `tls.ca_files`. No `insecure_skip_verify`, no client certificates, no hot reload, no per-registry trust.
- Feature branch `feat/upstream-errors-and-ca-trust` (already created, spec committed there), PR into `main`.

---

## File Structure

**Created:**

- `internal/upstream/attempts.go` — the `Attempt`/`Attempts` types, their `error`, `Unwrap`, `AllNotFound`, and zerolog marshaling; plus `AttemptsFrom` and `SanitizeURL`. One responsibility: representing a fan-out of upstream failures.
- `internal/upstream/attempts_test.go` — unit tests for the above.
- `internal/httpx/tls.go` — `RootPool` (system pool + configured PEM files) and `NewTransport` (cloned default transport carrying that pool).
- `internal/httpx/tls_test.go` — unit and TLS end-to-end tests.

**Modified:**

- `internal/proxy/handler.go` — `downloadFromUpstreams`, `proxyTransparent`, and three log sites (metadata failure, artifact-not-found, download failure).
- `internal/proxy/adapters/{npm,pypi,rubygems,go}.go` — `FetchMetadata` loops and their `fetchMetadataFrom` / `fetchInfoFrom` helpers. (`maven.go` has no loop: its `FetchMetadata` is a documented no-op.)
- `internal/proxy/dockerproxy/adapter.go` — `ResolveDigest`, `getManifest`, `FetchBlob`.
- `internal/proxy/dockerproxy/handler.go:57` — attach attempts to the gate-error log.
- `internal/config/config.go` — new `TLSConfig` and the `Config.TLS` field.
- `cmd/jo-ei/main.go:190-211` — build the trust pool, log it, use it as the transport chain's base.
- `config.yaml`, `docs/configuration.md`, `CHANGELOG.md` — documentation.

---

## Task 1: The `upstream.Attempts` type

**Files:**
- Create: `internal/upstream/attempts.go`
- Test: `internal/upstream/attempts_test.go`

**Interfaces:**
- Consumes: nothing (first task).
- Produces, relied on by every later task:
  - `type Attempt struct { URL string; Status int; Err error; Duration time.Duration }`
  - `type Attempts []Attempt`
  - `func (a *Attempts) Add(rawURL string, status int, err error, d time.Duration)`
  - `func (a Attempts) Error() string`
  - `func (a Attempts) Unwrap() []error`
  - `func (a Attempts) AllNotFound() bool`
  - `func (a Attempts) MarshalZerologArray(arr *zerolog.Array)`
  - `func AttemptsFrom(err error) (Attempts, bool)`
  - `func SanitizeURL(raw string) string`
  - Import path: `github.com/ggwpLab/Jo-ei/internal/upstream`

- [ ] **Step 1: Write the failing tests**

Create `internal/upstream/attempts_test.go`:

```go
package upstream_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/upstream"
)

func TestAttempts_AllNotFound(t *testing.T) {
	tests := []struct {
		name     string
		statuses []int
		want     bool
	}{
		{"every mirror 404", []int{http.StatusNotFound, http.StatusNotFound}, true},
		{"404 and 410 both count as absent", []int{http.StatusNotFound, http.StatusGone}, true},
		{"a transport error is not an absence", []int{0, http.StatusNotFound}, false},
		{"a server error is not an absence", []int{http.StatusInternalServerError}, false},
		{"no attempts at all", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var atts upstream.Attempts
			for _, s := range tc.statuses {
				atts.Add("https://mirror", s, fmt.Errorf("boom"), time.Millisecond)
			}
			if got := atts.AllNotFound(); got != tc.want {
				t.Fatalf("AllNotFound() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAttempts_ErrorMentionsEveryMirror(t *testing.T) {
	var atts upstream.Attempts
	atts.Add("https://mirror-a", 0, errors.New("x509: certificate signed by unknown authority"), 11*time.Millisecond)
	atts.Add("https://mirror-b", http.StatusNotFound, errors.New("upstream returned HTTP 404"), 92*time.Millisecond)

	msg := upstream.Attempts(atts).Error()
	for _, want := range []string{"all 2 upstreams failed", "mirror-a", "x509", "mirror-b", "HTTP 404"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("Error() = %q, missing %q", msg, want)
		}
	}
}

func TestAttempts_UnwrapReachesIndividualErrors(t *testing.T) {
	sentinel := errors.New("sentinel")
	var atts upstream.Attempts
	atts.Add("https://mirror-a", 0, fmt.Errorf("dialing: %w", sentinel), time.Millisecond)
	atts.Add("https://mirror-b", http.StatusNotFound, errors.New("HTTP 404"), time.Millisecond)

	var err error = atts
	if !errors.Is(err, sentinel) {
		t.Fatal("errors.Is did not reach the wrapped sentinel through Unwrap")
	}
}

func TestAttemptsFrom_RecoversThroughWrapping(t *testing.T) {
	var atts upstream.Attempts
	atts.Add("https://mirror-a", http.StatusNotFound, errors.New("HTTP 404"), time.Millisecond)

	wrapped := fmt.Errorf("resolving manifest lib/nginx:1.25: %w", error(atts))
	got, ok := upstream.AttemptsFrom(wrapped)
	if !ok {
		t.Fatal("AttemptsFrom did not recover Attempts through a wrapping error")
	}
	if len(got) != 1 || got[0].Status != http.StatusNotFound {
		t.Fatalf("recovered %+v, want the single 404 attempt", got)
	}
	if _, ok := upstream.AttemptsFrom(errors.New("unrelated")); ok {
		t.Fatal("AttemptsFrom reported success on an unrelated error")
	}
}

func TestAttempts_MarshalZerologArray(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	var atts upstream.Attempts
	atts.Add("https://mirror-a", 0, errors.New("tls handshake failed"), 11*time.Millisecond)
	atts.Add("https://mirror-b", http.StatusNotFound, errors.New("upstream returned HTTP 404"), 92*time.Millisecond)
	logger.Warn().Array("upstream_attempts", atts).Msg("all upstreams failed")

	var entry struct {
		Attempts []struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
			Error  string `json:"error"`
			MS     int64  `json:"ms"`
		} `json:"upstream_attempts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("log line is not valid JSON: %v (%s)", err, buf.String())
	}
	if len(entry.Attempts) != 2 {
		t.Fatalf("logged %d attempts, want 2: %s", len(entry.Attempts), buf.String())
	}
	if entry.Attempts[0].Status != 0 || entry.Attempts[0].Error != "tls handshake failed" {
		t.Fatalf("first attempt = %+v, want status 0 with the TLS error", entry.Attempts[0])
	}
	if entry.Attempts[1].Status != http.StatusNotFound || entry.Attempts[1].MS != 92 {
		t.Fatalf("second attempt = %+v, want status 404 and ms 92", entry.Attempts[1])
	}
}

func TestAdd_StripsCredentialsFromURL(t *testing.T) {
	var atts upstream.Attempts
	atts.Add("https://bob:hunter2@mirror.corp/repo", http.StatusNotFound, errors.New("HTTP 404"), time.Millisecond)

	if got := atts[0].URL; got != "https://mirror.corp/repo" {
		t.Fatalf("URL = %q, want credentials stripped", got)
	}
}

func TestAttempts_EmptyErrorText(t *testing.T) {
	var atts upstream.Attempts
	if msg := atts.Error(); msg != "no upstream attempts were made" {
		t.Fatalf("Error() = %q on an empty Attempts", msg)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/upstream/ -v`
Expected: FAIL — the package does not exist (`no Go files in .../internal/upstream`).

- [ ] **Step 3: Write the implementation**

Create `internal/upstream/attempts.go`:

```go
// Package upstream records one entry per attempted upstream mirror so a fetch
// that failed across every mirror can be logged with each mirror's own error.
// Retry loops used to keep a single lastErr variable, which meant a mirror's
// TLS or DNS failure was silently replaced by the next mirror's plain 404.
package upstream

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Attempt is one mirror's outcome. Status is the upstream HTTP status, or 0
// when the request never produced a response at all (TLS verification, DNS,
// connection refused, timeout, an open circuit breaker). That distinction is
// the reason this type exists: a 0 and a 404 mean very different things to an
// operator, and collapsing them hides misconfigured mirrors.
type Attempt struct {
	URL      string
	Status   int
	Err      error
	Duration time.Duration
}

// Attempts is the ordered list of mirror outcomes for one logical fetch. It
// implements error, so a retry loop can return it directly, and
// zerolog.LogArrayMarshaler, so a log site can render every attempt as one
// structured array field.
type Attempts []Attempt

// Add appends one outcome. Credentials embedded in rawURL are stripped so they
// never reach the log.
func (a *Attempts) Add(rawURL string, status int, err error, d time.Duration) {
	*a = append(*a, Attempt{
		URL:      SanitizeURL(rawURL),
		Status:   status,
		Err:      err,
		Duration: d,
	})
}

// Error renders every attempt, so the flat message of a wrapped error still
// carries all mirrors even where the structured array is unavailable.
func (a Attempts) Error() string {
	if len(a) == 0 {
		return "no upstream attempts were made"
	}
	parts := make([]string, 0, len(a))
	for _, at := range a {
		msg := "unknown error"
		if at.Err != nil {
			msg = at.Err.Error()
		}
		parts = append(parts, at.URL+": "+msg)
	}
	return fmt.Sprintf("all %d upstreams failed: %s", len(a), strings.Join(parts, "; "))
}

// Unwrap exposes the individual errors to errors.Is / errors.As.
func (a Attempts) Unwrap() []error {
	errs := make([]error, 0, len(a))
	for _, at := range a {
		if at.Err != nil {
			errs = append(errs, at.Err)
		}
	}
	return errs
}

// AllNotFound reports whether every mirror answered 404 or 410 — the condition
// under which the proxy returns 404 rather than 502. An empty list is false:
// nothing was tried, so nothing proved the artifact absent.
func (a Attempts) AllNotFound() bool {
	if len(a) == 0 {
		return false
	}
	for _, at := range a {
		if at.Status != http.StatusNotFound && at.Status != http.StatusGone {
			return false
		}
	}
	return true
}

// MarshalZerologArray renders the attempts as an array of objects.
func (a Attempts) MarshalZerologArray(arr *zerolog.Array) {
	for _, at := range a {
		d := zerolog.Dict().
			Str("url", at.URL).
			Int("status", at.Status).
			Int64("ms", at.Duration.Milliseconds())
		if at.Err != nil {
			d = d.Str("error", at.Err.Error())
		}
		arr.Dict(d)
	}
}

// AttemptsFrom recovers the attempts from err, including when err wraps them.
// Log sites use it to attach the structured array to an error they did not
// produce themselves.
func AttemptsFrom(err error) (Attempts, bool) {
	var a Attempts
	if errors.As(err, &a) {
		return a, true
	}
	return nil, false
}

// SanitizeURL removes any userinfo component. An unparseable URL is returned
// unchanged: it came from configuration, and hiding it entirely would be worse
// than logging it verbatim.
func SanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/upstream/ -v`
Expected: PASS, all seven tests.

- [ ] **Step 5: Lint and commit**

```bash
make lint
git add internal/upstream/
git commit -m "feat(upstream): attempt list that logs every mirror's own error

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 2: Artifact download records every mirror

**Files:**
- Modify: `internal/proxy/handler.go:212-224` (call site), `internal/proxy/handler.go:514-534` (`downloadFromUpstreams`)
- Test: `internal/proxy/handler_test.go` (append)

**Interfaces:**
- Consumes: `upstream.Attempts`, `(*Attempts).Add`, `Attempts.AllNotFound` from Task 1.
- Produces: `func (h *Handler) downloadFromUpstreams(ctx context.Context, urls []string) (tmpPath string, header http.Header, atts upstream.Attempts, err error)` — on success `err` is nil and `atts` holds the mirrors that failed before the winning one; on failure `err` is `atts` itself.

- [ ] **Step 1: Write the failing tests**

Append to `internal/proxy/handler_test.go`. Note the helper: a server that is created and immediately closed yields a connection-refused error, which is a deterministic transport failure (`Status: 0`) without needing real TLS.

```go
// A mirror that cannot be reached at all and a mirror that answers 404 must
// both appear in the log. Before attempt aggregation the transport failure was
// overwritten by the 404 and vanished.
func TestHandler_LogsEveryUpstreamAttempt(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // nothing listens here any more: connection refused

	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer missing.Close()

	var logBuf bytes.Buffer
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewMavenAdapter([]string{deadURL, missing.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   newFakeCache(),
		Logger:  zerolog.New(&logBuf),
	})

	req := httptest.NewRequest(http.MethodGet, "/com/example/lib/1.0.0/lib-1.0.0.jar", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (one mirror failed at the transport layer)", rec.Code)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, `"status":0`) {
		t.Fatalf("log does not carry the transport failure (status 0): %s", logs)
	}
	if !strings.Contains(logs, `"status":404`) {
		t.Fatalf("log does not carry the 404 mirror: %s", logs)
	}
	if !strings.Contains(logs, "upstream_attempts") {
		t.Fatalf("log has no upstream_attempts array: %s", logs)
	}
}

// Regression guard on the 404-versus-502 rule: every mirror absent is a 404.
func TestHandler_AllMirrors404Yields404(t *testing.T) {
	notFound := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}))
	}
	a, b := notFound(), notFound()
	defer a.Close()
	defer b.Close()

	var logBuf bytes.Buffer
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewMavenAdapter([]string{a.URL, b.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   newFakeCache(),
		Logger:  zerolog.New(&logBuf),
	})

	req := httptest.NewRequest(http.MethodGet, "/com/example/lib/1.0.0/lib-1.0.0.jar", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when every mirror answered 404", rec.Code)
	}
	if !strings.Contains(logBuf.String(), "upstream_attempts") {
		t.Fatalf("404 path lost the attempt array: %s", logBuf.String())
	}
}
```

`newFakeCache()` and the `supplychain.NewFilter(...)` fixture are the ones the file already uses (see `TestHandler_MavenFallsBackToMirrorOnThrottle` at `internal/proxy/handler_test.go:56`). `strings`, `zerolog`, `config`, `supplychain`, and `adapters` are already imported; add `bytes`.

Maven defers its supply-chain check to the download response, so the filter never runs here — the request fails at the download stage, which is exactly what these tests exercise. Paths carry no `/maven` prefix: the mux strips it before the handler sees the request.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/proxy/ -run 'TestHandler_LogsEveryUpstreamAttempt|TestHandler_AllMirrors404Yields404' -v`
Expected: FAIL — the log contains neither `upstream_attempts` nor `"status":0`.

- [ ] **Step 3: Rewrite `downloadFromUpstreams`**

In `internal/proxy/handler.go`, replace the function at line 514:

```go
// downloadFromUpstreams tries each candidate URL in order, returning the first
// HTTP 200 with its response header. Every failed mirror is recorded in atts,
// which is also returned as the error when no mirror succeeded — so the caller
// can both log each attempt and ask atts.AllNotFound() whether the artifact was
// merely absent (404) rather than unreachable (502).
func (h *Handler) downloadFromUpstreams(ctx context.Context, urls []string) (tmpPath string, header http.Header, atts upstream.Attempts, err error) {
	for _, u := range urls {
		start := time.Now()
		path, hdr, status, derr := h.tryDownload(ctx, u)
		if derr == nil {
			return path, hdr, atts, nil
		}
		atts.Add(u, status, derr, time.Since(start))
	}
	return "", nil, atts, atts
}
```

Add `"github.com/ggwpLab/Jo-ei/internal/upstream"` to the imports.

- [ ] **Step 4: Update the call site**

In `internal/proxy/handler.go`, replace lines 212-224:

```go
	tmpPath, header, atts, err := h.downloadFromUpstreams(ctx, upstreamURLs)
	if err != nil {
		if atts.AllNotFound() {
			log.Warn().Array("upstream_attempts", atts).Msg("artifact not found on any upstream")
			record(gate.VerdictError, gate.GateSupply, "artifact_not_found", http.StatusNotFound, nil)
			h.writeError(w, requestID, ref, http.StatusNotFound, "artifact_not_found")
			return
		}
		log.Error().Err(err).Array("upstream_attempts", atts).Msg("failed to download artifact")
		record(gate.VerdictError, gate.GateSupply, "upstream_unavailable", http.StatusBadGateway, nil)
		h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_unavailable")
		return
	}
```

The `Strs("upstream_urls", upstreamURLs)` field is dropped from both lines: `upstream_attempts` carries the same URLs plus each one's outcome.

- [ ] **Step 5: Run the whole proxy package**

Run: `go test ./internal/proxy/... -v`
Expected: PASS. If a pre-existing test asserts on the old flat error text of a download failure, update its expectation to match `Attempts.Error()` (`all N upstreams failed: …`).

- [ ] **Step 6: Lint and commit**

```bash
make lint
git add internal/proxy/handler.go internal/proxy/handler_test.go
git commit -m "feat(proxy): log every mirror's error on a failed artifact download

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 3: Transparent proxy stops swallowing errors

**Files:**
- Modify: `internal/proxy/handler.go:415-483` (`proxyTransparent`)
- Test: `internal/proxy/handler_test.go` (append)

**Interfaces:**
- Consumes: `upstream.Attempts` from Task 1.
- Produces: no new exported surface; `proxyTransparent` keeps its signature.

Today this function `continue`s past both request-build and transport errors with no logging at all, so a metadata request that fails on every mirror produces a bare 502 and complete silence in the log.

- [ ] **Step 1: Write the failing test**

Append to `internal/proxy/handler_test.go`:

```go
// A transparent (non-intercepted) request that fails everywhere must leave a
// log trail. It previously produced a silent 502.
func TestHandler_TransparentProxyLogsAttempts(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer broken.Close()

	var logBuf bytes.Buffer
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewNPMAdapter([]string{deadURL, broken.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   newFakeCache(),
		Logger:  zerolog.New(&logBuf),
	})

	// A bare package document is metadata, not a tarball download, so
	// NormalizeRequest returns false and the request goes transparent.
	req := httptest.NewRequest(http.MethodGet, "/left-pad", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, `"status":0`) || !strings.Contains(logs, `"status":500`) {
		t.Fatalf("transparent proxy did not log both mirror outcomes: %s", logs)
	}
}
```

`NPMAdapter.NormalizeRequest` (`internal/proxy/adapters/npm.go:62`) recognises only tarball paths of the form `/<pkg>/-/<pkg>-<version>.tgz`, so a bare `/left-pad` takes the transparent path.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/proxy/ -run TestHandler_TransparentProxyLogsAttempts -v`
Expected: FAIL — the log is empty of attempt data.

- [ ] **Step 3: Rewrite the loop and the tail of `proxyTransparent`**

In `internal/proxy/handler.go`, replace the `allNotFound := true` declaration at line 435 with `var atts upstream.Attempts`, then replace the three failure branches and the tail:

```go
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
			for _, hop := range hopByHopHeaders {
				resp.Header.Del(hop)
			}
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
		atts.Add(url, resp.StatusCode, fmt.Errorf("upstream returned HTTP %d", resp.StatusCode), time.Since(start))
		resp.Body.Close()
	}

	if atts.AllNotFound() {
		h.cfg.Logger.Warn().Array("upstream_attempts", atts).
			Str("path", r.URL.Path).Msg("transparent proxy: not found on any upstream")
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	h.cfg.Logger.Error().Array("upstream_attempts", atts).
		Str("path", r.URL.Path).Msg("transparent proxy: no upstream available")
	http.Error(w, "upstream unavailable", http.StatusBadGateway)
```

- [ ] **Step 4: Run the proxy package**

Run: `go test ./internal/proxy/... -v`
Expected: PASS, including the existing transparent-proxy tests (status selection is unchanged: all-404 → 404, anything else → 502).

- [ ] **Step 5: Lint and commit**

```bash
make lint
git add internal/proxy/handler.go internal/proxy/handler_test.go
git commit -m "feat(proxy): log upstream attempts in the transparent proxy path

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 4: Metadata adapters record every mirror

**Files:**
- Modify: `internal/proxy/adapters/npm.go:111-162`, `internal/proxy/adapters/pypi.go:86-98` (+ its `fetchMetadataFrom`), `internal/proxy/adapters/rubygems.go:107-118` (+ its `fetchMetadataFrom` at line 119), `internal/proxy/adapters/go.go:129-169`
- Modify: `internal/proxy/handler.go:161-172` (metadata log site)
- Test: `internal/proxy/adapters/npm_test.go` (append; create if absent)

`internal/proxy/adapters/maven.go` is **not** touched: its `FetchMetadata` is a documented no-op because Maven reads the publish date from the download's `Last-Modified`.

**Interfaces:**
- Consumes: `upstream.Attempts` from Task 1, `upstream.AttemptsFrom` for the handler log site.
- Produces: each adapter's private helper gains the request URL and status in its return values:
  - `func (a *NPMAdapter) fetchMetadataFrom(ctx context.Context, base string, ref *gate.PackageRef) (meta *gate.PackageMetadata, url string, status int, err error)`
  - identical shape for `PyPIAdapter.fetchMetadataFrom` and `RubyGemsAdapter.fetchMetadataFrom`
  - `func (a *GoAdapter) fetchInfoFrom(ctx context.Context, base, encModule, encVersion string) (meta *gate.PackageMetadata, url string, status int, err error)`
  - `status` is the upstream HTTP status, or 0 when no response arrived (transport failure, request-build failure, or a body that could not be decoded before a status was seen). A decode failure after HTTP 200 reports 200.
  - The public `FetchMetadata(ctx, ref) (*gate.PackageMetadata, error)` signatures are unchanged.

- [ ] **Step 1: Write the failing test**

Append to `internal/proxy/adapters/npm_test.go` (create the file with `package adapters_test` and the imports below if it does not exist):

```go
// FetchMetadata must surface every mirror it tried, not just the last.
func TestNPMAdapter_FetchMetadataReportsEveryMirror(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer missing.Close()

	a := adapters.NewNPMAdapter([]string{deadURL, missing.URL})
	_, err := a.FetchMetadata(context.Background(), &gate.PackageRef{
		Ecosystem: "npm", Name: "left-pad", Version: "1.3.0",
	})
	if err == nil {
		t.Fatal("expected an error when every mirror fails")
	}

	atts, ok := upstream.AttemptsFrom(err)
	if !ok {
		t.Fatalf("error does not carry upstream attempts: %v", err)
	}
	if len(atts) != 2 {
		t.Fatalf("recorded %d attempts, want 2: %+v", len(atts), atts)
	}
	if atts[0].Status != 0 {
		t.Fatalf("first attempt status = %d, want 0 (unreachable mirror)", atts[0].Status)
	}
	if atts[1].Status != http.StatusNotFound {
		t.Fatalf("second attempt status = %d, want 404", atts[1].Status)
	}
}

func TestNPMAdapter_FetchMetadataWithNoUpstreams(t *testing.T) {
	a := adapters.NewNPMAdapter(nil)
	_, err := a.FetchMetadata(context.Background(), &gate.PackageRef{
		Ecosystem: "npm", Name: "left-pad", Version: "1.3.0",
	})
	if err == nil || !strings.Contains(err.Error(), "no upstreams configured for npm") {
		t.Fatalf("err = %v, want the no-upstreams message preserved", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/proxy/adapters/ -run TestNPMAdapter_FetchMetadata -v`
Expected: FAIL — `AttemptsFrom` returns false, because the adapter still returns a bare `lastErr`.

- [ ] **Step 3: Rewrite `NPMAdapter.FetchMetadata` and its helper**

In `internal/proxy/adapters/npm.go`, replace lines 111-139 (the loop and the head of the helper through the status check):

```go
// FetchMetadata walks the configured upstreams in order, returning the first
// success. When every upstream fails, the returned error is an
// upstream.Attempts carrying each mirror's own outcome.
func (a *NPMAdapter) FetchMetadata(ctx context.Context, ref *gate.PackageRef) (*gate.PackageMetadata, error) {
	if len(a.upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured for npm")
	}
	var atts upstream.Attempts
	for _, base := range a.upstreams {
		start := time.Now()
		meta, url, status, err := a.fetchMetadataFrom(ctx, base, ref)
		if err == nil {
			return meta, nil
		}
		atts.Add(url, status, err, time.Since(start))
	}
	return nil, atts
}

func (a *NPMAdapter) fetchMetadataFrom(ctx context.Context, base string, ref *gate.PackageRef) (*gate.PackageMetadata, string, int, error) {
	apiURL := base + "/" + ref.Name

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, apiURL, 0, fmt.Errorf("building npm metadata request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, apiURL, 0, fmt.Errorf("fetching npm metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apiURL, resp.StatusCode, fmt.Errorf("npm returned HTTP %d for %s", resp.StatusCode, ref.Name)
	}
```

Then update the remaining `return nil, fmt.Errorf(...)` statements in the same helper (the decode failure, the missing `Time` entry, the publish-time parse failure, and the missing versions entry — `internal/proxy/adapters/npm.go:143-156`) to `return nil, apiURL, resp.StatusCode, fmt.Errorf(...)`, and the success return to `return &gate.PackageMetadata{...}, apiURL, resp.StatusCode, nil`.

Add `"time"` and `"github.com/ggwpLab/Jo-ei/internal/upstream"` to the file's imports.

- [ ] **Step 4: Run the npm tests**

Run: `go test ./internal/proxy/adapters/ -run TestNPM -v`
Expected: PASS.

- [ ] **Step 5: Apply the identical shape to pypi**

In `internal/proxy/adapters/pypi.go`, replace `FetchMetadata` (line 86):

```go
// FetchMetadata walks the configured upstreams in order, returning the first
// success. When every upstream fails, the returned error is an
// upstream.Attempts carrying each mirror's own outcome.
func (a *PyPIAdapter) FetchMetadata(ctx context.Context, ref *gate.PackageRef) (*gate.PackageMetadata, error) {
	if len(a.upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured for pypi")
	}
	var atts upstream.Attempts
	for _, base := range a.upstreams {
		start := time.Now()
		meta, url, status, err := a.fetchMetadataFrom(ctx, base, ref)
		if err == nil {
			return meta, nil
		}
		atts.Add(url, status, err, time.Since(start))
	}
	return nil, atts
}
```

Change `fetchMetadataFrom`'s signature to `(*gate.PackageMetadata, string, int, error)`; it already builds `apiURL` on its first line (`internal/proxy/adapters/pypi.go:101`). Every `return nil, err` in it becomes `return nil, apiURL, <status>, err`, where `<status>` is `0` before a response exists and `resp.StatusCode` after. The success return gains `apiURL, resp.StatusCode`.

- [ ] **Step 6: Apply the identical shape to rubygems**

Same edit in `internal/proxy/adapters/rubygems.go`: guard on `len(a.upstreams) == 0` with the message `no upstreams configured for rubygems`, accumulate into `upstream.Attempts`, and widen `fetchMetadataFrom` (line 119) to return the URL and status.

- [ ] **Step 7: Apply the identical shape to go**

In `internal/proxy/adapters/go.go`, replace `FetchMetadata` (line 133):

```go
func (a *GoAdapter) FetchMetadata(ctx context.Context, ref *gate.PackageRef) (*gate.PackageMetadata, error) {
	if len(a.upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured for go")
	}
	encModule := encodeGoPath(ref.Name)
	encVersion := encodeGoPath(ref.Version)
	var atts upstream.Attempts
	for _, base := range a.upstreams {
		start := time.Now()
		meta, url, status, err := a.fetchInfoFrom(ctx, base, encModule, encVersion)
		if err == nil {
			return meta, nil
		}
		atts.Add(url, status, err, time.Since(start))
	}
	return nil, atts
}
```

Widen `fetchInfoFrom` (line 147) to `(*gate.PackageMetadata, string, int, error)`, returning `apiURL` (already built on its first line) and `0` / `resp.StatusCode` as appropriate — including the `has no Time` branch at line 166, which reports `resp.StatusCode`.

- [ ] **Step 8: Attach attempts to the handler's metadata log**

In `internal/proxy/handler.go`, replace lines 162-168:

```go
		meta, err := h.cfg.Adapter.FetchMetadata(ctx, ref)
		if err != nil {
			ev := log.Error().Err(err)
			if atts, ok := upstream.AttemptsFrom(err); ok {
				ev = ev.Array("upstream_attempts", atts)
			}
			ev.Msg("failed to fetch upstream metadata")
			record(gate.VerdictError, gate.GateSupply, "upstream_metadata_unavailable", http.StatusBadGateway, nil)
			h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_metadata_unavailable")
			return
		}
```

- [ ] **Step 9: Run the adapter and proxy packages**

Run: `go test ./internal/proxy/... -v`
Expected: PASS. Tests asserting the old flat metadata-error text now see `all N upstreams failed: …`; update those expectations to assert on a substring that still holds (e.g. `HTTP 404`) rather than the whole message.

- [ ] **Step 10: Lint and commit**

```bash
make lint
git add internal/proxy/adapters/ internal/proxy/handler.go
git commit -m "feat(adapters): report every mirror's error from FetchMetadata

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 5: Docker adapter records every mirror

**Files:**
- Modify: `internal/proxy/dockerproxy/adapter.go:125-145` (`ResolveDigest`), `:205-233` (`getManifest`), `:235-253` (`FetchBlob`)
- Modify: `internal/proxy/dockerproxy/handler.go:57` (gate-error log site)
- Modify: `CHANGELOG.md`
- Test: `internal/proxy/dockerproxy/adapter_test.go` (append; create if absent)

**Interfaces:**
- Consumes: `upstream.Attempts`, `upstream.AttemptsFrom` from Task 1.
- Produces: no signature changes — `ResolveDigest`, `getManifest`/`FetchManifest`, and `FetchBlob` keep their current returns; only the concrete error type behind `error` changes.

Note a latent bug this fixes: with zero upstreams configured, all three methods currently return a **nil** error alongside an empty result, so `ResolveDigest` would report success with an empty digest. Returning the (empty) `Attempts` makes the failure explicit — its `Error()` reads `no upstream attempts were made`.

- [ ] **Step 1: Write the failing test**

Append to `internal/proxy/dockerproxy/adapter_test.go`:

```go
func TestAdapter_ResolveDigestReportsEveryMirror(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer missing.Close()

	a := dockerproxy.NewAdapter([]string{deadURL, missing.URL}, nil)
	_, err := a.ResolveDigest(context.Background(), "library/nginx", "1.25")
	if err == nil {
		t.Fatal("expected an error when every mirror fails")
	}

	atts, ok := upstream.AttemptsFrom(err)
	if !ok {
		t.Fatalf("error does not carry upstream attempts: %v", err)
	}
	if len(atts) != 2 || atts[0].Status != 0 || atts[1].Status != http.StatusNotFound {
		t.Fatalf("attempts = %+v, want [status 0, status 404]", atts)
	}
}

func TestAdapter_ResolveDigestWithNoUpstreamsFails(t *testing.T) {
	a := dockerproxy.NewAdapter(nil, nil)
	if _, err := a.ResolveDigest(context.Background(), "library/nginx", "1.25"); err == nil {
		t.Fatal("zero upstreams must be an error, not an empty digest with nil error")
	}
}
```

`NewAdapter(upstreams []string, client *http.Client)` is the constructor (`internal/proxy/dockerproxy/adapter.go:38`); a nil client gives it a private one with a 120s timeout, which is fine here.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/proxy/dockerproxy/ -run TestAdapter_ResolveDigest -v`
Expected: FAIL — `AttemptsFrom` returns false; the no-upstreams case returns a nil error.

- [ ] **Step 3: Rewrite the three loops**

In `internal/proxy/dockerproxy/adapter.go`:

```go
// ResolveDigest HEADs the manifest and returns the canonical content digest.
// When no upstream yields one, the error is an upstream.Attempts carrying each
// mirror's own outcome.
func (a *Adapter) ResolveDigest(ctx context.Context, repo, ref string) (string, error) {
	path := "/v2/" + repo + "/manifests/" + ref
	var atts upstream.Attempts
	for _, base := range a.upstreams {
		start := time.Now()
		resp, err := a.do(ctx, http.MethodHead, base, path, manifestAccept)
		if err != nil {
			atts.Add(base+path, 0, err, time.Since(start))
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if dg := resp.Header.Get("Docker-Content-Digest"); dg != "" {
				return dg, nil
			}
			atts.Add(base+path, resp.StatusCode,
				fmt.Errorf("upstream omitted Docker-Content-Digest for %s/%s", repo, ref), time.Since(start))
			continue
		}
		atts.Add(base+path, resp.StatusCode,
			fmt.Errorf("HEAD manifest %s/%s: HTTP %d", repo, ref, resp.StatusCode), time.Since(start))
	}
	return "", atts
}
```

```go
// getManifest GETs a manifest by ref/digest from the first working upstream.
func (a *Adapter) getManifest(ctx context.Context, repo, ref string) ([]byte, string, string, error) {
	path := "/v2/" + repo + "/manifests/" + ref
	var atts upstream.Attempts
	for _, base := range a.upstreams {
		start := time.Now()
		resp, err := a.do(ctx, http.MethodGet, base, path, manifestAccept)
		if err != nil {
			atts.Add(base+path, 0, err, time.Since(start))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			status := resp.StatusCode
			resp.Body.Close()
			atts.Add(base+path, status,
				fmt.Errorf("GET manifest %s/%s: HTTP %d", repo, ref, status), time.Since(start))
			continue
		}
		b, rerr := io.ReadAll(resp.Body)
		dg := resp.Header.Get("Docker-Content-Digest")
		ct := resp.Header.Get("Content-Type")
		status := resp.StatusCode
		resp.Body.Close()
		if rerr != nil {
			atts.Add(base+path, status, rerr, time.Since(start))
			continue
		}
		if dg == "" {
			dg = ref
		}
		return b, ct, dg, nil
	}
	return nil, "", "", atts
}
```

```go
// FetchBlob opens a blob (config or layer) stream from the first working
// upstream. The caller must close the returned ReadCloser.
func (a *Adapter) FetchBlob(ctx context.Context, repo, digest string) (io.ReadCloser, int64, error) {
	path := "/v2/" + repo + "/blobs/" + digest
	var atts upstream.Attempts
	for _, base := range a.upstreams {
		start := time.Now()
		resp, err := a.do(ctx, http.MethodGet, base, path, "")
		if err != nil {
			atts.Add(base+path, 0, err, time.Since(start))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			status := resp.StatusCode
			resp.Body.Close()
			atts.Add(base+path, status,
				fmt.Errorf("GET blob %s/%s: HTTP %d", repo, digest, status), time.Since(start))
			continue
		}
		return resp.Body, resp.ContentLength, nil
	}
	return nil, 0, atts
}
```

Add `"time"` and `"github.com/ggwpLab/Jo-ei/internal/upstream"` to the imports.

- [ ] **Step 4: Attach attempts to the Docker gate-error log**

In `internal/proxy/dockerproxy/handler.go`, replace line 57 (`log.Error().Err(err).Msg("docker gate error")`):

```go
		ev := log.Error().Err(err)
		if atts, ok := upstream.AttemptsFrom(err); ok {
			ev = ev.Array("upstream_attempts", atts)
		}
		ev.Msg("docker gate error")
```

The gate wraps adapter errors with `%w` (`internal/proxy/dockerproxy/gate.go:136`, `:324`), so `AttemptsFrom` still finds them.

- [ ] **Step 5: Run the dockerproxy package**

Run: `go test ./internal/proxy/dockerproxy/ -v`
Expected: PASS. A test asserting the old flat text of a manifest/blob failure now sees `all N upstreams failed: …`; relax it to a substring such as `HTTP 404`.

- [ ] **Step 6: Add the CHANGELOG entry for this half**

In `CHANGELOG.md`, under `## [Unreleased]`, add:

```markdown
### Changed

- **Every upstream mirror's own error now reaches the log.** A fetch that fails
  across several mirrors used to report only the last mirror's error, so a
  mirror rejected for a TLS or DNS failure was hidden behind another mirror's
  plain 404. Artifact downloads, transparent proxying, npm/PyPI/RubyGems/Go
  metadata fetches, and Docker manifest/blob fetches now log an
  `upstream_attempts` array with each mirror's URL, HTTP status (0 for a
  transport failure), error, and duration. Response statuses are unchanged.
```

- [ ] **Step 7: Lint and commit**

```bash
make lint
git add internal/proxy/dockerproxy/ CHANGELOG.md
git commit -m "feat(docker): report every mirror's error from manifest and blob fetches

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 6: CA trust pool and transport

**Files:**
- Create: `internal/httpx/tls.go`, `internal/httpx/tls_test.go`
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go` (append)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces, relied on by Task 7:
  - `func RootPool(caFiles []string) (pool *x509.CertPool, added int, err error)` in package `httpx`
  - `func NewTransport(pool *x509.CertPool) *http.Transport` in package `httpx`
  - `type TLSConfig struct { CAFiles []string \`mapstructure:"ca_files"\` }` in package `config`
  - `Config.TLS TLSConfig` with `mapstructure:"tls"`

- [ ] **Step 1: Write the failing tests**

Create `internal/httpx/tls_test.go`:

```go
package httpx_test

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/httpx"
)

// writeCertPEM writes srv's self-signed certificate to a PEM file and returns
// its path — the same thing an operator does with a corporate CA.
func writeCertPEM(t *testing.T, der []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test-ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("writing PEM: %v", err)
	}
	return path
}

// The feature, end to end: a self-signed mirror is rejected with the system
// roots and accepted once its CA is configured.
func TestNewTransport_SelfSignedRejectedThenTrusted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	systemPool, added, err := httpx.RootPool(nil)
	if err != nil {
		t.Fatalf("RootPool(nil): %v", err)
	}
	if added != 0 {
		t.Fatalf("added = %d with no CA files, want 0", added)
	}
	untrusted := &http.Client{Transport: httpx.NewTransport(systemPool)}
	if _, err := untrusted.Get(srv.URL); err == nil {
		t.Fatal("self-signed server was accepted without its CA configured")
	} else if !strings.Contains(err.Error(), "x509") {
		t.Fatalf("expected a certificate verification error, got: %v", err)
	}

	caPath := writeCertPEM(t, srv.Certificate().Raw)
	pool, added, err := httpx.RootPool([]string{caPath})
	if err != nil {
		t.Fatalf("RootPool with the test CA: %v", err)
	}
	if added != 1 {
		t.Fatalf("added = %d, want 1", added)
	}
	trusted := &http.Client{Transport: httpx.NewTransport(pool)}
	resp, err := trusted.Get(srv.URL)
	if err != nil {
		t.Fatalf("configured CA did not make the mirror reachable: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// A custom TLSClientConfig must not silently disable HTTP/2 to upstreams.
func TestNewTransport_KeepsHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	pool, _, err := httpx.RootPool([]string{writeCertPEM(t, srv.Certificate().Raw)})
	if err != nil {
		t.Fatalf("RootPool: %v", err)
	}
	resp, err := (&http.Client{Transport: httpx.NewTransport(pool)}).Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("proto = %s, want HTTP/2.0", resp.Proto)
	}
}

func TestRootPool_RejectsBadInput(t *testing.T) {
	dir := t.TempDir()

	notPEM := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(notPEM, []byte("-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		files   []string
		wantSub string
	}{
		{"missing file", []string{filepath.Join(dir, "absent.pem")}, "reading CA file"},
		{"a private key, not a certificate", []string{notPEM}, "contains no certificates"},
		{"not PEM at all", []string{garbage}, "contains no certificates"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := httpx.RootPool(tc.files)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantSub)
			}
		})
	}
}

func TestRootPool_CountsEveryCertificateInABundle(t *testing.T) {
	a := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer a.Close()
	b := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer b.Close()

	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Certificate().Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Certificate().Raw})...,
	)
	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}

	_, added, err := httpx.RootPool([]string{path})
	if err != nil {
		t.Fatalf("RootPool: %v", err)
	}
	if added != 2 {
		t.Fatalf("added = %d, want 2 from a two-certificate bundle", added)
	}
}
```

Append to `internal/config/config_test.go`:

```go
func TestLoad_TLSCAFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `
database:
  path: ./jo-ei.db
tls:
  ca_files:
    - /etc/jo-ei/ca/corp-root.pem
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.TLS.CAFiles) != 1 || cfg.TLS.CAFiles[0] != "/etc/jo-ei/ca/corp-root.pem" {
		t.Fatalf("TLS.CAFiles = %v, want the single configured path", cfg.TLS.CAFiles)
	}
}

func TestLoad_TLSSectionIsOptional(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("database:\n  path: ./jo-ei.db\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.TLS.CAFiles) != 0 {
		t.Fatalf("TLS.CAFiles = %v, want empty when the section is absent", cfg.TLS.CAFiles)
	}
}
```

Match the minimal-valid-config shape used by the tests already in `internal/config/config_test.go` (`database.path` is required by `Validate`); copy their fixture if it differs.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/httpx/ ./internal/config/ -run 'TLS|RootPool|NewTransport' -v`
Expected: FAIL — `undefined: httpx.RootPool`, `undefined: httpx.NewTransport`, `cfg.TLS undefined`.

- [ ] **Step 3: Write `internal/httpx/tls.go`**

```go
package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
)

// RootPool returns the system root pool with every certificate from caFiles
// added, and how many certificates were added. Configured CAs supplement the
// public roots rather than replacing them, so a private mirror signed by a
// corporate CA and a public registry both verify through the same pool.
//
// Every failure is fatal to the caller by design: a CA file that cannot be read
// or parsed is a misconfiguration, and continuing with silently reduced trust
// would surface much later as an opaque x509 error on a fetch.
func RootPool(caFiles []string) (*x509.CertPool, int, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, 0, fmt.Errorf("loading system CA pool: %w", err)
	}
	added := 0
	for _, f := range caFiles {
		raw, err := os.ReadFile(f) // #nosec G304 -- the path comes from the operator's own config
		if err != nil {
			return nil, 0, fmt.Errorf("reading CA file %q: %w", f, err)
		}
		n := 0
		rest := raw
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, perr := x509.ParseCertificate(block.Bytes)
			if perr != nil {
				return nil, 0, fmt.Errorf("parsing a certificate in CA file %q: %w", f, perr)
			}
			pool.AddCert(cert)
			n++
		}
		if n == 0 {
			return nil, 0, fmt.Errorf("CA file %q contains no certificates", f)
		}
		added += n
	}
	return pool, added, nil
}

// NewTransport clones the default transport and points its root pool at the
// given one. A nil pool keeps the platform default. Cloning preserves the
// default connection pooling, proxy handling, and HTTP/2 negotiation.
func NewTransport(pool *x509.CertPool) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tr.TLSClientConfig.RootCAs = pool
	return tr
}
```

Certificates are counted by decoding the PEM blocks directly rather than by diffing `pool.Subjects()`, which is deprecated and would fail the lint gate.

- [ ] **Step 4: Add the config field**

In `internal/config/config.go`, add the field to `Config` (after `Server`, keeping the section order of the struct aligned with `config.yaml`):

```go
	TLS         TLSConfig         `mapstructure:"tls"`
```

and the type, next to the other section types:

```go
// TLSConfig configures trust for outbound connections to upstream registries.
// CAFiles lists PEM files whose certificates are added to the system root pool,
// which is what makes a mirror with a corporate or self-signed certificate
// reachable. An empty list means system roots only.
type TLSConfig struct {
	CAFiles []string `mapstructure:"ca_files"`
}
```

No `Validate` rule is added: the files are validated when they are loaded at startup (Task 7), which is where a useful error message can name the failing path.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/httpx/ ./internal/config/ -v`
Expected: PASS.

- [ ] **Step 6: Lint and commit**

```bash
make lint
git add internal/httpx/tls.go internal/httpx/tls_test.go internal/config/config.go internal/config/config_test.go
git commit -m "feat(httpx): trusted CA pool and transport for upstream TLS

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 7: Wire the trust pool into the upstream transport, and document it

**Files:**
- Modify: `cmd/jo-ei/main.go:185-211`
- Modify: `config.yaml`, `docs/configuration.md`, `CHANGELOG.md`
- Test: `cmd/jo-ei/serve_test.go` or `cmd/jo-ei/main_test.go` (append — pick whichever already exercises config-driven startup)

**Interfaces:**
- Consumes: `httpx.RootPool`, `httpx.NewTransport` (Task 6), `config.Config.TLS` (Task 6).
- Produces: no new exported surface.

- [ ] **Step 1: Write the failing test**

Append to `cmd/jo-ei/main_test.go` (package `main`, so the test can drive the real entry point `runProxy` through the package-level `cfgFile` variable that the cobra flag binds to):

```go
// A CA file that cannot be parsed must stop startup with a message naming it,
// not surface later as an opaque x509 failure on the first artifact fetch.
func TestRunProxy_FailsFastOnUnusableCAFile(t *testing.T) {
	dir := t.TempDir()
	badCA := filepath.Join(dir, "not-a-cert.pem")
	if err := os.WriteFile(badCA, []byte("definitely not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}

	slash := filepath.ToSlash
	body := "" +
		"database:\n  path: " + slash(filepath.Join(dir, "jo-ei.db")) + "\n" +
		"cache:\n  backend: local\n  local:\n    path: " + slash(filepath.Join(dir, "cache")) + "\n" +
		"tls:\n  ca_files:\n    - " + slash(badCA) + "\n"
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	old := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = old })

	err := runProxy(nil, nil)
	if err == nil {
		t.Fatal("startup succeeded with an unusable CA file")
	}
	if !strings.Contains(err.Error(), "not-a-cert.pem") {
		t.Fatalf("err = %v, want it to name the offending CA file", err)
	}
}
```

The trust pool is built before the HTTP server binds a port, so this returns rather than blocking. Every registry is disabled in this config, which keeps the wiring ahead of the CA load trivially valid.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/jo-ei/ -run TestRunProxy_FailsFastOnUnusableCAFile -v`
Expected: FAIL — startup ignores `tls.ca_files` entirely.

- [ ] **Step 3: Wire the pool into the transport chain**

In `cmd/jo-ei/main.go`, insert before the limiter construction at line 202 and change the chain's base:

```go
	// Upstream TLS trust: the system roots plus any operator-supplied CA files,
	// so mirrors with a corporate or self-signed certificate can be fetched. A
	// bad CA file stops startup here rather than becoming an x509 error on the
	// first pull.
	rootPool, addedCAs, err := httpx.RootPool(cfg.TLS.CAFiles)
	if err != nil {
		return fmt.Errorf("upstream TLS trust: %w", err)
	}
	if addedCAs > 0 {
		logger.Info().
			Int("certificates", addedCAs).
			Int("sources", len(cfg.TLS.CAFiles)).
			Msg("tls: added CA certificates to the upstream trust pool")
	}

	upstreamLimiter := httpx.NewCircuitBreaker(
		httpx.NewRateLimiter(
			httpx.NewConcurrencyLimiter(httpx.NewTransport(rootPool), maxConc),
			float64(rate), 2*rate,
		),
		upstreamRetryBaseDelay, upstreamRetryMaxDelay,
	)
```

Also update the comment block at lines 185-201 so its last line reads "…then a concurrency cap, over a transport carrying the configured CA trust pool." If `net/http` becomes unused in the file after `http.DefaultTransport` goes away, drop the import (the lint gate rejects unused imports); it is very likely still used by the `http.Client` literals on the following lines.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./cmd/jo-ei/ -v`
Expected: PASS.

- [ ] **Step 5: Document the option in `config.yaml`**

Add after the `server:` block:

```yaml
# Extra certificate authorities trusted when connecting to upstream registries.
# Use this when a mirror presents a corporate or self-signed certificate: the
# listed PEM files are added to the system root pool, so public registries keep
# working alongside it. A file that cannot be read or parsed stops startup.
# tls:
#   ca_files:
#     - /etc/jo-ei/ca/corp-root.pem
```

- [ ] **Step 6: Document the section in `docs/configuration.md`**

Insert a `## \`tls\`` section between `## \`server\`` and `## \`registries\`` (mirroring the layout of the neighbouring sections):

````markdown
## `tls`

Trust for outbound connections to upstream registries.

```yaml
tls:
  ca_files:
    - /etc/jo-ei/ca/corp-root.pem
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ca_files` | list of paths | empty | PEM files whose certificates are added to the system root pool |

The listed certificates **supplement** the system roots — they do not replace
them — so an internal mirror signed by a corporate CA and a public registry both
verify through the same pool. A bundle containing several certificates in one
file is fine; all of them are added.

Startup fails, naming the file, when a listed file cannot be read, contains no
certificate (a private key or a DER file with a `.pem` name are the usual
causes), or holds an unparseable certificate. On success the startup log reads:

```
tls: added CA certificates to the upstream trust pool certificates=1 sources=1
```

### Getting a mirror's CA certificate

```bash
openssl s_client -showcerts -connect mirror.corp:443 </dev/null \
  | openssl x509 -outform PEM > /etc/jo-ei/ca/corp-root.pem
```

Prefer the CA that signed the mirror over the mirror's own leaf certificate: a
leaf must be replaced in this file every time it is rotated.
````

- [ ] **Step 7: Add the CHANGELOG entry**

Under `## [Unreleased]`, add an `### Added` block above the `### Changed` block from Task 5:

```markdown
### Added

- **Trusted CA certificates for upstream registries** (`tls.ca_files`) — PEM
  files listed here are added to the system root pool used for every upstream
  connection, so a mirror presenting a corporate or self-signed certificate can
  be fetched without weakening verification for public registries. An unreadable
  or certificate-less file stops startup with a message naming it.
```

- [ ] **Step 8: Full test run and lint**

Run: `go test ./... && make lint`
Expected: PASS on both.

- [ ] **Step 9: Commit**

```bash
git add cmd/jo-ei/ config.yaml docs/configuration.md CHANGELOG.md
git commit -m "feat(config): tls.ca_files for upstream registry trust

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 8: End-to-end verification and pull request

**Files:** none modified — this task verifies and ships.

- [ ] **Step 1: Full suite with the race detector, as CI runs it**

Run: `make test`
Expected: PASS. (`make test` is `go test ./... -v -race`.)

- [ ] **Step 2: Lint gate**

Run: `make lint`
Expected: no findings.

- [ ] **Step 3: Confirm the executable bit and line endings survived**

Run: `git diff --stat main...HEAD`
Expected: only the files listed in this plan; no mode changes on existing scripts.

- [ ] **Step 4: Manual smoke test of the log output**

Run:

```bash
go run ./cmd/jo-ei --config config.yaml
```

with a temporary `config.yaml` whose `registries.npm.upstreams` lists one
unreachable host (`https://127.0.0.1:9`) followed by `https://registry.npmjs.org`,
then request a package that does not exist:

```bash
curl -i http://localhost:8080/npm/left-pad/-/left-pad-0.0.0-nope.tgz
```

Expected: the response is 502, and the log line carries an `upstream_attempts`
array whose first element has `"status":0` with a connection error and whose
second has `"status":404`.

- [ ] **Step 5: Push and open the pull request**

```bash
git push -u origin feat/upstream-errors-and-ca-trust
gh pr create --base main \
  --title "feat: log every upstream mirror's error, and trust configured CAs" \
  --body "$(cat <<'EOF'
## Summary

Two operational blind spots, closed.

**Every mirror's own error now reaches the log.** Upstream retry loops kept a
single `lastErr`, so a mirror rejected for a TLS or DNS failure was overwritten
by the next mirror's plain 404 and vanished. A new `internal/upstream.Attempts`
type accumulates one entry per mirror — URL (credentials stripped), HTTP status
(0 for a transport failure), error, and duration — and renders as a structured
`upstream_attempts` array. It is wired into artifact downloads, the transparent
proxy, the npm/PyPI/RubyGems/Go metadata adapters, and the Docker
manifest/blob fetches. Response statuses are unchanged.

**`tls.ca_files` adds trusted CAs for upstream registries.** The listed PEM
files are added to the system root pool that backs the shared upstream
transport, so a mirror with a corporate or self-signed certificate is reachable
without weakening verification for public registries. A file that cannot be read
or holds no certificate stops startup with a message naming it.

Also fixed along the way: with zero upstreams configured, the Docker adapter
used to return a nil error alongside an empty digest.

## Test plan

- `make test` (race detector) and `make lint` pass
- New: unit tests for `upstream.Attempts`; handler tests proving a transport
  failure and a 404 both reach the log and that all-404 still yields 404; an
  end-to-end TLS test where a self-signed `httptest` server is rejected with the
  system roots and accepted once its CA is configured; an HTTP/2 regression test
  on the cloned transport; config parsing and startup fail-fast tests

Spec: `docs/superpowers/specs/2026-08-24-upstream-errors-and-ca-trust-design.md`
Plan: `docs/superpowers/plans/2026-08-24-upstream-errors-and-ca-trust.md`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

# Docker proxy polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Trivy health probe reflect real server reachability, surface supply-chain-blocked Docker images in the Quarantine view, and document that Docker layers are scanned by every configured AV engine.

**Architecture:** Three independent changes in `internal/proxy/dockerproxy` (+ one README edit). The Trivy probe switches from a `trivy version` shell-out to an HTTP `GET /healthz`. The manifest gate carries `BlockUntil`/`PublishedAt` on supply-chain blocks and stops caching them (time-based, must re-evaluate each pull); the handler copies those onto the telemetry event so the existing quarantine query returns them.

**Tech Stack:** Go 1.26, standard `net/http`/`net/http/httptest`, zerolog, existing telemetry/health packages.

## Global Constraints

- Lint gate is **golangci-lint** (ineffassign/staticcheck/unused/…), not just `go vet`. Run `golangci-lint run ./...` before considering a task done.
- Tests live in the same package (`package dockerproxy`) and may touch unexported fields.
- Supply-chain block reason string is the literal `"package_younger_than_min_age"`; `blockedByForReason` maps it to `"supply_chain"` (default case).
- Docker block path returns **HTTP 403** for every reason (unchanged — no 423).

---

### Task 1: Trivy health probe → HTTP `/healthz`

**Files:**
- Modify: `internal/proxy/dockerproxy/trivy.go` (struct `TrivyScanner`, `NewTrivyScannerWithRunner`, `Probe`)
- Test: `internal/proxy/dockerproxy/trivy_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `TrivyScanner.Probe(ctx) error` now performs `GET <serverURL>/healthz` and returns nil only on a 2xx response. `TrivyScanner` gains an unexported `httpClient *http.Client` (defaulted in the constructor).

- [ ] **Step 1: Write the failing tests**

Add to `internal/proxy/dockerproxy/trivy_test.go`. First extend the import block to:

```go
import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)
```

Then append:

```go
func TestTrivyProbeHitsHealthz(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	s := NewTrivyScanner(srv.URL, "vuln", time.Second)
	if err := s.Probe(context.Background()); err != nil {
		t.Fatalf("Probe against healthy server: %v", err)
	}
	if gotPath != "/healthz" {
		t.Errorf("probed path = %q, want /healthz", gotPath)
	}
}

func TestTrivyProbeFailsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	s := NewTrivyScanner(srv.URL, "vuln", time.Second)
	if err := s.Probe(context.Background()); err == nil {
		t.Fatal("Probe should fail when the server returns 503")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/dockerproxy/ -run TestTrivyProbe -v`
Expected: FAIL — the current `Probe` shells out to `trivy version` (binary not present / wrong behavior), and `gotPath` is never `/healthz`.

- [ ] **Step 3: Implement the HTTP probe**

In `internal/proxy/dockerproxy/trivy.go`, extend the import block to include `io` and `net/http`:

```go
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)
```

Add the `httpClient` field to the struct (after `run commandRunner`):

```go
type TrivyScanner struct {
	serverURL  string
	scanners   string
	timeout    time.Duration
	run        commandRunner
	httpClient *http.Client

	healthMu      sync.Mutex
	healthOK      bool
	healthHasData bool
	healthLatency time.Duration
}
```

Set the default client in `NewTrivyScannerWithRunner` (the returned struct literal):

```go
	return &TrivyScanner{
		serverURL:  serverURL,
		scanners:   scanners,
		timeout:    timeout,
		run:        run,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
```

Replace the existing `Probe` method:

```go
// Probe checks Trivy server liveness via its /healthz endpoint (returns "ok"
// with HTTP 200). Unlike `trivy version`, this is a real round-trip to the
// server, so the reported status and latency reflect actual reachability.
func (s *TrivyScanner) Probe(ctx context.Context) error {
	url := strings.TrimRight(s.serverURL, "/") + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("building trivy health request: %w", err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("probing trivy server: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("trivy health check returned status %d", resp.StatusCode)
	}
	return nil
}
```

Note: `ScanImage` still uses `s.run` (the `commandRunner`); only `Probe` changes. The `os/exec` import stays.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/dockerproxy/ -run TestTrivy -v`
Expected: PASS (both new probe tests and the existing `TestTrivyScanner*` tests).

- [ ] **Step 5: Lint + commit**

```bash
golangci-lint run ./internal/proxy/dockerproxy/
git add internal/proxy/dockerproxy/trivy.go internal/proxy/dockerproxy/trivy_test.go
git commit -m "fix(dockerproxy): probe Trivy server via /healthz instead of trivy version"
```

---

### Task 2: Gate carries `BlockUntil` and stops caching supply-chain blocks

**Files:**
- Modify: `internal/proxy/dockerproxy/gate.go` (`GateVerdict` struct, supply-chain branch in `Evaluate`)
- Test: `internal/proxy/dockerproxy/gate_test.go`

**Interfaces:**
- Consumes: `proxy.FilterResult{Allowed, Reason, PublishedAt, BlockUntil}` (already returned by `g.filter.Check`).
- Produces: `GateVerdict` gains `BlockUntil time.Time`. A supply-chain block sets `Allowed=false, BlockedBy="supply_chain", PublishedAt=fr.PublishedAt, BlockUntil=fr.BlockUntil` and is **not** written to the verdict store.

- [ ] **Step 1: Write the failing test**

In `internal/proxy/dockerproxy/gate_test.go`, add `"time"` to the import block:

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)
```

Append the stub and test:

```go
// blockFilter denies every package as "younger than min age", echoing the
// published/block-until timestamps the real supply-chain filter would return.
type blockFilter struct {
	published  time.Time
	blockUntil time.Time
}

func (f blockFilter) Check(_ context.Context, _ *proxy.PackageRef, _ *proxy.PackageMetadata) proxy.FilterResult {
	return proxy.FilterResult{
		Allowed:     false,
		Reason:      "package_younger_than_min_age",
		PublishedAt: f.published,
		BlockUntil:  f.blockUntil,
	}
}

func TestGateSupplyChainBlockCarriesTimesAndIsNotCached(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t)
	published := time.Now().Add(-1 * time.Hour)
	until := time.Now().Add(23 * time.Hour)
	store := newVerdictStore(newFakeCache())
	d := gateDeps{
		adapter: NewAdapter([]string{srvURL}, nil),
		scanner: stubScanner{}, av: stubAV{},
		filter: blockFilter{published: published, blockUntil: until},
		policy: findingPolicy{},
		store:  store, logger: zerolog.Nop(),
	}
	digest, v, err := newManifestGate(d).Evaluate(context.Background(), repo, ref)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed || v.BlockedBy != "supply_chain" {
		t.Fatalf("verdict = %+v, want supply_chain block", v)
	}
	if v.BlockUntil.IsZero() || v.PublishedAt.IsZero() {
		t.Errorf("supply block must carry BlockUntil/PublishedAt, got %+v", v)
	}
	if _, _, found := store.GetImageVerdict(repo, digest); found {
		t.Error("time-based supply-chain block must NOT be cached")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/dockerproxy/ -run TestGateSupplyChainBlockCarriesTimesAndIsNotCached -v`
Expected: FAIL — `GateVerdict` has no `BlockUntil` field (compile error), and once that compiles the block is still cached / `BlockUntil` zero.

- [ ] **Step 3: Implement**

In `internal/proxy/dockerproxy/gate.go`, add `BlockUntil` to `GateVerdict` (right after `PublishedAt time.Time`):

```go
	PublishedAt time.Time
	BlockUntil  time.Time // non-zero only for supply-chain holds (drives the quarantine view)
```

Replace the supply-chain branch in `Evaluate` (currently):

```go
	// 1. Supply-chain (config.created as the publish proxy).
	fr := g.filter.Check(ctx, pkgRef, &proxy.PackageMetadata{PublishedAt: created})
	if !fr.Allowed {
		v := GateVerdict{Allowed: false, Reason: fr.Reason, BlockedBy: "supply_chain", PublishedAt: created}
		_ = g.cacheVerdict(ctx, repo, digest, manifestBody, v)
		return digest, v, nil
	}
```

with:

```go
	// 1. Supply-chain (config.created as the publish proxy).
	fr := g.filter.Check(ctx, pkgRef, &proxy.PackageMetadata{PublishedAt: created})
	if !fr.Allowed {
		// A supply-chain hold is time-based: it expires when the image matures.
		// Do NOT cache it — re-evaluate on every pull so the block lifts on its
		// own, and so each pull records a fresh block event with a current
		// block_until for the quarantine view.
		return digest, GateVerdict{
			Allowed:     false,
			Reason:      fr.Reason,
			BlockedBy:   "supply_chain",
			PublishedAt: fr.PublishedAt,
			BlockUntil:  fr.BlockUntil,
		}, nil
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/dockerproxy/ -run TestGate -v`
Expected: PASS (new test plus existing `TestGateBlocksOnCVE`, `TestGateBlocksOnMalware`, `TestGateAllowsCleanImageAndCachesVerdict`, `TestGateFailClosedOnOversizedLayer`).

- [ ] **Step 5: Lint + commit**

```bash
golangci-lint run ./internal/proxy/dockerproxy/
git add internal/proxy/dockerproxy/gate.go internal/proxy/dockerproxy/gate_test.go
git commit -m "fix(dockerproxy): carry block_until on supply-chain blocks, stop caching them"
```

---

### Task 3: Handler records `BlockUntil`/`PublishedAt` on block events

**Files:**
- Modify: `internal/proxy/dockerproxy/handler.go` (`serveManifest` block path)
- Test: `internal/proxy/dockerproxy/handler_test.go`

**Interfaces:**
- Consumes: `GateVerdict.PublishedAt` / `GateVerdict.BlockUntil` (from Task 2), `blockFilter` (from Task 2 test file).
- Produces: block telemetry events now set `ev.PublishedAt` and `ev.BlockUntil`, so `Store.Quarantine` returns supply-chain Docker holds.

- [ ] **Step 1: Write the failing test**

In `internal/proxy/dockerproxy/handler_test.go`, add `"time"` to the import block (keep the others already present). Append:

```go
func TestHandlerSupplyChainBlockRecordsBlockUntil(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t)
	adapter := NewAdapter([]string{srvURL}, nil)
	store := newVerdictStore(newFakeCache())
	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: stubScanner{}, av: stubAV{},
		filter: blockFilter{published: time.Now().Add(-time.Hour), blockUntil: time.Now().Add(23 * time.Hour)},
		policy: findingPolicy{},
		store:  store, logger: zerolog.Nop(),
	})
	rec := &recspy{}
	h := NewHandler(Config{Adapter: adapter, Gate: gate, Store: store, Recorder: rec, Logger: zerolog.Nop()})

	pull := func() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+ref, nil))
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
	}
	// Two pulls: the second must not be shadowed by a cached zero-block verdict.
	pull()
	pull()

	if len(rec.events) != 2 {
		t.Fatalf("want 2 block events, got %d: %+v", len(rec.events), rec.events)
	}
	for i, ev := range rec.events {
		if ev.Verdict != proxy.VerdictBlock || ev.Gate != proxy.GateSupply {
			t.Errorf("event %d: verdict=%q gate=%q, want block/supply", i, ev.Verdict, ev.Gate)
		}
		if ev.BlockUntil.IsZero() {
			t.Errorf("event %d: BlockUntil is zero — image will not appear in quarantine", i)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/dockerproxy/ -run TestHandlerSupplyChainBlockRecordsBlockUntil -v`
Expected: FAIL — `ev.BlockUntil` is zero because `serveManifest` does not yet copy the verdict timestamps onto the event.

- [ ] **Step 3: Implement**

In `internal/proxy/dockerproxy/handler.go`, in `serveManifest`, extend the block-path `record` modifier. Replace:

```go
		h.record(requestID, pp, proxy.VerdictBlock, gateForBlockedBy(v.BlockedBy), v.Reason, http.StatusForbidden, start, func(ev *proxy.Event) {
			ev.BlockedBy = []string{v.BlockedBy}
			ev.CVEs = v.Findings
			ev.Version = displayVer
		})
```

with:

```go
		h.record(requestID, pp, proxy.VerdictBlock, gateForBlockedBy(v.BlockedBy), v.Reason, http.StatusForbidden, start, func(ev *proxy.Event) {
			ev.BlockedBy = []string{v.BlockedBy}
			ev.CVEs = v.Findings
			ev.Version = displayVer
			// Supply-chain holds carry these; other block reasons leave them zero
			// (correct — only supply-chain blocks are quarantined).
			ev.PublishedAt = v.PublishedAt
			ev.BlockUntil = v.BlockUntil
		})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/dockerproxy/ -v`
Expected: PASS (the whole package, including the new handler test and the existing `TestHandlerManifestCVEBlocked403` etc.).

- [ ] **Step 5: Lint + commit**

```bash
golangci-lint run ./internal/proxy/dockerproxy/
git add internal/proxy/dockerproxy/handler.go internal/proxy/dockerproxy/handler_test.go
git commit -m "fix(dockerproxy): record block_until so supply-chain holds show in quarantine"
```

---

### Task 4: README — Docker layers scanned by all AV engines; Trivy probed

**Files:**
- Modify: `README.md` (Docker caveat ~`:133-135`; Scanner health ~`:239-240`)

**Interfaces:** none (documentation only).

- [ ] **Step 1: Update the Docker images caveat**

Replace (`README.md`, the "Caveats" bullet):

```
- Images are gated by both Trivy (vulnerability + secret scanning) and ClamAV
  (malware signatures). Blocking happens on the **manifest** before any layer
  data is downloaded, so a rejected image never reaches the client.
```

with:

```
- Images are gated by Trivy (vulnerability + secret scanning) and by every
  configured malware engine in `malware.scanners[]` (ClamAV and/or ICAP), which
  scan the image config blob and each layer. The verdict is returned on the
  **manifest** request, so a rejected image is never served to the client.
```

- [ ] **Step 2: Note Trivy in the Scanner health section**

Replace (`README.md`, "Scanner health"):

```
- **ClamAV / ICAP** are actively probed (clamd `PING`, ICAP `OPTIONS`) every
  `health.probe_interval_seconds` (default 30s).
```

with:

```
- **ClamAV / ICAP** are actively probed (clamd `PING`, ICAP `OPTIONS`) every
  `health.probe_interval_seconds` (default 30s).
- **Trivy** (Docker image scanner) is actively probed via its `/healthz`
  endpoint on the same interval.
```

- [ ] **Step 3: Verify the edits landed**

Run: `git diff --stat README.md` and skim `git diff README.md`.
Expected: only the two blocks above changed; no stray edits. No "ClamAV (malware signatures)"-only wording remains for Docker.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: clarify Docker layers are scanned by all AV engines; note Trivy health probe"
```

---

## Final verification (after all tasks)

- [ ] Run the full package suite: `go test ./...`
  Expected: PASS across the repo.
- [ ] Run the lint gate: `golangci-lint run ./...`
  Expected: no findings.

## Spec coverage

- Spec §1 (Trivy `/healthz` probe, `httpClient` field, httptest tests, reject `trivy version`) → **Task 1**.
- Spec §2 (`GateVerdict.BlockUntil`, populate from filter, do-not-cache decision, handler sets `ev.PublishedAt`/`ev.BlockUntil`, keep 403, two-pull no-shadow) → **Tasks 2 + 3**.
- Spec §3 (README: all AV engines scan Docker layers) → **Task 4** (plus Trivy health note).

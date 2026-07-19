# Re-check Coalescing + Offline By-digest Serving Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Coalesce concurrent identical re-checks/evaluations into one scan (packages + docker) and serve by-digest docker pulls with a cached verdict without contacting the upstream.

**Architecture:** `golang.org/x/sync/singleflight` groups on the package handler (key `ref.Key()`) and the docker manifest gate (key `repo@digest`, wrapped around the scan pipeline). The package re-check splits into a pure decision function (`runRechecks` → shared `recheckOutcome`) and per-request response mapping. `Evaluate` gains a by-digest pre-fetch verdict lookup: fresh → serve from cache (Content-Type sniffed from the stored manifest body), expired → stale fallback on `FetchManifest` failure.

**Tech Stack:** Go 1.26, golang.org/x/sync/singleflight, testify.

**Spec:** `docs/superpowers/specs/2026-07-19-recheck-coalescing-offline-digest-design.md`

## Global Constraints

- Branch: `feat/recheck-coalescing` (already created; PR into `main`).
- `golangci-lint run ./...` before pushing — CI gates on it.
- Blocking guarantee unchanged: nobody serves bytes past an expired TTL without the flight's fresh verdict (scanner-outage stale serve excepted).
- Scanner error in a flight → outcome nil / stale verdict, timestamps NOT bumped.
- Every waiter writes its own response and telemetry event (own `request_id`); the scan runs once.
- Flight bodies run on `context.WithoutCancel(ctx)` so a disconnecting leader does not kill the shared scan for followers.
- By-digest fast path: never serve with a guessed Content-Type — no top-level `mediaType` in the stored body ⇒ skip the fast path.
- Tag refs: behavior unchanged (resolution requires upstream).
- Commits: Conventional Commits, body trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: Package re-check coalescing

**Files:**
- Modify: `go.mod` / `go.sum` (add `golang.org/x/sync`)
- Modify: `internal/proxy/handler.go` (Handler struct, `recheckExpired` split)
- Test: `internal/proxy/handler_recheck_test.go` (append concurrency tests)

**Interfaces:**
- Consumes: existing `recheckExpired(ctx, w, requestID, ref, entry, record, log) bool` (handler.go:293-348), `evictRechecked`, `writeCVEBlockedResponse(w, requestID, ref, decision)`, `writeMalwareBlockedResponse(w, requestID, ref, engine, signature)`; test harness `newRecheckHarness`, `fakeCache.entries`, `makeUpstream` (handler_recheck_test.go).
- Produces: `runRechecks(ctx, ref, entry, log) *recheckOutcome`, `recheckDue(entry) bool`, `Handler.recheckGroup singleflight.Group`. Task 2 mirrors the same singleflight pattern.

- [ ] **Step 1: Add the dependency**

Run: `go get golang.org/x/sync@latest ; go mod tidy`
Expected: `golang.org/x/sync` appears in go.mod require block.

- [ ] **Step 2: Write failing concurrency tests**

Append to `internal/proxy/handler_recheck_test.go` (package `proxy_test`; reuses `newFakeCache`, `makeUpstream`, `flipCVE`, `blockOnFindings`, `eventSpy` already in this file):

```go
// gatedAV blocks every Scan until release is closed, then answers per the
// infected/scanErr flags. Lets tests hold N concurrent requests inside one
// re-check flight before letting the leader finish.
type gatedAV struct {
	infected bool
	scanErr  bool
	release  chan struct{}
	calls    atomic.Int32
}

func (s *gatedAV) Scan(context.Context, string) (*gate.AVResult, error) {
	s.calls.Add(1)
	<-s.release
	if s.scanErr {
		return nil, errors.New("clamd down")
	}
	if s.infected {
		return &gate.AVResult{Clean: false, Engine: "clamav", Signature: "EICAR"}, nil
	}
	return &gate.AVResult{Clean: true}, nil
}

// coalesceHarness is newRecheckHarness with a gated AV scanner and an
// entered-request counter for barrier synchronization.
type coalesceHarness struct {
	srv     *httptest.Server
	fc      *fakeCache
	av      *gatedAV
	rec     *eventSpy
	entered *atomic.Int32
	ref     gate.PackageRef
	path    string
}

func newCoalesceHarness(t *testing.T, infected bool) *coalesceHarness {
	t.Helper()
	upstream := makeUpstream(t, "victim", "1.0.0", 72)
	t.Cleanup(upstream.Close)

	fc := newFakeCache()
	av := &gatedAV{infected: false, release: make(chan struct{})}
	rec := &eventSpy{}
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:           adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:            supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:             fc,
		Logger:            zerolog.Nop(),
		AVScanner:         av,
		Recorder:          rec,
		MalwareRecheckTTL: time.Hour,
	})
	var entered atomic.Int32
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered.Add(1)
		h.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(wrapped)
	t.Cleanup(srv.Close)

	hs := &coalesceHarness{
		srv: srv, fc: fc, av: av, rec: rec, entered: &entered,
		ref:  gate.PackageRef{Ecosystem: "pypi", Name: "victim", Version: "1.0.0"},
		path: "/packages/py3/v/victim/victim-1.0.0-py3-none-any.whl",
	}
	// Seed pull passes with the gate open (no re-check on a fresh insert; the
	// live-path AV scan still runs, so hold the gate open just for it).
	close(av.release)
	resp, err := http.Get(srv.URL + hs.path)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed download must pass")

	// Re-arm the gate and set the verdict for the re-check phase.
	av.release = make(chan struct{})
	av.infected = infected
	av.calls.Store(0)
	entered.Store(0)

	// Expire the malware check.
	e := fc.entries[hs.ref.Key()]
	e.LastMalwareCheck = e.LastMalwareCheck.Add(-2 * time.Hour)
	return hs
}

// fire launches n concurrent GETs, waits until all have entered the handler
// (plus a settle so followers reach the flight), releases the scanner, and
// returns the status codes.
func (hs *coalesceHarness) fire(t *testing.T, n int) []int {
	t.Helper()
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := http.Get(hs.srv.URL + hs.path)
			if err != nil {
				codes[i] = -1
				return
			}
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}(i)
	}
	require.Eventually(t, func() bool { return hs.entered.Load() == int32(n) },
		5*time.Second, 5*time.Millisecond, "all requests must enter the handler")
	time.Sleep(100 * time.Millisecond) // let followers reach the flight
	close(hs.av.release)
	wg.Wait()
	return codes
}

func TestRecheckCoalesce_CleanSingleScan(t *testing.T) {
	hs := newCoalesceHarness(t, false)
	codes := hs.fire(t, 8)
	for i, c := range codes {
		assert.Equal(t, http.StatusOK, c, "request %d", i)
	}
	assert.Equal(t, int32(1), hs.av.calls.Load(), "one flight, one scan")
	_, cached := hs.fc.entries[hs.ref.Key()]
	assert.True(t, cached, "clean re-check must keep the entry")
}

func TestRecheckCoalesce_BlockSharedByAllWaiters(t *testing.T) {
	hs := newCoalesceHarness(t, true)
	codes := hs.fire(t, 8)
	for i, c := range codes {
		assert.Equal(t, http.StatusForbidden, c, "request %d", i)
	}
	assert.Equal(t, int32(1), hs.av.calls.Load(), "one flight, one scan")
	_, cached := hs.fc.entries[hs.ref.Key()]
	assert.False(t, cached, "blocked entry must be evicted")

	// Every waiter records its own BLOCK event with a distinct request_id.
	var blocks []gate.Event
	for _, ev := range hs.rec.events {
		if ev.Verdict == gate.VerdictBlock && ev.Gate == gate.GateMalware {
			blocks = append(blocks, ev)
		}
	}
	assert.Len(t, blocks, 8, "one BLOCK event per waiter")
	ids := map[string]bool{}
	for _, ev := range blocks {
		ids[ev.RequestID] = true
	}
	assert.Len(t, ids, 8, "request_ids must be distinct")
}

func TestRecheckCoalesce_ScannerErrorAllServeStale(t *testing.T) {
	hs := newCoalesceHarness(t, false)
	hs.av.scanErr = true
	before := hs.fc.entries[hs.ref.Key()].LastMalwareCheck
	codes := hs.fire(t, 8)
	for i, c := range codes {
		assert.Equal(t, http.StatusOK, c, "request %d: scanner outage must serve stale", i)
	}
	assert.Equal(t, int32(1), hs.av.calls.Load(), "one flight, one (failed) scan")
	assert.Equal(t, before, hs.fc.entries[hs.ref.Key()].LastMalwareCheck,
		"failed re-check must not bump the timestamp")
}
```

Add `"sync"` to the file's imports (`"errors"` is likely present already — check).

- [ ] **Step 3: Run tests, verify failure mode**

Run: `go test ./internal/proxy/ -race -run TestRecheckCoalesce -v`
Expected: FAIL — with the current per-request `recheckExpired`, `av.calls` is 8, not 1 (every request scans independently).

- [ ] **Step 4: Implement the split + singleflight**

`internal/proxy/handler.go`:

Imports: add `"golang.org/x/sync/singleflight"`.

`Handler` struct gains a field:

```go
// Handler is the main HTTP handler: intercepts downloads, applies SC filter, caches, proxies.
type Handler struct {
	cfg        HandlerConfig
	httpClient *http.Client
	// recheckGroup coalesces concurrent lazy re-checks of the same cache
	// entry: one flight scans, every waiter shares the outcome.
	recheckGroup singleflight.Group
}
```

Replace `recheckExpired` + keep `evictRechecked` as-is; the new shape:

```go
// recheckOutcome is the shared result of one coalesced re-check flight.
// nil means "serve from cache": every check passed, was skipped, or failed
// against an unreachable scanner (stale serve).
type recheckOutcome struct {
	gate      string              // gate.GateCVE | gate.GateMalware
	blockedBy string              // "cve" | "denylist" | "malware"
	decision  gate.PolicyDecision // CVE block details
	av        *gate.AVResult      // malware block details
}

// recheckDue reports whether any gate's TTL has lapsed for this entry. Kept
// outside the singleflight group so fresh hits pay zero coalescing overhead.
func (h *Handler) recheckDue(entry *gate.ArtifactEntry) bool {
	now := time.Now()
	if h.cfg.CVERecheckTTL > 0 && h.cfg.CVEScanner != nil && h.cfg.Policy != nil &&
		now.Sub(entry.LastCVECheck) > h.cfg.CVERecheckTTL {
		return true
	}
	if h.cfg.MalwareRecheckTTL > 0 && h.cfg.AVScanner != nil &&
		now.Sub(entry.LastMalwareCheck) > h.cfg.MalwareRecheckTTL {
		return true
	}
	return false
}

// recheckExpired lazily re-runs each gate whose TTL has lapsed for a cache
// hit. Concurrent requests for the same entry coalesce into one flight: the
// leader scans (and evicts on a block), every waiter maps the shared outcome
// to its own response and telemetry event. Returns true when the entry was
// blocked (response already written). A scanner failure inside the flight
// serves the previously clean entry to every waiter and leaves the check
// timestamps untouched, so the next hit retries.
func (h *Handler) recheckExpired(ctx context.Context, w http.ResponseWriter, requestID string, ref *gate.PackageRef, entry *gate.ArtifactEntry, record func(string, string, string, int, func(*gate.Event)), log zerolog.Logger) bool {
	if !h.recheckDue(entry) {
		return false
	}
	// WithoutCancel: the flight's scan serves every waiter — a leader whose
	// client disconnects must not cancel it for the others.
	flightCtx := context.WithoutCancel(ctx)
	v, _, _ := h.recheckGroup.Do(ref.Key(), func() (any, error) {
		return h.runRechecks(flightCtx, ref, entry, log), nil
	})
	out, _ := v.(*recheckOutcome)
	if out == nil {
		return false
	}
	switch out.gate {
	case gate.GateCVE:
		log.Warn().Str("reason", out.decision.Reason).Int("findings", len(out.decision.Findings)).
			Msg("re-check: CVE policy blocked cached package")
		record(gate.VerdictBlock, gate.GateCVE, out.decision.Reason, http.StatusForbidden, func(ev *gate.Event) {
			ev.BlockedBy = []string{out.blockedBy}
			ev.CVEs = out.decision.Findings
		})
		h.writeCVEBlockedResponse(w, requestID, ref, out.decision)
	case gate.GateMalware:
		log.Warn().Str("engine", out.av.Engine).Str("signature", out.av.Signature).
			Msg("re-check: malware detected in cached artifact")
		record(gate.VerdictBlock, gate.GateMalware, "malware_found", http.StatusForbidden, func(ev *gate.Event) {
			ev.BlockedBy = []string{"malware"}
			ev.MalwareEngine = out.av.Engine
			ev.MalwareSignature = out.av.Signature
		})
		h.writeMalwareBlockedResponse(w, requestID, ref, out.av.Engine, out.av.Signature)
	}
	return true
}

// runRechecks executes the expired-gate re-checks once per flight: CVE+policy
// against current metadata, then malware against the cached bytes (cheap
// metadata check first). Evicts on a block; bumps a gate's timestamp only on
// a passed check.
func (h *Handler) runRechecks(ctx context.Context, ref *gate.PackageRef, entry *gate.ArtifactEntry, log zerolog.Logger) *recheckOutcome {
	now := time.Now()

	if h.cfg.CVERecheckTTL > 0 && h.cfg.CVEScanner != nil && h.cfg.Policy != nil &&
		now.Sub(entry.LastCVECheck) > h.cfg.CVERecheckTTL {
		res, err := h.cfg.CVEScanner.Scan(ctx, ref)
		switch {
		case err != nil:
			log.Warn().Err(err).Msg("CVE re-check failed; serving cached artifact")
		default:
			if decision := h.cfg.Policy.Evaluate(ref, res); !decision.Allowed {
				h.evictRechecked(ref, log)
				blockedBy := "cve"
				if decision.Reason == gate.ReasonDenylisted {
					blockedBy = "denylist"
				}
				return &recheckOutcome{gate: gate.GateCVE, blockedBy: blockedBy, decision: decision}
			}
			if err := h.cfg.Cache.MarkCVEChecked(ref, now); err != nil {
				log.Warn().Err(err).Msg("marking CVE re-check")
			}
		}
	}

	if h.cfg.MalwareRecheckTTL > 0 && h.cfg.AVScanner != nil &&
		now.Sub(entry.LastMalwareCheck) > h.cfg.MalwareRecheckTTL {
		res, err := h.cfg.AVScanner.Scan(ctx, entry.ArtifactPath)
		switch {
		case err != nil:
			log.Warn().Err(err).Msg("malware re-check failed; serving cached artifact")
		case !res.Clean:
			h.evictRechecked(ref, log)
			return &recheckOutcome{gate: gate.GateMalware, blockedBy: "malware", av: res}
		default:
			if err := h.cfg.Cache.MarkMalwareChecked(ref, now); err != nil {
				log.Warn().Err(err).Msg("marking malware re-check")
			}
		}
	}
	return nil
}
```

(The two `log.Warn` block messages move from the flight into the per-request mapping so each request logs with its own `request_id` logger; the flight logs only scanner failures and mark-bump failures.)

- [ ] **Step 5: Run the new and existing tests**

Run: `go test ./internal/proxy/ -race -v`
Expected: PASS, including all pre-existing `TestRecheck_*` (semantics unchanged for the single-request case).

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/proxy/handler.go internal/proxy/handler_recheck_test.go
git commit -m "feat(proxy): coalesce concurrent lazy re-checks into one flight"
```

---

### Task 2: Docker pipeline coalescing

**Files:**
- Modify: `internal/proxy/dockerproxy/gate.go` (flights group, pipeline extraction)
- Test: `internal/proxy/dockerproxy/gate_recheck_test.go` (append)

**Interfaces:**
- Consumes: `manifestGate`/`gateDeps` (gate.go), `Evaluate` body lines ~145-228 (supply chain → Trivy → ClamAV → cacheVerdict), `staleOr`, `evictBlobs`; test helpers `newRecheckGate(t, sc, ttl, c)`, `newFakeCache`, `stubScanner`, `rewindVerdict` (gate_recheck_test.go), `newGateTestServer` (gate_test.go).
- Produces: `manifestGate.flights singleflight.Group`; `runPipeline(ctx, repo, ref, digest string, manifestBody []byte, contentType string, cascadeOnBlock bool) (GateVerdict, error)`. Task 3 leaves this intact.

- [ ] **Step 1: Write the failing concurrency test**

Append to `internal/proxy/dockerproxy/gate_recheck_test.go`:

```go
// gatedImageScanner blocks ScanImage until release is closed. Counts calls.
type gatedImageScanner struct {
	stubScanner
	release chan struct{}
	calls   atomic.Int32
}

func (s *gatedImageScanner) ScanImage(ctx context.Context, ref string) (*ImageScanResult, error) {
	s.calls.Add(1)
	<-s.release
	return s.stubScanner.ScanImage(ctx, ref)
}

func TestGateCoalesce_ParallelEvaluateSingleScan(t *testing.T) {
	c := newFakeCache()
	sc := &gatedImageScanner{release: make(chan struct{})}
	g, _, repo := newRecheckGate(t, sc, time.Hour, c)

	const n = 6
	type result struct {
		v   GateVerdict
		err error
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, v, err := g.Evaluate(context.Background(), repo, "latest")
			results[i] = result{v, err}
		}(i)
	}
	// Wait for the leader to reach the scanner, settle so followers join the
	// flight, then release.
	require.Eventually(t, func() bool { return sc.calls.Load() >= 1 },
		5*time.Second, 5*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	close(sc.release)
	wg.Wait()

	if got := sc.calls.Load(); got != 1 {
		t.Fatalf("ScanImage called %d times, want 1 (parallel evaluations must coalesce)", got)
	}
	for i, r := range results {
		if r.err != nil || !r.v.Allowed {
			t.Fatalf("result %d: v=%+v err=%v, want shared allowed verdict", i, r.v, r.err)
		}
	}
}
```

Add `"sync"` and `"sync/atomic"` to the file's imports if missing.

- [ ] **Step 2: Run, verify failure**

Run: `go test ./internal/proxy/dockerproxy/ -race -run TestGateCoalesce -v`
Expected: FAIL — `ScanImage called 6 times, want 1`.

(Note: the by-tag path re-fetches the manifest per request; the scanner-call count is the coalescing signal, not the fetch count.)

- [ ] **Step 3: Extract the pipeline and wrap it in a flight**

`internal/proxy/dockerproxy/gate.go`:

Imports: add `"golang.org/x/sync/singleflight"`.

`manifestGate` becomes:

```go
type manifestGate struct {
	gateDeps
	// flights coalesces concurrent scan pipelines for one repo@digest: N
	// parallel pulls of the same image (first pull or expired verdict) run
	// the supply-chain/Trivy/ClamAV pipeline once and share the verdict.
	flights singleflight.Group
}

func newManifestGate(d gateDeps) *manifestGate { return &manifestGate{gateDeps: d} }
```

In `Evaluate`, replace everything from the `pkgRef := …` line (~145) to the end of the clean-verdict return (~227) with:

```go
	// Coalesce the scan pipeline per digest. The leader's ref labels the
	// policy lookups for every waiter (refs for one digest differ only
	// between a tag and its digest form; docker allow/deny entries are
	// repo-level in practice). staleVerdict's presence (not its value)
	// decides the blob cascade, and all concurrent waiters observe the same
	// cached-entry state, so the leader's flag is shared safely. WithoutCancel:
	// a disconnecting leader must not cancel the flight for the others.
	flightCtx := context.WithoutCancel(ctx)
	cascadeOnBlock := staleVerdict != nil
	res, err, _ := g.flights.Do(repo+"@"+digest, func() (any, error) {
		v, perr := g.runPipeline(flightCtx, repo, ref, digest, manifestBody, contentType, cascadeOnBlock)
		if perr != nil {
			return nil, perr
		}
		return v, nil
	})
	if err != nil {
		return g.staleOr(digest, staleVerdict, err)
	}
	return digest, res.(GateVerdict), nil
}

// runPipeline is the gate's scan pipeline for one concrete image manifest:
// supply-chain check, Trivy+policy, ClamAV over config+layers, verdict store
// write. Runs once per coalesced flight. cascadeOnBlock evicts the image's
// blobs when a previously cached (now expired) verdict turns into a block.
func (g *manifestGate) runPipeline(ctx context.Context, repo, ref, digest string, manifestBody []byte, contentType string, cascadeOnBlock bool) (GateVerdict, error) {
	pkgRef := &gate.PackageRef{Ecosystem: "docker", Name: repo, Version: ref}

	// Parse manifest → config.created + config digest + layer digests.
	created, configDigest, layers, err := g.adapter.ImageConfig(ctx, repo, manifestBody)
	if err != nil {
		return GateVerdict{}, err
	}

	// 1. Supply-chain (config.created as the publish proxy).
	fr := g.filter.Check(ctx, pkgRef, &gate.PackageMetadata{PublishedAt: created})
	if !fr.Allowed {
		// A supply-chain hold is time-based: it expires when the image matures.
		// Do NOT cache it — re-evaluate on every pull so the block lifts on its
		// own, and so each pull records a fresh block event with a current
		// block_until for the quarantine view.
		return GateVerdict{
			Allowed:     false,
			Reason:      fr.Reason,
			BlockedBy:   "supply_chain",
			PublishedAt: fr.PublishedAt,
			BlockUntil:  fr.BlockUntil,
		}, nil
	}

	// 2. Trivy → policy (severity threshold + denylist).
	scan, err := g.scanner.ScanImage(ctx, g.imageRef(repo, digest))
	if err != nil {
		return GateVerdict{}, err
	}
	if g.policy != nil {
		decision := g.policy.Evaluate(pkgRef, &gate.ScanResult{
			Clean:    len(scan.Findings) == 0,
			Findings: scan.Findings,
		})
		if !decision.Allowed {
			by := "cve"
			if decision.Reason == gate.ReasonDenylisted {
				by = "denylist"
			}
			v := GateVerdict{Allowed: false, Reason: decision.Reason, BlockedBy: by, Findings: decision.Findings}
			_ = g.cacheVerdict(ctx, repo, digest, manifestBody, v)
			if cascadeOnBlock {
				g.evictBlobs(manifestBody)
			}
			return v, nil
		}
	}

	// 3. ClamAV over the config blob and each layer (fail-closed on oversize /
	// infection / error). The config blob is included so that subsequent
	// GET /v2/<repo>/blobs/<configDigest> requests are served from cache;
	// scanLayer is cache-aware, so the small double-fetch of the config is
	// acceptable.
	if g.av != nil {
		blobs := layers
		if configDigest != "" {
			blobs = append([]string{configDigest}, layers...)
		}
		for _, b := range blobs {
			infected, scanErr := g.scanLayer(ctx, repo, b)
			if scanErr != nil {
				return GateVerdict{}, scanErr
			}
			if infected {
				v := GateVerdict{Allowed: false, Reason: "malware_found", BlockedBy: "malware"}
				_ = g.cacheVerdict(ctx, repo, digest, manifestBody, v)
				if cascadeOnBlock {
					g.evictBlobs(manifestBody)
				}
				return v, nil
			}
		}
	}

	// Clean.
	v := GateVerdict{Allowed: true, Reason: "ok", PublishedAt: created, ContentType: contentType}
	if err := g.cacheVerdict(ctx, repo, digest, manifestBody, v); err != nil {
		return GateVerdict{}, err
	}
	if path, ok := g.store.GetManifestBody(repo, digest); ok {
		v.ManifestPath = path
	}
	return v, nil
}
```

The old inline pipeline body (`pkgRef` through the clean return) is deleted from `Evaluate` — it now lives in `runPipeline` verbatim, with `return g.staleOr(…)` sites replaced by plain error returns (staleOr is applied per-waiter after the flight).

- [ ] **Step 4: Run tests**

Run: `go test ./internal/proxy/dockerproxy/ -race -v`
Expected: PASS — new coalescing test plus every existing `TestGateRecheck_*` (stale-on-error still works: the flight returns the error, `Evaluate` applies `staleOr`).

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/dockerproxy/gate.go internal/proxy/dockerproxy/gate_recheck_test.go
git commit -m "feat(docker): coalesce concurrent gate evaluations per digest"
```

---

### Task 3: By-digest offline fast path

**Files:**
- Modify: `internal/proxy/dockerproxy/gate.go` (`Evaluate` head + `manifestMediaType` helper)
- Test: `internal/proxy/dockerproxy/gate_recheck_test.go` (append)

**Interfaces:**
- Consumes: `verdictStore.GetImageVerdict(repo, digest) (clean, reason string, checkedAt time.Time, found bool)`, `GetManifestBody`, `isDigestRef`, `isStaleSupplyBlock`, `blockedByForReason`, `isPassthroughReason`, `staleOr` (all existing); Task 2's flight (unchanged).
- Produces: `manifestMediaType(path string) string`.

- [ ] **Step 1: Write failing tests**

Append to `internal/proxy/dockerproxy/gate_recheck_test.go`:

```go
// deadGate builds a manifest gate over the given store whose upstream is
// unreachable, for offline-serving tests.
func deadGate(ttl time.Duration, c *fakeCache) (*manifestGate, *verdictStore) {
	adapter := NewAdapter([]string{"http://127.0.0.1:1"}, nil)
	store := newVerdictStore(c)
	g := newManifestGate(gateDeps{
		adapter: adapter, scanner: stubScanner{}, av: stubAV{},
		filter: allowFilter{}, policy: findingPolicy{},
		store: store, tags: newTagIndex(0), recheckTTL: ttl, logger: zerolog.Nop(),
	})
	return g, store
}

func TestFastPath_FreshVerdictServedWithoutUpstream(t *testing.T) {
	c := newFakeCache()
	// Seed through a live registry, then re-point at a dead upstream.
	liveG, _, repo := newRecheckGate(t, stubScanner{}, time.Hour, c)
	digest, seeded, err := liveG.Evaluate(context.Background(), repo, "latest")
	if err != nil || !seeded.Allowed {
		t.Fatalf("seed: v=%+v err=%v", seeded, err)
	}

	g, _ := deadGate(time.Hour, c)
	gotDigest, v, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil {
		t.Fatalf("fresh by-digest pull must not touch the upstream: %v", err)
	}
	if gotDigest != digest || !v.Allowed || !v.FromCache {
		t.Fatalf("digest=%s v=%+v, want cached allowed verdict for %s", gotDigest, v, digest)
	}
	if v.ManifestPath == "" || v.ContentType == "" {
		t.Fatalf("fast path must carry manifest path and sniffed content type, got %+v", v)
	}
}

func TestFastPath_FreshBlockedVerdictServes403WithoutUpstream(t *testing.T) {
	c := newFakeCache()
	g, store := deadGate(time.Hour, c)
	if err := store.PutImageVerdict("library/app", "sha256:bad", writeManifestFile(t), false, "cve_found"); err != nil {
		t.Fatal(err)
	}
	_, v, err := g.Evaluate(context.Background(), "library/app", "sha256:bad")
	if err != nil {
		t.Fatalf("blocked fast path must not touch the upstream: %v", err)
	}
	if v.Allowed || v.BlockedBy != "cve" || !v.FromCache {
		t.Fatalf("v=%+v, want cached cve block", v)
	}
}

func TestFastPath_ExpiredVerdictDeadUpstreamServesStale(t *testing.T) {
	c := newFakeCache()
	liveG, _, repo := newRecheckGate(t, stubScanner{}, time.Hour, c)
	digest, _, err := liveG.Evaluate(context.Background(), repo, "latest")
	if err != nil {
		t.Fatal(err)
	}
	rewindVerdict(c, repo, digest, 2*time.Hour)

	g, _ := deadGate(time.Hour, c)
	_, v, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil {
		t.Fatalf("expired by-digest + dead upstream must serve stale, got err %v", err)
	}
	if !v.Allowed || !v.FromCache {
		t.Fatalf("v=%+v, want stale allowed verdict", v)
	}
}

func TestFastPath_NoVerdictDeadUpstreamFailsClosed(t *testing.T) {
	c := newFakeCache()
	g, _ := deadGate(time.Hour, c)
	_, _, err := g.Evaluate(context.Background(), "library/app", "sha256:unknown")
	if err == nil {
		t.Fatal("no cached verdict + dead upstream must fail closed")
	}
}

func TestFastPath_MissingMediaTypeFallsThroughToFetch(t *testing.T) {
	c := newFakeCache()
	liveG, store, repo := newRecheckGate(t, stubScanner{}, time.Hour, c)
	digest, _, err := liveG.Evaluate(context.Background(), repo, "latest")
	if err != nil {
		t.Fatal(err)
	}
	// Overwrite the stored body with one lacking a top-level mediaType.
	p := filepath.Join(t.TempDir(), "untyped.json")
	if err := os.WriteFile(p, []byte(`{"schemaVersion":2,"config":{"digest":"sha256:cfg"},"layers":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.PutImageVerdict(repo, digest, p, true, "ok"); err != nil {
		t.Fatal(err)
	}
	// Live upstream: the fall-through fetch succeeds and still serves.
	_, v, err := liveG.Evaluate(context.Background(), repo, digest)
	if err != nil || !v.Allowed {
		t.Fatalf("v=%+v err=%v, want allowed via fetch fall-through", v, err)
	}
}
```

`writeManifestFile(t)` — if no equivalent helper exists in the package's test files (check `rg -n "func writeManifest" internal/proxy/dockerproxy/`), add:

```go
// writeManifestFile writes a minimal schema2 manifest (with mediaType) to a
// temp file and returns its path.
func writeManifestFile(t *testing.T) string {
	t.Helper()
	body := `{"schemaVersion":2,"mediaType":"` + mediaTypeSchema2Manifest + `",` +
		`"config":{"digest":"sha256:cfg"},"layers":[{"digest":"sha256:layer1"}]}`
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
```

(Verify the constant name for the schema2 media type via `rg -n "mediaTypeSchema2" internal/proxy/dockerproxy/` and use the package's actual identifier. `newRecheckGate` returns `(*manifestGate, *verdictStore, string)` — the second value is the store used above.)

Imports to add if missing: `"os"`, `"path/filepath"`.

- [ ] **Step 2: Run, verify failure**

Run: `go test ./internal/proxy/dockerproxy/ -race -run TestFastPath -v`
Expected: FAIL — `TestFastPath_FreshVerdictServedWithoutUpstream` errors with "resolving manifest … connection refused" (today every Evaluate fetches first).

- [ ] **Step 3: Implement the fast path**

`internal/proxy/dockerproxy/gate.go`. Add the helper (near `manifestBlobDigests`/`evictBlobs`):

```go
// manifestMediaType reads a stored manifest body and returns its top-level
// mediaType, or "" when the file is unreadable or the field is absent (some
// OCI manifests omit it). Callers must not serve a manifest with a guessed
// content type — "" means "fetch instead".
func manifestMediaType(path string) string {
	body, err := os.ReadFile(path) // #nosec G304 -- path comes from the verdict store, inside the cache root
	if err != nil {
		return ""
	}
	var m struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	return m.MediaType
}
```

At the top of `Evaluate`, before the `FetchManifest` call, insert:

```go
	// By-digest fast path: a digest ref IS the canonical cache key, so a
	// cached verdict can be consulted before touching the upstream at all. A
	// fresh verdict — clean or blocked — is served straight from the cache
	// (repeat pulls skip the upstream round-trip and survive registry
	// outages). An expired verdict is remembered so an unreachable upstream
	// degrades to the stale verdict instead of failing the pull. Tag refs
	// always resolve against the upstream. Supply-chain blocks are never
	// cached, so isStaleSupplyBlock entries fall through to a fresh
	// evaluation exactly as in the post-fetch check below.
	var offlineStale *GateVerdict
	if isDigestRef(ref) {
		if clean, reason, checkedAt, found := g.store.GetImageVerdict(repo, ref); found && !isStaleSupplyBlock(clean, reason) {
			v := GateVerdict{Allowed: clean, Reason: reason, Passthrough: isPassthroughReason(reason), FromCache: true}
			if !clean {
				v.BlockedBy = blockedByForReason(reason)
			} else if path, ok := g.store.GetManifestBody(repo, ref); ok {
				if ct := manifestMediaType(path); ct != "" {
					v.ManifestPath, v.ContentType = path, ct
				}
			}
			fresh := g.recheckTTL <= 0 || time.Since(checkedAt) <= g.recheckTTL
			servable := !v.Allowed || v.ManifestPath != "" // blocks need no body; serves do
			switch {
			case fresh && servable:
				return ref, v, nil
			case !fresh && servable:
				offlineStale = &v // FetchManifest failure below serves this
			}
			// fresh && !servable (body missing or untyped): fall through to
			// the fetch path — never serve with a guessed content type.
		}
	}
```

And change the `FetchManifest` error return to:

```go
	manifestBody, contentType, digest, err := g.adapter.FetchManifest(ctx, repo, ref)
	if err != nil {
		if offlineStale != nil {
			g.logger.Warn().Err(err).Str("repo", repo).Str("digest", ref).
				Msg("upstream unreachable; serving stale cached verdict for by-digest pull")
			return ref, *offlineStale, nil
		}
		return "", GateVerdict{}, fmt.Errorf("resolving manifest %s:%s: %w", repo, ref, err)
	}
```

Also update `Evaluate`'s doc comment: replace the sentence "The one exception is FetchManifest itself: an unreachable upstream registry fails closed immediately…" with:

```
// FetchManifest failures fail closed for tag refs (resolution needs the
// upstream) and for digest refs with no cached verdict; a digest ref whose
// verdict merely expired degrades to that stale verdict instead.
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/proxy/dockerproxy/ -race -v`
Expected: PASS — all `TestFastPath_*`, plus existing tests: `TestGateRecheck_FreshVerdictShortCircuits` now short-circuits via the fast path (same observable behavior — no scan), `TestGateRecheck_ExpiredVerdictReScans` and cascade/stale tests unchanged (live upstream → fetch happens → post-fetch flow as before). If `TestGateRecheck_FreshVerdictShortCircuits` asserts a fetch-count that changed, adjust only that expectation and note it in the report.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/dockerproxy/gate.go internal/proxy/dockerproxy/gate_recheck_test.go
git commit -m "feat(docker): serve by-digest pulls from cached verdicts without upstream"
```

---

### Task 4: Integration test — offline by-digest pull

**Files:**
- Modify: `integration/lazy_recheck_test.go` (append one test; reuses the file's fake registry, `switchableImageScanner`, `blockFindingsPolicy`, `switchableAV` and `cache.AsArtifactCache` helpers)

**Interfaces:**
- Consumes: `dockerproxy.New(HandlerDeps{…, RecheckTTL})`, `cache.NewLocalCache`; the existing docker test in this file (`TestLazyRecheckDockerBlocksExpiredImage`) shows the exact registry/manifest fixture pattern — mirror it.

- [ ] **Step 1: Write the test**

Append to `integration/lazy_recheck_test.go` (build tag `integration` already set at the top):

```go
// TestOfflineByDigestPullSurvivesUpstreamOutage: a by-digest repeat pull with
// a fresh cached verdict is served entirely from the cache — the upstream
// registry can be down.
func TestOfflineByDigestPullSurvivesUpstreamOutage(t *testing.T) {
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })

	// Reuse the same manifest/config fixtures as the blocking test above:
	// build the registry handler identically (copy the const digests and
	// handler literal from TestLazyRecheckDockerBlocksExpiredImage).
	registry, manifestDigestStr := newOfflineTestRegistry(t)

	h := dockerproxy.New(dockerproxy.HandlerDeps{
		Upstreams:  []string{registry.URL},
		Scanner:    &switchableImageScanner{},
		AV:         &switchableAV{},
		Filter:     supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Policy:     blockFindingsPolicy{},
		Cache:      lc,
		Logger:     zerolog.Nop(),
		RecheckTTL: time.Hour,
	})
	srv := httptest.NewServer(stripV2Prefix(h))
	t.Cleanup(srv.Close)

	// Seed pull by tag — caches the verdict + manifest body under the digest.
	resp, err := http.Get(srv.URL + "/v2/library/app/manifests/latest")
	require.NoError(t, err)
	digest := resp.Header.Get("Docker-Content-Digest")
	body1, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, manifestDigestStr, digest)

	// Kill the upstream.
	registry.Close()

	// The by-digest repeat pull must still serve, byte-identical.
	resp, err = http.Get(srv.URL + "/v2/library/app/manifests/" + digest)
	require.NoError(t, err)
	body2, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "fresh cached verdict must serve without upstream")
	require.Equal(t, body1, body2, "served manifest must be byte-identical")
	require.Equal(t, digest, resp.Header.Get("Docker-Content-Digest"))
	require.NotEmpty(t, resp.Header.Get("Content-Type"))
}
```

Refactor note (do it, not optional): the existing docker test builds its registry+manifest fixture inline. Extract that block into `newOfflineTestRegistry(t) (*httptest.Server, string)` (returns the server and the manifest digest string) and a `stripV2Prefix(h http.Handler) http.Handler` helper, and reuse both from BOTH docker tests — do not duplicate the fixture. Keep the extracted code identical to what the existing test uses today.

- [ ] **Step 2: Run**

Run: `go test -tags=integration ./integration/ -run "TestOffline|TestLazyRecheck" -v`
Expected: PASS (all — the refactored fixture must not change the existing test's behavior).

- [ ] **Step 3: Commit**

```bash
git add integration/lazy_recheck_test.go
git commit -m "test(integration): by-digest pull survives upstream outage"
```

---

### Task 5: Docs + CHANGELOG

**Files:**
- Modify: `docs/configuration.md`, `docs/superpowers/specs/2026-07-18-lazy-ttl-revalidation-design.md`, `CHANGELOG.md`

- [ ] **Step 1: configuration.md**

In the `### cache.revalidation` section, find the sentence added by the v0.2.0 fix wave stating that an unreachable upstream registry still fails the pull (locate with `rg -n "unreachable upstream" docs/configuration.md`). Replace it with:

```markdown
For Docker, scan-infrastructure outages (Trivy, ClamAV) serve the stale
verdict. An unreachable upstream registry fails **by-tag** pulls (tag
resolution needs the upstream), but **by-digest** repeat pulls are served
from the cache: a fresh cached verdict is served without contacting the
upstream at all, and an expired one degrades to the stale verdict.
```

- [ ] **Step 2: 2026-07-18 spec pointer**

In `docs/superpowers/specs/2026-07-18-lazy-ttl-revalidation-design.md`, find the "Exception: `FetchManifest` …" sentence (rg "FetchManifest") and append after it:

```markdown
    (Superseded for digest refs by
    `2026-07-19-recheck-coalescing-offline-digest-design.md`: a by-digest
    pull consults the cached verdict before the fetch and survives an
    unreachable upstream.)
```

- [ ] **Step 3: CHANGELOG.md**

Under `## [Unreleased]` (create the section heading above `## [0.2.0]` if it is absent — v0.2.0 was just cut):

```markdown
## [Unreleased]

### Added

- Docker: by-digest pulls with a cached gate verdict are served without
  contacting the upstream registry — repeat pulls are faster and survive
  registry outages (fresh verdict → straight from cache; expired verdict →
  stale fallback when the upstream is unreachable). By-tag pulls still
  require the upstream for resolution.

### Changed

- Concurrent re-checks of one expired cache entry (and concurrent Docker
  evaluations of one image digest) coalesce into a single scan whose verdict
  is shared by all waiting requests.
```

- [ ] **Step 4: Commit**

```bash
git add docs/configuration.md docs/superpowers/specs/2026-07-18-lazy-ttl-revalidation-design.md CHANGELOG.md
git commit -m "docs: offline by-digest serving and re-check coalescing"
```

---

### Task 6: Final verification

- [ ] **Step 1: Full suites**

Run: `go build ./... ; go test -race ./... ; go test -tags=integration ./integration/`
Expected: PASS everywhere (race detector on — the new singleflight paths must be race-clean).

- [ ] **Step 2: Lint + fmt**

Run: `golangci-lint run ./... ; gofmt -l .`
Expected: 0 issues, no files listed.

- [ ] **Step 3: Push, PR**

PR into `main` titled `feat: re-check coalescing + offline by-digest serving`; body links the spec; end with the 🤖 Generated with [Claude Code](https://claude.com/claude-code) footer.

# Console Cache Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the always-zero cache eviction counter, replace stale "since start" console labels with "total", and add a 30-day hit-rate sparkline plus eviction-headroom meter to the LOCAL CACHE card.

**Architecture:** One Go change (an atomic eviction counter inside `LocalCache`, surfaced through the existing `Stats()`/`/api/overview` path — API shape unchanged) and two JSX label/markup changes. The sparkline reuses the global `Spark` component and the already-fetched `JOEI.daily` array; the hatched headroom segment reuses the existing `.cache-meter > i.evict` CSS class. The console bundle is a generated, committed artifact regenerated with `go generate ./...`.

**Tech Stack:** Go 1.x (stdlib `sync/atomic`, testify), React JSX compiled by esbuild via `go generate`, SQLite-backed telemetry (untouched).

**Spec:** `docs/superpowers/specs/2026-07-12-console-cache-cleanup-design.md`

## Global Constraints

- Work on branch `feat/console-cache-cleanup`; PR into `main`. Never commit to `main` directly.
- Replacement wording is exactly **"total"** (e.g. `Requests · total`); the eviction counter caption is exactly **"since restart"**.
- Sparkline caption is exactly **"hit rate · 30d"** (per-day data; do not claim 24h granularity).
- No backend API-shape changes, no schema migrations, no new endpoints, no new CSS color tokens.
- `web/console/app.bundle.js` is generated and committed; CI fails if stale. After any `web/console/src/*` edit, run `go generate ./...` and commit the regenerated bundle in the same commit.
- Run `golangci-lint run` before pushing (CI gate includes ineffassign/staticcheck/unused).
- Commit messages end with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: Eviction counter in LocalCache

**Files:**
- Modify: `internal/cache/local.go` (struct at ~line 23, `Stats()` at ~line 137, `evictToSize` at ~line 167)
- Test: `internal/cache/local_internal_test.go`

**Interfaces:**
- Consumes: existing `LocalCache.Invalidate(*gate.PackageRef) error`, `Index.Count()`.
- Produces: `LocalCache.Stats()` now returns `CacheStats{..., Evictions: N}` where N = entries actually evicted by `evictToSize` since process start. `internal/console/server.go:171` already forwards `cs.Evictions` — no console change needed.

- [ ] **Step 1: Write the failing test**

Add to `internal/cache/local_internal_test.go` (after `TestLocalCache_EvictToSizeRemovesEntries`):

```go
func TestLocalCache_EvictionsAreCounted(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	for _, n := range []string{"a", "b", "c"} {
		ref := &gate.PackageRef{Ecosystem: "pypi", Name: n, Version: "1.0"}
		require.NoError(t, lc.Put(ref, writeTemp(t, "data-"+n), true, ""))
	}
	before, err := lc.index.Count()
	require.NoError(t, err)

	lc.evictToSize(1)

	after, err := lc.index.Count()
	require.NoError(t, err)
	evicted := before - after
	require.Positive(t, evicted, "eviction must have removed entries")

	stats, err := lc.Stats()
	require.NoError(t, err)
	assert.Equal(t, evicted, stats.Evictions)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache/ -run TestLocalCache_EvictionsAreCounted -v`
Expected: FAIL — `stats.Evictions` is 0, `evicted` is ≥ 1.

- [ ] **Step 3: Implement the counter**

In `internal/cache/local.go`:

Add `"sync/atomic"` to imports.

Add the field to the struct (after `evictCh`):

```go
// LocalCache implements Cache using the local filesystem with a SQLite index.
type LocalCache struct {
	cfg       LocalCacheConfig
	index     *Index
	evictCh   chan struct{}
	evictions atomic.Int64 // entries evicted by evictToSize since process start
	workerWG  sync.WaitGroup
	closeOnce sync.Once
}
```

In `evictToSize`, count each successful invalidation (replace the candidate loop body):

```go
		for _, ref := range candidates {
			r := ref
			if lc.Invalidate(&r) == nil {
				lc.evictions.Add(1)
			}
		}
```

In `Stats()`, return the counter:

```go
	return CacheStats{Entries: count, SizeBytes: size, Evictions: lc.evictions.Load()}, nil
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cache/ -v`
Expected: all cache tests PASS, including `TestLocalCache_EvictionsAreCounted`.

- [ ] **Step 5: Run the full Go test suite**

Run: `go test ./...`
Expected: PASS (console/server tests use a `fakeStats` stub — unaffected).

- [ ] **Step 6: Commit**

```bash
git add internal/cache/local.go internal/cache/local_internal_test.go
git commit -m "fix(cache): count LRU evictions in LocalCache stats

Stats() always reported Evictions: 0 because nothing incremented it.
Track successful evictToSize invalidations in an atomic counter.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Overview labels — "since start" → "total"

**Files:**
- Modify: `web/console/src/overview.jsx:50,70,74,76`
- Modify (generated): `web/console/app.bundle.js`

**Interfaces:**
- Consumes: nothing new.
- Produces: label copy only; no props or data-shape changes.

- [ ] **Step 1: Edit the four labels**

In `web/console/src/overview.jsx`:

Line 50 — eyebrow:

```jsx
          <div className="eyebrow">Totals · uptime {uptime}</div>
```

Line 70 — requests card:

```jsx
        <KpiCard label="Requests · total" value={fmtCompact(k.requests_total)}
```

Line 74 — cache-hits delta:

```jsx
          delta={<><b>{fmtCompact(k.cache_hits)}</b> hits total</>} watermark="蔵"
```

Line 76 — blocked card:

```jsx
        <KpiCard label="Blocked · total" value={fmtNum(k.blocked_total)} accent="verm"
```

- [ ] **Step 2: Regenerate the bundle**

Run: `go generate ./...`
Expected: `web/console/app.bundle.js` modified (check with `git status`).

- [ ] **Step 3: Verify no stale-label leftovers in overview**

Run: `grep -in "since start" web/console/src/overview.jsx`
Expected: no matches.

- [ ] **Step 4: Run web asset tests**

Run: `go test ./web/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/console/src/overview.jsx web/console/app.bundle.js
git commit -m "fix(console): label lifetime counters 'total', not 'since start'

Counters persist in SQLite and survive restarts; 'since start' was
stale wording from the in-memory telemetry era.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Cache card — labels, hit-rate sparkline, eviction headroom

**Files:**
- Modify: `web/console/src/registries.jsx:135-154` (the `{/* cache panel */}` block inside `Registries`)
- Modify (generated): `web/console/app.bundle.js`

**Interfaces:**
- Consumes: global `Spark({ data, color, h, w })` from `web/console/src/shared.jsx:126` (breaks on < 2 points — guard required); `JOEI.daily` — chronological per-day rows `{ day, requests, cache_hits, ... }`, ≤ 30 entries, already fetched in `api.js` (empty when persistence is off); existing CSS `.cache-meter > i.used` and `.cache-meter > i.evict` (hatched) in `web/console/screens.css:392-395`.
- Produces: presentation only.

- [ ] **Step 1: Build the hit-rate series**

In `web/console/src/registries.jsx`, inside `Registries` after `const usedPct = ...` (line 65), add:

```jsx
  // Per-day request-level hit rate, same series the Overview uses. Spark
  // breaks on <2 points, so pass undefined and render number-only below.
  const hitSpark = JOEI.daily.length >= 2
    ? JOEI.daily.map((r) => (r.requests ? r.cache_hits / r.requests : 0))
    : undefined;
```

- [ ] **Step 2: Replace the cache panel block**

Replace the whole `{/* cache panel */}` card (lines 136–154) with:

```jsx
      {/* cache panel */}
      <div className="card" style={{ padding: 22, marginBottom: 22 }}>
        <div className="row" style={{ alignItems: "flex-end", marginBottom: 16 }}>
          <div>
            <div className="eyebrow" style={{ fontSize: 11, letterSpacing: ".18em", color: "var(--washi-mut)" }}>LOCAL CACHE</div>
            <div className="row" style={{ alignItems: "baseline", gap: 8, marginTop: 4 }}>
              <span className="mono" style={{ fontSize: 28, fontWeight: 600, color: "var(--jade-l)" }}>{c.used_gb}</span>
              <span className="muted mono">/ {c.max_gb} GB used</span>
            </div>
          </div>
          {hitSpark && (
            <div className="right" style={{ width: 200 }}>
              <div className="muted" style={{ fontSize: 11, textAlign: "right", marginBottom: 4 }}>hit rate · 30d</div>
              <Spark data={hitSpark} color="var(--jade)" h={36} w={200} />
            </div>
          )}
        </div>
        <div className="cache-meter">
          <i className="used" style={{ width: usedPct + "%" }}></i>
          <i className="evict" style={{ width: (100 - usedPct) + "%" }}></i>
        </div>
        <div className="row" style={{ marginTop: 12, gap: 28, fontSize: 12.5 }}>
          <span className="muted">Objects <b className="mono" style={{ color: "var(--washi)" }}>{c.objects}</b></span>
          <span className="muted">Hit rate · total <b className="mono" style={{ color: "var(--jade-l)" }}>{(c.hit_rate * 100).toFixed(1)}%</b></span>
          <span className="muted">LRU evictions · since restart <b className="mono" style={{ color: "var(--gold-l)" }}>{fmtNum(c.evictions)}</b></span>
          <span className="muted right" style={{ fontSize: 11 }}>⟍ eviction headroom</span>
        </div>
      </div>
```

Changes vs. current code: right-aligned sparkline block in the header row (rendered only when `hitSpark` exists); hatched `i.evict` segment filling the meter remainder; `Hit rate · total`; `LRU evictions · since restart`; `⟍ eviction headroom` caption right-aligned on the stats row.

- [ ] **Step 3: Regenerate the bundle**

Run: `go generate ./...`
Expected: `web/console/app.bundle.js` modified.

- [ ] **Step 4: Verify no stale labels remain anywhere in src**

Run: `grep -rin "since start" web/console/src/`
Expected: no matches.

- [ ] **Step 5: Run web asset tests**

Run: `go test ./web/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add web/console/src/registries.jsx web/console/app.bundle.js
git commit -m "feat(console): hit-rate sparkline and eviction headroom on cache card

30-day per-day hit rate from the existing daily metrics, rendered with
the shared Spark component; meter remainder hatched as eviction
headroom. Eviction count captioned 'since restart' (process-lifetime).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Changelog + final verification

**Files:**
- Modify: `CHANGELOG.md:8` (`[Unreleased]` section)

**Interfaces:**
- Consumes: nothing.
- Produces: release notes source (`release-notes.sh` builds notes from this file).

- [ ] **Step 1: Add Unreleased entries**

Replace `## [Unreleased]` (line 8) with:

```markdown
## [Unreleased]

### Changed

- Console: lifetime counters are labeled "total" instead of "since start" —
  they persist in SQLite and survive restarts.
- Console: the local-cache card shows a 30-day hit-rate sparkline and an
  eviction-headroom treatment on the usage meter.

### Fixed

- Cache: LRU evictions are now counted and reported; the console previously
  always showed 0 evictions.
```

- [ ] **Step 2: Run the full test suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 3: Run the linter**

Run: `golangci-lint run`
Expected: no issues.

- [ ] **Step 4: Verify the committed bundle is fresh**

Run: `go generate ./... ; git diff --exit-code -- web/console/app.bundle.js`
Expected: exit 0, no diff (mirrors the CI staleness check).

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: changelog entries for console cache cleanup

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Manual verification (after all tasks)

JS has no unit harness; verify by running the proxy with the console enabled:

1. Overview: eyebrow reads `Totals · uptime …`; cards read `Requests · total`, `… hits total`, `Blocked · total`.
2. Registries: cache card shows `hit rate · 30d` sparkline top-right (requires ≥ 2 days of history in `daily_metrics`; with < 2 the header renders number-only), hatched meter remainder with `⟍ eviction headroom` caption, `Hit rate · total`, `LRU evictions · since restart`.
3. With `database.path` unset: sparkline absent, no console errors.

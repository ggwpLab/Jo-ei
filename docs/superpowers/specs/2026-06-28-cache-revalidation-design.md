# Cache Re-validation — Design

**Date:** 2026-06-28
**Status:** Approved
**Stage:** Production-readiness

## Problem

The original SCA-proxy spec (`2026-05-30-sca-proxy-design.md`) assumed cached
artifacts would be **periodically re-checked against all gates and evicted when a
check now fails**. That function does not exist. Today a cached artifact is
trusted until its TTL expires (default 24h) or it is LRU-evicted. Between caching
and expiry, the world changes:

- **osv.dev** publishes a new CVE for an already-cached package version.
- **ClamAV** signature database updates and would now flag a cached artifact.
- An operator adds a package to the **denylist** in policy.

In all three cases the proxy keeps serving the cached "clean" artifact until TTL.
There is no proactive mechanism to re-run the gates over what is already cached
and purge anything that has since become disallowed.

## Goal

A background worker that periodically re-runs the applicable checks over cached
entries and **evicts** any entry that now produces a definitive block verdict,
recording a telemetry event so the eviction is visible in the console.

Non-goals: changing the on-request gate pipeline; changing TTL/LRU eviction
(orthogonal — TTL remains the absolute lifetime cap); re-running the supply-chain
time rule (a cached entry has already matured; denylist changes are caught by the
policy step).

## Decisions (from brainstorming)

1. **Trigger:** background timer sweep (not lazy-on-access).
2. **Scope:** one unified mechanism with per-ecosystem revalidators, including
   Docker.
3. **Eviction policy:** evict **only** on a definitive non-clean verdict. A
   scanner that cannot complete (clamd timeout, osv.dev 5xx) leaves the entry in
   place to be retried on the next sweep — a transient outage must not wipe the
   cache.
4. **Cadence:** per-entry, driven by a new `last_validated` timestamp. Each tick
   processes only entries due for re-validation, in a bounded batch.

## Architecture

The cache package (`internal/cache`) must not depend on the scanners. A new
package **`internal/revalidate`** imports both `cache` and
`proxy`/`dockerproxy` and is wired in `cmd/jo-ei/main.go` alongside the existing
`health.Monitor`.

```
revalidate.Sweeper
  ├─ store         RevalidationStore          (satisfied by *cache.LocalCache)
  ├─ revalidators  map[string]Revalidator     (keyed by ecosystem)
  ├─ recorder      proxy.Recorder             (eviction telemetry)
  ├─ cfg           Config                     (interval, revalidateAfter, batch)
  └─ logger        zerolog.Logger
```

### Revalidator contract

```go
// Outcome is the per-entry decision a Revalidator returns.
type Outcome int

const (
    Keep   Outcome = iota // still clean → bump last_validated
    Evict                 // definitive non-clean verdict → remove + record event
    Retry                 // could not check (scanner down) → leave untouched
)

// RevalEntry is a cached entry presented for re-validation. It is defined in the
// cache package (which already imports proxy) and returned by
// DueForRevalidation; revalidate imports cache, so there is no import cycle.
type RevalEntry struct {
    Ref       proxy.PackageRef // ecosystem/name/version/classifier
    FilePath  string           // cached artifact bytes on disk
    ScanClean bool             // last recorded verdict
    ScanJSON  string           // serialized prior ScanResult
}

// EvictReason carries why an entry was evicted, for telemetry.
type EvictReason struct {
    Gate      string // proxy.GateCVE | GateMalware | GateImageScan | GateSupply
    Reason    string // "cve_found" | "malware_found" | "denylisted" | ...
    BlockedBy string // "cve" | "malware" | "denylist" | "supply_chain"
    Engine    string // malware engine, when applicable
    Signature string // malware signature, when applicable
    Findings  []proxy.CVEFinding
}

type Revalidator interface {
    // Revalidate re-runs the applicable checks for one cached entry.
    // On Evict, the returned EvictReason is non-nil.
    Revalidate(ctx context.Context, e cache.RevalEntry) (Outcome, *EvictReason)
}
```

(`RevalEntry` is shown above for field reference; it lives in `cache` — see
Storage changes.)

The sweeper dispatches each entry to `revalidators[e.Ref.Ecosystem]`. An entry
whose ecosystem has no registered revalidator is left untouched (and its
`last_validated` is **not** bumped, so it is not repeatedly re-queried — see
Sweeper). Docker registers under `"docker"`; the package ecosystems
(`pypi`/`npm`/`maven`/`rubygems`) share one `packageRevalidator`.

### packageRevalidator

Holds the same `proxy.CVEScanner`, `proxy.PolicyDecider`, and `proxy.AVScanner`
the live handler uses. For an entry:

1. **CVE + policy:** `CVEScanner.Scan(ctx, &e.Ref)` → `Policy.Evaluate(&e.Ref,
   result)`. A blocked decision (`cve_found` or `denylisted`) → `Evict`. A
   scanner error → `Retry`.
2. **Malware:** `AVScanner.Scan(ctx, e.FilePath)`. Infected → `Evict`. A scanner
   error (e.g. clamd timeout) → `Retry`.
3. Otherwise → `Keep`.

CVE/policy run before malware so a cheap metadata check short-circuits before the
byte re-scan. If the cached file is missing on disk, that is not a security
failure — return `Keep` and let the cache's own `os.Stat` miss handle it on next
access. (The CVE/policy step still runs first regardless.)

The supply-chain time rule is intentionally not re-run: a cached entry has
already matured past it; denylist changes are caught by the policy step above.

### dockerRevalidator

Holds the existing `*dockerproxy.manifestGate` (or a thin wrapper exposing
re-evaluation) and the store.

- **Image-verdict entries** (`Ref.Name` is the repo, `Ref.Version` is the
  digest): re-run `manifestGate.Evaluate(ctx, repo, digest)` — the same
  supply-chain + Trivy + ClamAV pipeline. A blocked verdict → `Evict`, and the
  layer/config blob entries for that image are also invalidated (their digests
  are read from the cached manifest body). A gate infrastructure error →
  `Retry`.
- **Standalone blob entries** (`Ref.Name == "blobs"`): `Keep` without work — a
  blob is owned by its image and is re-validated transitively through the image
  verdict (and cascaded on eviction). This avoids double-scanning every layer.

Distinguishing the two is by `Ref.Name`: `"blobs"` vs anything else (the repo).

## Storage changes (`internal/cache`)

Add a re-validation timestamp and the query/update methods.

- **Schema:** new column `last_validated INTEGER NOT NULL DEFAULT 0` on
  `artifacts`. A migration (mirroring `migrateClassifier`) adds the column and
  backfills `last_validated = stored_at` for existing rows. `Insert` sets
  `last_validated = stored_at` (a freshly cached entry was just validated).
- **`DueForRevalidation(before int64, limit int) ([]RevalEntry, error)`:**
  returns up to `limit` entries with `last_validated < before`, ordered
  `last_validated ASC` (oldest first), carrying
  ecosystem/name/version/classifier/file_path/scan_clean/scan_json. Expired
  entries (`expires_at` past) are excluded — they will be dropped on access
  anyway.
- **`MarkValidated(ref *proxy.PackageRef, ts int64) error`:** sets
  `last_validated = ts` for the row.
- `Invalidate(ref)` already exists (removes index row + artifact file).

`RevalEntry` (fields above) is defined in the `cache` package. These methods are
added to `*cache.LocalCache`. The `revalidate` package declares a narrow
interface it depends on (satisfied by `*cache.LocalCache`):

```go
type RevalidationStore interface {
    DueForRevalidation(before int64, limit int) ([]cache.RevalEntry, error)
    MarkValidated(ref *proxy.PackageRef, ts int64) error
    Invalidate(ref *proxy.PackageRef) error
}
```

`revalidate` imports `cache`, and `cache` imports `proxy`, so there is no cycle.

## Sweeper loop

```
NewSweeper(store, revalidators, recorder, cfg, logger)
Start():  if !cfg.Enabled return
          go loop()
loop():   ticker every cfg.Interval
          on each tick: sweepOnce()
          on ctx cancel: return
sweepOnce():
    cutoff = now - cfg.RevalidateAfter
    entries = store.DueForRevalidation(cutoff, cfg.BatchSize)
    for e in entries:
        outcome, reason = revalidators[e.Ref.Ecosystem].Revalidate(ctx, e)
        switch outcome:
          Keep:  store.MarkValidated(e.Ref, now)
          Evict: store.Invalidate(e.Ref); recordEviction(e, reason)
          Retry: // leave as-is; re-queried next tick
```

- **Sequential** processing within a tick — natural rate-limiting, and malware
  scans are already globally capped by `LimitedScanner`
  (`[[av-scan-concurrency-limit]]`).
- **Bounded batch** (`cfg.BatchSize`) keeps each tick's load predictable on large
  caches; remaining due entries are picked up on subsequent ticks.
- Entries with no registered revalidator are skipped without bumping
  `last_validated` (cheap to skip; avoids hiding them if a revalidator is added
  later).
- **Graceful shutdown:** `context` + `sync.WaitGroup`, `Close()` cancels and
  waits — same pattern as `health.Monitor` and the cache `evictWorker`.

## Telemetry

On eviction the sweeper records:

```go
proxy.Event{
    RequestID: "revalidation",
    Time:      time.Now(),
    Ecosystem: e.Ref.Ecosystem,
    Package:   e.Ref.Name,
    Version:   e.Ref.Version,
    Verdict:   proxy.VerdictBlock,
    Gate:      reason.Gate,
    Reason:    reason.Reason,
    BlockedBy: []string{reason.BlockedBy},
    // CVEs / MalwareEngine / MalwareSignature filled from reason
}
```

This surfaces re-validation evictions in the console feed (and quarantine view
for supply-chain reasons) using the existing event schema — no console changes
required. The `RequestID: "revalidation"` marks the source.

## Configuration

```yaml
cache:
  revalidation:
    enabled: true
    interval_minutes: 60         # how often the sweep ticks
    revalidate_after_hours: 24   # an entry is due when now - last_validated > this
    batch_size: 50               # max entries processed per tick
```

`config.CacheConfig` gains a `Revalidation` sub-struct. Validation: non-negative
values; zero `interval_minutes` / `revalidate_after_hours` / `batch_size` fall
back to defaults (60 min / 24 h / 50) applied at wiring time. `enabled: false`
(or the section omitted) disables the sweeper entirely — `Start()` is a no-op.

## Error handling

| Situation | Outcome |
|-----------|---------|
| CVE scan returns a finding above threshold / denylisted | `Evict` (gate cve/denylist) |
| Malware scan reports infected | `Evict` (gate malware) |
| Docker gate re-eval blocks | `Evict` + cascade blob invalidation |
| Scanner unreachable / error (clamd timeout, osv 5xx, gate infra error) | `Retry` — entry kept, `last_validated` unchanged |
| Cached file missing on disk | `Keep` (cache drops it on next access) |
| No revalidator for ecosystem | skip, do not bump `last_validated` |

## Testing

- **packageRevalidator** (unit, fake scanners): clean→`Keep`; infected→`Evict`
  (malware); CVE finding→`Evict` (cve); denylisted→`Evict`; scanner error→`Retry`;
  CVE-error short-circuits before malware.
- **dockerRevalidator** (unit, stub gate): clean image→`Keep`; blocked image→
  `Evict` + blob entries invalidated; blob entry→`Keep` no-op; gate error→`Retry`.
- **Index** (unit, real SQLite): migration adds column + backfills
  `last_validated = stored_at`; `DueForRevalidation` returns only due, oldest-first,
  respects limit, excludes expired; `MarkValidated` updates the row.
- **Sweeper** (unit, fake store + revalidators): `Keep` bumps `last_validated`;
  `Evict` invalidates + records one event with correct gate/reason; `Retry`
  leaves entry and does not bump; batch size respected; disabled → no-op.
- **Integration** (`-tags=integration`): cache a clean artifact, swap the
  AV scanner for an infected stub, run one sweep, assert the entry is gone and a
  BLOCK/malware event was recorded.

## Files touched

- `internal/cache/index.go` — `last_validated` column + migration, `DueForRevalidation`, `MarkValidated`
- `internal/cache/local.go` — expose the new methods on `LocalCache`
- `internal/revalidate/` — new package: `Sweeper`, `Revalidator`, `packageRevalidator`, `dockerRevalidator`, `Config`
- `internal/config/config.go` — `CacheConfig.Revalidation` + validation
- `cmd/jo-ei/main.go` — build revalidators, wire and `Start()`/`Close()` the sweeper
- `config.yaml` — documented `cache.revalidation` block
- tests alongside each

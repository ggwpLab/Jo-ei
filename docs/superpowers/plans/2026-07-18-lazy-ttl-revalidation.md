# Lazy TTL Re-validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the timer-based revalidation sweep with lazy per-gate TTL re-checks on the cache-hit serve path (packages + Docker), evicting entries that now fail.

**Architecture:** Two per-gate check timestamps (`last_cve_check`, `last_malware_check`) replace `last_validated` in the cache index. The package handler re-runs only the expired gate on a cache hit; the Docker manifest gate re-runs the full pipeline when its cached verdict is older than min(enabled TTLs). Scanner outages serve the stale (previously clean) entry. `internal/revalidate` is deleted.

**Tech Stack:** Go 1.26, modernc.org/sqlite, viper, zerolog, testify.

**Spec:** `docs/superpowers/specs/2026-07-18-lazy-ttl-revalidation-design.md`

## Global Constraints

- Branch: `feat/lazy-ttl-revalidation` (already created; PR into `main`).
- Run `golangci-lint run ./...` before pushing — CI gates on it (ineffassign, staticcheck, unused, …).
- Windows dev box: use `go test ./...` (PowerShell), forward slashes in Go code only.
- Config defaults: `cve_ttl_minutes` 1440, `malware_ttl_minutes` 1440, explicit `0` disables that re-check, negative = validation error.
- Telemetry events from lazy re-checks use the live request's `request_id` — never the synthetic `"revalidation"`.
- Scanner error during re-check → serve stale, do NOT bump the check timestamp.
- Commit messages: Conventional Commits, end body with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: Remove the sweep + new config keys

Deletes the sweep end-to-end and lands the new `RevalidationConfig` so every later task builds green.

**Files:**
- Delete: `internal/revalidate/` (revalidate.go, sweeper.go, package.go, all `*_test.go`)
- Delete: `internal/proxy/dockerproxy/revalidate.go`, `internal/proxy/dockerproxy/revalidate_test.go`
- Delete: `integration/revalidate_test.go` (lazy replacement lands in Task 6)
- Modify: `cmd/jo-ei/main.go` (sweep wiring block ~lines 303-350, `revalidate` import)
- Modify: `internal/config/config.go` (RevalidationConfig, Load defaults, Validate)
- Modify: `internal/config/config_test.go` (old revalidation-key tests → new)
- Modify: `config.yaml` (revalidation block)

**Interfaces:**
- Produces: `config.RevalidationConfig{CVETTLMinutes, MalwareTTLMinutes int}` with mapstructure keys `cve_ttl_minutes` / `malware_ttl_minutes`; viper defaults 1440/1440. Tasks 4-5 read these fields.

- [ ] **Step 1: Write failing config tests**

In `internal/config/config_test.go`, delete tests referencing `Revalidation.Enabled`, `IntervalMinutes`, `RevalidateAfterHours`, `BatchSize` (find with `rg -n "Revalidation" internal/config/`) and add. First look at how the file's existing tests build a valid config (they write YAML to a temp file and call `config.Load`; a valid config needs at minimum `database.path`). Define one local helper for these tests:

```go
// loadTTLConfig writes yaml to a temp file and loads it.
func loadTTLConfig(t *testing.T, yaml string) (*config.Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(yaml), 0o600))
	return config.Load(p)
}

// ttlBaseYAML is the smallest config that passes Validate. If the existing
// tests already share such a constant, reuse theirs instead.
const ttlBaseYAML = `
database:
  path: "/tmp/joei.db"
`

func TestRevalidationTTLDefaults(t *testing.T) {
	// No revalidation section at all → both TTLs default to 1440.
	cfg, err := loadTTLConfig(t, ttlBaseYAML)
	require.NoError(t, err)
	assert.Equal(t, 1440, cfg.Cache.Revalidation.CVETTLMinutes)
	assert.Equal(t, 1440, cfg.Cache.Revalidation.MalwareTTLMinutes)
}

func TestRevalidationTTLExplicitZeroDisables(t *testing.T) {
	cfg, err := loadTTLConfig(t, ttlBaseYAML+`
cache:
  revalidation:
    cve_ttl_minutes: 0
    malware_ttl_minutes: 90
`)
	require.NoError(t, err)
	assert.Equal(t, 0, cfg.Cache.Revalidation.CVETTLMinutes)
	assert.Equal(t, 90, cfg.Cache.Revalidation.MalwareTTLMinutes)
}

func TestRevalidationTTLNegativeRejected(t *testing.T) {
	_, err := loadTTLConfig(t, ttlBaseYAML+`
cache:
  revalidation:
    cve_ttl_minutes: -1
`)
	require.ErrorContains(t, err, "cve_ttl_minutes")
}
```

Adjust `ttlBaseYAML` if `Validate` demands more required keys (run the test; the error message names the missing key). Beware: don't duplicate a top-level `cache:` key if the base YAML already has one — merge into it.

- [ ] **Step 2: Run tests, verify failure**

Run: `go test ./internal/config/`
Expected: FAIL — `CVETTLMinutes` undefined.

- [ ] **Step 3: Implement RevalidationConfig**

`internal/config/config.go` — replace the whole `RevalidationConfig` type:

```go
// RevalidationConfig sets per-gate TTLs for lazy re-validation of cache hits.
// A cache hit whose CVE or malware check is older than its TTL re-runs that
// gate before serving; an entry that now fails is blocked and evicted. 0
// disables that gate's re-check. Defaults (1440 = 24h) come from viper
// defaults, so an omitted key gets the default while an explicit 0 disables.
type RevalidationConfig struct {
	CVETTLMinutes     int `mapstructure:"cve_ttl_minutes"`
	MalwareTTLMinutes int `mapstructure:"malware_ttl_minutes"`
}
```

In `Load`, after `v := viper.New()`:

```go
v.SetDefault("cache.revalidation.cve_ttl_minutes", 1440)
v.SetDefault("cache.revalidation.malware_ttl_minutes", 1440)
```

In `Validate`, replace the three old revalidation checks (lines 80-88) with:

```go
if c.Cache.Revalidation.CVETTLMinutes < 0 {
	return fmt.Errorf("cache.revalidation.cve_ttl_minutes must not be negative")
}
if c.Cache.Revalidation.MalwareTTLMinutes < 0 {
	return fmt.Errorf("cache.revalidation.malware_ttl_minutes must not be negative")
}
```

- [ ] **Step 4: Delete sweep packages and wiring**

```powershell
Remove-Item -Recurse -Force internal/revalidate
Remove-Item -Force internal/proxy/dockerproxy/revalidate.go, internal/proxy/dockerproxy/revalidate_test.go, integration/revalidate_test.go
```

`cmd/jo-ei/main.go`: delete the entire `if cfg.Cache.Revalidation.Enabled { … } else { … }` block (comment included, ~lines 303-350) and the `"github.com/ggwpLab/Jo-ei/internal/revalidate"` import. Nothing replaces it here (TTL wiring lands in Tasks 4-5).

Note: deleting `dockerproxy/revalidate.go` removes `manifestBlobDigests` — it is resurrected inside `gate.go` in Task 5. `revalidate_test.go` helpers (`writeManifest`, `countingScanner`) are re-created in Task 5's test file.

- [ ] **Step 5: Update config.yaml**

Replace the `revalidation:` block (and its comment, lines ~91-100):

```yaml
  # Lazy re-validation: a cache hit whose CVE or malware check is older than
  # its TTL re-runs that gate (CVE by metadata, malware by re-scanning the
  # cached file; Docker re-runs the full image gate) before serving. An entry
  # that now fails is blocked and its binary evicted. A temporarily
  # unreachable scanner serves the previously clean entry and retries on the
  # next hit. 0 disables that gate's re-check.
  revalidation:
    cve_ttl_minutes: 1440
    malware_ttl_minutes: 1440
```

Also fix the `stale_after_days` comment above it (line ~81-83): replace "There is no TTL — verdict freshness is the re-validation sweep's job (below)." with "Verdict freshness is handled separately by lazy re-validation (below)."

- [ ] **Step 6: Build + test**

Run: `go build ./... ; go test ./internal/config/ ./cmd/...`
Expected: PASS, no references to `revalidate` remain (`rg -l "internal/revalidate"` → only docs/specs).

- [ ] **Step 7: Commit**

`git commit -m "feat(config)!: per-gate lazy TTLs replace the revalidation sweep"` (body: sweep removed; old keys ignored; Co-Authored-By trailer).

---

### Task 2: Cache index — per-gate check timestamps

**Files:**
- Modify: `internal/cache/index.go` (schema, migration, Insert, Get, Mark*, delete DueForRevalidation/MarkValidated)
- Modify: `internal/cache/cache.go` (CacheEntry fields, Cache interface Mark*)
- Modify: `internal/cache/local.go` (Mark* delegates, delete DueForRevalidation/MarkValidated)
- Delete: `internal/cache/reval.go`
- Modify: `internal/cache/index_test.go` (replace DueForRevalidation/MarkValidated tests)
- Modify: any `cache.Cache` fakes that now fail to compile (known: dockerproxy's test fake in `gate_test.go`; find the rest via `go build ./... && go vet ./...`, e.g. console test fakes)

**Interfaces:**
- Produces: `cache.CacheEntry.LastCVECheck / LastMalwareCheck time.Time`; `cache.Cache` gains `MarkCVEChecked(ref *gate.PackageRef, ts time.Time) error` and `MarkMalwareChecked(ref *gate.PackageRef, ts time.Time) error`. Tasks 3-5 consume both.

- [ ] **Step 1: Write failing index tests**

In `internal/cache/index_test.go`: delete tests for `DueForRevalidation`/`MarkValidated` (rg the names), add:

```go
func TestIndexCheckTimestamps(t *testing.T) {
	idx, err := NewIndex(filepath.Join(t.TempDir(), "index.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = idx.Close() })
	ref := &gate.PackageRef{Ecosystem: "pypi", Name: "pkg", Version: "1.0"}
	stored := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, idx.Insert(ref, &CacheEntry{ArtifactPath: "/x", StoredAt: stored}))

	e, ok := idx.Get(ref)
	require.True(t, ok)
	// Fresh insert: both checks stamped at stored_at.
	require.Equal(t, stored.Unix(), e.LastCVECheck.Unix())
	require.Equal(t, stored.Unix(), e.LastMalwareCheck.Unix())

	cveTS := time.Now().Add(-10 * time.Minute)
	require.NoError(t, idx.MarkCVEChecked(ref, cveTS.Unix()))
	e, _ = idx.Get(ref)
	require.Equal(t, cveTS.Unix(), e.LastCVECheck.Unix())
	require.Equal(t, stored.Unix(), e.LastMalwareCheck.Unix(), "malware timestamp must not move")

	avTS := time.Now()
	require.NoError(t, idx.MarkMalwareChecked(ref, avTS.Unix()))
	e, _ = idx.Get(ref)
	require.Equal(t, avTS.Unix(), e.LastMalwareCheck.Unix())
}

func TestMigrateCheckTimestampsFromLastValidated(t *testing.T) {
	// Build a pre-migration DB by hand: old schema with last_validated.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "index.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE artifacts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
		classifier TEXT NOT NULL DEFAULT '', file_path TEXT NOT NULL,
		scan_clean INTEGER NOT NULL DEFAULT 0, scan_json TEXT NOT NULL DEFAULT '',
		stored_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
		last_hit INTEGER NOT NULL DEFAULT 0, hit_count INTEGER NOT NULL DEFAULT 0,
		size_bytes INTEGER NOT NULL DEFAULT 0,
		last_validated INTEGER NOT NULL DEFAULT 0,
		UNIQUE(ecosystem, name, version, classifier))`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO artifacts
		(ecosystem, name, version, file_path, stored_at, expires_at, last_validated)
		VALUES ('pypi','a','1','/a',100,0,500), ('pypi','b','1','/b',200,0,0)`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	idx, err := NewIndex(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = idx.Close() })

	// Row a: backfilled from last_validated. Row b: last_validated was 0 → stored_at.
	ea, _ := idx.Get(&gate.PackageRef{Ecosystem: "pypi", Name: "a", Version: "1"})
	require.EqualValues(t, 500, ea.LastCVECheck.Unix())
	require.EqualValues(t, 500, ea.LastMalwareCheck.Unix())
	eb, _ := idx.Get(&gate.PackageRef{Ecosystem: "pypi", Name: "b", Version: "1"})
	require.EqualValues(t, 200, eb.LastCVECheck.Unix())

	// last_validated is gone.
	has, err := hasColumn(idx.db, "artifacts", "last_validated")
	require.NoError(t, err)
	require.False(t, has)
}
```

(`hasColumn` and `idx.db` are package-private; this test file is package `cache` — check the existing test file's package declaration; if it is `cache_test`, put the migration test in a new `index_internal_test.go` with `package cache`.)

- [ ] **Step 2: Run, verify failure**

Run: `go test ./internal/cache/`
Expected: FAIL — `MarkCVEChecked` undefined / missing columns.

- [ ] **Step 3: Implement schema + migration + methods**

`internal/cache/index.go`:

Schema const — replace `last_validated INTEGER NOT NULL DEFAULT 0,` with:

```
	last_cve_check     INTEGER NOT NULL DEFAULT 0,
	last_malware_check INTEGER NOT NULL DEFAULT 0,
```

Replace `migrateLastValidated` (and its call in `NewIndex`) with:

```go
// migrateCheckTimestamps replaces the sweep-era last_validated column with
// per-gate check timestamps. Both are backfilled from last_validated when the
// column exists (stored_at for rows where it is 0 — never a real timestamp),
// or from stored_at on databases that predate re-validation entirely. The old
// column is then dropped. No-op once last_cve_check exists.
func migrateCheckTimestamps(db *sql.DB) error {
	has, err := hasColumn(db, "artifacts", "last_cve_check")
	if err != nil || has {
		return err
	}
	hadLV, err := hasColumn(db, "artifacts", "last_validated")
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rolled back unless Commit succeeds

	steps := []string{
		`ALTER TABLE artifacts ADD COLUMN last_cve_check INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE artifacts ADD COLUMN last_malware_check INTEGER NOT NULL DEFAULT 0`,
	}
	if hadLV {
		steps = append(steps,
			`UPDATE artifacts SET
				last_cve_check     = CASE WHEN last_validated > 0 THEN last_validated ELSE stored_at END,
				last_malware_check = CASE WHEN last_validated > 0 THEN last_validated ELSE stored_at END`,
			`ALTER TABLE artifacts DROP COLUMN last_validated`,
		)
	} else {
		steps = append(steps,
			`UPDATE artifacts SET last_cve_check = stored_at, last_malware_check = stored_at`,
		)
	}
	for _, stmt := range steps {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("check-timestamp migration step failed: %w", err)
		}
	}
	return tx.Commit()
}
```

`Insert` — column list becomes `(…, size_bytes, last_cve_check, last_malware_check)` with 14 placeholders, `DO UPDATE SET` sets `last_cve_check = excluded.last_cve_check, last_malware_check = excluded.last_malware_check` (drop the `last_validated` line), and args end with:

```go
	entry.StoredAt.Unix(), 0,
	entry.StoredAt.Unix(), 0, entry.SizeBytes,
	entry.StoredAt.Unix(), entry.StoredAt.Unix(),
```

`Get` — SELECT adds `last_cve_check, last_malware_check`; scan into two `int64`s and set:

```go
entry.LastCVECheck = time.Unix(cveUnix, 0).UTC()
entry.LastMalwareCheck = time.Unix(avUnix, 0).UTC()
```

Replace `DueForRevalidation` + `MarkValidated` with:

```go
// MarkCVEChecked sets last_cve_check for ref to ts (unix seconds).
func (idx *Index) MarkCVEChecked(ref *gate.PackageRef, ts int64) error {
	_, err := idx.db.Exec(
		`UPDATE artifacts SET last_cve_check = ? WHERE ecosystem=? AND name=? AND version=? AND classifier=?`,
		ts, ref.Ecosystem, ref.Name, ref.Version, ref.Classifier,
	)
	return err
}

// MarkMalwareChecked sets last_malware_check for ref to ts (unix seconds).
func (idx *Index) MarkMalwareChecked(ref *gate.PackageRef, ts int64) error {
	_, err := idx.db.Exec(
		`UPDATE artifacts SET last_malware_check = ? WHERE ecosystem=? AND name=? AND version=? AND classifier=?`,
		ts, ref.Ecosystem, ref.Name, ref.Version, ref.Classifier,
	)
	return err
}
```

`internal/cache/cache.go` — `CacheEntry` gains:

```go
	// LastCVECheck / LastMalwareCheck record when each gate last confirmed
	// this entry clean; lazy re-validation compares them to the configured TTLs.
	LastCVECheck     time.Time
	LastMalwareCheck time.Time
```

`Cache` interface gains (before `Stats`):

```go
	// MarkCVEChecked records a passed CVE re-check for ref at ts.
	MarkCVEChecked(ref *gate.PackageRef, ts time.Time) error
	// MarkMalwareChecked records a passed malware re-check for ref at ts.
	MarkMalwareChecked(ref *gate.PackageRef, ts time.Time) error
```

`internal/cache/local.go` — replace `DueForRevalidation`/`MarkValidated` with:

```go
// MarkCVEChecked records a passed CVE re-check for ref.
func (lc *LocalCache) MarkCVEChecked(ref *gate.PackageRef, ts time.Time) error {
	return lc.index.MarkCVEChecked(ref, ts.Unix())
}

// MarkMalwareChecked records a passed malware re-check for ref.
func (lc *LocalCache) MarkMalwareChecked(ref *gate.PackageRef, ts time.Time) error {
	return lc.index.MarkMalwareChecked(ref, ts.Unix())
}
```

Delete `internal/cache/reval.go` (`RevalEntry`).

- [ ] **Step 4: Fix cache.Cache fakes**

`go build ./... ; go vet ./...` — every fake implementing `cache.Cache` fails. Known: dockerproxy's `newFakeCache` (in `gate_test.go`). Fix pattern — store timestamps on Put and honor Mark*:

```go
func (f *fakeCache) MarkCVEChecked(ref *gate.PackageRef, ts time.Time) error {
	if e, ok := f.entries[ref.Key()]; ok {
		e.LastCVECheck = ts
	}
	return nil
}

func (f *fakeCache) MarkMalwareChecked(ref *gate.PackageRef, ts time.Time) error {
	if e, ok := f.entries[ref.Key()]; ok {
		e.LastMalwareCheck = ts
	}
	return nil
}
```

and in its `Put`, set `LastCVECheck: time.Now(), LastMalwareCheck: time.Now()` on the stored `*cache.CacheEntry`. Apply the same no-op/two-liner pattern to any console-test fakes `go vet` flags.

- [ ] **Step 5: Test + commit**

Run: `go test ./...`
Expected: PASS.
`git commit -m "feat(cache): per-gate check timestamps replace last_validated"`

---

### Task 3: gate.ArtifactCache + adapter plumbing

**Files:**
- Modify: `internal/gate/cache.go` (ArtifactEntry fields, ArtifactCache Mark*)
- Create: `internal/cache/artifactcache.go` (exported adapter, replaces main's private `cacheAdapter`)
- Modify: `cmd/jo-ei/main.go` (delete `cacheAdapter`, use `cache.AsArtifactCache`)
- Modify: `internal/proxy/handler_test.go` (`fakeCache`)

**Interfaces:**
- Consumes: `cache.Cache.Mark*`, `cache.CacheEntry.Last*` (Task 2).
- Produces: `gate.ArtifactEntry.LastCVECheck / LastMalwareCheck time.Time`; `gate.ArtifactCache.MarkCVEChecked / MarkMalwareChecked(ref *PackageRef, ts time.Time) error`. Task 4 consumes.

- [ ] **Step 1: Extend gate.ArtifactEntry / ArtifactCache**

`internal/gate/cache.go` (add `"time"` import):

```go
// ArtifactEntry is a minimal view of a cached artifact, avoiding an import
// cycle with the cache package (which itself imports gate for PackageRef).
type ArtifactEntry struct {
	// ArtifactPath is the absolute path to the cached file on disk.
	ArtifactPath string
	// ScanClean is true if all scanners passed.
	ScanClean bool
	// LastCVECheck / LastMalwareCheck record when each gate last confirmed the
	// entry clean; the handler re-runs a gate when its TTL has lapsed.
	LastCVECheck     time.Time
	LastMalwareCheck time.Time
}

// ArtifactCache is the storage interface used by the proxy handler.
// The real cache.LocalCache satisfies this interface via the cacheAdapter in
// cmd/jo-ei.
type ArtifactCache interface {
	Get(ref *PackageRef) (*ArtifactEntry, bool)
	Put(ref *PackageRef, tmpPath string, scanClean bool, scanJSON string) error
	Invalidate(ref *PackageRef) error
	// MarkCVEChecked / MarkMalwareChecked record a passed lazy re-check at ts.
	MarkCVEChecked(ref *PackageRef, ts time.Time) error
	MarkMalwareChecked(ref *PackageRef, ts time.Time) error
}
```

- [ ] **Step 2: Exported adapter in internal/cache; delete main's cacheAdapter**

Create `internal/cache/artifactcache.go`:

```go
package cache

import (
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// AsArtifactCache bridges a Cache to the narrower gate.ArtifactCache the
// proxy handler consumes (gate cannot import cache — see gate.ArtifactEntry).
func AsArtifactCache(c Cache) gate.ArtifactCache { return &artifactCacheAdapter{c: c} }

type artifactCacheAdapter struct{ c Cache }

func (a *artifactCacheAdapter) Get(ref *gate.PackageRef) (*gate.ArtifactEntry, bool) {
	entry, found := a.c.Get(ref)
	if !found {
		return nil, false
	}
	return &gate.ArtifactEntry{
		ArtifactPath:     entry.ArtifactPath,
		ScanClean:        entry.ScanClean,
		LastCVECheck:     entry.LastCVECheck,
		LastMalwareCheck: entry.LastMalwareCheck,
	}, true
}

func (a *artifactCacheAdapter) Put(ref *gate.PackageRef, tmpPath string, scanClean bool, scanJSON string) error {
	return a.c.Put(ref, tmpPath, scanClean, scanJSON)
}

func (a *artifactCacheAdapter) Invalidate(ref *gate.PackageRef) error {
	return a.c.Invalidate(ref)
}

func (a *artifactCacheAdapter) MarkCVEChecked(ref *gate.PackageRef, ts time.Time) error {
	return a.c.MarkCVEChecked(ref, ts)
}

func (a *artifactCacheAdapter) MarkMalwareChecked(ref *gate.PackageRef, ts time.Time) error {
	return a.c.MarkMalwareChecked(ref, ts)
}
```

In `cmd/jo-ei/main.go`: delete the whole `cacheAdapter` type and its three methods (~lines 490-512); replace its only use (`cache: &cacheAdapter{c: artifactCache}` in the `sharedDeps` literal) with `cache: cache.AsArtifactCache(artifactCache)`.

- [ ] **Step 3: Update proxy fakeCache (internal/proxy/handler_test.go)**

In `Put`, store timestamps: `f.entries[ref.Key()] = &gate.ArtifactEntry{ArtifactPath: dst.Name(), ScanClean: clean, LastCVECheck: time.Now(), LastMalwareCheck: time.Now()}`. Add:

```go
func (f *fakeCache) MarkCVEChecked(ref *gate.PackageRef, ts time.Time) error {
	if e, ok := f.entries[ref.Key()]; ok {
		e.LastCVECheck = ts
	}
	return nil
}

func (f *fakeCache) MarkMalwareChecked(ref *gate.PackageRef, ts time.Time) error {
	if e, ok := f.entries[ref.Key()]; ok {
		e.LastMalwareCheck = ts
	}
	return nil
}
```

- [ ] **Step 4: Build, test, commit**

Run: `go build ./... ; go test ./internal/proxy/ ./cmd/...`
Expected: PASS.
`git commit -m "feat(gate): artifact cache carries per-gate check timestamps"`

---

### Task 4: Package handler — lazy re-check on cache hit

**Files:**
- Modify: `internal/proxy/handler.go` (HandlerConfig + cache-hit branch)
- Create: `internal/proxy/handler_recheck_test.go`
- Modify: `cmd/jo-ei/main.go` (wire TTLs into HandlerConfig)

**Interfaces:**
- Consumes: `gate.ArtifactCache.Mark*`, `ArtifactEntry.Last*` (Task 3); `config.RevalidationConfig` (Task 1).
- Produces: `HandlerConfig.CVERecheckTTL, MalwareRecheckTTL time.Duration` (0 = disabled).

- [ ] **Step 1: Write failing handler tests**

Create `internal/proxy/handler_recheck_test.go`, package `proxy_test`. Uses the existing `newFakeCache`, `makeUpstream`, and adds local stubs:

```go
package proxy_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

// flipCVE returns clean until vulnerable is set; scanErr forces an error.
type flipCVE struct {
	vulnerable atomic.Bool
	scanErr    atomic.Bool
	calls      atomic.Int32
}

func (s *flipCVE) Scan(context.Context, *gate.PackageRef) (*gate.ScanResult, error) {
	s.calls.Add(1)
	if s.scanErr.Load() {
		return nil, errors.New("osv down")
	}
	if s.vulnerable.Load() {
		return &gate.ScanResult{Findings: []gate.CVEFinding{{ID: "CVE-2026-0001", Severity: gate.SeverityCritical}}}, nil
	}
	return &gate.ScanResult{Clean: true}, nil
}

// blockOnFindings blocks whenever the scan has findings.
type blockOnFindings struct{}

func (blockOnFindings) Evaluate(_ *gate.PackageRef, res *gate.ScanResult) gate.PolicyDecision {
	if len(res.Findings) > 0 {
		return gate.PolicyDecision{Allowed: false, Reason: "cve_found", Findings: res.Findings}
	}
	return gate.PolicyDecision{Allowed: true, Reason: "ok"}
}

// flipAV mirrors flipCVE for the malware scanner.
type flipAV struct {
	infected atomic.Bool
	scanErr  atomic.Bool
	calls    atomic.Int32
}

func (s *flipAV) Scan(context.Context, string) (*gate.AVResult, error) {
	s.calls.Add(1)
	if s.scanErr.Load() {
		return nil, errors.New("clamd down")
	}
	if s.infected.Load() {
		return &gate.AVResult{Clean: false, Engine: "clamav", Signature: "EICAR"}, nil
	}
	return &gate.AVResult{Clean: true}, nil
}

type eventSpy struct{ events []gate.Event }

func (r *eventSpy) Record(e gate.Event) { r.events = append(r.events, e) }

// recheckHarness caches one clean artifact through the full pipeline and
// returns everything a re-check test needs to manipulate.
type recheckHarness struct {
	srv  *httptest.Server
	fc   *fakeCache
	cve  *flipCVE
	av   *flipAV
	rec  *eventSpy
	ref  gate.PackageRef
	path string // download path for repeat GETs
}

func newRecheckHarness(t *testing.T, cveTTL, avTTL time.Duration) *recheckHarness {
	t.Helper()
	upstream := makeUpstream(t, "victim", "1.0.0", 72)
	t.Cleanup(upstream.Close)

	fc := newFakeCache()
	cve := &flipCVE{}
	av := &flipAV{}
	rec := &eventSpy{}
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:           adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:            supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:             fc,
		Logger:            zerolog.Nop(),
		CVEScanner:        cve,
		Policy:            blockOnFindings{},
		AVScanner:         av,
		Recorder:          rec,
		CVERecheckTTL:     cveTTL,
		MalwareRecheckTTL: avTTL,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	hs := &recheckHarness{
		srv: srv, fc: fc, cve: cve, av: av, rec: rec,
		ref:  gate.PackageRef{Ecosystem: "pypi", Name: "victim", Version: "1.0.0"},
		path: "/packages/py3/v/victim/victim-1.0.0-py3-none-any.whl",
	}
	resp, err := http.Get(srv.URL + hs.path)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed download must pass")
	return hs
}

// rewind pushes both check timestamps into the past on the cached entry.
func (hs *recheckHarness) rewind(d time.Duration) {
	e := hs.fc.entries[hs.ref.Key()]
	e.LastCVECheck = e.LastCVECheck.Add(-d)
	e.LastMalwareCheck = e.LastMalwareCheck.Add(-d)
}

func (hs *recheckHarness) get(t *testing.T) *http.Response {
	t.Helper()
	resp, err := http.Get(hs.srv.URL + hs.path)
	require.NoError(t, err)
	resp.Body.Close()
	return resp
}

func TestRecheck_FreshHitSkipsScanners(t *testing.T) {
	hs := newRecheckHarness(t, time.Hour, time.Hour)
	cveCalls, avCalls := hs.cve.calls.Load(), hs.av.calls.Load()
	resp := hs.get(t)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, cveCalls, hs.cve.calls.Load(), "fresh hit must not re-run CVE")
	assert.Equal(t, avCalls, hs.av.calls.Load(), "fresh hit must not re-run AV")
}

func TestRecheck_ExpiredCVEBlocksAndEvicts(t *testing.T) {
	hs := newRecheckHarness(t, time.Hour, time.Hour)
	hs.rewind(2 * time.Hour)
	hs.cve.vulnerable.Store(true)
	artifact := hs.fc.entries[hs.ref.Key()].ArtifactPath

	resp := hs.get(t)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_, cached := hs.fc.entries[hs.ref.Key()]
	assert.False(t, cached, "entry must be evicted")
	_, statErr := os.Stat(artifact)
	assert.True(t, os.IsNotExist(statErr), "binary must be deleted")
	last := hs.rec.events[len(hs.rec.events)-1]
	assert.Equal(t, gate.VerdictBlock, last.Verdict)
	assert.Equal(t, gate.GateCVE, last.Gate)
	assert.NotEqual(t, "revalidation", last.RequestID)
}

func TestRecheck_ExpiredMalwareBlocksAndEvicts(t *testing.T) {
	hs := newRecheckHarness(t, time.Hour, time.Hour)
	hs.rewind(2 * time.Hour)
	hs.av.infected.Store(true)
	artifact := hs.fc.entries[hs.ref.Key()].ArtifactPath

	resp := hs.get(t)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_, cached := hs.fc.entries[hs.ref.Key()]
	assert.False(t, cached)
	_, statErr := os.Stat(artifact)
	assert.True(t, os.IsNotExist(statErr))
	last := hs.rec.events[len(hs.rec.events)-1]
	assert.Equal(t, gate.GateMalware, last.Gate)
	assert.Equal(t, "EICAR", last.MalwareSignature)
}

func TestRecheck_CleanRecheckBumpsAndServes(t *testing.T) {
	hs := newRecheckHarness(t, time.Hour, time.Hour)
	hs.rewind(2 * time.Hour)
	before := hs.fc.entries[hs.ref.Key()].LastCVECheck

	resp := hs.get(t)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	e := hs.fc.entries[hs.ref.Key()]
	assert.True(t, e.LastCVECheck.After(before), "clean re-check must bump last_cve_check")
	assert.True(t, e.LastMalwareCheck.After(before), "clean re-check must bump last_malware_check")
	last := hs.rec.events[len(hs.rec.events)-1]
	assert.Equal(t, gate.VerdictCache, last.Verdict, "a clean re-check still serves as a cache hit")
}

func TestRecheck_ScannerErrorServesStale(t *testing.T) {
	hs := newRecheckHarness(t, time.Hour, time.Hour)
	hs.rewind(2 * time.Hour)
	hs.cve.scanErr.Store(true)
	hs.av.scanErr.Store(true)
	before := hs.fc.entries[hs.ref.Key()].LastCVECheck

	resp := hs.get(t)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "scanner outage must serve the stale clean artifact")
	e := hs.fc.entries[hs.ref.Key()]
	assert.Equal(t, before, e.LastCVECheck, "failed re-check must not bump the timestamp")
}

func TestRecheck_ZeroTTLDisables(t *testing.T) {
	hs := newRecheckHarness(t, 0, 0)
	hs.rewind(1000 * time.Hour)
	hs.cve.vulnerable.Store(true)
	hs.av.infected.Store(true)
	cveCalls, avCalls := hs.cve.calls.Load(), hs.av.calls.Load()

	resp := hs.get(t)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "TTL 0 disables re-checks entirely")
	assert.Equal(t, cveCalls, hs.cve.calls.Load())
	assert.Equal(t, avCalls, hs.av.calls.Load())
}
```

- [ ] **Step 2: Run, verify failure**

Run: `go test ./internal/proxy/ -run TestRecheck -v`
Expected: FAIL — `CVERecheckTTL` undefined.

- [ ] **Step 3: Implement handler re-check**

`internal/proxy/handler.go`. Add to `HandlerConfig`:

```go
	// CVERecheckTTL / MalwareRecheckTTL: a cache hit whose respective check is
	// older than this re-runs that gate before serving (0 disables). A scanner
	// failure serves the stale entry and leaves the timestamp untouched.
	CVERecheckTTL     time.Duration
	MalwareRecheckTTL time.Duration
```

Replace the cache-hit branch body (after the `!entry.ScanClean` early-return, before `log.Debug().Msg("cache hit")`):

```go
	// Check cache first
	if entry, found := h.cfg.Cache.Get(ref); found {
		if !entry.ScanClean {
			// Fail-closed: cached entry has failed scan result
			record(gate.VerdictBlock, gate.GateCache, "scan_failed", http.StatusForbidden, nil)
			h.writeError(w, requestID, ref, http.StatusForbidden, "scan_failed")
			return
		}
		if h.recheckExpired(r.Context(), w, requestID, ref, entry, record, log) {
			return // blocked and evicted; response already written
		}
		log.Debug().Msg("cache hit")
		if err := h.serveFromCache(w, entry); err != nil {
			record(gate.VerdictError, gate.GateCache, "cache_read_error", http.StatusInternalServerError, nil)
			return
		}
		record(gate.VerdictCache, gate.GateCache, "cache_hit", http.StatusOK, nil)
		return
	}
```

New method (place after `ServeHTTP`):

```go
// recheckExpired lazily re-runs each gate whose TTL has lapsed for a cache
// hit: CVE+policy against current metadata, then malware against the cached
// bytes (cheap metadata check first). A gate that now blocks evicts the entry
// (index row + binary) and writes the block response — the return value true
// tells the caller the request is finished. A scanner failure serves the
// previously clean entry and leaves its timestamp untouched, so the next hit
// retries; the timestamp is bumped only on a passed check.
func (h *Handler) recheckExpired(ctx context.Context, w http.ResponseWriter, requestID string, ref *gate.PackageRef, entry *gate.ArtifactEntry, record func(string, string, string, int, func(*gate.Event)), log zerolog.Logger) bool {
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
				log.Warn().Str("reason", decision.Reason).Int("findings", len(decision.Findings)).
					Msg("re-check: CVE policy blocked cached package")
				record(gate.VerdictBlock, gate.GateCVE, decision.Reason, http.StatusForbidden, func(ev *gate.Event) {
					ev.BlockedBy = []string{blockedBy}
					ev.CVEs = decision.Findings
				})
				h.writeCVEBlockedResponse(w, requestID, ref, decision)
				return true
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
			log.Warn().Str("engine", res.Engine).Str("signature", res.Signature).
				Msg("re-check: malware detected in cached artifact")
			record(gate.VerdictBlock, gate.GateMalware, "malware_found", http.StatusForbidden, func(ev *gate.Event) {
				ev.BlockedBy = []string{"malware"}
				ev.MalwareEngine = res.Engine
				ev.MalwareSignature = res.Signature
			})
			h.writeMalwareBlockedResponse(w, requestID, ref, res.Engine, res.Signature)
			return true
		default:
			if err := h.cfg.Cache.MarkMalwareChecked(ref, now); err != nil {
				log.Warn().Err(err).Msg("marking malware re-check")
			}
		}
	}
	return false
}

// evictRechecked removes a cached entry that failed a lazy re-check. Eviction
// failure is logged but never blocks the block response.
func (h *Handler) evictRechecked(ref *gate.PackageRef, log zerolog.Logger) {
	if err := h.cfg.Cache.Invalidate(ref); err != nil {
		log.Error().Err(err).Str("package", ref.Key()).Msg("re-check: evicting cached artifact")
	}
}
```

(`writeCVEBlockedResponse` / `writeMalwareBlockedResponse` already exist — same calls as the live path.)

- [ ] **Step 4: Run tests**

Run: `go test ./internal/proxy/ -v`
Expected: all PASS (TestRecheck_* and existing).

- [ ] **Step 5: Wire TTLs in cmd/jo-ei/main.go**

Add fields to `sharedDeps`:

```go
	cveRecheckTTL     time.Duration
	malwareRecheckTTL time.Duration
```

Populate where `shared` is built:

```go
	shared := sharedDeps{
		// … existing fields …
		cveRecheckTTL:     time.Duration(cfg.Cache.Revalidation.CVETTLMinutes) * time.Minute,
		malwareRecheckTTL: time.Duration(cfg.Cache.Revalidation.MalwareTTLMinutes) * time.Minute,
	}
```

In the `newProxyHandler`-style constructor at the bottom of main.go (the `proxy.NewHandler(proxy.HandlerConfig{…})` call, ~line 478), add:

```go
		CVERecheckTTL:     shared.cveRecheckTTL,
		MalwareRecheckTTL: shared.malwareRecheckTTL,
```

- [ ] **Step 6: Build, test, commit**

Run: `go build ./... ; go test ./internal/proxy/ ./cmd/...`
Expected: PASS.
`git commit -m "feat(proxy): lazy per-gate TTL re-check on cache hits"`

---

### Task 5: Docker — verdict TTL, cascade, stale-on-error

**Files:**
- Modify: `internal/proxy/dockerproxy/blobcache.go` (GetImageVerdict age, InvalidateBlob)
- Modify: `internal/proxy/dockerproxy/gate.go` (recheckTTL, expiry, stale fallback, blob cascade)
- Modify: `internal/proxy/dockerproxy/handler.go` (HandlerDeps.RecheckTTL → gateDeps)
- Modify: `internal/proxy/dockerproxy/gate_test.go` (call-site of GetImageVerdict if asserted)
- Create: `internal/proxy/dockerproxy/gate_recheck_test.go`
- Modify: `cmd/jo-ei/main.go` (pass RecheckTTL, minEnabledTTL helper)

**Interfaces:**
- Consumes: `cache.CacheEntry.Last*` (Task 2).
- Produces: `HandlerDeps.RecheckTTL time.Duration` (0 = cached verdicts never expire); `verdictStore.GetImageVerdict(repo, digest) (clean bool, reason string, checkedAt time.Time, found bool)`; `verdictStore.InvalidateBlob(digest string)`.

- [ ] **Step 1: Write failing gate tests**

Create `internal/proxy/dockerproxy/gate_recheck_test.go`, package `dockerproxy`. First read `gate_test.go` for the existing helpers (`newGateTestServer`, `stubScanner`, `stubAV`, `findingPolicy`, `allowFilter`, `newFakeCache`) and mirror their usage. Re-create `countingScanner` (deleted with revalidate_test.go):

```go
package dockerproxy

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// countingScanner wraps stubScanner and counts ScanImage calls so tests can
// tell a fresh evaluation from a cached-verdict short-circuit.
type countingScanner struct {
	stubScanner
	calls *int
}

func (s countingScanner) ScanImage(ctx context.Context, ref string) (*ImageScanResult, error) {
	*s.calls++
	return s.stubScanner.ScanImage(ctx, ref)
}

// newRecheckGate builds a manifest gate over the shared fake registry with the
// given TTL and scanner, returning the gate, its store, and the repo name.
func newRecheckGate(t *testing.T, sc ImageScanner, ttl time.Duration, c *fakeCache) (*manifestGate, *verdictStore, string) {
	t.Helper()
	srvURL, repo, _ := newGateTestServer(t)
	adapter := NewAdapter([]string{srvURL}, nil)
	store := newVerdictStore(c)
	g := newManifestGate(gateDeps{
		adapter: adapter, scanner: sc, av: stubAV{},
		filter: allowFilter{}, policy: findingPolicy{},
		store: store, tags: newTagIndex(0), recheckTTL: ttl, logger: zerolog.Nop(),
	})
	return g, store, repo
}

// rewindVerdict pushes the image verdict's check timestamps into the past.
func rewindVerdict(c *fakeCache, repo, digest string, d time.Duration) {
	e := c.entries[imageRefKey(repo, digest).Key()]
	e.LastCVECheck = e.LastCVECheck.Add(-d)
	e.LastMalwareCheck = e.LastMalwareCheck.Add(-d)
}

func TestGateRecheck_FreshVerdictShortCircuits(t *testing.T) {
	c := newFakeCache()
	calls := 0
	g, _, repo := newRecheckGate(t, countingScanner{calls: &calls}, time.Hour, c)

	// First evaluation stores the verdict…
	digest, v, err := g.Evaluate(context.Background(), repo, "latest")
	if err != nil || !v.Allowed {
		t.Fatalf("seed evaluate: v=%+v err=%v", v, err)
	}
	// …the repeat pull inside the TTL must not re-scan.
	before := calls
	_, v2, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil || !v2.FromCache {
		t.Fatalf("repeat evaluate: v=%+v err=%v, want FromCache", v2, err)
	}
	if calls != before {
		t.Fatalf("fresh cached verdict must not re-scan (calls %d→%d)", before, calls)
	}
}

func TestGateRecheck_ExpiredVerdictReScans(t *testing.T) {
	c := newFakeCache()
	calls := 0
	g, _, repo := newRecheckGate(t, countingScanner{calls: &calls}, time.Hour, c)

	digest, _, err := g.Evaluate(context.Background(), repo, "latest")
	if err != nil {
		t.Fatal(err)
	}
	rewindVerdict(c, repo, digest, 2*time.Hour)
	before := calls
	_, v, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil || !v.Allowed {
		t.Fatalf("re-eval: v=%+v err=%v", v, err)
	}
	if calls == before {
		t.Fatal("expired verdict must force a fresh scan")
	}
	if v.FromCache {
		t.Fatal("a fresh re-evaluation must not be marked FromCache")
	}
}

func TestGateRecheck_ExpiredBlockCascadesBlobs(t *testing.T) {
	c := newFakeCache()
	calls := 0
	sc := countingScanner{calls: &calls}
	g, store, repo := newRecheckGate(t, sc, time.Hour, c)

	digest, _, err := g.Evaluate(context.Background(), repo, "latest")
	if err != nil {
		t.Fatal(err)
	}
	// The seed evaluation cached the config/layer blobs (fake registry serves
	// sha256:cfg + sha256:layer1 — check newGateTestServer for exact digests).
	rewindVerdict(c, repo, digest, 2*time.Hour)

	// Now the scanner finds a blocking CVE.
	g.scanner = countingScanner{
		stubScanner: stubScanner{findings: []gate.CVEFinding{{ID: "CVE-1", Severity: gate.SeverityHigh}}},
		calls:       &calls,
	}
	_, v, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil || v.Allowed {
		t.Fatalf("re-eval: v=%+v err=%v, want block", v, err)
	}
	if _, _, found := store.GetBlob("sha256:cfg"); found {
		t.Error("config blob must be cascade-evicted on re-check block")
	}
	if _, _, found := store.GetBlob("sha256:layer1"); found {
		t.Error("layer blob must be cascade-evicted on re-check block")
	}
}

func TestGateRecheck_ScanErrorServesStaleVerdict(t *testing.T) {
	c := newFakeCache()
	calls := 0
	g, _, repo := newRecheckGate(t, countingScanner{calls: &calls}, time.Hour, c)

	digest, _, err := g.Evaluate(context.Background(), repo, "latest")
	if err != nil {
		t.Fatal(err)
	}
	rewindVerdict(c, repo, digest, 2*time.Hour)
	g.scanner = errScanner{} // add: type errScanner struct{}; ScanImage returns an error
	_, v, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil {
		t.Fatalf("scanner outage on re-check must serve the stale verdict, got err %v", err)
	}
	if !v.Allowed || !v.FromCache {
		t.Fatalf("v=%+v, want stale allowed FromCache verdict", v)
	}
}

func TestGateRecheck_ZeroTTLNeverExpires(t *testing.T) {
	c := newFakeCache()
	calls := 0
	g, _, repo := newRecheckGate(t, countingScanner{calls: &calls}, 0, c)

	digest, _, err := g.Evaluate(context.Background(), repo, "latest")
	if err != nil {
		t.Fatal(err)
	}
	rewindVerdict(c, repo, digest, 1000*time.Hour)
	before := calls
	_, v, err := g.Evaluate(context.Background(), repo, digest)
	if err != nil || !v.FromCache || calls != before {
		t.Fatalf("TTL 0: verdict must never expire (v=%+v err=%v calls %d→%d)", v, err, before, calls)
	}
}
```

Add `errScanner`:

```go
type errScanner struct{}

func (errScanner) ScanImage(context.Context, string) (*ImageScanResult, error) {
	return nil, context.DeadlineExceeded
}
```

Adjust blob digests / stub signatures to whatever `gate_test.go` actually defines (the deleted revalidate_test.go used `sha256:cfg` / `sha256:layer1`).

- [ ] **Step 2: Run, verify failure**

Run: `go test ./internal/proxy/dockerproxy/ -run TestGateRecheck -v`
Expected: FAIL — `recheckTTL` unknown field.

- [ ] **Step 3: Implement blobcache changes**

`internal/proxy/dockerproxy/blobcache.go` (add `"time"` import):

```go
// GetImageVerdict returns the cached gate verdict for an image digest, and
// when the gates last confirmed it (the older of the two per-gate timestamps —
// they move together for Docker, where one evaluation covers both gates). The
// block reason is stored in the entry's ScanJSON field.
func (v *verdictStore) GetImageVerdict(repo, digest string) (bool, string, time.Time, bool) {
	e, ok := v.c.Get(imageRefKey(repo, digest))
	if !ok {
		return false, "", time.Time{}, false
	}
	checkedAt := e.LastCVECheck
	if e.LastMalwareCheck.Before(checkedAt) {
		checkedAt = e.LastMalwareCheck
	}
	return e.ScanClean, e.ScanJSON, checkedAt, true
}

// InvalidateBlob removes a cached blob entry (its bytes included).
func (v *verdictStore) InvalidateBlob(digest string) error {
	return v.c.Invalidate(blobRef(digest))
}
```

Fix any other `GetImageVerdict` call sites (`rg -n "GetImageVerdict"`).

- [ ] **Step 4: Implement gate expiry + cascade + stale fallback**

`internal/proxy/dockerproxy/gate.go`:

`gateDeps` gains:

```go
	// recheckTTL: a cached verdict older than this is re-evaluated by the full
	// gate before being trusted (min of the enabled per-gate TTLs; 0 = never).
	recheckTTL time.Duration
```

In `evaluate`, replace the cached-verdict block (lines ~110-118) with:

```go
	// staleVerdict holds an expired cached verdict: the gate below re-evaluates
	// from scratch, but an infrastructure failure (Trivy/ClamAV/upstream down)
	// falls back to serving it — mirroring the package path's serve-stale rule —
	// instead of failing the pull. nil when there was no cached verdict.
	var staleVerdict *GateVerdict
	if clean, reason, checkedAt, found := g.store.GetImageVerdict(repo, digest); found && !skipVerdictCache && !isStaleSupplyBlock(clean, reason) {
		v := GateVerdict{Allowed: clean, Reason: reason, Passthrough: isPassthroughReason(reason), FromCache: true}
		if !clean {
			v.BlockedBy = blockedByForReason(reason)
		} else if path, ok := g.store.GetManifestBody(repo, digest); ok {
			v.ManifestPath, v.ContentType = path, contentType
		}
		if g.recheckTTL <= 0 || time.Since(checkedAt) <= g.recheckTTL {
			return digest, v, nil
		}
		staleVerdict = &v
		g.logger.Debug().Str("repo", repo).Str("digest", digest).
			Msg("cached verdict expired; re-running the gate")
	}
```

Wrap the post-digest infra-error returns in a stale fallback. Add helper:

```go
// staleOr returns the expired cached verdict when a re-evaluation hits an
// infrastructure error, so a scanner outage serves the last known verdict
// instead of failing the pull; without one it propagates the error (the
// handler fails closed with 5xx, unchanged first-pull behavior).
func (g *manifestGate) staleOr(digest string, stale *GateVerdict, err error) (string, GateVerdict, error) {
	if stale != nil {
		g.logger.Warn().Err(err).Str("digest", digest).
			Msg("gate re-evaluation failed; serving stale cached verdict")
		return digest, *stale, nil
	}
	return "", GateVerdict{}, err
}
```

Apply it to the error returns after the cached-verdict block:
- `ImageConfig` error: `return g.staleOr(digest, staleVerdict, err)`
- `ScanImage` error: `return g.staleOr(digest, staleVerdict, err)`
- `scanLayer` error: `return g.staleOr(digest, staleVerdict, scanErr)`
- final `cacheVerdict` error (clean path): `return g.staleOr(digest, staleVerdict, err)`

(`FetchManifest` failures stay fatal — no digest yet, and the manifest itself is unavailable.)

Cascade on a re-check block — in both block branches (CVE/policy and malware), before returning, add:

```go
			if staleVerdict != nil {
				g.evictBlobs(manifestBody)
			}
```

New helper (replaces the deleted `manifestBlobDigests`, parsing the in-memory body instead of a file; needs `"encoding/json"` import):

```go
// evictBlobs removes the config/layer blob entries listed in manifestBody so a
// re-checked image that turned bad does not keep serving its bytes on direct
// blob requests. Best-effort: parse failures evict nothing.
func (g *manifestGate) evictBlobs(manifestBody []byte) {
	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestBody, &m); err != nil {
		return
	}
	digests := make([]string, 0, len(m.Layers)+1)
	if m.Config.Digest != "" {
		digests = append(digests, m.Config.Digest)
	}
	for _, l := range m.Layers {
		if l.Digest != "" {
			digests = append(digests, l.Digest)
		}
	}
	for _, d := range digests {
		if err := g.store.InvalidateBlob(d); err != nil {
			g.logger.Warn().Err(err).Str("digest", d).Msg("cascade-evicting blob")
		}
	}
}
```

Cascade only when `staleVerdict != nil` — a first-time block keeps today's behavior (the infected-blob memo stays cached so repeats don't re-scan).

- [ ] **Step 5: Wire RecheckTTL through HandlerDeps + main.go**

`internal/proxy/dockerproxy/handler.go` — `HandlerDeps` gains:

```go
	// RecheckTTL: cached image verdicts older than this are re-evaluated by the
	// full gate on the next pull (0 = never expire). Wire min of the enabled
	// per-gate TTLs.
	RecheckTTL time.Duration
```

and `New` passes `recheckTTL: d.RecheckTTL` into `gateDeps`.

`cmd/jo-ei/main.go` — helper + wiring:

```go
// minEnabledTTL returns the smaller of the enabled (positive) TTLs; 0 when
// both are disabled. Docker's single verdict covers both gates, so it expires
// by the stricter one.
func minEnabledTTL(a, b time.Duration) time.Duration {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}
```

In the docker `HandlerDeps` literal (~line 356): `RecheckTTL: minEnabledTTL(shared.cveRecheckTTL, shared.malwareRecheckTTL),`

- [ ] **Step 6: Run, commit**

Run: `go test ./internal/proxy/dockerproxy/ -v ; go build ./...`
Expected: PASS.
`git commit -m "feat(docker): image verdicts expire by TTL and re-run the gate"`

---

### Task 6: Integration tests (lazy model)

**Files:**
- Create: `integration/lazy_recheck_test.go`

**Interfaces:**
- Consumes: `cache.NewLocalCache`, `LocalCache.MarkCVEChecked/MarkMalwareChecked` (rewind mechanism), `proxy.NewHandler` TTL fields, `dockerproxy.New(HandlerDeps{RecheckTTL: …})`.

- [ ] **Step 1: Write the package-path integration test**

`integration/lazy_recheck_test.go` (build tag `integration`, package `integration_test`). The handler needs a `gate.ArtifactCache`; wrap the real `LocalCache` with `cache.AsArtifactCache(lc)` (Task 3's exported adapter):

```go
//go:build integration

package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/proxy/dockerproxy"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)
```

(`sha256`/`hex`/`dockerproxy` are used by the Docker test in Step 2 of this task — one shared import block for the whole file.)

```go
// switchableAV reports clean until flipped to infected.
type switchableAV struct{ infected bool }

func (s *switchableAV) Scan(context.Context, string) (*gate.AVResult, error) {
	if s.infected {
		return &gate.AVResult{Clean: false, Engine: "clamav", Signature: "EICAR"}, nil
	}
	return &gate.AVResult{Clean: true}, nil
}

type recSpy struct{ events []gate.Event }

func (r *recSpy) Record(e gate.Event) { r.events = append(r.events, e) }

// TestLazyRecheckEvictsNewlyInfected: a cached clean artifact whose malware
// TTL has lapsed is re-scanned on the next hit; when the scanner now reports
// infected, the pull is blocked, the binary is removed from disk, and a
// BLOCK/malware event is recorded.
func TestLazyRecheckEvictsNewlyInfected(t *testing.T) {
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })

	// PyPI-style upstream serving metadata (old artifact) + wheel bytes.
	published := time.Now().UTC().Add(-72 * time.Hour)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pypi/victim/1.0.0/json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"info":{"name":"victim","version":"1.0.0"},` +
				`"urls":[{"upload_time_iso_8601":"` + published.Format(time.RFC3339) + `","url":"x","digests":{"sha256":"a"}}]}`))
			return
		}
		_, _ = w.Write([]byte("wheel-bytes"))
	}))
	t.Cleanup(upstream.Close)

	av := &switchableAV{}
	rec := &recSpy{}
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:           adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:            supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:             cache.AsArtifactCache(lc),
		Logger:            zerolog.Nop(),
		AVScanner:         av,
		Recorder:          rec,
		MalwareRecheckTTL: time.Hour,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	url := srv.URL + "/packages/py3/v/victim/victim-1.0.0-py3-none-any.whl"
	resp, err := http.Get(url)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed pull must pass and cache")

	ref := gate.PackageRef{Ecosystem: "pypi", Name: "victim", Version: "1.0.0"}
	entry, found := lc.Get(&ref)
	require.True(t, found)

	// Expire the malware check and flip the scanner.
	require.NoError(t, lc.MarkMalwareChecked(&ref, time.Now().Add(-72*time.Hour)))
	av.infected = true

	resp, err = http.Get(url)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "expired entry must be re-scanned and blocked")

	_, found = lc.Get(&ref)
	require.False(t, found, "infected artifact must be evicted from the index")
	_, statErr := os.Stat(entry.ArtifactPath)
	require.True(t, os.IsNotExist(statErr), "binary must be deleted from disk")

	last := rec.events[len(rec.events)-1]
	require.Equal(t, gate.VerdictBlock, last.Verdict)
	require.Equal(t, gate.GateMalware, last.Gate)
}
```

Add a sibling `TestLazyRecheckEvictsNewCVE` in the same file: same harness plus a CVE stub (copy `flipCVE`/`blockOnFindings` shapes from `internal/proxy/handler_recheck_test.go`), `CVERecheckTTL: time.Hour`, rewind via `lc.MarkCVEChecked(&ref, time.Now().Add(-72*time.Hour))`, flip to vulnerable, assert 403 + eviction + `gate.GateCVE` event.

- [ ] **Step 2: Write the Docker integration test**

Same file. Fake registry + `dockerproxy.New`:

```go
// TestLazyRecheckDockerBlocksExpiredImage: a cached clean image verdict whose
// TTL has lapsed re-runs the gate on the next manifest pull; a scanner that
// now reports a blocking CVE turns the pull into 403 and cascades the image's
// blobs out of the cache.
func TestLazyRecheckDockerBlocksExpiredImage(t *testing.T) {
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })

	const (
		cfgDigest   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		layerDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)
	manifest := `{"schemaVersion":2,` +
		`"mediaType":"application/vnd.docker.distribution.manifest.v2+json",` +
		`"config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"` + cfgDigest + `","size":2},` +
		`"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","digest":"` + layerDigest + `","size":2}]}`
	configBlob := `{"created":"` + time.Now().UTC().Add(-72*time.Hour).Format(time.RFC3339) + `"}`

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/library/app/manifests/latest",
			r.URL.Path == "/v2/library/app/manifests/"+manifestDigest(manifest):
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write([]byte(manifest))
		case r.URL.Path == "/v2/library/app/blobs/"+cfgDigest:
			_, _ = w.Write([]byte(configBlob))
		case r.URL.Path == "/v2/library/app/blobs/"+layerDigest:
			_, _ = w.Write([]byte("xx"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(registry.Close)

	scanner := &switchableImageScanner{}
	h := dockerproxy.New(dockerproxy.HandlerDeps{
		Upstreams:  []string{registry.URL},
		Scanner:    scanner,
		AV:         &switchableAV{},
		Filter:     supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Policy:     blockFindingsPolicy{},
		Cache:      lc,
		Logger:     zerolog.Nop(),
		RecheckTTL: time.Hour,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// Seed pull: clean, verdict + blobs cached.
	resp, err := http.Get(srv.URL + "/v2/library/app/manifests/latest")
	require.NoError(t, err)
	digest := resp.Header.Get("Docker-Content-Digest")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotEmpty(t, digest)

	// Expire the verdict, flip the scanner to a blocking CVE.
	imgRef := gate.PackageRef{Ecosystem: "docker", Name: "library/app", Version: digest}
	past := time.Now().Add(-72 * time.Hour)
	require.NoError(t, lc.MarkCVEChecked(&imgRef, past))
	require.NoError(t, lc.MarkMalwareChecked(&imgRef, past))
	scanner.vulnerable = true

	resp, err = http.Get(srv.URL + "/v2/library/app/manifests/" + digest)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "expired image must be re-gated and blocked")

	// Manifest bytes stay as the blocked-verdict record, but the blobs are gone.
	for _, d := range []string{cfgDigest, layerDigest} {
		blobRef := gate.PackageRef{Ecosystem: "docker", Name: "blobs", Version: d}
		_, found := lc.Get(&blobRef)
		require.False(t, found, "blob %s must be cascade-evicted", d)
	}
}
```

Support types in the same file:

```go
type switchableImageScanner struct{ vulnerable bool }

func (s *switchableImageScanner) ScanImage(context.Context, string) (*dockerproxy.ImageScanResult, error) {
	if s.vulnerable {
		return &dockerproxy.ImageScanResult{Findings: []gate.CVEFinding{{ID: "CVE-2026-7", Severity: gate.SeverityCritical}}}, nil
	}
	return &dockerproxy.ImageScanResult{}, nil
}

type blockFindingsPolicy struct{}

func (blockFindingsPolicy) Evaluate(_ *gate.PackageRef, res *gate.ScanResult) gate.PolicyDecision {
	if len(res.Findings) > 0 {
		return gate.PolicyDecision{Allowed: false, Reason: "cve_found", Findings: res.Findings}
	}
	return gate.PolicyDecision{Allowed: true, Reason: "ok"}
}

// manifestDigest computes the canonical sha256 digest string of a manifest
// body, matching what the adapter reports as Docker-Content-Digest.
func manifestDigest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha256:" + hex.EncodeToString(sum[:])
}
```

Verify `dockerproxy.ImageScanResult` / `ImageScanner` exported names against `trivy.go` (rg `type ImageScan`); adjust field names if they differ.

- [ ] **Step 3: Run, commit**

Run: `go test -tags=integration ./integration/ -run TestLazyRecheck -v`
Expected: PASS (three tests).
`git commit -m "test(integration): lazy TTL re-check evicts newly failing entries"`

---

### Task 7: Documentation

**Files:**
- Modify: `docs/configuration.md`, `docs/architecture.md`, `CHANGELOG.md`

**Interfaces:** none (prose).

- [ ] **Step 1: configuration.md**

Replace the `### cache.revalidation` section (lines ~158-170):

```markdown
### `cache.revalidation`

Lazy per-gate re-validation. A cache hit whose CVE or malware check is older
than its TTL re-runs **only that gate** before serving — CVE against current
osv.dev data, malware by re-scanning the cached bytes; Docker re-runs the full
image gate when its verdict is older than the smaller enabled TTL. An entry
that now fails is blocked and evicted (index entry and binary). A temporarily
unreachable scanner serves the previously clean entry and retries on the next
hit. Load is proportional to traffic, not cache size.

| Key | Default | Description |
|---|---|---|
| `cve_ttl_minutes` | `1440` | Re-run the CVE gate on hits older than this. `0` disables. |
| `malware_ttl_minutes` | `1440` | Re-scan cached bytes on hits older than this. `0` disables. |

Note: the CVE scanner keeps its own in-memory result cache
(`cve.cache_ttl_minutes`). A newly published CVE becomes visible only after
both TTLs lapse, so keep `cve.cache_ttl_minutes` ≤ `cve_ttl_minutes`.
```

In the `cve` table (line ~100), replace the `cache_ttl_minutes` description tail "Unrelated to the artifact cache, which has no TTL (see `cache.local.stale_after_days`)." with "Keep it at or below `cache.revalidation.cve_ttl_minutes` so lazy CVE re-checks see fresh data."

Reword the `## image_scan` intro (lines ~102-106):

```markdown
## `image_scan`

Trivy is the engine behind the **CVE gate for Docker images** — the same gate
that osv.dev implements for package ecosystems, applied to a different
artifact type. The verdict is returned on the **manifest** request, so a
rejected image never reaches the client. Severity threshold and denylist come
from the same active policy profile as package CVE decisions.
```

(keep the existing key table; drop the old "Separate engine from the osv.dev scanner" phrasing and the duplicated closing "Severity threshold…" line).

- [ ] **Step 2: architecture.md**

- Line ~19 diagram: remove `revalidate` from the row (and its arrow), keep alignment.
- Line ~52 (`internal/proxy/dockerproxy` row): append "Trivy here is the CVE gate's engine for images (policy shared with package CVE decisions)."
- Line ~56 (`internal/cache` row): "revalidation bookkeeping" → "per-gate check timestamps for lazy re-validation".
- Line ~57: delete the `internal/revalidate` row.
- Line ~105-108: replace "Verdicts are cached; repeat pulls record `CACHE`." with "Verdicts are cached and trusted until the re-check TTL (`cache.revalidation`) lapses, then re-evaluated on the next pull; repeat pulls inside the TTL record `CACHE`."
- Line ~119 (persistence table): "last-validated (revalidation)" → "per-gate check timestamps (lazy re-validation)".
- Line ~132-133: replace "The cache eviction worker and the revalidation sweeper are single background goroutines with coalescing triggers." with "The cache eviction worker is a single background goroutine with a coalescing trigger; re-validation is lazy on the serve path, so it adds no background load."

- [ ] **Step 3: CHANGELOG.md**

Under `## [Unreleased]`:

- **Changed**: add "Cache re-validation is now lazy: per-gate TTLs (`cache.revalidation.cve_ttl_minutes` / `malware_ttl_minutes`, default 24 h, `0` disables) re-run the expired gate on the next cache hit and evict entries that now fail. The background sweep and its keys (`enabled`, `interval_minutes`, `revalidate_after_hours`, `batch_size`) are removed; old keys in existing configs are ignored. Scanner outages serve the previously clean entry and retry on the next hit."
- **Removed** (new subsection if absent): "`internal/revalidate` background sweep — replaced by lazy TTL re-checks; re-validation load now scales with traffic instead of cache size."
- Delete the now-stale Unreleased "Added" bullet about the sweep info summary (lines ~20-21) — the sweep no longer exists in this release.

- [ ] **Step 4: Commit**

`git commit -m "docs: lazy TTL revalidation; trivy is the docker CVE gate engine"`

---

### Task 8: Final verification

- [ ] **Step 1: Full test suite**

Run: `go test ./... ; go test -tags=integration ./integration/`
Expected: PASS everywhere.

- [ ] **Step 2: Lint + vet + fmt**

Run: `golangci-lint run ./... ; gofmt -l .`
Expected: no findings, no files listed. Fix anything reported.

- [ ] **Step 3: Residue scan**

Run: `rg -n "last_validated|DueForRevalidation|MarkValidated|RevalidateAfter|revalidate\." --glob "!docs/superpowers/**" --glob "!CHANGELOG.md"`
Expected: no hits in code (index migration SQL strings mentioning `last_validated` are allowed — they implement the drop).

- [ ] **Step 4: Commit any fixes, push, PR**

PR into `main` titled `feat: lazy per-gate TTL revalidation replaces the sweep`; body links the spec; end with the 🤖 Generated with [Claude Code](https://claude.com/claude-code) footer.

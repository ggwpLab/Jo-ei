# Cache Stale Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drop the hardcoded 24 h cache TTL (verdict freshness is the re-validation sweep's job), define staleness as idle time via a new `cache.local.stale_after_days` config key, and let operators purge stale entries on demand through `POST /api/cache/cleanup` and a console button.

**Architecture:** `CacheEntry.ExpiresAt`/`IsExpired` are deleted; `Index.Get` stops discarding expired rows and `DueForRevalidation` stops excluding them (the `expires_at` column stays in the schema, written as 0 — no migration). `CacheStats.ExpiredBytes` becomes `StaleBytes` (`SUM(size_bytes) WHERE last_hit < now − stale_after`). A new `LocalCache.PurgeStale` deletes stale entries in batches reusing `Invalidate`, exposed to the console through an optional `CachePurger` interface and a new POST endpoint; the UI's hatched meter slice and legend switch from "expired" to "stale" and gain a Clean up button. Background behavior is unchanged: automatic deletion still happens only under size pressure (existing LRU eviction by `last_hit`).

**Tech Stack:** Go 1.x (stdlib, testify, modernc.org/sqlite), React JSX compiled by esbuild via `go generate`, viper/mapstructure config.

**Spec:** `docs/superpowers/specs/2026-07-14-cache-stale-cleanup-design.md`

## Global Constraints

- Work on branch `feat/console-cache-cleanup` (the `expired_bytes` work being reworked lives here, unmerged); PR into `main`. Never commit to `main` directly.
- Config key is exactly `cache.local.stale_after_days`; default **30**, applied at wiring when the value is ≤ 0; negative values rejected by `Validate()`. No explicit "off".
- API: `/api/overview` cache envelope gets `stale_bytes` + `stale_after_days` and **loses** `expired_bytes` (pre-merge rename, console is the only consumer). New endpoint: `POST /api/cache/cleanup` → `{"removed": N, "freed_bytes": M}`; 404 when no purger; 500 when the purge query fails.
- SQLite schema unchanged: `expires_at` column stays, new rows write 0 there.
- The `evictions` counter is untouched — manual purge is not an LRU eviction.
- UI legend copy: `reclaimable · unused {stale_after_days}d+ · {n} GB`; button label `Clean up` (`Cleaning…` while in flight).
- `web/console/app.bundle.js` is generated and committed; CI fails if stale. After any `web/console/src/*` edit, run `go generate ./...` and commit the regenerated bundle in the same commit.
- Run `golangci-lint run` before pushing (CI gate includes ineffassign/staticcheck/unused).
- Commit messages end with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: Config key `cache.local.stale_after_days`

**Files:**
- Modify: `internal/config/config.go` (LocalCache struct ~line 160, `Validate()` ~line 88)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `config.LocalCache.StaleAfterDays int` (mapstructure `stale_after_days`); `Validate()` errors on negative values. Task 2's factory reads this field.

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go` (after `TestValidate_RejectsNegativeRevalidation`, ~line 443):

```go
func TestValidate_RejectsNegativeStaleAfterDays(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c.Cache.Local.StaleAfterDays = -1
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stale_after_days")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestValidate_RejectsNegativeStaleAfterDays -v`
Expected: FAIL — compile error `c.Cache.Local.StaleAfterDays undefined`.

- [ ] **Step 3: Implement**

In `internal/config/config.go`, extend the LocalCache struct (~line 160):

```go
type LocalCache struct {
	Path      string `mapstructure:"path"`
	MaxSizeGB int    `mapstructure:"max_size_gb"`
	// StaleAfterDays marks entries idle this long as stale (reclaimable via
	// console cleanup). ≤0 uses the default (30) applied at wiring.
	StaleAfterDays int `mapstructure:"stale_after_days"`
}
```

In `Validate()`, after the `c.Cache.Revalidation.BatchSize` check (~line 88):

```go
	if c.Cache.Local.StaleAfterDays < 0 {
		return fmt.Errorf("cache.local.stale_after_days must not be negative")
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/ -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): cache.local.stale_after_days key

Idle threshold for cache staleness; <=0 falls back to the default 30
at wiring, negatives are rejected.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Drop TTL; stale-bytes metric replaces expired-bytes

**Files:**
- Modify: `internal/cache/cache.go` (CacheEntry ~line 11, CacheStats ~line 30)
- Modify: `internal/cache/index.go` (`Insert` ~153, `Get` ~177, `ExpiredSizeBytes` ~262, `DueForRevalidation` ~279)
- Modify: `internal/cache/local.go` (LocalCacheConfig ~17, `Put` ~101, `Stats` ~139)
- Modify: `internal/cache/factory.go`
- Test: `internal/cache/index_test.go`, `internal/cache/local_internal_test.go`

**Interfaces:**
- Consumes: `config.LocalCache.StaleAfterDays` from Task 1.
- Produces: `LocalCacheConfig{RootPath string, MaxSizeGB int, StaleAfter time.Duration}` (TTL field gone); `CacheEntry` without `ExpiresAt`/`IsExpired`; `CacheStats.StaleBytes int64` (ExpiredBytes gone); `Index.StaleSizeBytes(cutoff int64) (int64, error)`; exported `cache.DefaultStaleAfterDays = 30`. Tasks 3–5 rely on all of these.

- [ ] **Step 1: Write the failing tests**

In `internal/cache/index_test.go`:

Replace `TestIndex_DueForRevalidationAndMarkValidated` (lines 141–179) — the "expired" row is now due too:

```go
func TestIndex_DueForRevalidationAndMarkValidated(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	now := time.Now().UTC()
	// stored_at drives initial last_validated (set by Insert).
	old := gate.PackageRef{Ecosystem: "pypi", Name: "old", Version: "1.0"}
	fresh := gate.PackageRef{Ecosystem: "pypi", Name: "fresh", Version: "1.0"}
	older := gate.PackageRef{Ecosystem: "pypi", Name: "older", Version: "1.0"}

	require.NoError(t, idx.Insert(&old, &cache.CacheEntry{
		ArtifactPath: "/c/old", ScanClean: true, ScanJSON: `{"clean":true}`,
		StoredAt: now.Add(-48 * time.Hour), SizeBytes: 1,
	}))
	require.NoError(t, idx.Insert(&fresh, &cache.CacheEntry{
		ArtifactPath: "/c/fresh", ScanClean: true,
		StoredAt: now, SizeBytes: 1,
	}))
	require.NoError(t, idx.Insert(&older, &cache.CacheEntry{
		ArtifactPath: "/c/older", ScanClean: true,
		StoredAt: now.Add(-72 * time.Hour), SizeBytes: 1,
	}))

	// Due = last_validated older than 24h ago, oldest first. There is no TTL:
	// every idle entry stays revalidation-eligible until evicted or purged.
	cutoff := now.Add(-24 * time.Hour).Unix()
	due, err := idx.DueForRevalidation(cutoff, 10)
	require.NoError(t, err)
	require.Len(t, due, 2)
	assert.Equal(t, "older", due[0].Ref.Name)
	assert.Equal(t, "old", due[1].Ref.Name)
	assert.Equal(t, "/c/old", due[1].FilePath)
	assert.True(t, due[1].ScanClean)
	assert.Equal(t, `{"clean":true}`, due[1].ScanJSON)

	// After marking validated now, neither is due.
	require.NoError(t, idx.MarkValidated(&old, now.Unix()))
	require.NoError(t, idx.MarkValidated(&older, now.Unix()))
	due, err = idx.DueForRevalidation(cutoff, 10)
	require.NoError(t, err)
	assert.Empty(t, due)
}
```

Add after it:

```go
func TestIndex_StaleSizeBytes(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	now := time.Now().UTC()
	// Insert seeds last_hit from StoredAt, so backdating StoredAt makes an
	// entry stale without touching SQL directly.
	stale := gate.PackageRef{Ecosystem: "pypi", Name: "stale", Version: "1.0"}
	fresh := gate.PackageRef{Ecosystem: "pypi", Name: "fresh", Version: "1.0"}
	require.NoError(t, idx.Insert(&stale, &cache.CacheEntry{
		ArtifactPath: "/c/stale", StoredAt: now.Add(-40 * 24 * time.Hour), SizeBytes: 100,
	}))
	require.NoError(t, idx.Insert(&fresh, &cache.CacheEntry{
		ArtifactPath: "/c/fresh", StoredAt: now, SizeBytes: 11,
	}))

	got, err := idx.StaleSizeBytes(now.Add(-30 * 24 * time.Hour).Unix())
	require.NoError(t, err)
	assert.Equal(t, int64(100), got, "only the idle entry counts")
}
```

In the same file, delete every `ExpiresAt: ...` line from `CacheEntry` literals (the field is being removed): lines ~33, 58, 65, 108, 130, 197. Delete the `TestIndex_ExpiredSizeBytes` test if present (search for `ExpiredSizeBytes`).

In `internal/cache/local_internal_test.go`:

Replace every `TTL: time.Hour` with `StaleAfter: time.Hour` (5 occurrences: lines 91, 112, 134, 161, 168), and delete the `ExpiresAt: time.Now().UTC().Add(time.Hour),` line from the migration test's Insert literal (line 71). In `internal/cache/local_test.go:21`, replace `TTL: 24 * time.Hour,` with `StaleAfter: 24 * time.Hour,`. Remove the `ExpiresAt`/`StoredAt` expired-entry setup by replacing `TestLocalCache_StatsReportsExpiredBytes` (lines 111–131) with:

```go
func TestLocalCache_StatsReportsStaleBytes(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	fresh := &gate.PackageRef{Ecosystem: "pypi", Name: "fresh", Version: "1.0"}
	require.NoError(t, lc.Put(fresh, writeTemp(t, "fresh-data"), true, ""))

	// Insert an already-idle entry directly; Insert seeds last_hit from StoredAt.
	stale := &gate.PackageRef{Ecosystem: "pypi", Name: "stale", Version: "1.0"}
	require.NoError(t, lc.index.Insert(stale, &CacheEntry{
		ArtifactPath: filepath.Join(lc.cfg.RootPath, "gone.bin"),
		StoredAt:     time.Now().UTC().Add(-2 * time.Hour),
		SizeBytes:    123,
	}))

	stats, err := lc.Stats()
	require.NoError(t, err)
	assert.Equal(t, int64(123), stats.StaleBytes, "only the idle entry's bytes are reclaimable")
}
```

Also add a regression test for the TTL removal (after `TestNewIndex_MigratesLegacyDatabase`):

```go
func TestIndex_GetIgnoresLegacyExpiry(t *testing.T) {
	idx, err := NewIndex(filepath.Join(t.TempDir(), "i.db"))
	require.NoError(t, err)
	defer idx.Close()

	ref := gate.PackageRef{Ecosystem: "pypi", Name: "legacy", Version: "1.0"}
	require.NoError(t, idx.Insert(&ref, &CacheEntry{
		ArtifactPath: "/c/legacy", StoredAt: time.Now().UTC().Add(-48 * time.Hour), SizeBytes: 1,
	}))
	// Simulate a row written by a pre-stale binary whose TTL has lapsed.
	_, err = idx.db.Exec(`UPDATE artifacts SET expires_at = ? WHERE name = 'legacy'`,
		time.Now().Add(-time.Hour).Unix())
	require.NoError(t, err)

	_, found := idx.Get(&ref)
	assert.True(t, found, "expiry is gone; old expires_at values must not hide entries")
}
```

(This one lives in `local_internal_test.go` — it needs the unexported `idx.db`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cache/`
Expected: FAIL — compile errors (`StaleAfter`, `StaleBytes`, `StaleSizeBytes` undefined; `ExpiresAt` still required by Insert).

- [ ] **Step 3: Implement — `internal/cache/cache.go`**

Replace the `CacheEntry` type and delete `IsExpired` (lines 10–27):

```go
// CacheEntry stores an artifact path and its scan results.
type CacheEntry struct {
	// ArtifactPath is the absolute path to the cached file on disk.
	ArtifactPath string
	// ScanClean is true if all scanners passed.
	ScanClean bool
	// ScanJSON stores the serialized ScanResult for future inspection.
	ScanJSON  string
	StoredAt  time.Time
	HitCount  int64
	SizeBytes int64
}
```

In `CacheStats`, replace the `ExpiredBytes` field (lines 35–37):

```go
	// StaleBytes is the total size of entries idle longer than the configured
	// staleness threshold — reclaimable via PurgeStale / console cleanup.
	StaleBytes int64
```

- [ ] **Step 4: Implement — `internal/cache/index.go`**

`Insert` (~line 153): entries no longer carry an expiry; keep the column for schema compatibility and write 0. Replace the `Exec` call:

```go
	_, err := idx.db.Exec(`
		INSERT INTO artifacts
			(ecosystem, name, version, classifier, file_path, scan_clean, scan_json,
			 stored_at, expires_at, last_hit, hit_count, size_bytes, last_validated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ecosystem, name, version, classifier) DO UPDATE SET
			file_path      = excluded.file_path,
			scan_clean     = excluded.scan_clean,
			scan_json      = excluded.scan_json,
			stored_at      = excluded.stored_at,
			expires_at     = excluded.expires_at,
			last_hit       = excluded.last_hit,
			size_bytes     = excluded.size_bytes,
			last_validated = excluded.last_validated`,
		ref.Ecosystem, ref.Name, ref.Version, ref.Classifier,
		entry.ArtifactPath, boolToInt(entry.ScanClean), entry.ScanJSON,
		// expires_at is legacy: entries no longer expire (freshness is the
		// re-validation sweep's job); the column stays for schema compatibility.
		entry.StoredAt.Unix(), 0,
		entry.StoredAt.Unix(), 0, entry.SizeBytes, entry.StoredAt.Unix(),
	)
	return err
```

`Get` (~line 176): drop `expires_at` from the query and the expiry check:

```go
// Get retrieves a cache entry. Returns (nil, false) if not found.
func (idx *Index) Get(ref *gate.PackageRef) (*CacheEntry, bool) {
	row := idx.db.QueryRow(`
		SELECT file_path, scan_clean, scan_json, stored_at, hit_count, size_bytes
		FROM artifacts
		WHERE ecosystem=? AND name=? AND version=? AND classifier=?`,
		ref.Ecosystem, ref.Name, ref.Version, ref.Classifier,
	)

	var (
		entry        CacheEntry
		scanCleanInt int
		storedAtUnix int64
	)
	err := row.Scan(
		&entry.ArtifactPath, &scanCleanInt, &entry.ScanJSON,
		&storedAtUnix, &entry.HitCount, &entry.SizeBytes,
	)
	if err != nil {
		return nil, false
	}

	entry.ScanClean = scanCleanInt == 1
	entry.StoredAt = time.Unix(storedAtUnix, 0).UTC()
	return &entry, true
}
```

(The `err == sql.ErrNoRows` special case collapses into the generic `err != nil` return; delete the now-unused `"database/sql"` import if nothing else uses it — `sql.DB`/`sql.NullString` still do, so it stays.)

Replace `ExpiredSizeBytes` (~lines 260–267):

```go
// StaleSizeBytes returns the sum of size_bytes for entries whose last_hit is
// older than cutoff — the reclaimable portion surfaced in the console.
func (idx *Index) StaleSizeBytes(cutoff int64) (int64, error) {
	var total int64
	err := idx.db.QueryRow(`SELECT COALESCE(SUM(size_bytes),0) FROM artifacts WHERE last_hit < ?`,
		cutoff).Scan(&total)
	return total, err
}
```

`DueForRevalidation` (~line 279): drop the expiry filter:

```go
// DueForRevalidation returns up to limit entries whose last_validated is older
// than `before` (a unix timestamp), oldest-first.
func (idx *Index) DueForRevalidation(before int64, limit int) ([]RevalEntry, error) {
	rows, err := idx.db.Query(`
		SELECT ecosystem, name, version, classifier, file_path, scan_clean, scan_json
		FROM artifacts
		WHERE last_validated < ?
		ORDER BY last_validated ASC
		LIMIT ?`, before, limit,
	)
```

(rest of the function body unchanged; the local `now` variable is deleted).

- [ ] **Step 5: Implement — `internal/cache/local.go`**

`LocalCacheConfig` (~line 17):

```go
// LocalCacheConfig configures the local filesystem cache.
type LocalCacheConfig struct {
	RootPath  string
	MaxSizeGB int
	// StaleAfter is the idle threshold: entries not hit for this long count
	// as stale (reclaimable via PurgeStale / the console Clean up button).
	StaleAfter time.Duration
}
```

`Put` (~line 101): delete the TTL block and the `ExpiresAt` field:

```go
	entry := &CacheEntry{
		ArtifactPath: destPath,
		ScanClean:    scanClean,
		ScanJSON:     scanJSON,
		StoredAt:     time.Now().UTC(),
		SizeBytes:    written,
	}
```

Add the cutoff helper (before `Stats`):

```go
// staleCutoff is the last_hit unix timestamp below which an entry is stale.
func (lc *LocalCache) staleCutoff() int64 {
	return time.Now().Add(-lc.cfg.StaleAfter).Unix()
}
```

`Stats` (~line 139): swap the expired call:

```go
	stale, err := lc.index.StaleSizeBytes(lc.staleCutoff())
	if err != nil {
		return CacheStats{}, err
	}
	return CacheStats{Entries: count, SizeBytes: size, Evictions: lc.evictions.Load(), StaleBytes: stale}, nil
```

- [ ] **Step 6: Implement — `internal/cache/factory.go`**

Replace the whole file body:

```go
package cache

import (
	"fmt"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/config"
)

// DefaultStaleAfterDays is the idle threshold applied when
// cache.local.stale_after_days is unset or zero.
const DefaultStaleAfterDays = 30

// New constructs the cache backend selected by cfg.Backend.
// "" and "local" build a LocalCache; "s3" is reserved but not yet implemented
// (fail-fast rather than silently falling back to local).
func New(cfg config.CacheConfig) (Cache, error) {
	switch cfg.Backend {
	case "", "local":
		days := cfg.Local.StaleAfterDays
		if days <= 0 {
			days = DefaultStaleAfterDays
		}
		return NewLocalCache(LocalCacheConfig{
			RootPath:   cfg.Local.Path,
			MaxSizeGB:  cfg.Local.MaxSizeGB,
			StaleAfter: time.Duration(days) * 24 * time.Hour,
		})
	case "s3":
		return nil, fmt.Errorf("s3 cache backend not yet implemented")
	default:
		return nil, fmt.Errorf("unknown cache backend %q (want local|s3)", cfg.Backend)
	}
}
```

- [ ] **Step 7: Run cache tests**

Run: `go test ./internal/cache/`
Expected: PASS (all `TTL:`/`ExpiresAt:` occurrences in the cache package's tests were handled in Step 1; `factory_test.go` has none).

- [ ] **Step 8: Fix remaining compile fallout across the repo**

Run: `go build ./... && go test ./...`
Expected failures to fix (only these consume the removed API — verified by grep during planning):
- `internal/console/server_test.go:71` still sets `ExpiredBytes` in `fakeStats` — leave for Task 4 if the build of that package fails; if so, change `ExpiredBytes: 7 << 20` to `StaleBytes: 7 << 20` and `server.go:172` `"expired_bytes": cs.ExpiredBytes` to `"stale_bytes": cs.StaleBytes` now (Task 4 refines the envelope further); update `server_test.go:122,134` field/assert names to match.
Then: `go build ./... && go test ./...` → PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/cache/ internal/console/
git commit -m "feat(cache): drop TTL; idle-based staleness replaces expiry

Entries no longer expire: verdict freshness is the re-validation
sweep's job, artifacts are immutable, and expired entries were never
actually deleted anyway (Get left row and file in place). Staleness is
now idle time: last_hit older than LocalCacheConfig.StaleAfter
(cache.local.stale_after_days, default 30). Stats reports StaleBytes;
DueForRevalidation no longer excludes formerly-expired rows.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: `LocalCache.PurgeStale`

**Files:**
- Modify: `internal/cache/index.go` (add `StaleCandidate` + `StaleCandidates` after `LRUCandidates`, ~line 251)
- Modify: `internal/cache/local.go` (add `PurgeStale` after `Stats`)
- Test: `internal/cache/local_internal_test.go`

**Interfaces:**
- Consumes: `Index.StaleCandidates`, `LocalCache.Invalidate`, `staleCutoff()` from Task 2.
- Produces: `LocalCache.PurgeStale() (removed int64, freedBytes int64, err error)` — Task 4's console `CachePurger` interface matches this signature exactly. `Index.StaleCandidates(cutoff int64, n int) ([]StaleCandidate, error)` with `StaleCandidate{Ref gate.PackageRef, SizeBytes int64}`.

- [ ] **Step 1: Write the failing test**

Add to `internal/cache/local_internal_test.go`:

```go
func TestLocalCache_PurgeStale(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	fresh := &gate.PackageRef{Ecosystem: "pypi", Name: "fresh", Version: "1.0"}
	require.NoError(t, lc.Put(fresh, writeTemp(t, "fresh-data"), true, ""))

	// Two idle entries with real files on disk; Insert seeds last_hit from StoredAt.
	var stalePaths []string
	for i, n := range []string{"s1", "s2"} {
		p := filepath.Join(lc.cfg.RootPath, n+".bin")
		require.NoError(t, os.WriteFile(p, []byte("stale-data"), 0644))
		stalePaths = append(stalePaths, p)
		ref := &gate.PackageRef{Ecosystem: "pypi", Name: n, Version: "1.0"}
		require.NoError(t, lc.index.Insert(ref, &CacheEntry{
			ArtifactPath: p,
			StoredAt:     time.Now().UTC().Add(-time.Duration(2+i) * time.Hour),
			SizeBytes:    50,
		}))
	}

	removed, freed, err := lc.PurgeStale()
	require.NoError(t, err)
	assert.Equal(t, int64(2), removed)
	assert.Equal(t, int64(100), freed)
	for _, p := range stalePaths {
		_, statErr := os.Stat(p)
		assert.True(t, os.IsNotExist(statErr), "purged artifact %s must be deleted", p)
	}

	// The fresh entry survives, and nothing is stale anymore.
	_, found := lc.Get(fresh)
	assert.True(t, found)
	stats, err := lc.Stats()
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.StaleBytes)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache/ -run TestLocalCache_PurgeStale -v`
Expected: FAIL — `lc.PurgeStale undefined`.

- [ ] **Step 3: Implement — `internal/cache/index.go`**

After `LRUCandidates` (~line 251):

```go
// StaleCandidate is a stale entry surfaced for purging: the ref plus its size
// so the purge can report freed bytes without a second lookup.
type StaleCandidate struct {
	Ref       gate.PackageRef
	SizeBytes int64
}

// StaleCandidates returns up to n entries whose last_hit is older than cutoff,
// oldest first.
func (idx *Index) StaleCandidates(cutoff int64, n int) ([]StaleCandidate, error) {
	rows, err := idx.db.Query(`
		SELECT ecosystem, name, version, classifier, size_bytes
		FROM artifacts WHERE last_hit < ? ORDER BY last_hit ASC LIMIT ?`, cutoff, n,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StaleCandidate
	for rows.Next() {
		var c StaleCandidate
		if err := rows.Scan(&c.Ref.Ecosystem, &c.Ref.Name, &c.Ref.Version, &c.Ref.Classifier, &c.SizeBytes); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Implement — `internal/cache/local.go`**

After `Stats`:

```go
// purgeBatch is how many stale candidates PurgeStale fetches per round.
const purgeBatch = 100

// PurgeStale removes every entry idle longer than cfg.StaleAfter and returns
// how many entries were removed and their total size. Individual failures are
// skipped (same policy as evictToSize); a round that makes no progress aborts
// instead of spinning on undeletable rows.
func (lc *LocalCache) PurgeStale() (removed, freedBytes int64, err error) {
	cutoff := lc.staleCutoff()
	for {
		candidates, err := lc.index.StaleCandidates(cutoff, purgeBatch)
		if err != nil {
			return removed, freedBytes, err
		}
		if len(candidates) == 0 {
			return removed, freedBytes, nil
		}
		progress := false
		for _, cand := range candidates {
			c := cand
			if lc.Invalidate(&c.Ref) == nil {
				removed++
				freedBytes += c.SizeBytes
				progress = true
			}
		}
		if !progress {
			return removed, freedBytes, fmt.Errorf("cache purge: no progress on %d stale entries", len(candidates))
		}
	}
}
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/cache/ -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cache/index.go internal/cache/local.go internal/cache/local_internal_test.go
git commit -m "feat(cache): PurgeStale deletes idle entries on demand

Batched over StaleCandidates (last_hit < now - StaleAfter), reusing
Invalidate for file+row removal; bails on a zero-progress round.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Console — cleanup endpoint + envelope fields

**Files:**
- Modify: `internal/console/server.go` (Config ~line 55, `NewHandler` routes ~line 100, cache envelope ~line 166)
- Test: `internal/console/server_test.go`

**Interfaces:**
- Consumes: `LocalCache.PurgeStale() (removed, freedBytes int64, err error)` from Task 3 (via a new local interface, not a cache-package import).
- Produces: `console.CachePurger` interface; `console.Config.Purger CachePurger` and `Config.CacheStaleAfterDays int` fields — Task 5 (main.go) sets both. Wire shape: overview `cache.stale_bytes`, `cache.stale_after_days`; `POST /api/cache/cleanup` → `{"removed": N, "freed_bytes": M}` / 404 `{"error":"no_cache"}` / 500 `{"error":"purge_failed"}`.

- [ ] **Step 1: Write the failing tests**

In `internal/console/server_test.go`:

Add next to `fakeStats` (~line 48):

```go
type fakePurger struct {
	removed, freed int64
	err            error
	calls          int
}

func (f *fakePurger) PurgeStale() (int64, int64, error) {
	f.calls++
	return f.removed, f.freed, f.err
}
```

In `newFixture`, add to the `console.Config` literal (after `CacheMaxBytes`):

```go
		CacheStaleAfterDays: 30,
		Purger:              &fakePurger{removed: 12, freed: 5 << 20},
```

In `TestOverview`, the `Cache` struct becomes:

```go
		Cache struct {
			Objects        int64   `json:"objects"`
			MaxBytes       int64   `json:"max_bytes"`
			HitRate        float64 `json:"hit_rate"`
			StaleBytes     int64   `json:"stale_bytes"`
			StaleAfterDays int     `json:"stale_after_days"`
		} `json:"cache"`
```

and the assertion (line ~134):

```go
	assert.Equal(t, int64(7<<20), body.Cache.StaleBytes)
	assert.Equal(t, 30, body.Cache.StaleAfterDays)
```

(`fakeStats` in the fixture must read `StaleBytes: 7 << 20` — done in Task 2 Step 8 if not already.)

Add the endpoint tests:

```go
func TestCacheCleanup(t *testing.T) {
	f := newFixture(t)

	resp, err := http.Post(f.srv.URL+"/api/cache/cleanup", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Removed    int64 `json:"removed"`
		FreedBytes int64 `json:"freed_bytes"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, int64(12), body.Removed)
	assert.Equal(t, int64(5<<20), body.FreedBytes)
}

func TestCacheCleanup_NoPurger(t *testing.T) {
	h := console.NewHandler(console.Config{
		Store:       newTelemetryStore(t),
		Broadcaster: telemetry.NewBroadcaster(),
		Logger:      zerolog.Nop(),
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/cache/cleanup", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/console/`
Expected: FAIL — `console.Config` has no `Purger`/`CacheStaleAfterDays` fields.

- [ ] **Step 3: Implement — `internal/console/server.go`**

After `CacheStatsProvider` (~line 30):

```go
// CachePurger deletes stale cache entries on demand; *cache.LocalCache
// satisfies it.
type CachePurger interface {
	PurgeStale() (removed int64, freedBytes int64, err error)
}
```

In `Config`, after `CacheMaxBytes`:

```go
	// Purger enables POST /api/cache/cleanup; nil returns 404 there.
	Purger CachePurger
	// CacheStaleAfterDays is the effective idle threshold, echoed to the UI
	// for the "unused Nd+" legend.
	CacheStaleAfterDays int
```

In `NewHandler`, after the `PUT /api/registries` route:

```go
	mux.HandleFunc("POST /api/cache/cleanup", s.cacheCleanup)
```

In `overview`, the cache envelope becomes:

```go
		"cache": map[string]any{
			"objects":          cs.Entries,
			"size_bytes":       cs.SizeBytes,
			"max_bytes":        s.cfg.CacheMaxBytes,
			"hit_rate":         hitRate,
			"evictions":        cs.Evictions,
			"stale_bytes":      cs.StaleBytes,
			"stale_after_days": s.cfg.CacheStaleAfterDays,
		},
```

New handler (after `overview`):

```go
// cacheCleanup deletes stale cache entries (idle longer than the configured
// threshold) and reports what was freed.
func (s *server) cacheCleanup(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Purger == nil {
		s.writeJSON(w, http.StatusNotFound, map[string]any{"error": "no_cache"})
		return
	}
	removed, freed, err := s.cfg.Purger.PurgeStale()
	if err != nil {
		s.cfg.Logger.Error().Err(err).Msg("console: cache cleanup")
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "purge_failed"})
		return
	}
	s.cfg.Logger.Info().Int64("removed", removed).Int64("freed_bytes", freed).Msg("console: cache cleanup")
	s.writeJSON(w, http.StatusOK, map[string]any{"removed": removed, "freed_bytes": freed})
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/console/ -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/console/server.go internal/console/server_test.go
git commit -m "feat(console): POST /api/cache/cleanup purges stale entries

Optional CachePurger in the server config; overview envelope carries
stale_bytes and stale_after_days for the cache card legend.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Wiring in cmd/jo-ei — purger, threshold, revalidation-off warning

**Files:**
- Modify: `cmd/jo-ei/main.go` (revalidation block ~line 305–347, console.Config ~line 403–415)

**Interfaces:**
- Consumes: `console.CachePurger`, `console.Config.Purger`/`CacheStaleAfterDays` (Task 4); `cache.DefaultStaleAfterDays` (Task 2).
- Produces: running binary behavior only.

- [ ] **Step 1: Add the revalidation-off warning**

The block at ~line 305 currently has no `else` on the outer `if`. Add one:

```go
	if cfg.Cache.Revalidation.Enabled {
		// ... existing body unchanged ...
	} else {
		logger.Warn().Msg("cache.revalidation.enabled is false — cached artifacts are never rescanned (entries have no TTL; they persist until LRU-evicted or purged)")
	}
```

- [ ] **Step 2: Pass purger + threshold to the console**

Before the `root.Handle("/api/", ...)` call (~line 403):

```go
	// The console needs the effective staleness threshold (mirrors the default
	// cache.New applies) and, when the backend supports it, on-demand purge.
	staleDays := cfg.Cache.Local.StaleAfterDays
	if staleDays <= 0 {
		staleDays = cache.DefaultStaleAfterDays
	}
	var cachePurger console.CachePurger
	if p, ok := artifactCache.(console.CachePurger); ok {
		cachePurger = p
	}
```

In the `console.Config` literal, after `CacheMaxBytes`:

```go
		Purger:              cachePurger,
		CacheStaleAfterDays: staleDays,
```

- [ ] **Step 3: Build and run the full suite**

Run: `go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add cmd/jo-ei/main.go
git commit -m "feat: wire cache purger and stale threshold into the console

Warn at startup when revalidation is disabled, since entries no longer
carry a TTL and would otherwise never be rescanned.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Console UI — stale legend + Clean up button

**Files:**
- Modify: `web/console/src/api.js` (defaults ~line 42, `applyOverview` ~line 100, exports ~line 225)
- Modify: `web/console/src/registries.jsx` (cache panel, lines 64–75 and 145–176)
- Modify (generated): `web/console/app.bundle.js`

**Interfaces:**
- Consumes: overview `cache.stale_bytes`/`cache.stale_after_days`, `POST /api/cache/cleanup` (Task 4); global `notify({kind, code, title, msg})` prop already passed to `Registries`.
- Produces: presentation + `JOEI.cleanupCache()` helper.

- [ ] **Step 1: api.js — data mapping and cleanup helper**

Line 42, replace the cache defaults:

```js
    cache: { used_gb: 0, max_gb: 0, stale_gb: 0, stale_after_days: 0, objects: "0", hit_rate: 0, evictions: 0 },
```

In `applyOverview` (~line 101), replace the `expired_gb` line with:

```js
      stale_gb: +((o.cache.stale_bytes || 0) / GB).toFixed(2),
      stale_after_days: o.cache.stale_after_days || 0,
```

After `saveRegistries` (~line 201), add:

```js
  // Purge stale cache entries (idle past the server-side threshold), then
  // refresh so the meter reflects the freed space immediately.
  async function cleanupCache() {
    const res = await fetch("/api/cache/cleanup", { method: "POST" });
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON error body */ }
    if (!res.ok) throw new Error((data && data.error) || "cache cleanup failed (HTTP " + res.status + ")");
    await load();
    return data; // { removed, freed_bytes }
  }
```

And register it next to the other exports (~line 228):

```js
  J.cleanupCache = cleanupCache;
```

- [ ] **Step 2: registries.jsx — stale slice, legend, button**

Replace lines 66–69 (the expired slice computation):

```jsx
  // Stale entries (idle past the threshold) are part of used space; hatch that
  // slice — it is what the Clean up button would reclaim.
  const stalePct = c.max_gb > 0 ? Math.min(usedPct, (c.stale_gb / c.max_gb) * 100) : 0;
  const livePct = usedPct - stalePct;
```

Inside `Registries`, after the `[saving, setSaving]` state (~line 84), add:

```jsx
  const [cleaning, setCleaning] = useState(false);
  const cleanup = () => {
    setCleaning(true);
    JOEI.cleanupCache()
      .then(({ removed, freed_bytes }) => notify({ kind: "ok", code: "200 OK", title: "Cache cleaned",
        msg: <>Freed <b>{(freed_bytes / 1024 ** 3).toFixed(2)} GB</b> — {removed} objects removed.</> }))
      .catch((err) => notify({ kind: "block", code: "500 Internal Server Error", title: "Cleanup failed",
        msg: String(err.message || err) }))
      .finally(() => setCleaning(false));
  };
```

In the cache panel, replace the meter (`lines ~162–165`):

```jsx
        <div className="cache-meter">
          <i className="used" style={{ width: livePct + "%" }}></i>
          {stalePct > 0 && <i className="evict" style={{ width: stalePct + "%" }}></i>}
        </div>
```

and the legend span (`{expiredPct > 0 && (...)}`, lines ~170–174):

```jsx
          {c.stale_gb > 0 && (
            <span className="muted right row" style={{ fontSize: 11, alignItems: "center", gap: 8 }}>
              <i className="legend-chip"></i>reclaimable · unused {c.stale_after_days}d+ · <b className="mono">{c.stale_gb} GB</b>
              <button className="btn sm" onClick={cleanup} disabled={cleaning}>{cleaning ? "Cleaning…" : "Clean up"}</button>
            </span>
          )}
```

- [ ] **Step 3: Verify no stale references remain**

Run: `grep -rn "expired" web/console/src/`
Expected: no matches.

- [ ] **Step 4: Regenerate the bundle and test**

Run: `go generate ./... && go test ./web/`
Expected: `web/console/app.bundle.js` modified (`git status`), tests PASS.

- [ ] **Step 5: Commit**

```bash
git add web/console/src/api.js web/console/src/registries.jsx web/console/app.bundle.js
git commit -m "feat(console): Clean up button reclaims stale cache entries

The hatched meter slice and legend now mean idle-past-threshold
(stale), not TTL-expired; the button calls POST /api/cache/cleanup and
toasts the freed space.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Config sample, docs, changelog, final verification

**Files:**
- Modify: `config.yaml` (cache.local block, lines 78–80)
- Modify: `docs/configuration.md` (cache table, ~line 150)
- Modify: `CHANGELOG.md` (`[Unreleased]`, lines 8–21)

**Interfaces:**
- Consumes: nothing.
- Produces: operator-facing docs; `release-notes.sh` builds notes from CHANGELOG.

- [ ] **Step 1: config.yaml**

Replace the `local:` block:

```yaml
  local:
    path: "/var/cache/jo-ei"
    max_size_gb: 100
    # Entries not requested for this long count as stale: the console shows
    # them as reclaimable and its Clean up button deletes them. There is no
    # TTL — verdict freshness is the re-validation sweep's job (below).
    stale_after_days: 30
```

- [ ] **Step 2: docs/configuration.md**

After the `local.max_size_gb` row (~line 150), add:

```markdown
| `local.stale_after_days` | `30` | Entries idle this long are stale: shown as reclaimable in the console and deleted by its Clean up button (`POST /api/cache/cleanup`). |
```

- [ ] **Step 3: CHANGELOG.md**

Replace the `[Unreleased]` section (lines 8–21) with:

```markdown
## [Unreleased]

### Added

- Cache cleanup on demand: `POST /api/cache/cleanup` and a Clean up button on
  the console cache card delete stale entries and report the freed space.

### Changed

- Cache entries no longer expire on a fixed 24 h TTL — verdict freshness is
  handled by the re-validation sweep, and TTL-expired entries were never
  actually deleted from disk anyway. Entries idle longer than
  `cache.local.stale_after_days` (default 30) are reported as reclaimable.
- Console: lifetime counters are labeled "total" instead of "since start" —
  they persist in SQLite and survive restarts.
- Console: the local-cache card shows a 30-day hit-rate sparkline, and the
  usage meter marks the reclaimable (stale) slice of used space with a
  hatched segment and legend.

### Fixed

- Cache: LRU evictions are now counted and reported; the console previously
  always showed 0 evictions.
```

- [ ] **Step 4: Full verification**

Run, expecting success on each:

```bash
go test ./...
golangci-lint run
go generate ./... && git diff --exit-code -- web/console/app.bundle.js
```

- [ ] **Step 5: Commit**

```bash
git add config.yaml docs/configuration.md CHANGELOG.md
git commit -m "docs: stale_after_days config, changelog for cache stale cleanup

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Manual verification (after all tasks)

Run the proxy with the console enabled and ≥ 1 cached artifact:

1. Cache card: hatch + legend `reclaimable · unused 30d+ … GB` appear only when stale bytes > 0 (backdate `last_hit` in `<cache>/index.db` to fake it: `sqlite3 index.db "UPDATE artifacts SET last_hit = strftime('%s','now') - 40*86400"`).
2. Clean up button: click → toast `Freed X GB — N objects removed`, meter shrinks, legend disappears.
3. `curl -X POST -u admin:… http://…/api/cache/cleanup` → `{"removed":0,"freed_bytes":0}` when nothing is stale.
4. Set `cache.revalidation.enabled: false` → startup log warns that artifacts are never rescanned.
5. Previously-cached entries (with old real `expires_at` values) still serve as hits.

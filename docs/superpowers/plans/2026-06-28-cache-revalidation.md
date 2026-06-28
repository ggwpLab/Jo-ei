# Cache Re-validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a background sweep that periodically re-runs the gates over cached artifacts and evicts any that now produce a definitive block verdict.

**Architecture:** A new `internal/revalidate` package owns a `Sweeper` and per-ecosystem `Revalidator`s. The cache gains a `last_validated` column plus `DueForRevalidation`/`MarkValidated` so the sweep processes only stale entries in bounded batches. The Docker revalidator lives in `dockerproxy` (it needs the unexported gate) and implements `revalidate.Revalidator`. Everything is wired in `main.go` next to the health monitor.

**Tech Stack:** Go, SQLite (`modernc.org/sqlite`), zerolog, testify.

## Global Constraints

- Evict **only** on a definitive non-clean verdict. A scanner that errors (clamd timeout, osv 5xx, gate infra error) returns `Retry` — the entry is left in place and `last_validated` is not bumped.
- The cache package must not import scanners/proxy-handlers. `revalidate` imports `cache` and `proxy`; `dockerproxy` imports `revalidate`; `revalidate` never imports `dockerproxy` (no cycle).
- Supply-chain time rule is not re-run; denylist changes are caught by the policy step.
- TTL/LRU eviction is unchanged and orthogonal.
- Follow existing patterns: migrations mirror `migrateClassifier`; lifecycle (`Start`/`Close` with context+WaitGroup) mirrors `health.Monitor`.
- Defaults applied at wiring time: interval 60 min, revalidate-after 24 h, batch 50.

---

### Task 1: Cache `last_validated` column, migration, and query/update methods

**Files:**
- Create: `internal/cache/reval.go`
- Modify: `internal/cache/index.go` (schema const, `NewIndex`, `Insert`; add `migrateLastValidated`, `DueForRevalidation`, `MarkValidated`)
- Modify: `internal/cache/local.go` (delegate methods on `*LocalCache`)
- Test: `internal/cache/index_test.go`

**Interfaces:**
- Produces:
  - `cache.RevalEntry{ Ref proxy.PackageRef; FilePath string; ScanClean bool; ScanJSON string }`
  - `(*cache.Index).DueForRevalidation(before int64, limit int) ([]RevalEntry, error)`
  - `(*cache.Index).MarkValidated(ref *proxy.PackageRef, ts int64) error`
  - `(*cache.LocalCache).DueForRevalidation(before int64, limit int) ([]RevalEntry, error)`
  - `(*cache.LocalCache).MarkValidated(ref *proxy.PackageRef, ts int64) error`

- [ ] **Step 1: Write the failing test**

Add to `internal/cache/index_test.go`:

```go
func TestIndex_DueForRevalidationAndMarkValidated(t *testing.T) {
	idx, cleanup := newTestIndex(t)
	defer cleanup()

	now := time.Now().UTC()
	// stored_at drives initial last_validated (set by Insert).
	old := proxy.PackageRef{Ecosystem: "pypi", Name: "old", Version: "1.0"}
	fresh := proxy.PackageRef{Ecosystem: "pypi", Name: "fresh", Version: "1.0"}
	expired := proxy.PackageRef{Ecosystem: "pypi", Name: "expired", Version: "1.0"}

	require.NoError(t, idx.Insert(&old, &cache.CacheEntry{
		ArtifactPath: "/c/old", ScanClean: true, ScanJSON: `{"clean":true}`,
		StoredAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(24 * time.Hour), SizeBytes: 1,
	}))
	require.NoError(t, idx.Insert(&fresh, &cache.CacheEntry{
		ArtifactPath: "/c/fresh", ScanClean: true,
		StoredAt: now, ExpiresAt: now.Add(24 * time.Hour), SizeBytes: 1,
	}))
	require.NoError(t, idx.Insert(&expired, &cache.CacheEntry{
		ArtifactPath: "/c/expired", ScanClean: true,
		StoredAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-1 * time.Hour), SizeBytes: 1,
	}))

	// Due = last_validated older than 24h ago AND not expired → only "old".
	cutoff := now.Add(-24 * time.Hour).Unix()
	due, err := idx.DueForRevalidation(cutoff, 10)
	require.NoError(t, err)
	require.Len(t, due, 1)
	assert.Equal(t, "old", due[0].Ref.Name)
	assert.Equal(t, "/c/old", due[0].FilePath)
	assert.True(t, due[0].ScanClean)
	assert.Equal(t, `{"clean":true}`, due[0].ScanJSON)

	// After marking validated now, it is no longer due.
	require.NoError(t, idx.MarkValidated(&old, now.Unix()))
	due, err = idx.DueForRevalidation(cutoff, 10)
	require.NoError(t, err)
	assert.Empty(t, due)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache/ -run TestIndex_DueForRevalidationAndMarkValidated -count=1`
Expected: FAIL — `idx.DueForRevalidation`/`idx.MarkValidated` undefined (build error).

- [ ] **Step 3: Create the RevalEntry type**

Create `internal/cache/reval.go`:

```go
package cache

import "github.com/ggwpLab/Jo-ei/internal/proxy"

// RevalEntry is a cached entry presented to the re-validation sweep. It carries
// just enough to re-run the gates: the package ref, the artifact bytes on disk,
// and the prior verdict.
type RevalEntry struct {
	Ref       proxy.PackageRef
	FilePath  string
	ScanClean bool
	ScanJSON  string
}
```

- [ ] **Step 4: Add the column to the schema and the migration**

In `internal/cache/index.go`, add the column to the `schema` const (before the `UNIQUE(...)` line):

```go
	size_bytes   INTEGER NOT NULL DEFAULT 0,
	last_validated INTEGER NOT NULL DEFAULT 0,
	UNIQUE(ecosystem, name, version, classifier)
```

In `NewIndex`, after the `migrateClassifier` call, add:

```go
	if err := migrateLastValidated(db); err != nil {
		return nil, fmt.Errorf("migrating last_validated: %w", err)
	}
```

Add the migration function (next to `migrateClassifier`):

```go
// migrateLastValidated adds the re-validation timestamp column to a pre-existing
// database and backfills it from stored_at so old rows are treated as validated
// at store time rather than all immediately due. No-op once present and backfilled.
func migrateLastValidated(db *sql.DB) error {
	has, err := hasColumn(db, "artifacts", "last_validated")
	if err != nil {
		return err
	}
	if !has {
		if _, err := db.Exec(`ALTER TABLE artifacts ADD COLUMN last_validated INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	// Backfill rows that predate the column (last_validated == 0 is never a real
	// timestamp). Idempotent: a no-op once every row has a real value.
	if _, err := db.Exec(`UPDATE artifacts SET last_validated = stored_at WHERE last_validated = 0`); err != nil {
		return err
	}
	return nil
}
```

- [ ] **Step 5: Set last_validated on Insert**

Replace the `Insert` method body's SQL in `internal/cache/index.go` so the column is written and refreshed on conflict:

```go
func (idx *Index) Insert(ref *proxy.PackageRef, entry *CacheEntry) error {
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
		entry.StoredAt.Unix(), entry.ExpiresAt.Unix(),
		entry.StoredAt.Unix(), 0, entry.SizeBytes, entry.StoredAt.Unix(),
	)
	return err
}
```

- [ ] **Step 6: Add DueForRevalidation and MarkValidated to Index**

Append to `internal/cache/index.go`:

```go
// DueForRevalidation returns up to limit non-expired entries whose last_validated
// is older than `before` (a unix timestamp), oldest-first. Expired entries are
// excluded — they are dropped on access anyway.
func (idx *Index) DueForRevalidation(before int64, limit int) ([]RevalEntry, error) {
	now := time.Now().Unix()
	rows, err := idx.db.Query(`
		SELECT ecosystem, name, version, classifier, file_path, scan_clean, scan_json
		FROM artifacts
		WHERE last_validated < ? AND expires_at > ?
		ORDER BY last_validated ASC
		LIMIT ?`, before, now, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RevalEntry
	for rows.Next() {
		var (
			e            RevalEntry
			scanCleanInt int
		)
		if err := rows.Scan(
			&e.Ref.Ecosystem, &e.Ref.Name, &e.Ref.Version, &e.Ref.Classifier,
			&e.FilePath, &scanCleanInt, &e.ScanJSON,
		); err != nil {
			return nil, err
		}
		e.ScanClean = scanCleanInt == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

// MarkValidated sets last_validated for ref to ts (a unix timestamp).
func (idx *Index) MarkValidated(ref *proxy.PackageRef, ts int64) error {
	_, err := idx.db.Exec(
		`UPDATE artifacts SET last_validated = ? WHERE ecosystem=? AND name=? AND version=? AND classifier=?`,
		ts, ref.Ecosystem, ref.Name, ref.Version, ref.Classifier,
	)
	return err
}
```

- [ ] **Step 7: Delegate the methods on LocalCache**

Append to `internal/cache/local.go`:

```go
// DueForRevalidation returns cached entries due for re-validation. See Index.
func (lc *LocalCache) DueForRevalidation(before int64, limit int) ([]RevalEntry, error) {
	return lc.index.DueForRevalidation(before, limit)
}

// MarkValidated records that ref passed re-validation at ts (unix seconds).
func (lc *LocalCache) MarkValidated(ref *proxy.PackageRef, ts int64) error {
	return lc.index.MarkValidated(ref, ts)
}
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `go test ./internal/cache/ -count=1`
Expected: PASS (all cache tests, including the new one).

- [ ] **Step 9: Commit**

```bash
git add internal/cache/reval.go internal/cache/index.go internal/cache/local.go internal/cache/index_test.go
git commit -m "feat(cache): add last_validated column and revalidation queries"
```

---

### Task 2: Config `cache.revalidation` block

**Files:**
- Modify: `internal/config/config.go` (`CacheConfig`, new `RevalidationConfig`, `Validate`)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.RevalidationConfig{ Enabled bool; IntervalMinutes int; RevalidateAfterHours int; BatchSize int }`, reachable as `cfg.Cache.Revalidation`.

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
func TestValidate_RejectsNegativeRevalidation(t *testing.T) {
	c := &config.Config{}
	c.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c.Cache.Revalidation.IntervalMinutes = -1
	require.Error(t, c.Validate())

	c2 := &config.Config{}
	c2.Database.Path = "/var/lib/jo-ei/jo-ei.db"
	c2.Cache.Revalidation.BatchSize = -5
	require.Error(t, c2.Validate())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestValidate_RejectsNegativeRevalidation -count=1`
Expected: FAIL — `c.Cache.Revalidation` undefined (build error).

- [ ] **Step 3: Add the config struct**

In `internal/config/config.go`, extend `CacheConfig` and add the new type:

```go
type CacheConfig struct {
	Backend      string             `mapstructure:"backend"` // local | s3
	Local        LocalCache         `mapstructure:"local"`
	S3           S3Cache            `mapstructure:"s3"`
	Revalidation RevalidationConfig `mapstructure:"revalidation"`
}

// RevalidationConfig tunes the periodic cache re-validation sweep. Zero values
// use defaults (60 min interval, 24 h freshness, 50 per batch) applied at wiring
// time; negative values are rejected. enabled:false disables the sweep.
type RevalidationConfig struct {
	Enabled              bool `mapstructure:"enabled"`
	IntervalMinutes      int  `mapstructure:"interval_minutes"`
	RevalidateAfterHours int  `mapstructure:"revalidate_after_hours"`
	BatchSize            int  `mapstructure:"batch_size"`
}
```

- [ ] **Step 4: Add validation**

In `Validate()` (after the existing `ImageScan.MaxLayerBytes` check), add:

```go
	if c.Cache.Revalidation.IntervalMinutes < 0 {
		return fmt.Errorf("cache.revalidation.interval_minutes must not be negative")
	}
	if c.Cache.Revalidation.RevalidateAfterHours < 0 {
		return fmt.Errorf("cache.revalidation.revalidate_after_hours must not be negative")
	}
	if c.Cache.Revalidation.BatchSize < 0 {
		return fmt.Errorf("cache.revalidation.batch_size must not be negative")
	}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/config/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add cache.revalidation settings"
```

---

### Task 3: `revalidate` core types + package revalidator

**Files:**
- Create: `internal/revalidate/revalidate.go` (types + interfaces)
- Create: `internal/revalidate/package.go` (`packageRevalidator`)
- Test: `internal/revalidate/package_test.go`

**Interfaces:**
- Consumes: `cache.RevalEntry` (Task 1); `proxy.CVEScanner`, `proxy.PolicyDecider`, `proxy.AVScanner`, `proxy.GateCVE`, `proxy.GateMalware`, `proxy.ReasonDenylisted` (existing).
- Produces:
  - `revalidate.Outcome` with `Keep`, `Evict`, `Retry`
  - `revalidate.EvictReason{ Gate, Reason, BlockedBy, Engine, Signature string; Findings []proxy.CVEFinding }`
  - `revalidate.Revalidator` interface: `Revalidate(ctx context.Context, e cache.RevalEntry) (Outcome, *EvictReason)`
  - `revalidate.RevalidationStore` interface: `DueForRevalidation(before int64, limit int) ([]cache.RevalEntry, error)`, `MarkValidated(ref *proxy.PackageRef, ts int64) error`, `Invalidate(ref *proxy.PackageRef) error`
  - `revalidate.Config{ Interval, RevalidateAfter time.Duration; BatchSize int }`
  - `revalidate.NewPackageRevalidator(cve proxy.CVEScanner, policy proxy.PolicyDecider, av proxy.AVScanner) Revalidator`

- [ ] **Step 1: Write the failing test**

Create `internal/revalidate/package_test.go`:

```go
package revalidate_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/revalidate"
)

type fakeCVE struct {
	res *proxy.ScanResult
	err error
}

func (f fakeCVE) Scan(context.Context, *proxy.PackageRef) (*proxy.ScanResult, error) {
	return f.res, f.err
}

type fakePolicy struct{ decision proxy.PolicyDecision }

func (f fakePolicy) Evaluate(*proxy.PackageRef, *proxy.ScanResult) proxy.PolicyDecision {
	return f.decision
}

type fakeAV struct {
	res   *proxy.AVResult
	err   error
	calls *int
}

func (f fakeAV) Scan(context.Context, string) (*proxy.AVResult, error) {
	if f.calls != nil {
		*f.calls++
	}
	return f.res, f.err
}

func entry() cache.RevalEntry {
	return cache.RevalEntry{Ref: proxy.PackageRef{Ecosystem: "pypi", Name: "x", Version: "1.0"}, FilePath: "/tmp/x"}
}

func TestPackageRevalidator_CleanKeeps(t *testing.T) {
	r := revalidate.NewPackageRevalidator(
		fakeCVE{res: &proxy.ScanResult{Clean: true}},
		fakePolicy{decision: proxy.PolicyDecision{Allowed: true}},
		fakeAV{res: &proxy.AVResult{Clean: true}},
	)
	out, reason := r.Revalidate(context.Background(), entry())
	assert.Equal(t, revalidate.Keep, out)
	assert.Nil(t, reason)
}

func TestPackageRevalidator_NewCVEEvicts(t *testing.T) {
	finding := proxy.CVEFinding{ID: "CVE-1", Severity: proxy.SeverityHigh}
	r := revalidate.NewPackageRevalidator(
		fakeCVE{res: &proxy.ScanResult{Findings: []proxy.CVEFinding{finding}}},
		fakePolicy{decision: proxy.PolicyDecision{Allowed: false, Reason: "cve_found", Findings: []proxy.CVEFinding{finding}}},
		fakeAV{res: &proxy.AVResult{Clean: true}},
	)
	out, reason := r.Revalidate(context.Background(), entry())
	require.Equal(t, revalidate.Evict, out)
	require.NotNil(t, reason)
	assert.Equal(t, proxy.GateCVE, reason.Gate)
	assert.Equal(t, "cve", reason.BlockedBy)
	assert.Len(t, reason.Findings, 1)
}

func TestPackageRevalidator_DenylistEvicts(t *testing.T) {
	r := revalidate.NewPackageRevalidator(
		fakeCVE{res: &proxy.ScanResult{Clean: true}},
		fakePolicy{decision: proxy.PolicyDecision{Allowed: false, Reason: proxy.ReasonDenylisted}},
		fakeAV{res: &proxy.AVResult{Clean: true}},
	)
	out, reason := r.Revalidate(context.Background(), entry())
	require.Equal(t, revalidate.Evict, out)
	assert.Equal(t, "denylist", reason.BlockedBy)
}

func TestPackageRevalidator_InfectedEvicts(t *testing.T) {
	r := revalidate.NewPackageRevalidator(
		fakeCVE{res: &proxy.ScanResult{Clean: true}},
		fakePolicy{decision: proxy.PolicyDecision{Allowed: true}},
		fakeAV{res: &proxy.AVResult{Clean: false, Engine: "clamav", Signature: "EICAR"}},
	)
	out, reason := r.Revalidate(context.Background(), entry())
	require.Equal(t, revalidate.Evict, out)
	assert.Equal(t, proxy.GateMalware, reason.Gate)
	assert.Equal(t, "malware", reason.BlockedBy)
	assert.Equal(t, "EICAR", reason.Signature)
}

func TestPackageRevalidator_CVEErrorRetriesAndSkipsAV(t *testing.T) {
	avCalls := 0
	r := revalidate.NewPackageRevalidator(
		fakeCVE{err: errors.New("osv 500")},
		fakePolicy{decision: proxy.PolicyDecision{Allowed: true}},
		fakeAV{res: &proxy.AVResult{Clean: true}, calls: &avCalls},
	)
	out, reason := r.Revalidate(context.Background(), entry())
	assert.Equal(t, revalidate.Retry, out)
	assert.Nil(t, reason)
	assert.Equal(t, 0, avCalls, "malware scan must not run after a CVE scan error")
}

func TestPackageRevalidator_AVErrorRetries(t *testing.T) {
	r := revalidate.NewPackageRevalidator(
		fakeCVE{res: &proxy.ScanResult{Clean: true}},
		fakePolicy{decision: proxy.PolicyDecision{Allowed: true}},
		fakeAV{err: errors.New("clamd timeout")},
	)
	out, _ := r.Revalidate(context.Background(), entry())
	assert.Equal(t, revalidate.Retry, out)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/revalidate/ -count=1`
Expected: FAIL — package `revalidate` does not exist / undefined symbols.

- [ ] **Step 3: Create the core types**

Create `internal/revalidate/revalidate.go`:

```go
// Package revalidate periodically re-runs the gates over cached artifacts and
// evicts any that now produce a definitive block verdict.
package revalidate

import (
	"context"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// Outcome is the per-entry decision a Revalidator returns.
type Outcome int

const (
	Keep  Outcome = iota // still clean → bump last_validated
	Evict                // definitive non-clean verdict → remove + record event
	Retry                // could not check (scanner down) → leave untouched
)

// EvictReason carries why an entry was evicted, for telemetry.
type EvictReason struct {
	Gate      string // proxy.GateCVE | GateMalware | GateImageScan | GateSupply
	Reason    string // "cve_found" | "malware_found" | "denylisted" | ...
	BlockedBy string // "cve" | "malware" | "denylist" | "supply_chain"
	Engine    string // malware engine, when applicable
	Signature string // malware signature, when applicable
	Findings  []proxy.CVEFinding
}

// Revalidator re-runs the applicable checks for one cached entry.
type Revalidator interface {
	Revalidate(ctx context.Context, e cache.RevalEntry) (Outcome, *EvictReason)
}

// RevalidationStore is the slice of the cache the sweep depends on.
// *cache.LocalCache satisfies it.
type RevalidationStore interface {
	DueForRevalidation(before int64, limit int) ([]cache.RevalEntry, error)
	MarkValidated(ref *proxy.PackageRef, ts int64) error
	Invalidate(ref *proxy.PackageRef) error
}

// Config tunes the sweep loop.
type Config struct {
	Interval        time.Duration // how often the sweep ticks
	RevalidateAfter time.Duration // an entry is due when now-last_validated > this
	BatchSize       int           // max entries processed per tick
}
```

- [ ] **Step 4: Create the package revalidator**

Create `internal/revalidate/package.go`:

```go
package revalidate

import (
	"context"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// packageRevalidator re-checks a cached package artifact (pypi/npm/maven/rubygems)
// against CVE+policy and malware. The supply-chain time rule is not re-run (a
// cached entry has matured); denylist changes are caught by the policy step.
type packageRevalidator struct {
	cve    proxy.CVEScanner
	policy proxy.PolicyDecider
	av     proxy.AVScanner
}

// NewPackageRevalidator builds a Revalidator for package ecosystems. Any of the
// scanners may be nil (that check is skipped).
func NewPackageRevalidator(cve proxy.CVEScanner, policy proxy.PolicyDecider, av proxy.AVScanner) Revalidator {
	return &packageRevalidator{cve: cve, policy: policy, av: av}
}

func (p *packageRevalidator) Revalidate(ctx context.Context, e cache.RevalEntry) (Outcome, *EvictReason) {
	ref := e.Ref

	// 1. CVE + policy (cheap metadata check first).
	if p.cve != nil && p.policy != nil {
		res, err := p.cve.Scan(ctx, &ref)
		if err != nil {
			return Retry, nil
		}
		if decision := p.policy.Evaluate(&ref, res); !decision.Allowed {
			by := "cve"
			if decision.Reason == proxy.ReasonDenylisted {
				by = "denylist"
			}
			return Evict, &EvictReason{
				Gate: proxy.GateCVE, Reason: decision.Reason,
				BlockedBy: by, Findings: decision.Findings,
			}
		}
	}

	// 2. Malware re-scan of the cached bytes.
	if p.av != nil {
		res, err := p.av.Scan(ctx, e.FilePath)
		if err != nil {
			return Retry, nil
		}
		if !res.Clean {
			return Evict, &EvictReason{
				Gate: proxy.GateMalware, Reason: "malware_found",
				BlockedBy: "malware", Engine: res.Engine, Signature: res.Signature,
			}
		}
	}

	return Keep, nil
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/revalidate/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/revalidate/revalidate.go internal/revalidate/package.go internal/revalidate/package_test.go
git commit -m "feat(revalidate): core types and package revalidator"
```

---

### Task 4: The sweeper

**Files:**
- Create: `internal/revalidate/sweeper.go`
- Test: `internal/revalidate/sweeper_test.go`

**Interfaces:**
- Consumes: `RevalidationStore`, `Revalidator`, `Config`, `Outcome`, `EvictReason` (Task 3); `proxy.Recorder`, `proxy.Event`, `proxy.VerdictBlock` (existing); `zerolog.Logger`.
- Produces:
  - `revalidate.NewSweeper(store RevalidationStore, revalidators map[string]Revalidator, recorder proxy.Recorder, cfg Config, logger zerolog.Logger) *Sweeper`
  - `(*Sweeper).Start()`, `(*Sweeper).Close()`, `(*Sweeper).sweepOnce(ctx context.Context)` (unexported; tested in-package)

- [ ] **Step 1: Write the failing test**

Create `internal/revalidate/sweeper_test.go`:

```go
package revalidate

import (
	"context"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

type fakeStore struct {
	mu         sync.Mutex
	due        []cache.RevalEntry
	lastBefore int64
	lastLimit  int
	validated  []proxy.PackageRef
	invalidated []proxy.PackageRef
}

func (f *fakeStore) DueForRevalidation(before int64, limit int) ([]cache.RevalEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastBefore, f.lastLimit = before, limit
	out := f.due
	f.due = nil // consumed
	return out, nil
}
func (f *fakeStore) MarkValidated(ref *proxy.PackageRef, _ int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validated = append(f.validated, *ref)
	return nil
}
func (f *fakeStore) Invalidate(ref *proxy.PackageRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalidated = append(f.invalidated, *ref)
	return nil
}

type stubRevalidator struct {
	outcome Outcome
	reason  *EvictReason
}

func (s stubRevalidator) Revalidate(context.Context, cache.RevalEntry) (Outcome, *EvictReason) {
	return s.outcome, s.reason
}

type recspy struct{ events []proxy.Event }

func (r *recspy) Record(e proxy.Event) { r.events = append(r.events, e) }

func pkgEntry(name string) cache.RevalEntry {
	return cache.RevalEntry{Ref: proxy.PackageRef{Ecosystem: "pypi", Name: name, Version: "1.0"}}
}

func TestSweeper_KeepBumpsValidated(t *testing.T) {
	store := &fakeStore{due: []cache.RevalEntry{pkgEntry("a")}}
	s := NewSweeper(store, map[string]Revalidator{"pypi": stubRevalidator{outcome: Keep}}, &recspy{}, Config{BatchSize: 10}, zerolog.Nop())
	s.sweepOnce(context.Background())
	assert.Equal(t, []proxy.PackageRef{{Ecosystem: "pypi", Name: "a", Version: "1.0"}}, store.validated)
	assert.Empty(t, store.invalidated)
}

func TestSweeper_EvictInvalidatesAndRecords(t *testing.T) {
	store := &fakeStore{due: []cache.RevalEntry{pkgEntry("bad")}}
	rec := &recspy{}
	reason := &EvictReason{Gate: proxy.GateMalware, Reason: "malware_found", BlockedBy: "malware", Engine: "clamav", Signature: "EICAR"}
	s := NewSweeper(store, map[string]Revalidator{"pypi": stubRevalidator{outcome: Evict, reason: reason}}, rec, Config{BatchSize: 10}, zerolog.Nop())
	s.sweepOnce(context.Background())

	require.Len(t, store.invalidated, 1)
	assert.Equal(t, "bad", store.invalidated[0].Name)
	assert.Empty(t, store.validated)
	require.Len(t, rec.events, 1)
	ev := rec.events[0]
	assert.Equal(t, proxy.VerdictBlock, ev.Verdict)
	assert.Equal(t, proxy.GateMalware, ev.Gate)
	assert.Equal(t, "revalidation", ev.RequestID)
	assert.Equal(t, "EICAR", ev.MalwareSignature)
	assert.Equal(t, []string{"malware"}, ev.BlockedBy)
}

func TestSweeper_RetryLeavesEntry(t *testing.T) {
	store := &fakeStore{due: []cache.RevalEntry{pkgEntry("x")}}
	s := NewSweeper(store, map[string]Revalidator{"pypi": stubRevalidator{outcome: Retry}}, &recspy{}, Config{BatchSize: 10}, zerolog.Nop())
	s.sweepOnce(context.Background())
	assert.Empty(t, store.validated)
	assert.Empty(t, store.invalidated)
}

func TestSweeper_UnknownEcosystemSkipped(t *testing.T) {
	store := &fakeStore{due: []cache.RevalEntry{{Ref: proxy.PackageRef{Ecosystem: "go", Name: "m", Version: "1"}}}}
	s := NewSweeper(store, map[string]Revalidator{"pypi": stubRevalidator{outcome: Keep}}, &recspy{}, Config{BatchSize: 10}, zerolog.Nop())
	s.sweepOnce(context.Background())
	assert.Empty(t, store.validated)
	assert.Empty(t, store.invalidated)
}

func TestSweeper_PassesBatchSizeAndCutoff(t *testing.T) {
	store := &fakeStore{}
	s := NewSweeper(store, map[string]Revalidator{}, &recspy{}, Config{BatchSize: 7, RevalidateAfter: 0}, zerolog.Nop())
	s.sweepOnce(context.Background())
	assert.Equal(t, 7, store.lastLimit)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/revalidate/ -run TestSweeper -count=1`
Expected: FAIL — `NewSweeper`/`Sweeper` undefined.

- [ ] **Step 3: Implement the sweeper**

Create `internal/revalidate/sweeper.go`:

```go
package revalidate

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// Sweeper periodically re-validates due cache entries and evicts failures.
type Sweeper struct {
	store        RevalidationStore
	revalidators map[string]Revalidator
	recorder     proxy.Recorder
	cfg          Config
	logger       zerolog.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewSweeper builds a sweeper. revalidators is keyed by ecosystem; entries whose
// ecosystem has no revalidator are skipped.
func NewSweeper(store RevalidationStore, revalidators map[string]Revalidator, recorder proxy.Recorder, cfg Config, logger zerolog.Logger) *Sweeper {
	return &Sweeper{store: store, revalidators: revalidators, recorder: recorder, cfg: cfg, logger: logger}
}

// Start launches the background loop. Safe to call once.
func (s *Sweeper) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(s.cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sweepOnce(ctx)
			}
		}
	}()
}

// Close stops the loop and waits for it to exit. Safe to call once.
func (s *Sweeper) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

// sweepOnce processes one batch of due entries.
func (s *Sweeper) sweepOnce(ctx context.Context) {
	cutoff := time.Now().Add(-s.cfg.RevalidateAfter).Unix()
	entries, err := s.store.DueForRevalidation(cutoff, s.cfg.BatchSize)
	if err != nil {
		s.logger.Error().Err(err).Msg("revalidation: querying due entries")
		return
	}
	for _, e := range entries {
		rv, ok := s.revalidators[e.Ref.Ecosystem]
		if !ok {
			continue // no revalidator → skip without bumping last_validated
		}
		outcome, reason := rv.Revalidate(ctx, e)
		switch outcome {
		case Keep:
			if err := s.store.MarkValidated(&e.Ref, time.Now().Unix()); err != nil {
				s.logger.Error().Err(err).Str("package", e.Ref.Key()).Msg("revalidation: marking validated")
			}
		case Evict:
			if err := s.store.Invalidate(&e.Ref); err != nil {
				s.logger.Error().Err(err).Str("package", e.Ref.Key()).Msg("revalidation: invalidating")
			}
			s.recordEviction(e, reason)
			s.logger.Warn().Str("package", e.Ref.Key()).Str("reason", reasonText(reason)).Msg("revalidation evicted artifact")
		case Retry:
			// Leave as-is; re-queried next tick.
		}
	}
}

func reasonText(r *EvictReason) string {
	if r == nil {
		return ""
	}
	return r.Reason
}

func (s *Sweeper) recordEviction(e cache.RevalEntry, r *EvictReason) {
	if s.recorder == nil || r == nil {
		return
	}
	s.recorder.Record(proxy.Event{
		RequestID:        "revalidation",
		Time:             time.Now(),
		Ecosystem:        e.Ref.Ecosystem,
		Package:          e.Ref.Name,
		Version:          e.Ref.Version,
		Verdict:          proxy.VerdictBlock,
		Gate:             r.Gate,
		Reason:           r.Reason,
		BlockedBy:        []string{r.BlockedBy},
		CVEs:             r.Findings,
		MalwareEngine:    r.Engine,
		MalwareSignature: r.Signature,
	})
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/revalidate/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/revalidate/sweeper.go internal/revalidate/sweeper_test.go
git commit -m "feat(revalidate): background sweeper with eviction telemetry"
```

---

### Task 5: Docker revalidator

**Files:**
- Create: `internal/proxy/dockerproxy/revalidate.go`
- Test: `internal/proxy/dockerproxy/revalidate_test.go`

**Interfaces:**
- Consumes: `revalidate.Outcome`, `revalidate.EvictReason`, `revalidate.Keep/Evict/Retry` (Task 3); `cache.RevalEntry` (Task 1); existing in-package `manifestGate`, `gateDeps`, `newManifestGate`, `Adapter`, `NewAdapter`, `verdictStore`, `newVerdictStore`, `newTagIndex`, `blobRef`, `imageRefKey`, `gateForBlockedBy`, `HandlerDeps`.
- Produces: `dockerproxy.NewRevalidator(d HandlerDeps) *Revalidator`; `(*Revalidator).Revalidate(ctx context.Context, e cache.RevalEntry) (revalidate.Outcome, *revalidate.EvictReason)` (satisfies `revalidate.Revalidator`).

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/dockerproxy/revalidate_test.go`:

```go
package dockerproxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/revalidate"
)

// writeManifest writes a schema2 image manifest (config + 1 layer) to a temp
// file and returns its path; mirrors newGateTestServer's image.
func writeManifest(t *testing.T) string {
	t.Helper()
	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     mediaTypeSchema2Manifest,
		"config":        map[string]string{"digest": "sha256:cfg"},
		"layers": []map[string]interface{}{
			{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": "sha256:layer1"},
		},
	}
	b, _ := json.Marshal(manifest)
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestRevalidator(t *testing.T, sc ImageScanner, av proxy.AVScanner, pol proxy.PolicyDecider, c cache.Cache) (*Revalidator, string) {
	srvURL, repo, _ := newGateTestServer(t)
	adapter := NewAdapter([]string{srvURL}, nil)
	store := newVerdictStore(c)
	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: sc, av: av,
		filter: allowFilter{}, policy: pol,
		store: store, tags: newTagIndex(0), logger: zerolog.Nop(),
	})
	return &Revalidator{gate: gate, cache: c}, repo
}

func TestDockerRevalidator_CleanKeeps(t *testing.T) {
	c := newFakeCache()
	r, repo := newTestRevalidator(t, stubScanner{}, stubAV{}, findingPolicy{}, c)
	e := cache.RevalEntry{Ref: proxy.PackageRef{Ecosystem: "docker", Name: repo, Version: "sha256:img"}, FilePath: writeManifest(t)}
	out, reason := r.Revalidate(context.Background(), e)
	if out != revalidate.Keep || reason != nil {
		t.Fatalf("out=%v reason=%v, want Keep/nil", out, reason)
	}
}

func TestDockerRevalidator_CVEBlockEvictsAndCascades(t *testing.T) {
	c := newFakeCache()
	// Pre-cache the two blobs so we can assert they are invalidated on eviction.
	tmp := filepath.Join(t.TempDir(), "b")
	_ = os.WriteFile(tmp, []byte("x"), 0o600)
	store := newVerdictStore(c)
	_ = store.PutBlob("sha256:cfg", tmp, true)
	_ = store.PutBlob("sha256:layer1", tmp, true)

	r, repo := newTestRevalidator(t,
		stubScanner{findings: []proxy.CVEFinding{{ID: "CVE-1", Severity: proxy.SeverityHigh}}},
		stubAV{}, findingPolicy{}, c)
	e := cache.RevalEntry{Ref: proxy.PackageRef{Ecosystem: "docker", Name: repo, Version: "sha256:img"}, FilePath: writeManifest(t)}

	out, reason := r.Revalidate(context.Background(), e)
	if out != revalidate.Evict {
		t.Fatalf("out=%v, want Evict", out)
	}
	if reason == nil || reason.BlockedBy != "cve" {
		t.Fatalf("reason=%+v, want blocked_by cve", reason)
	}
	if _, _, found := store.GetBlob("sha256:cfg"); found {
		t.Error("config blob should have been cascade-invalidated")
	}
	if _, _, found := store.GetBlob("sha256:layer1"); found {
		t.Error("layer blob should have been cascade-invalidated")
	}
}

func TestDockerRevalidator_BlobEntryIsNoOp(t *testing.T) {
	c := newFakeCache()
	r, _ := newTestRevalidator(t, stubScanner{}, stubAV{}, findingPolicy{}, c)
	e := cache.RevalEntry{Ref: proxy.PackageRef{Ecosystem: "docker", Name: "blobs", Version: "sha256:layer1"}}
	out, reason := r.Revalidate(context.Background(), e)
	if out != revalidate.Keep || reason != nil {
		t.Fatalf("out=%v reason=%v, want Keep/nil for blob entry", out, reason)
	}
}

func TestDockerRevalidator_GateErrorRetries(t *testing.T) {
	c := newFakeCache()
	// Adapter pointed at a dead upstream → FetchManifest fails → Retry.
	adapter := NewAdapter([]string{"http://127.0.0.1:1"}, nil)
	store := newVerdictStore(c)
	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: stubScanner{}, av: stubAV{},
		filter: allowFilter{}, policy: findingPolicy{}, store: store,
		tags: newTagIndex(0), logger: zerolog.Nop(),
	})
	r := &Revalidator{gate: gate, cache: c}
	e := cache.RevalEntry{Ref: proxy.PackageRef{Ecosystem: "docker", Name: "library/test", Version: "sha256:img"}, FilePath: writeManifest(t)}
	out, _ := r.Revalidate(context.Background(), e)
	if out != revalidate.Retry {
		t.Fatalf("out=%v, want Retry", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/dockerproxy/ -run TestDockerRevalidator -count=1`
Expected: FAIL — `Revalidator` undefined.

- [ ] **Step 3: Implement the Docker revalidator**

Create `internal/proxy/dockerproxy/revalidate.go`:

```go
package dockerproxy

import (
	"context"
	"encoding/json"
	"os"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/revalidate"
)

// Revalidator re-validates cached Docker entries by re-running the manifest gate.
// It implements revalidate.Revalidator.
type Revalidator struct {
	gate  *manifestGate
	cache cache.Cache
}

// NewRevalidator builds a Docker revalidator sharing the same upstreams,
// scanners, and cache as the live handler (HandlerDeps).
func NewRevalidator(d HandlerDeps) *Revalidator {
	adapter := NewAdapter(d.Upstreams, d.HTTPClient)
	store := newVerdictStore(d.Cache)
	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: d.Scanner, av: d.AV,
		filter: d.Filter, policy: d.Policy, store: store, tags: newTagIndex(0),
		maxLayerBytes: d.MaxLayerBytes, logger: d.Logger,
	})
	return &Revalidator{gate: gate, cache: d.Cache}
}

// Revalidate re-runs the gate for an image-verdict entry. Standalone blob entries
// are owned by their image and re-validated transitively, so they are a no-op.
func (r *Revalidator) Revalidate(ctx context.Context, e cache.RevalEntry) (revalidate.Outcome, *revalidate.EvictReason) {
	if e.Ref.Name == "blobs" {
		return revalidate.Keep, nil
	}
	repo, digest := e.Ref.Name, e.Ref.Version
	_, v, err := r.gate.Evaluate(ctx, repo, digest)
	if err != nil {
		return revalidate.Retry, nil // upstream/scan infra error → retry next sweep
	}
	if v.Allowed {
		return revalidate.Keep, nil
	}
	// Blocked: cascade-evict the image's config + layer blobs (their digests come
	// from the cached manifest body), then signal the manifest entry's eviction.
	for _, d := range manifestBlobDigests(e.FilePath) {
		_ = r.cache.Invalidate(blobRef(d))
	}
	return revalidate.Evict, &revalidate.EvictReason{
		Gate:      gateForBlockedBy(v.BlockedBy),
		Reason:    v.Reason,
		BlockedBy: v.BlockedBy,
	}
}

// manifestBlobDigests reads the cached manifest file and returns its config and
// layer digests. Best-effort: read/parse failures yield nil.
func manifestBlobDigests(manifestPath string) []string {
	body, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil
	}
	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	var out []string
	if m.Config.Digest != "" {
		out = append(out, m.Config.Digest)
	}
	for _, l := range m.Layers {
		if l.Digest != "" {
			out = append(out, l.Digest)
		}
	}
	return out
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/proxy/dockerproxy/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/dockerproxy/revalidate.go internal/proxy/dockerproxy/revalidate_test.go
git commit -m "feat(dockerproxy): revalidator re-runs the gate and cascades blob eviction"
```

---

### Task 6: Wire the sweeper in main.go + config.yaml + integration test

**Files:**
- Modify: `cmd/jo-ei/main.go` (build revalidators, wire and start/close the sweeper)
- Modify: `config.yaml` (documented `cache.revalidation` block)
- Test: `integration/revalidate_test.go`

**Interfaces:**
- Consumes: `revalidate.NewSweeper`, `revalidate.NewPackageRevalidator`, `revalidate.Config`, `revalidate.RevalidationStore`, `revalidate.Revalidator` (Tasks 3-4); `dockerproxy.NewRevalidator` (Task 5); `artifactCache`, `shared`, `trivyScanner`, `cfg`, `logger`, `dockerClient` (existing in `main.go`).

- [ ] **Step 1: Write the failing integration test**

Create `integration/revalidate_test.go`:

```go
//go:build integration

package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/revalidate"
)

// switchableAV reports clean until flipped to infected.
type switchableAV struct{ infected bool }

func (s *switchableAV) Scan(context.Context, string) (*proxy.AVResult, error) {
	if s.infected {
		return &proxy.AVResult{Clean: false, Engine: "clamav", Signature: "EICAR"}, nil
	}
	return &proxy.AVResult{Clean: true}, nil
}

type recSpy struct{ events []proxy.Event }

func (r *recSpy) Record(e proxy.Event) { r.events = append(r.events, e) }

func TestRevalidationEvictsNewlyInfected(t *testing.T) {
	dir := t.TempDir()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })

	// Cache a clean artifact.
	art := filepath.Join(dir, "pkg.whl")
	require.NoError(t, os.WriteFile(art, []byte("payload"), 0o600))
	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "victim", Version: "1.0"}
	require.NoError(t, lc.Put(&ref, art, true, ""))

	// Make it due immediately (last_validated far in the past).
	require.NoError(t, lc.MarkValidated(&ref, time.Now().Add(-72*time.Hour).Unix()))

	// Sweep with an AV that now reports infected.
	av := &switchableAV{infected: true}
	rec := &recSpy{}
	sw := revalidate.NewSweeper(
		lc,
		map[string]revalidate.Revalidator{"pypi": revalidate.NewPackageRevalidator(nil, nil, av)},
		rec,
		revalidate.Config{Interval: time.Hour, RevalidateAfter: 24 * time.Hour, BatchSize: 10},
		zerolog.Nop(),
	)
	sw.SweepOnceForTest(context.Background())

	// Entry is gone and a malware block event was recorded.
	_, found := lc.Get(&ref)
	require.False(t, found, "infected artifact must be evicted")
	require.Len(t, rec.events, 1)
	require.Equal(t, proxy.VerdictBlock, rec.events[0].Verdict)
	require.Equal(t, proxy.GateMalware, rec.events[0].Gate)
}
```

Note: this test calls `SweepOnceForTest`, an exported test shim added in Step 2.

- [ ] **Step 2: Add an exported sweep shim for integration tests**

`sweepOnce` is unexported and the integration test is in another package. Add to `internal/revalidate/sweeper.go`:

```go
// SweepOnceForTest runs a single sweep synchronously. Exposed for integration
// tests that drive the sweep deterministically instead of waiting on the ticker.
func (s *Sweeper) SweepOnceForTest(ctx context.Context) { s.sweepOnce(ctx) }
```

- [ ] **Step 3: Run the integration test to verify it passes**

Run: `go test -tags=integration ./integration/ -run TestRevalidationEvictsNewlyInfected -count=1`
Expected: PASS. (Before Step 2 it would not compile — `SweepOnceForTest` undefined. Run it once Step 2 is in place.)

- [ ] **Step 4: Wire the sweeper in main.go**

In `cmd/jo-ei/main.go`, add the import `"github.com/ggwpLab/Jo-ei/internal/revalidate"`. After the `healthMon.Start()` / `defer healthMon.Close()` block (around line 266) and before `handlers := buildHandlers(...)`, insert:

```go
	// Cache re-validation sweep (optional): periodically re-run the gates over
	// cached artifacts and evict any that now fail.
	if cfg.Cache.Revalidation.Enabled {
		if rstore, ok := artifactCache.(revalidate.RevalidationStore); ok {
			revalidators := map[string]revalidate.Revalidator{}
			pr := revalidate.NewPackageRevalidator(shared.cveScanner, shared.policy, shared.avScanner)
			for _, eco := range []string{"pypi", "npm", "maven", "rubygems"} {
				revalidators[eco] = pr
			}
			if cfg.Registries.Docker.Enabled && trivyScanner != nil {
				revalidators["docker"] = dockerproxy.NewRevalidator(dockerproxy.HandlerDeps{
					Upstreams:     cfg.Registries.Docker.Upstreams,
					Scanner:       trivyScanner,
					AV:            shared.avScanner,
					Filter:        policyRuntime,
					Policy:        policyRuntime,
					Cache:         artifactCache,
					MaxLayerBytes: cfg.ImageScan.MaxLayerBytes,
					Logger:        logger,
					HTTPClient:    dockerClient,
				})
			}
			interval := time.Duration(cfg.Cache.Revalidation.IntervalMinutes) * time.Minute
			if interval <= 0 {
				interval = 60 * time.Minute
			}
			revalAfter := time.Duration(cfg.Cache.Revalidation.RevalidateAfterHours) * time.Hour
			if revalAfter <= 0 {
				revalAfter = 24 * time.Hour
			}
			batch := cfg.Cache.Revalidation.BatchSize
			if batch <= 0 {
				batch = 50
			}
			sweeper := revalidate.NewSweeper(rstore, revalidators, shared.recorder, revalidate.Config{
				Interval: interval, RevalidateAfter: revalAfter, BatchSize: batch,
			}, logger)
			sweeper.Start()
			defer sweeper.Close()
			logger.Info().Dur("interval", interval).Dur("revalidate_after", revalAfter).Int("batch", batch).
				Msg("cache re-validation sweep enabled")
		} else {
			logger.Warn().Msg("cache.revalidation.enabled but cache backend does not support re-validation; skipping")
		}
	}
```

- [ ] **Step 5: Document the config block**

In `config.yaml`, inside the `cache:` section (after the `local:` block), add:

```yaml
  # Periodic re-validation: a background sweep re-runs the gates (CVE, malware,
  # and for Docker the full image gate) over cached artifacts and evicts any that
  # now fail — e.g. a newly published CVE, an updated ClamAV signature, or a
  # newly denylisted package. A scanner that is temporarily unreachable does not
  # evict; the entry is retried on the next sweep.
  revalidation:
    enabled: true
    interval_minutes: 60         # how often the sweep ticks
    revalidate_after_hours: 24   # re-check an entry when this long since last check
    batch_size: 50               # max entries processed per tick
```

- [ ] **Step 6: Verify the full build and test suite**

Run: `go build ./... && go test ./... -count=1 && go test -tags=integration ./integration/ -run TestRevalidationEvictsNewlyInfected -count=1`
Expected: build OK; all unit tests PASS; integration test PASS.

- [ ] **Step 7: Lint**

Run: `golangci-lint run ./...`
Expected: `0 issues.`

- [ ] **Step 8: Commit**

```bash
git add cmd/jo-ei/main.go config.yaml internal/revalidate/sweeper.go integration/revalidate_test.go
git commit -m "feat(revalidate): wire cache re-validation sweep into main"
```

---

## Notes for the implementer

- Run `golangci-lint run ./...` before the final commit of each task — the CI lint gate is golangci-lint (not just `go vet`).
- The race detector needs cgo (`CGO_ENABLED=1` + a C compiler). If unavailable locally, rely on the sweeper's simple channel/WaitGroup design; CI runs the race detector.
- `e.Ref` in `sweepOnce` is taken by address (`&e.Ref`) and used synchronously within the loop iteration — safe under Go 1.22+ per-iteration loop variables.

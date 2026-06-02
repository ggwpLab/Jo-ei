# Operational Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring Jōei to operational maturity — enforced toolchain/CI, graceful shutdown, no dead configuration, and fixes for memory growth and unmanaged goroutines — without adding major features.

**Architecture:** Wire up the two previously-dead config knobs (`supply_chain.allowlist_path`, `logging.output`); remove TLS config; keep S3 config but route cache construction through a backend factory that fail-fasts on the unimplemented `s3`; convert the in-memory OSV cache and the cache eviction goroutine into lifecycle-managed workers with `Close()`; add graceful shutdown driven by `signal.NotifyContext`.

**Tech Stack:** Go 1.25, cobra, viper, zerolog, modernc.org/sqlite, testify, golangci-lint v2, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-06-02-operational-hardening-design.md`

---

## File structure overview

| File | Responsibility | Change |
|------|----------------|--------|
| `Makefile` | build/test/lint/fmt targets | modify |
| `.golangci.yml` | linter config | create |
| `.github/workflows/ci.yml` | CI pipeline | create |
| `config.yaml` | sample config | modify (drop `server.tls`, add commented `cache.s3`) |
| `cmd/jo-ei/main.go` | wiring, lifecycle | modify |
| `cmd/jo-ei/logging.go` | log writer selection | create |
| `cmd/jo-ei/serve.go` | server run + graceful shutdown | create |
| `internal/config/config.go` | config structs | modify (remove TLS) |
| `internal/proxy/adapter.go` | shared types | modify (remove `BlockedError`, doc) |
| `internal/proxy/handler.go` | HTTP handler | modify (remove dead `/health`, check write errors) |
| `internal/proxy/mux.go` | routing | modify (check write errors) |
| `internal/supplychain/filter.go` | age filter | modify (dynamic reason) |
| `internal/supplychain/allowlist_load.go` | allowlist file loader | create |
| `internal/cache/cache.go` | `Cache` interface | modify (add `Close`) |
| `internal/cache/local.go` | local backend + eviction worker | modify |
| `internal/cache/factory.go` | backend factory | create |
| `internal/scanner/osv.go` | OSV scanner + janitor | modify |
| every package | package doc comment | modify |

Each task is independently committable. Run all commands from the repo root on branch `chore/operational-hardening`.

---

### Task 1: Format the tree and add an `fmt` target

**Files:**
- Modify: every currently-unformatted `.go` file (via `gofmt`)
- Modify: `Makefile`

- [ ] **Step 1: Apply gofmt**

Run: `gofmt -w .`

- [ ] **Step 2: Verify no files remain unformatted**

Run: `gofmt -l .`
Expected: empty output.

- [ ] **Step 3: Add an `fmt` target to the Makefile**

Edit `Makefile`, replace the `.PHONY` line and add the target:

```makefile
.PHONY: build test lint fmt clean

fmt:
	gofmt -w .
```

(Keep the existing `build`, `test`, `lint`, `run`, `clean` targets unchanged for now; `lint` is updated in Task 13.)

- [ ] **Step 4: Verify build and tests still pass**

Run: `go build ./... && go test ./...`
Expected: build OK, all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "style: gofmt the tree and add fmt make target"
```

---

### Task 2: Remove dead code (`BlockedError`, unreachable `/health`)

**Files:**
- Modify: `internal/proxy/adapter.go:49-59`
- Modify: `internal/proxy/handler.go:71-77`

- [ ] **Step 1: Remove the unused `BlockedError` type**

In `internal/proxy/adapter.go`, delete this block entirely:

```go
// BlockedError is returned when a package is blocked by a policy.
type BlockedError struct {
	Package   PackageRef
	Reason    string
	BlockedBy []string
	Details   map[string]any
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("package %s blocked: %s (by %v)", e.Package.Key(), e.Reason, e.BlockedBy)
}
```

`fmt` is still used elsewhere in the file (`PackageRef.Key`), so leave the import.

- [ ] **Step 2: Remove the unreachable `/health` branch in the handler**

In `internal/proxy/handler.go`, inside `ServeHTTP`, delete this block (the `Mux` already serves `/health` before dispatch):

```go
	// Built-in endpoints
	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok"}`)
		return
	}

```

- [ ] **Step 3: Verify build and tests pass**

Run: `go build ./... && go test ./...`
Expected: build OK (no "declared and not used"), all tests PASS. The `/health` test lives in `mux_test.go` and still passes.

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/adapter.go internal/proxy/handler.go
git commit -m "refactor: remove unused BlockedError and unreachable handler /health branch"
```

---

### Task 3: Add package doc comments

**Files:** one file per package (modify)

- [ ] **Step 1: Add a `// Package ...` comment above each package clause**

Add the matching line directly above `package X` in one representative file per package:

- `cmd/jo-ei/main.go`: `// Command jo-ei is the Jōei supply-chain security proxy for package registries.`
- `internal/proxy/adapter.go`: `// Package proxy contains the HTTP handler, routing, and shared registry types.`
- `internal/proxy/adapters/pypi.go`: `// Package adapters implements per-registry RegistryAdapter implementations.`
- `internal/cache/cache.go`: `// Package cache stores downloaded artifacts and their scan results.`
- `internal/config/config.go`: `// Package config loads and validates the Jōei YAML/env configuration.`
- `internal/policy/engine.go`: `// Package policy evaluates packages against CVE/allow/deny policy profiles.`
- `internal/supplychain/filter.go`: `// Package supplychain implements the package-age supply-chain filter.`
- `internal/scanner/factory.go`: `// Package scanner implements CVE and malware scanners.`

- [ ] **Step 2: Verify build**

Run: `go build ./...`
Expected: build OK.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "docs: add package-level doc comments"
```

---

### Task 4: Check ResponseWriter write errors

**Files:**
- Modify: `internal/proxy/handler.go`
- Modify: `internal/proxy/mux.go`

- [ ] **Step 1: Wrap the four `json.NewEncoder(w).Encode(body)` calls in handler.go**

In `internal/proxy/handler.go`, in each of `writeBlockedResponse`, `writeError`, `writeMalwareBlockedResponse`, `writeCVEBlockedResponse`, replace the trailing:

```go
	json.NewEncoder(w).Encode(body)
```

with:

```go
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.cfg.Logger.Error().Err(err).Msg("writing JSON response")
	}
```

- [ ] **Step 2: Check the `w.Write` calls in mux.go**

In `internal/proxy/mux.go` `ServeHTTP`, replace the two `w.Write([]byte(...))` calls:

```go
		w.Write([]byte(`{"status":"ok"}`))
```
→
```go
		if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
			m.logger.Error().Err(err).Msg("writing health response")
		}
```

and
```go
		w.Write([]byte(`{"error":"unknown_registry"}`))
```
→
```go
		if _, err := w.Write([]byte(`{"error":"unknown_registry"}`)); err != nil {
			m.logger.Error().Err(err).Msg("writing not-found response")
		}
```

- [ ] **Step 3: Verify build and tests pass**

Run: `go build ./... && go test ./...`
Expected: build OK, all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/handler.go internal/proxy/mux.go
git commit -m "fix: check ResponseWriter write/encode errors"
```

---

### Task 5: Dynamic supply-chain block reason

The hardcoded reason `"package_version_newer_than_24h"` is wrong when `min_age_hours != 24`. Replace it with the honest, age-independent `"package_younger_than_min_age"`.

**Files:**
- Modify: `internal/supplychain/filter.go`
- Modify: `internal/proxy/adapter.go:155`
- Test: `internal/supplychain/filter_test.go:30`, `internal/proxy/handler_test.go:152`, `integration/phase1_test.go:123`

- [ ] **Step 1: Update the assertion in the unit test (failing test first)**

In `internal/supplychain/filter_test.go`, line 30, change:

```go
	assert.Equal(t, "package_version_newer_than_24h", result.Reason)
```
to:
```go
	assert.Equal(t, "package_younger_than_min_age", result.Reason)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/supplychain/ -run TestFilter_BlocksPackageUnder24h -v`
Expected: FAIL (still returns the old string).

- [ ] **Step 3: Implement the new reason constant**

In `internal/supplychain/filter.go`, add a constant near the top of the file (after the imports):

```go
// reasonTooNew is returned when a package version is younger than min_age_hours.
const reasonTooNew = "package_younger_than_min_age"
```

Then replace the literal in the enforce branch:

```go
			Reason:      "package_version_newer_than_24h",
```
with:
```go
			Reason:      reasonTooNew,
```

- [ ] **Step 4: Update the doc comment in adapter.go**

In `internal/proxy/adapter.go`, line 155, change the `FilterResult.Reason` comment:

```go
	Reason      string    // "ok" | "allowlisted" | "dry_run" | "off" | "package_version_newer_than_24h"
```
to:
```go
	Reason      string    // "ok" | "allowlisted" | "dry_run" | "off" | "package_younger_than_min_age"
```

- [ ] **Step 5: Update the proxy and integration test assertions**

In `internal/proxy/handler_test.go` line 152 and `integration/phase1_test.go` line 123, change each:

```go
	assert.Equal(t, "package_version_newer_than_24h", body["reason"])
```
to:
```go
	assert.Equal(t, "package_younger_than_min_age", body["reason"])
```

- [ ] **Step 6: Run all affected tests**

Run: `go test ./internal/supplychain/ ./internal/proxy/ && go test -tags integration ./integration/ -run TestProxy -count=1`
(If the integration test name differs, run `go test -tags integration ./integration/...`.)
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/supplychain/filter.go internal/proxy/adapter.go internal/supplychain/filter_test.go internal/proxy/handler_test.go integration/phase1_test.go
git commit -m "fix: use min-age-agnostic supply-chain block reason"
```

---

### Task 6: Load and wire the supply-chain allowlist (fail-fast)

`main.go` passes `nil` for the allowlist, so `supply_chain.allowlist_path` is dead. Add a loader and wire it; missing/unreadable file is a startup error.

**Files:**
- Create: `internal/supplychain/allowlist_load.go`
- Test: `internal/supplychain/allowlist_load_test.go`
- Modify: `cmd/jo-ei/main.go`

- [ ] **Step 1: Write the failing loader test**

Create `internal/supplychain/allowlist_load_test.go`:

```go
package supplychain_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAllowlist_ParsesEntriesIgnoringCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	content := "# comment\npypi/requests\n\n  npm/left-pad@1.3.0  \n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	al, err := supplychain.LoadAllowlist(path)
	require.NoError(t, err)

	assert.True(t, al.Contains(&proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "9.9.9"}))
	assert.True(t, al.Contains(&proxy.PackageRef{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}))
	assert.False(t, al.Contains(&proxy.PackageRef{Ecosystem: "npm", Name: "left-pad", Version: "2.0.0"}))
}

func TestLoadAllowlist_MissingFileIsError(t *testing.T) {
	_, err := supplychain.LoadAllowlist(filepath.Join(t.TempDir(), "nope.txt"))
	require.Error(t, err)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/supplychain/ -run TestLoadAllowlist -v`
Expected: FAIL — `undefined: supplychain.LoadAllowlist`.

- [ ] **Step 3: Implement the loader**

Create `internal/supplychain/allowlist_load.go`:

```go
package supplychain

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadAllowlist reads an allowlist file and returns an *Allowlist.
// Each non-blank, non-comment line is one entry: "ecosystem/name" or
// "ecosystem/name@version". Lines beginning with '#' and blank lines are
// ignored; entries are whitespace-trimmed.
func LoadAllowlist(path string) (*Allowlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening allowlist %q: %w", path, err)
	}
	defer f.Close()

	var entries []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading allowlist %q: %w", path, err)
	}
	return NewAllowlist(entries), nil
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/supplychain/ -run TestLoadAllowlist -v`
Expected: PASS.

- [ ] **Step 5: Wire it into main.go**

In `cmd/jo-ei/main.go` `runProxy`, before `shared := sharedDeps{...}`, add:

```go
	var allowlist *supplychain.Allowlist
	if cfg.SupplyChain.AllowlistPath != "" {
		allowlist, err = supplychain.LoadAllowlist(cfg.SupplyChain.AllowlistPath)
		if err != nil {
			return err
		}
	}
```

Then change the filter construction in the `sharedDeps` literal from:

```go
		filter: supplychain.NewFilter(cfg.SupplyChain, nil),
```
to:
```go
		filter: supplychain.NewFilter(cfg.SupplyChain, allowlist),
```

- [ ] **Step 6: Verify build and tests pass**

Run: `go build ./... && go test ./...`
Expected: build OK, all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/supplychain/allowlist_load.go internal/supplychain/allowlist_load_test.go cmd/jo-ei/main.go
git commit -m "feat: load and wire supply-chain allowlist with fail-fast"
```

---

### Task 7: Honour `logging.output`

**Files:**
- Create: `cmd/jo-ei/logging.go`
- Test: `cmd/jo-ei/logging_test.go`
- Modify: `cmd/jo-ei/main.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/jo-ei/logging_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogWriter_StdoutStderrDefault(t *testing.T) {
	for _, out := range []string{"", "stderr"} {
		w, closeFn, err := logWriter(out)
		require.NoError(t, err)
		assert.Equal(t, os.Stderr, w)
		require.NoError(t, closeFn())
	}
	w, closeFn, err := logWriter("stdout")
	require.NoError(t, err)
	assert.Equal(t, os.Stdout, w)
	require.NoError(t, closeFn())
}

func TestLogWriter_FilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	w, closeFn, err := logWriter(path)
	require.NoError(t, err)
	_, err = w.Write([]byte("hello\n"))
	require.NoError(t, err)
	require.NoError(t, closeFn())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "hello")
}

func TestLogWriter_BadPathIsError(t *testing.T) {
	_, _, err := logWriter(filepath.Join(t.TempDir(), "no-such-dir", "app.log"))
	require.Error(t, err)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/jo-ei/ -run TestLogWriter -v`
Expected: FAIL — `undefined: logWriter`.

- [ ] **Step 3: Implement logWriter**

Create `cmd/jo-ei/logging.go`:

```go
package main

import (
	"fmt"
	"io"
	"os"
)

// logWriter resolves a logging.output value to a writer and a close function.
// "" or "stderr" → os.Stderr, "stdout" → os.Stdout, anything else → a file
// opened for append. The returned closeFn is a no-op for the standard streams.
func logWriter(output string) (io.Writer, func() error, error) {
	switch output {
	case "", "stderr":
		return os.Stderr, func() error { return nil }, nil
	case "stdout":
		return os.Stdout, func() error { return nil }, nil
	default:
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, nil, fmt.Errorf("opening log output %q: %w", output, err)
		}
		return f, f.Close, nil
	}
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./cmd/jo-ei/ -run TestLogWriter -v`
Expected: PASS.

- [ ] **Step 5: Use logWriter in runProxy**

In `cmd/jo-ei/main.go`, replace the current logger setup block:

```go
	level, levelErr := zerolog.ParseLevel(cfg.Logging.Level)
	if levelErr != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	logger := log.Logger
	if cfg.Logging.Format == "text" {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).
			With().Timestamp().Logger()
	}
	if levelErr != nil {
		logger.Warn().Str("value", cfg.Logging.Level).Msg("unknown log level; defaulting to info")
	}
```

with:

```go
	level, levelErr := zerolog.ParseLevel(cfg.Logging.Level)
	if levelErr != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	logOut, closeLog, err := logWriter(cfg.Logging.Output)
	if err != nil {
		return err
	}
	defer closeLog()

	var logger zerolog.Logger
	if cfg.Logging.Format == "text" {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: logOut, TimeFormat: time.RFC3339}).
			With().Timestamp().Logger()
	} else {
		logger = zerolog.New(logOut).With().Timestamp().Logger()
	}
	if levelErr != nil {
		logger.Warn().Str("value", cfg.Logging.Level).Msg("unknown log level; defaulting to info")
	}
```

Then remove the now-unused `"github.com/rs/zerolog/log"` import from `main.go`.

- [ ] **Step 6: Verify build and tests pass**

Run: `go build ./... && go test ./...`
Expected: build OK (no unused import), all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add cmd/jo-ei/logging.go cmd/jo-ei/logging_test.go cmd/jo-ei/main.go
git commit -m "feat: honour logging.output (stdout/stderr/file)"
```

---

### Task 8: Remove TLS config

TLS is never used (`ListenAndServeTLS` is never called). Remove the config so it does not advertise unimplemented behaviour.

**Files:**
- Modify: `internal/config/config.go:52-61`
- Modify: `config.yaml:1-4`

- [ ] **Step 1: Confirm there are no code references to TLS**

Run: `grep -rn "TLS\|CertFile\|KeyFile" --include="*.go" .`
Expected: only the `ServerConfig.TLS` / `TLSConfig` definitions in `internal/config/config.go` (no usages elsewhere).

- [ ] **Step 2: Remove the TLS field and struct**

In `internal/config/config.go`, change:

```go
type ServerConfig struct {
	Listen string    `mapstructure:"listen"`
	TLS    TLSConfig `mapstructure:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}
```
to:
```go
type ServerConfig struct {
	Listen string `mapstructure:"listen"`
}
```

- [ ] **Step 3: Remove the `tls` block from config.yaml**

In `config.yaml`, change:

```yaml
server:
  listen: ":8080"
  tls:
    enabled: false
```
to:
```yaml
server:
  listen: ":8080"
```

- [ ] **Step 4: Verify build and tests pass**

Run: `go build ./... && go test ./...`
Expected: build OK, all tests PASS (config tests do not reference TLS).

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go config.yaml
git commit -m "refactor: remove unimplemented TLS config"
```

---

### Task 9: Cache eviction worker + `Close()`

Replace the per-`Put` fire-and-forget `go lc.evictIfNeeded()` with one lifecycle-managed worker, and add `Close()` to both the `Cache` interface and `LocalCache`.

**Files:**
- Modify: `internal/cache/cache.go`
- Modify: `internal/cache/local.go`
- Test: `internal/cache/local_internal_test.go` (create)
- Modify: `internal/cache/local_test.go` (cleanup helper)

- [ ] **Step 1: Write the failing internal eviction test**

Create `internal/cache/local_internal_test.go`:

```go
package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/stretchr/testify/require"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "art.bin")
	require.NoError(t, os.WriteFile(p, []byte(content), 0644))
	return p
}

func TestLocalCache_EvictToSizeRemovesEntries(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)
	defer lc.Close()

	for _, n := range []string{"a", "b", "c"} {
		ref := &proxy.PackageRef{Ecosystem: "pypi", Name: n, Version: "1.0"}
		require.NoError(t, lc.Put(ref, writeTemp(t, "data-"+n), true, ""))
	}
	before, err := lc.index.Count()
	require.NoError(t, err)
	require.Equal(t, int64(3), before)

	// 1-byte budget forces eviction of everything over the limit.
	lc.evictToSize(1)

	after, err := lc.index.Count()
	require.NoError(t, err)
	require.Less(t, after, before)
}

func TestLocalCache_CloseIsIdempotent(t *testing.T) {
	lc, err := NewLocalCache(LocalCacheConfig{RootPath: t.TempDir(), MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)
	require.NoError(t, lc.Close())
	require.NoError(t, lc.Close())
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/cache/ -run TestLocalCache_EvictToSize -v`
Expected: FAIL — `lc.evictToSize undefined` and `lc.Close undefined`.

- [ ] **Step 3: Add `Close` to the `Cache` interface**

In `internal/cache/cache.go`, add to the `Cache` interface:

```go
	// Stats returns aggregate cache statistics.
	Stats() (CacheStats, error)
	// Close stops background workers and releases the index.
	Close() error
```

- [ ] **Step 4: Rework LocalCache with a worker, `evictToSize`, and `Close`**

In `internal/cache/local.go`:

Add `"sync"` to the imports. Change the struct:

```go
type LocalCache struct {
	cfg       LocalCacheConfig
	index     *Index
	evictCh   chan struct{}
	workerWG  sync.WaitGroup
	closeOnce sync.Once
}
```

In `NewLocalCache`, replace `return &LocalCache{cfg: cfg, index: idx}, nil` with:

```go
	lc := &LocalCache{cfg: cfg, index: idx, evictCh: make(chan struct{}, 1)}
	lc.workerWG.Add(1)
	go lc.evictWorker()
	return lc, nil
```

In `Put`, replace the line `go lc.evictIfNeeded()` and its comment with a non-blocking trigger:

```go
	// Signal the eviction worker (non-blocking; bursts coalesce).
	select {
	case lc.evictCh <- struct{}{}:
	default:
	}
```

Replace the existing `evictIfNeeded` method with the worker + split logic:

```go
// evictWorker drains eviction triggers until the channel is closed.
func (lc *LocalCache) evictWorker() {
	defer lc.workerWG.Done()
	for range lc.evictCh {
		lc.evictIfNeeded()
	}
}

// evictIfNeeded evicts LRU entries until the cache is under MaxSizeGB.
func (lc *LocalCache) evictIfNeeded() {
	maxBytes := int64(lc.cfg.MaxSizeGB) * 1024 * 1024 * 1024
	if maxBytes == 0 {
		return
	}
	lc.evictToSize(maxBytes)
}

// evictToSize removes LRU entries until total size is at or below maxBytes.
func (lc *LocalCache) evictToSize(maxBytes int64) {
	total, err := lc.index.TotalSizeBytes()
	if err != nil || total <= maxBytes {
		return
	}
	for total > maxBytes {
		candidates, err := lc.index.LRUCandidates(10)
		if err != nil || len(candidates) == 0 {
			return
		}
		for _, ref := range candidates {
			r := ref
			_ = lc.Invalidate(&r)
		}
		total, _ = lc.index.TotalSizeBytes()
	}
}

// Close stops the eviction worker and closes the index. Safe to call twice.
func (lc *LocalCache) Close() error {
	lc.closeOnce.Do(func() {
		close(lc.evictCh)
		lc.workerWG.Wait()
	})
	return lc.index.Close()
}
```

- [ ] **Step 5: Run to verify the internal test passes**

Run: `go test ./internal/cache/ -run TestLocalCache -v`
Expected: PASS.

- [ ] **Step 6: Close caches in the external test helper**

In `internal/cache/local_test.go`, in `newTestLocalCache`, after the `require.NoError(t, err)` and before `return c`, add cleanup:

```go
	t.Cleanup(func() { _ = c.Close() })
```

- [ ] **Step 7: Verify the whole cache package passes with race detector**

Run: `go test ./internal/cache/ -race`
Expected: PASS, no race reports.

- [ ] **Step 8: Commit**

```bash
git add internal/cache/cache.go internal/cache/local.go internal/cache/local_internal_test.go internal/cache/local_test.go
git commit -m "refactor: lifecycle-managed cache eviction worker with Close"
```

---

### Task 10: Cache backend factory + interface-based adapter

Route cache construction through `cache.New`, fail-fast on `s3`, and make `cacheAdapter` depend on the `cache.Cache` interface so a future S3 backend plugs in cleanly.

**Files:**
- Create: `internal/cache/factory.go`
- Test: `internal/cache/factory_test.go`
- Modify: `cmd/jo-ei/main.go`

- [ ] **Step 1: Write the failing factory test**

Create `internal/cache/factory_test.go`:

```go
package cache_test

import (
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_LocalBackend(t *testing.T) {
	for _, backend := range []string{"", "local"} {
		c, err := cache.New(config.CacheConfig{
			Backend: backend,
			Local:   config.LocalCache{Path: t.TempDir(), MaxSizeGB: 1},
		})
		require.NoError(t, err)
		require.NotNil(t, c)
		require.NoError(t, c.Close())
	}
}

func TestNew_S3NotImplemented(t *testing.T) {
	_, err := cache.New(config.CacheConfig{Backend: "s3"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestNew_UnknownBackend(t *testing.T) {
	_, err := cache.New(config.CacheConfig{Backend: "ftp"})
	require.Error(t, err)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/cache/ -run TestNew_ -v`
Expected: FAIL — `undefined: cache.New`.

- [ ] **Step 3: Implement the factory**

Create `internal/cache/factory.go`:

```go
package cache

import (
	"fmt"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/config"
)

// defaultTTL is the cache entry lifetime when not otherwise specified.
const defaultTTL = 24 * time.Hour

// New constructs the cache backend selected by cfg.Backend.
// "" and "local" build a LocalCache; "s3" is reserved but not yet implemented
// (fail-fast rather than silently falling back to local).
func New(cfg config.CacheConfig) (Cache, error) {
	switch cfg.Backend {
	case "", "local":
		return NewLocalCache(LocalCacheConfig{
			RootPath:  cfg.Local.Path,
			MaxSizeGB: cfg.Local.MaxSizeGB,
			TTL:       defaultTTL,
		})
	case "s3":
		return nil, fmt.Errorf("s3 cache backend not yet implemented")
	default:
		return nil, fmt.Errorf("unknown cache backend %q (want local|s3)", cfg.Backend)
	}
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/cache/ -run TestNew_ -v`
Expected: PASS.

- [ ] **Step 5: Switch main.go to the factory and interface-based adapter**

In `cmd/jo-ei/main.go`, replace the cache construction block:

```go
	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:  cfg.Cache.Local.Path,
		MaxSizeGB: cfg.Cache.Local.MaxSizeGB,
		TTL:       24 * time.Hour,
	})
	if err != nil {
		return err
	}
```
with:
```go
	artifactCache, err := cache.New(cfg.Cache)
	if err != nil {
		return err
	}
	defer artifactCache.Close()
```

Change the `sharedDeps` cache field from `cache: &cacheAdapter{lc: localCache},` to:

```go
		cache:  &cacheAdapter{c: artifactCache},
```

Replace the `cacheAdapter` type and methods at the bottom of the file:

```go
// cacheAdapter bridges cache.Cache to the proxy.ArtifactCache interface.
type cacheAdapter struct {
	c cache.Cache
}

func (a *cacheAdapter) Get(ref *proxy.PackageRef) (*proxy.ArtifactEntry, bool) {
	entry, found := a.c.Get(ref)
	if !found {
		return nil, false
	}
	return &proxy.ArtifactEntry{
		ArtifactPath: entry.ArtifactPath,
		ScanClean:    entry.ScanClean,
	}, true
}

func (a *cacheAdapter) Put(ref *proxy.PackageRef, tmpPath string, scanClean bool, scanJSON string) error {
	return a.c.Put(ref, tmpPath, scanClean, scanJSON)
}

func (a *cacheAdapter) Invalidate(ref *proxy.PackageRef) error {
	return a.c.Invalidate(ref)
}
```

If `time` is no longer referenced in `main.go` after this change, remove it from the imports. (It is still used by the `http.Server` timeouts, so it stays.)

- [ ] **Step 6: Verify build and tests pass**

Run: `go build ./... && go test ./...`
Expected: build OK, all tests PASS.

- [ ] **Step 7: Add a commented S3 example to config.yaml**

In `config.yaml`, under the `cache:` section, after the `local:` block, add:

```yaml
  # S3 backend is reserved for a future release; setting backend: s3 currently
  # fails fast at startup.
  # s3:
  #   endpoint: "https://s3.amazonaws.com"
  #   bucket: "joei-cache"
  #   region: "us-east-1"
```

- [ ] **Step 8: Commit**

```bash
git add internal/cache/factory.go internal/cache/factory_test.go cmd/jo-ei/main.go config.yaml
git commit -m "feat: cache backend factory with s3 fail-fast and interface-based adapter"
```

---

### Task 11: OSV in-memory cache janitor + `Close()`

The OSV result map never evicts expired entries. Add a background janitor and a `Close()`.

**Files:**
- Modify: `internal/scanner/osv.go`
- Test: `internal/scanner/osv_internal_test.go` (create)
- Modify: `cmd/jo-ei/main.go`

- [ ] **Step 1: Write the failing internal janitor test**

Create `internal/scanner/osv_internal_test.go`:

```go
package scanner

import (
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOSVScanner_JanitorEvictsExpired(t *testing.T) {
	s := NewOSVScanner("http://example.invalid", 20*time.Millisecond)
	defer s.Close()

	s.mu.Lock()
	s.cache["pypi/x@1.0"] = &cveEntry{
		result:    &proxy.ScanResult{Clean: true},
		expiresAt: time.Now().Add(-time.Hour), // already expired
	}
	s.mu.Unlock()

	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.cache) == 0
	}, time.Second, 10*time.Millisecond, "janitor should remove expired entries")
}

func TestOSVScanner_CloseStopsJanitor(t *testing.T) {
	s := NewOSVScanner("http://example.invalid", time.Hour)
	require.NoError(t, s.Close())
	assert.NoError(t, s.Close()) // idempotent
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/scanner/ -run TestOSVScanner_Janitor -v`
Expected: FAIL — `s.Close undefined`.

- [ ] **Step 3: Add the janitor to OSVScanner**

In `internal/scanner/osv.go`:

Add `"sync"` is already imported. Add a `stop` channel and `closeOnce` to the struct:

```go
type OSVScanner struct {
	baseURL string
	client  *http.Client
	ttl     time.Duration

	mu    sync.Mutex
	cache map[string]*cveEntry

	stop      chan struct{}
	closeOnce sync.Once
}
```

In `NewOSVScanner`, build the struct with the stop channel and start the janitor:

```go
func NewOSVScanner(baseURL string, ttl time.Duration) *OSVScanner {
	s := &OSVScanner{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 15 * time.Second},
		ttl:     ttl,
		cache:   make(map[string]*cveEntry),
		stop:    make(chan struct{}),
	}
	go s.janitor()
	return s
}

// janitor periodically removes expired cache entries so the map does not grow
// unbounded across distinct package keys.
func (s *OSVScanner) janitor() {
	interval := s.ttl
	if interval <= 0 {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for k, e := range s.cache {
				if now.After(e.expiresAt) {
					delete(s.cache, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

// Close stops the janitor goroutine. Safe to call more than once.
func (s *OSVScanner) Close() error {
	s.closeOnce.Do(func() { close(s.stop) })
	return nil
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/scanner/ -run TestOSVScanner -race -v`
Expected: PASS, no race reports.

- [ ] **Step 5: Close the scanner from main.go**

In `cmd/jo-ei/main.go`, inside the `if cfg.CVE.Enabled {` block, change:

```go
		shared.cveScanner = scanner.NewOSVScanner(baseURL, ttl)
		shared.policy = policy.NewEngine(cfg.CVE, profile)
```
to capture the concrete scanner so it can be closed:
```go
		osvScanner := scanner.NewOSVScanner(baseURL, ttl)
		defer osvScanner.Close()
		shared.cveScanner = osvScanner
		shared.policy = policy.NewEngine(cfg.CVE, profile)
```

- [ ] **Step 6: Verify build and tests pass**

Run: `go build ./... && go test ./...`
Expected: build OK, all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/scanner/osv.go internal/scanner/osv_internal_test.go cmd/jo-ei/main.go
git commit -m "fix: evict expired OSV cache entries via background janitor"
```

---

### Task 12: Graceful shutdown

Extract the server run into a testable `serve` function with `Shutdown`, and drive it from `main` via `signal.NotifyContext`.

**Files:**
- Create: `cmd/jo-ei/serve.go`
- Test: `cmd/jo-ei/serve_test.go`
- Modify: `cmd/jo-ei/main.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/jo-ei/serve_test.go`:

```go
package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestServe_ShutsDownOnContextCancel(t *testing.T) {
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: http.NewServeMux()}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- serve(ctx, srv) }()

	time.Sleep(50 * time.Millisecond) // let the listener bind
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not return after context cancel")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/jo-ei/ -run TestServe -v`
Expected: FAIL — `undefined: serve`.

- [ ] **Step 3: Implement serve**

Create `cmd/jo-ei/serve.go`:

```go
package main

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// serve runs srv until it errors or ctx is cancelled. On cancellation it
// gracefully drains in-flight requests with a bounded timeout. A clean
// shutdown returns nil.
func serve(ctx context.Context, srv *http.Server) error {
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./cmd/jo-ei/ -run TestServe -v`
Expected: PASS.

- [ ] **Step 5: Drive serve from runProxy**

In `cmd/jo-ei/main.go`, add `"os/signal"` and `"syscall"` to the imports.

At the very start of `runProxy`, establish the signal-aware context:

```go
func runProxy(_ *cobra.Command, _ []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
```

Add `"context"` to the imports if not present.

At the end of `runProxy`, replace:

```go
	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      mux,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}
	return srv.ListenAndServe()
```
with:
```go
	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      mux,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}
	return serve(ctx, srv)
```

(The `defer artifactCache.Close()`, `defer osvScanner.Close()`, and `defer closeLog()` added in earlier tasks now run on clean shutdown.)

- [ ] **Step 6: Verify build and tests pass**

Run: `go build ./... && go test ./...`
Expected: build OK, all tests PASS.

- [ ] **Step 7: Manual smoke check (optional but recommended)**

Run: `go run ./cmd/jo-ei --config config.yaml` then press Ctrl+C.
Expected: the process logs startup, then exits cleanly on the signal (no panic, no goroutine dump).

- [ ] **Step 8: Commit**

```bash
git add cmd/jo-ei/serve.go cmd/jo-ei/serve_test.go cmd/jo-ei/main.go
git commit -m "feat: graceful shutdown on SIGINT/SIGTERM"
```

---

### Task 13: Add golangci-lint configuration

**Files:**
- Create: `.golangci.yml`
- Modify: `Makefile`

- [ ] **Step 1: Create the config (golangci-lint v2 schema)**

Create `.golangci.yml`:

```yaml
version: "2"
linters:
  enable:
    - misspell
  settings:
    errcheck:
      exclude-functions:
        - (*os.File).Close
        - (io.Closer).Close
        - (io.ReadCloser).Close
        - (net.Conn).Close
        - os.Remove
formatters:
  enable:
    - gofmt
    - goimports
  settings:
    goimports:
      local-prefixes:
        - github.com/ggwpLab/Jo-ei
```

- [ ] **Step 2: Point `make lint` at golangci-lint**

In `Makefile`, change the `lint` target:

```makefile
lint:
	golangci-lint run
```

- [ ] **Step 3: Install golangci-lint (if not present) and run it**

Run: `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`
Then: `golangci-lint run`
Expected: `0 issues`. If errcheck flags a remaining `defer X.Close()` / `os.Remove`, add its exact reported signature to `errcheck.exclude-functions` and re-run. If `goimports` reports diffs, run `golangci-lint run --fix` and re-verify, then re-run the formatted build.

- [ ] **Step 4: Verify tests still pass after any --fix changes**

Run: `go build ./... && go test ./...`
Expected: build OK, all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add .golangci.yml Makefile
git commit -m "build: add golangci-lint config and wire make lint"
```

---

### Task 14: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create the workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [develop, main]
  pull_request:
    branches: [develop, main]

jobs:
  build-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - name: gofmt
        run: |
          unformatted=$(gofmt -l .)
          if [ -n "$unformatted" ]; then
            echo "These files are not gofmt-ed:"; echo "$unformatted"; exit 1
          fi
      - name: Build
        run: go build ./...
      - name: Unit tests (race)
        run: go test ./... -race
      - name: Integration tests
        run: go test -tags integration ./integration/... -race

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - uses: golangci/golangci-lint-action@v6
        with:
          version: latest
```

- [ ] **Step 2: Validate the workflow YAML locally**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions build/test/lint pipeline"
```

- [ ] **Step 4: Final full verification**

Run: `gofmt -l . && go build ./... && go test ./... -race && go test -tags integration ./integration/... && golangci-lint run`
Expected: `gofmt -l` empty, all builds/tests PASS, lint `0 issues`.

---

## Self-review notes

- **Spec coverage:** WS1 → Tasks 1, 13, 14. WS2 → Tasks 9 (Close), 11 (Close), 12 (shutdown). WS3 → Task 6 (allowlist), 7 (logging.output), 8 (TLS removal), 10 (S3 factory/kept config). WS4 → Task 11 (OSV janitor), 9 (eviction worker). WS5 → Tasks 2 (BlockedError, /health), 3 (package docs), 4 (write errors), 5 (dynamic reason). All spec sections map to at least one task.
- **Type consistency:** `cache.Cache.Close() error`, `LocalCache.Close`, `LocalCache.evictToSize`, `OSVScanner.Close`, `serve(ctx, *http.Server) error`, `logWriter(string) (io.Writer, func() error, error)`, `supplychain.LoadAllowlist(string) (*Allowlist, error)`, `cache.New(config.CacheConfig) (cache.Cache, error)`, `cacheAdapter{c cache.Cache}` — used consistently across tasks 6–12.
- **Ordering:** `Close` on the interface (Task 9) lands before the factory (Task 10) and shutdown deferreds (Task 12) use it; the dynamic-reason constant and write-error wrapping land before lint is enabled (Task 13), so the lint gate starts green.

# Persistent Settings (policy + registries) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist runtime-editable policy and registry settings to the embedded SQLite database (DB-wins / YAML-seeds) so console edits survive a restart, and make registries editable in the console UI (restart-applied).

**Architecture:** A new `internal/settings` package stores small config groups as key→JSON blobs in the shared SQLite DB (same file/migration framework telemetry already uses). `policy.Runtime` gains a persistence seam: seed-from-YAML on an empty store, load-from-DB otherwise, and save-before-install on every `Apply`. Registries are overlaid from the DB onto the loaded config at boot; the console gains `PUT /api/registries` that validates and persists edits which take effect on the next restart (no live mux rebuild).

**Tech Stack:** Go (modernc.org/sqlite, zerolog, testify), React (no-build JSX concatenated by `internal/uibuild` via esbuild).

## Global Constraints

- DB is the source of truth for policy + registries after first seed; YAML edits to those fields are ignored once the DB row exists. (verbatim: "DB wins, YAML seeds")
- Registries are **restart-required**: persist edits, never rebuild the live proxy mux at runtime.
- Scope is **policy + registries only** — do not move CVE/scanner, cache-revalidation, or health/upstream tuning to the DB.
- Policy persist ordering = **save → install**; on DB write failure the live policy is unchanged and the API returns 500.
- Settings storage = a single generic `settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)` table, one migration component named `settings`.
- Known ecosystems (exact, ordered): `pypi`, `npm`, `maven`, `rubygems`, `docker`.
- Lint gate is golangci-lint (not just `go vet`); run `gofmt` + the linter before each commit.
- Feature work stays on the `feat/settings-persistence` branch (already created); never commit to `main`.
- Go module path: `github.com/ggwpLab/Jo-ei`.

---

### Task 1: `internal/settings` key→JSON store

**Files:**
- Create: `internal/settings/settings.go`
- Test: `internal/settings/settings_test.go`

**Interfaces:**
- Consumes: `storage.Open`, `(*storage.DB).ApplyMigrations`, `(*storage.DB).SQL` from `internal/storage`.
- Produces:
  - `func New(db *storage.DB) (*Store, error)`
  - `func (s *Store) Get(key string) (value []byte, ok bool, err error)`
  - `func (s *Store) Put(key string, value []byte) error`

- [ ] **Step 1: Write the failing test**

```go
package settings_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

func newStore(t *testing.T) *settings.Store {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "s.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	st, err := settings.New(db)
	require.NoError(t, err)
	return st
}

func TestGetMissingKey(t *testing.T) {
	st := newStore(t)
	v, ok, err := st.Get("policy")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, v)
}

func TestPutThenGetRoundTrip(t *testing.T) {
	st := newStore(t)
	require.NoError(t, st.Put("policy", []byte(`{"mode":"enforce"}`)))
	v, ok, err := st.Get("policy")
	require.NoError(t, err)
	require.True(t, ok)
	assert.JSONEq(t, `{"mode":"enforce"}`, string(v))
}

func TestPutOverwrites(t *testing.T) {
	st := newStore(t)
	require.NoError(t, st.Put("registries", []byte(`[]`)))
	require.NoError(t, st.Put("registries", []byte(`[{"eco":"pypi"}]`)))
	v, ok, err := st.Get("registries")
	require.NoError(t, err)
	require.True(t, ok)
	assert.JSONEq(t, `[{"eco":"pypi"}]`, string(v))
}

func TestNewIsIdempotent(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "s.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	_, err = settings.New(db)
	require.NoError(t, err)
	_, err = settings.New(db) // second migration apply must be a no-op
	require.NoError(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/settings/...`
Expected: FAIL — `package settings is not in std` / `undefined: settings.New`.

- [ ] **Step 3: Write the implementation**

```go
// Package settings persists small, runtime-editable config groups (policy,
// registries) as key→JSON blobs in the shared SQLite database. The DB is the
// source of truth after first seed; callers own their JSON shapes so policy and
// config never import this package's storage dependency.
package settings

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/storage"
)

// Store reads and writes opaque JSON values keyed by name.
type Store struct {
	db *storage.DB
}

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS settings (
		key        TEXT PRIMARY KEY,
		value      TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	)`,
}

// New runs the settings migration on db and returns a Store.
func New(db *storage.DB) (*Store, error) {
	if err := db.ApplyMigrations("settings", migrations); err != nil {
		return nil, fmt.Errorf("settings migrations: %w", err)
	}
	return &Store{db: db}, nil
}

// Get returns the stored value for key. ok is false when the key is absent.
func (s *Store) Get(key string) ([]byte, bool, error) {
	var v string
	err := s.db.SQL().QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("reading setting %q: %w", key, err)
	}
	return []byte(v), true, nil
}

// Put writes value for key, overwriting any existing value.
func (s *Store) Put(key string, value []byte) error {
	_, err := s.db.SQL().Exec(
		`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, string(value), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("writing setting %q: %w", key, err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/settings/...`
Expected: PASS (4 tests).

- [ ] **Step 5: Lint + commit**

Run: `gofmt -w internal/settings && golangci-lint run ./internal/settings/...`
Expected: no output (clean).

```bash
git add internal/settings/
git commit -m "feat(settings): key→JSON store over shared SQLite DB"
```

---

### Task 2: policy persistence seam (seed / load / save-on-apply)

**Files:**
- Modify: `internal/policy/runtime.go`
- Test: `internal/policy/runtime_persist_test.go` (new file, same `policy_test` package)

**Interfaces:**
- Consumes: nothing new (tests use an in-package fake store).
- Produces:
  - `type SettingsStore interface { LoadPolicy() (RuntimeParams, bool, error); SavePolicy(RuntimeParams) error }`
  - `func NewRuntimeWithStore(sc config.SupplyChainConfig, cve config.CVEConfig, profile config.PolicyProfile, fileAllow []string, store SettingsStore) (*Runtime, error)`
  - `type PersistError struct { Err error }` with `Error() string` and `Unwrap() error`
  - `NewRuntime(...)` keeps its existing signature `(*Runtime)` (runtime-only, no store).
  - `Apply(p RuntimeParams) error` now persists before installing when a store is set.

- [ ] **Step 1: Write the failing test**

```go
package policy_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/policy"
)

// fakeStore is an in-memory policy.SettingsStore.
type fakeStore struct {
	saved   *policy.RuntimeParams
	loadOK  bool
	loadVal policy.RuntimeParams
	saveErr error
	saves   int
}

func (f *fakeStore) LoadPolicy() (policy.RuntimeParams, bool, error) {
	return f.loadVal, f.loadOK, nil
}
func (f *fakeStore) SavePolicy(p policy.RuntimeParams) error {
	f.saves++
	if f.saveErr != nil {
		return f.saveErr
	}
	cp := p
	f.saved = &cp
	return nil
}

func sc() config.SupplyChainConfig { return config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24} }
func cve() config.CVEConfig        { return config.CVEConfig{Enabled: true, BlockOn: "CRITICAL"} }
func prof() config.PolicyProfile   { return config.PolicyProfile{CVEBlock: true} }

func TestNewRuntimeWithStore_SeedsEmptyStore(t *testing.T) {
	fs := &fakeStore{loadOK: false}
	r, err := policy.NewRuntimeWithStore(sc(), cve(), prof(), nil, fs)
	require.NoError(t, err)
	// Seeded from YAML params and persisted.
	require.NotNil(t, fs.saved)
	assert.Equal(t, "enforce", fs.saved.Mode)
	assert.Equal(t, "CRITICAL", fs.saved.CVEBlockOn)
	assert.Equal(t, "enforce", r.Current().Mode)
}

func TestNewRuntimeWithStore_LoadsExisting(t *testing.T) {
	fs := &fakeStore{loadOK: true, loadVal: policy.RuntimeParams{
		Mode: "dry_run", MinAgeHours: 5, CVEBlockOn: "HIGH",
		Allowlist: []string{}, Denylist: []string{},
	}}
	r, err := policy.NewRuntimeWithStore(sc(), cve(), prof(), nil, fs)
	require.NoError(t, err)
	// DB wins over the YAML seed; no re-seed write happens.
	assert.Equal(t, "dry_run", r.Current().Mode)
	assert.Equal(t, 5, r.Current().MinAgeHours)
	assert.Equal(t, 0, fs.saves, "loading an existing row must not re-seed")
}

func TestApply_PersistsThenInstalls(t *testing.T) {
	fs := &fakeStore{loadOK: false}
	r, err := policy.NewRuntimeWithStore(sc(), cve(), prof(), nil, fs)
	require.NoError(t, err)
	fs.saved = nil // ignore the seed write

	p := r.Current()
	p.Mode = "off"
	require.NoError(t, r.Apply(p))
	require.NotNil(t, fs.saved)
	assert.Equal(t, "off", fs.saved.Mode)
	assert.Equal(t, "off", r.Current().Mode)
}

func TestApply_SaveFailure_DoesNotInstall(t *testing.T) {
	fs := &fakeStore{loadOK: false}
	r, err := policy.NewRuntimeWithStore(sc(), cve(), prof(), nil, fs)
	require.NoError(t, err)
	before := r.Current()

	fs.saveErr = errors.New("disk full")
	p := r.Current()
	p.Mode = "off"
	gotErr := r.Apply(p)

	var perr *policy.PersistError
	require.ErrorAs(t, gotErr, &perr, "save failure must surface as PersistError")
	assert.Equal(t, before, r.Current(), "live policy unchanged when persist fails")
}

func TestApply_ValidationBeatsPersist(t *testing.T) {
	fs := &fakeStore{loadOK: false}
	r, err := policy.NewRuntimeWithStore(sc(), cve(), prof(), nil, fs)
	require.NoError(t, err)
	savesAfterSeed := fs.saves

	p := r.Current()
	p.Mode = "yolo" // invalid
	gotErr := r.Apply(p)
	var verr *policy.ValidationError
	require.ErrorAs(t, gotErr, &verr)
	assert.Equal(t, savesAfterSeed, fs.saves, "invalid Apply must not reach the store")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run 'WithStore|Apply_Persists|Apply_SaveFailure|Apply_ValidationBeatsPersist'`
Expected: FAIL — `undefined: policy.NewRuntimeWithStore`, `undefined: policy.PersistError`.

- [ ] **Step 3: Refactor `NewRuntime` to extract the seed, add the store seam**

In `internal/policy/runtime.go`, add the `store` field and seam types, refactor the constructor, and persist in `Apply`.

Replace the `Runtime` struct (lines 43-48) with:

```go
type Runtime struct {
	cur       atomic.Pointer[runtimeSnapshot]
	cveCfg    config.CVEConfig
	profile   config.PolicyProfile
	fileAllow []string // supply_chain.allowlist_path entries, immutable
	store     SettingsStore // nil = runtime-only (no persistence)
}

// SettingsStore persists the runtime policy params. Implemented in cmd/jo-ei by
// an adapter over *settings.Store that marshals RuntimeParams to/from JSON.
type SettingsStore interface {
	LoadPolicy() (RuntimeParams, bool, error)
	SavePolicy(RuntimeParams) error
}

// PersistError wraps a failure to write the policy to the settings store. It is
// distinct from ValidationError so the console can map it to HTTP 500.
type PersistError struct{ Err error }

func (e *PersistError) Error() string { return "persisting policy: " + e.Err.Error() }
func (e *PersistError) Unwrap() error { return e.Err }
```

Replace `NewRuntime` (lines 57-77) with the seed-extracted version plus the store constructor:

```go
func NewRuntime(sc config.SupplyChainConfig, cve config.CVEConfig, profile config.PolicyProfile, fileAllow []string) *Runtime {
	r, seed := newRuntimeSeed(sc, cve, profile, fileAllow)
	r.install(seed)
	return r
}

// NewRuntimeWithStore seeds the store from YAML on first boot (empty store) or
// installs the stored params otherwise (DB wins). A nil store behaves like
// NewRuntime.
func NewRuntimeWithStore(sc config.SupplyChainConfig, cve config.CVEConfig, profile config.PolicyProfile, fileAllow []string, store SettingsStore) (*Runtime, error) {
	r, seed := newRuntimeSeed(sc, cve, profile, fileAllow)
	r.store = store
	if store != nil {
		p, ok, err := store.LoadPolicy()
		if err != nil {
			return nil, fmt.Errorf("loading stored policy: %w", err)
		}
		if ok {
			r.install(p)
			return r, nil
		}
	}
	r.install(seed)
	if store != nil {
		if err := store.SavePolicy(seed); err != nil {
			return nil, fmt.Errorf("seeding policy store: %w", err)
		}
	}
	return r, nil
}

// newRuntimeSeed builds the Runtime shell and the boot params derived from the
// YAML config, without installing them.
func newRuntimeSeed(sc config.SupplyChainConfig, cve config.CVEConfig, profile config.PolicyProfile, fileAllow []string) (*Runtime, RuntimeParams) {
	blockOn := cve.BlockOn
	if profile.CVEMinSeverity != "" {
		blockOn = profile.CVEMinSeverity
	}
	if blockOn == "" {
		blockOn = "LOW"
	}
	r := &Runtime{cveCfg: cve, profile: profile, fileAllow: append([]string{}, fileAllow...)}
	seed := RuntimeParams{
		Mode:        sc.Mode,
		MinAgeHours: sc.MinAgeHours,
		CVEBlockOn:  blockOn,
		Allowlist:   append([]string{}, profile.Allowlist...),
		Denylist:    append([]string{}, profile.Denylist...),
	}
	return r, seed
}
```

In `Apply` (lines 106-128), persist before installing. Replace the final `r.install(p)` / `return nil` (lines 126-127) with:

```go
	if r.store != nil {
		if err := r.store.SavePolicy(p); err != nil {
			return &PersistError{Err: err}
		}
	}
	r.install(p)
	return nil
```

(The validation block above it is unchanged, so validation still runs before any store write.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/...`
Expected: PASS (existing runtime tests + 5 new persistence tests).

- [ ] **Step 5: Lint + commit**

Run: `gofmt -w internal/policy && golangci-lint run ./internal/policy/...`
Expected: clean.

```bash
git add internal/policy/runtime.go internal/policy/runtime_persist_test.go
git commit -m "feat(policy): persist runtime policy via SettingsStore (seed/load, save-before-install)"
```

---

### Task 3: wire policy persistence into `cmd/jo-ei`

**Files:**
- Modify: `cmd/jo-ei/main.go`

**Interfaces:**
- Consumes: `settings.New`, `(*settings.Store).Get/Put`, `policy.NewRuntimeWithStore`, `policy.RuntimeParams`.
- Produces:
  - `type policySettingsStore struct { s *settings.Store }` implementing `policy.SettingsStore`.
  - A single `*storage.DB` opened once in `run` and shared by telemetry + settings.
  - `buildTelemetryStore` changed to accept an already-open `*storage.DB`.

- [ ] **Step 1: Open the shared DB and settings store**

In `cmd/jo-ei/main.go`, after the logger is constructed (just after line 116) and before `artifactCache` is built, add:

```go
	sdb, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("opening database at %q: %w", cfg.Database.Path, err)
	}
	defer func() { _ = sdb.Close() }()

	settingsStore, err := settings.New(sdb)
	if err != nil {
		return err
	}
```

Add `"github.com/ggwpLab/Jo-ei/internal/settings"` to the import block. (`storage` is already imported.)

- [ ] **Step 2: Change `buildTelemetryStore` to reuse the shared DB**

Replace `buildTelemetryStore` (lines 483-498) with:

```go
// buildTelemetryStore initialises the SQLite-backed telemetry store on the
// shared database. Telemetry is SQLite-only: any schema error aborts startup.
func buildTelemetryStore(sdb *storage.DB, cfg *config.Config, logger zerolog.Logger) (*telemetry.Store, error) {
	store, err := telemetry.Open(sdb, cfg.Database.EventRetentionDays, cfg.Database.DailyRetentionDays, logger)
	if err != nil {
		return nil, fmt.Errorf("initialising telemetry store: %w", err)
	}
	logger.Info().Str("path", cfg.Database.Path).Msg("telemetry persistence enabled")
	return store, nil
}
```

Update its call site (line 143) to pass `sdb` and drop the now-redundant `sdb.Close` in the store defer (the shared `sdb` is closed by the defer added in Step 1):

```go
	store, err := buildTelemetryStore(sdb, cfg, logger)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
```

- [ ] **Step 3: Add the policy adapter and use the store-backed constructor**

Add near `toAuthUsers` (after line 470):

```go
// policySettingsStore adapts *settings.Store to policy.SettingsStore, storing
// the runtime policy params as JSON under the "policy" key.
type policySettingsStore struct{ s *settings.Store }

func (p policySettingsStore) LoadPolicy() (policy.RuntimeParams, bool, error) {
	b, ok, err := p.s.Get("policy")
	if err != nil || !ok {
		return policy.RuntimeParams{}, ok, err
	}
	var rp policy.RuntimeParams
	if err := json.Unmarshal(b, &rp); err != nil {
		return policy.RuntimeParams{}, false, fmt.Errorf("decoding stored policy: %w", err)
	}
	return rp, true, nil
}

func (p policySettingsStore) SavePolicy(rp policy.RuntimeParams) error {
	b, err := json.Marshal(rp)
	if err != nil {
		return err
	}
	return p.s.Put("policy", b)
}
```

Add `"encoding/json"` to the imports if not already present.

Replace the `policyRuntime := policy.NewRuntime(...)` line (line 141) with:

```go
	policyRuntime, err := policy.NewRuntimeWithStore(cfg.SupplyChain, cfg.CVE, profile, fileAllow, policySettingsStore{s: settingsStore})
	if err != nil {
		return err
	}
```

Update the comment above it (lines 138-140) to note edits now persist to the database rather than reset on restart.

- [ ] **Step 4: Build and run the full Go test suite**

Run: `go build ./... && go test ./...`
Expected: PASS (no behavior change for existing tests; policy now persists through the shared DB).

- [ ] **Step 5: Lint + commit**

Run: `gofmt -w cmd/jo-ei && golangci-lint run ./cmd/...`
Expected: clean.

```bash
git add cmd/jo-ei/main.go
git commit -m "feat(cmd): persist runtime policy to shared SQLite settings store"
```

---

### Task 4: console registries API (PUT + GET pending_restart + validation)

**Files:**
- Modify: `internal/console/server.go`
- Test: `internal/console/registries_test.go` (new file, `console_test` package)

**Interfaces:**
- Consumes: nothing new (tests use an in-package fake `RegistryStore`).
- Produces (additions to `internal/console`):
  - `type RegistryStore interface { LoadRegistries() ([]RegistryInfo, bool, error); SaveRegistries([]RegistryInfo) error }`
  - `Config` new fields: `RegistryStore RegistryStore`, `RunningRegistries []RegistryInfo`, `ImageScanEnabled bool`.
  - Route `PUT /api/registries` → `s.putRegistries`.
  - `GET /api/registries` now returns `{registries, pending_restart, warnings}`.

- [ ] **Step 1: Write the failing test**

```go
package console_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

type fakeRegStore struct {
	regs []console.RegistryInfo
	ok   bool
}

func (f *fakeRegStore) LoadRegistries() ([]console.RegistryInfo, bool, error) {
	return f.regs, f.ok, nil
}
func (f *fakeRegStore) SaveRegistries(in []console.RegistryInfo) error {
	f.regs = in
	f.ok = true
	return nil
}

func allFive(dockerEnabled bool) []console.RegistryInfo {
	return []console.RegistryInfo{
		{Ecosystem: "pypi", Enabled: true, Upstreams: []string{"https://pypi.org/simple"}},
		{Ecosystem: "npm", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "maven", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "rubygems", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "docker", Enabled: dockerEnabled, Upstreams: func() []string {
			if dockerEnabled {
				return []string{"https://registry-1.docker.io"}
			}
			return []string{}
		}()},
	}
}

func regHandler(t *testing.T, store console.RegistryStore, running []console.RegistryInfo, imageScan bool) *httptest.Server {
	t.Helper()
	h := console.NewHandler(console.Config{
		Store:             newTelemetryStore(t),
		Broadcaster:       telemetry.NewBroadcaster(),
		RegistryStore:     store,
		RunningRegistries: running,
		ImageScanEnabled:  imageScan,
		Logger:            zerolog.Nop(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func putRegistries(t *testing.T, url string, regs []console.RegistryInfo) (*http.Response, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"registries": regs})
	req, err := http.NewRequest(http.MethodPut, url+"/api/registries", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	out := new(bytes.Buffer)
	_, _ = out.ReadFrom(resp.Body)
	_ = resp.Body.Close()
	return resp, out.Bytes()
}

func TestPutRegistries_PersistsAndFlagsPending(t *testing.T) {
	running := allFive(false)
	fs := &fakeRegStore{regs: running, ok: true}
	srv := regHandler(t, fs, running, false)

	edited := allFive(false)
	edited[1].Enabled = true
	edited[1].Upstreams = []string{"https://registry.npmjs.org"}

	resp, body := putRegistries(t, srv.URL, edited)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out struct {
		Registries     []console.RegistryInfo `json:"registries"`
		PendingRestart bool                   `json:"pending_restart"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	assert.True(t, out.PendingRestart, "edit differs from running set")
	assert.True(t, fs.regs[1].Enabled, "npm persisted as enabled")
}

func TestGetRegistries_NoPendingWhenUnchanged(t *testing.T) {
	running := allFive(false)
	fs := &fakeRegStore{regs: running, ok: true}
	srv := regHandler(t, fs, running, false)

	var out struct {
		Registries     []console.RegistryInfo `json:"registries"`
		PendingRestart bool                   `json:"pending_restart"`
	}
	code := getJSON(t, srv.URL+"/api/registries", &out)
	require.Equal(t, http.StatusOK, code)
	assert.False(t, out.PendingRestart)
	assert.Len(t, out.Registries, 5)
}

func TestPutRegistries_EnabledNeedsUpstream(t *testing.T) {
	running := allFive(false)
	srv := regHandler(t, &fakeRegStore{regs: running, ok: true}, running, false)

	bad := allFive(false)
	bad[1].Enabled = true // npm enabled with no upstreams
	resp, body := putRegistries(t, srv.URL, bad)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var e struct{ Error, Field string }
	require.NoError(t, json.Unmarshal(body, &e))
	assert.Equal(t, "invalid_registries", e.Error)
	assert.Equal(t, "npm", e.Field)
}

func TestPutRegistries_UnknownEcoRejected(t *testing.T) {
	running := allFive(false)
	srv := regHandler(t, &fakeRegStore{regs: running, ok: true}, running, false)

	bad := append(allFive(false), console.RegistryInfo{Ecosystem: "cargo", Enabled: false, Upstreams: []string{}})
	resp, body := putRegistries(t, srv.URL, bad)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var e struct{ Error, Field string }
	require.NoError(t, json.Unmarshal(body, &e))
	assert.Equal(t, "invalid_registries", e.Error)
	assert.Equal(t, "registries", e.Field)
}

func TestPutRegistries_DockerWithoutImageScanWarns(t *testing.T) {
	running := allFive(false)
	fs := &fakeRegStore{regs: running, ok: true}
	srv := regHandler(t, fs, running, false) // image_scan OFF

	edited := allFive(true) // docker enabled
	resp, body := putRegistries(t, srv.URL, edited)
	require.Equal(t, http.StatusOK, resp.StatusCode) // warning, not rejection
	var out struct {
		Warnings []string `json:"warnings"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	require.NotEmpty(t, out.Warnings)
	assert.Contains(t, out.Warnings[0], "image_scan")
	assert.True(t, fs.regs[4].Enabled, "docker still persisted despite warning")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/console/ -run 'Registries'`
Expected: FAIL — `unknown field 'RegistryStore' in struct literal`, `undefined: console.RegistryStore`.

- [ ] **Step 3: Implement the store interface, Config fields, validation, and handlers**

In `internal/console/server.go`:

Add `"net/url"` and `"sort"` to the imports.

Add after `RegistryInfo` (after line 35):

```go
// RegistryStore persists the editable registry set. Implemented in cmd/jo-ei by
// an adapter over *settings.Store. When nil, registries are read-only.
type RegistryStore interface {
	LoadRegistries() ([]RegistryInfo, bool, error)
	SaveRegistries([]RegistryInfo) error
}

var knownEcos = []string{"pypi", "npm", "maven", "rubygems", "docker"}
```

Add to the `Config` struct (after the `Registries` field, line 50):

```go
	// RegistryStore persists registry edits (PUT /api/registries). Nil keeps the
	// screen read-only using the static Registries field.
	RegistryStore RegistryStore
	// RunningRegistries is the registry set the live proxy mux actually serves
	// (captured at boot). GET/PUT report pending_restart when the stored set
	// differs from this.
	RunningRegistries []RegistryInfo
	// ImageScanEnabled reports whether Trivy image-scanning is configured; when
	// false, enabling the docker registry produces a warning (the docker handler
	// is gated on image-scan at boot).
	ImageScanEnabled bool
```

Add the route in `NewHandler` (after line 84):

```go
	mux.HandleFunc("PUT /api/registries", s.putRegistries)
```

Replace the existing `registries` handler (lines 299-301) with the read+pending+warnings version and add the PUT handler plus helpers:

```go
func (s *server) registries(w http.ResponseWriter, _ *http.Request) {
	regs, err := s.storedRegistries()
	if err != nil {
		s.cfg.Logger.Error().Err(err).Msg("console: load registries")
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "registries_unavailable"})
		return
	}
	s.writeRegistries(w, http.StatusOK, regs)
}

func (s *server) putRegistries(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RegistryStore == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "registries_read_only"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var in struct {
		Registries []RegistryInfo `json:"registries"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_registries", "field": "body", "message": err.Error(),
		})
		return
	}
	if field, msg := validateRegistries(in.Registries); field != "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_registries", "field": field, "message": msg,
		})
		return
	}
	for i := range in.Registries {
		if in.Registries[i].Upstreams == nil {
			in.Registries[i].Upstreams = []string{}
		}
	}
	if err := s.cfg.RegistryStore.SaveRegistries(in.Registries); err != nil {
		s.cfg.Logger.Error().Err(err).Msg("console: save registries")
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "persist_failed"})
		return
	}
	s.writeRegistries(w, http.StatusOK, in.Registries)
}

// storedRegistries returns the persisted set when a store is configured,
// otherwise the static Registries (read-only mode).
func (s *server) storedRegistries() ([]RegistryInfo, error) {
	if s.cfg.RegistryStore != nil {
		regs, ok, err := s.cfg.RegistryStore.LoadRegistries()
		if err != nil {
			return nil, err
		}
		if ok {
			return regs, nil
		}
	}
	return s.cfg.Registries, nil
}

func (s *server) writeRegistries(w http.ResponseWriter, status int, regs []RegistryInfo) {
	for i := range regs {
		if regs[i].Upstreams == nil {
			regs[i].Upstreams = []string{}
		}
	}
	warnings := registryWarnings(regs, s.cfg.ImageScanEnabled)
	s.writeJSON(w, status, map[string]any{
		"registries":      regs,
		"pending_restart": s.cfg.RunningRegistries != nil && !registriesEqual(regs, s.cfg.RunningRegistries),
		"warnings":        warnings,
	})
}

// validateRegistries checks the PUT payload. It returns ("","") when valid,
// otherwise the offending field and a message.
func validateRegistries(in []RegistryInfo) (field, msg string) {
	seen := map[string]bool{}
	for _, r := range in {
		if !contains(knownEcos, r.Ecosystem) {
			return "registries", fmt.Sprintf("unknown ecosystem %q", r.Ecosystem)
		}
		if seen[r.Ecosystem] {
			return "registries", fmt.Sprintf("duplicate ecosystem %q", r.Ecosystem)
		}
		seen[r.Ecosystem] = true
	}
	if len(seen) != len(knownEcos) {
		return "registries", fmt.Sprintf("must list all %d ecosystems", len(knownEcos))
	}
	for _, r := range in {
		if !r.Enabled {
			continue
		}
		if len(r.Upstreams) == 0 {
			return r.Ecosystem, "an enabled registry needs at least one upstream"
		}
		for _, u := range r.Upstreams {
			parsed, err := url.Parse(u)
			if u == "" || err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
				return r.Ecosystem, fmt.Sprintf("upstream %q must be an http(s) URL", u)
			}
		}
	}
	return "", ""
}

// registryWarnings flags non-fatal configuration problems (currently: docker
// enabled without image-scan, which won't serve /v2/ after restart).
func registryWarnings(regs []RegistryInfo, imageScan bool) []string {
	warnings := []string{}
	for _, r := range regs {
		if r.Ecosystem == "docker" && r.Enabled && !imageScan {
			warnings = append(warnings,
				"docker is enabled but image_scan is not configured in config.yaml; /v2/ will not serve after restart")
		}
	}
	return warnings
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// registriesEqual compares two sets order-independently by ecosystem.
func registriesEqual(a, b []RegistryInfo) bool {
	if len(a) != len(b) {
		return false
	}
	idx := func(list []RegistryInfo) map[string]RegistryInfo {
		m := make(map[string]RegistryInfo, len(list))
		for _, r := range list {
			m[r.Ecosystem] = r
		}
		return m
	}
	ma, mb := idx(a), idx(b)
	for eco, ra := range ma {
		rb, ok := mb[eco]
		if !ok || ra.Enabled != rb.Enabled {
			return false
		}
		ua := append([]string{}, ra.Upstreams...)
		ub := append([]string{}, rb.Upstreams...)
		if len(ua) != len(ub) {
			return false
		}
		for i := range ua {
			if ua[i] != ub[i] {
				return false
			}
		}
		_ = sort.StringSlice(ua) // upstream order is significant (primary first); compared positionally above
	}
	return true
}
```

> Note: `registriesEqual` compares upstreams positionally (order is significant — index 0 is the primary). The `sort` import is only retained if used; if `go vet`/lint flags the unused `sort.StringSlice` line, delete that line and the `"sort"` import. Prefer removing it — it is a no-op. (Cleaner: omit `"sort"` entirely and drop the `_ = sort...` line.)

- [ ] **Step 4: Remove the dead `sort` reference**

Delete the `_ = sort.StringSlice(ua) ...` line and the `"sort"` import (it was only illustrative). Re-run the build to confirm.

Run: `go build ./internal/console/...`
Expected: builds clean.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/console/...`
Expected: PASS (existing console tests + new registries tests). The existing `TestRegistries` / `TestRegistries_NilUpstreams` still pass because, with `RegistryStore` nil, GET falls back to the static `Registries` and `pending_restart` is `false`.

- [ ] **Step 6: Lint + commit**

Run: `gofmt -w internal/console && golangci-lint run ./internal/console/...`
Expected: clean.

```bash
git add internal/console/server.go internal/console/registries_test.go
git commit -m "feat(console): editable registries API (PUT, validation, pending_restart, warnings)"
```

---

### Task 5: wire registry persistence into `cmd/jo-ei`

**Files:**
- Modify: `cmd/jo-ei/main.go`

**Interfaces:**
- Consumes: `settings.Store`, `console.RegistryInfo`, `console.RegistryStore`, the new `console.Config` fields, `registryInfo`.
- Produces:
  - `type registrySettingsStore struct { s *settings.Store }` implementing `console.RegistryStore`.
  - `func applyStoredRegistries(cfg *config.Config, st *settings.Store) error` — overlay-or-seed at boot.

- [ ] **Step 1: Add the registry adapter and overlay helper**

In `cmd/jo-ei/main.go`, after `registryInfo` (after line 481), add:

```go
// registrySettingsStore adapts *settings.Store to console.RegistryStore, storing
// the registry set as JSON under the "registries" key.
type registrySettingsStore struct{ s *settings.Store }

func (r registrySettingsStore) LoadRegistries() ([]console.RegistryInfo, bool, error) {
	b, ok, err := r.s.Get("registries")
	if err != nil || !ok {
		return nil, ok, err
	}
	var regs []console.RegistryInfo
	if err := json.Unmarshal(b, &regs); err != nil {
		return nil, false, fmt.Errorf("decoding stored registries: %w", err)
	}
	return regs, true, nil
}

func (r registrySettingsStore) SaveRegistries(in []console.RegistryInfo) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return r.s.Put("registries", b)
}

// applyStoredRegistries overlays persisted registry settings onto cfg before the
// proxy mux is built (DB wins), or seeds the store from the YAML config on first
// boot. A corrupt stored value fails fast rather than silently using YAML.
func applyStoredRegistries(cfg *config.Config, st *settings.Store) error {
	b, ok, err := st.Get("registries")
	if err != nil {
		return err
	}
	if !ok {
		seed, err := json.Marshal(registryInfo(cfg))
		if err != nil {
			return err
		}
		return st.Put("registries", seed)
	}
	var stored []console.RegistryInfo
	if err := json.Unmarshal(b, &stored); err != nil {
		return fmt.Errorf("decoding stored registries: %w", err)
	}
	for _, ri := range stored {
		rc := config.RegistryConfig{Enabled: ri.Enabled, Upstreams: ri.Upstreams}
		switch ri.Ecosystem {
		case "pypi":
			cfg.Registries.PyPI = rc
		case "npm":
			cfg.Registries.NPM = rc
		case "maven":
			cfg.Registries.Maven = rc
		case "rubygems":
			cfg.Registries.RubyGems = rc
		case "docker":
			cfg.Registries.Docker = rc
		}
	}
	return nil
}
```

- [ ] **Step 2: Apply the overlay at boot**

Immediately after the `settingsStore, err := settings.New(sdb)` block (from Task 3, Step 1) and before `artifactCache`/`profile`/registry usage, add:

```go
	if err := applyStoredRegistries(cfg, settingsStore); err != nil {
		return err
	}
```

- [ ] **Step 3: Capture the running snapshot and wire the console fields**

After the proxy mux is built (after line 351, `mux := proxy.NewMux(...)`), the effective registry set is final. Add:

```go
	runningRegistries := registryInfo(cfg)
```

Then update the `console.NewHandler(console.Config{...})` literal (lines 369-378) to add the new fields:

```go
	root.Handle("/api/", authUsers.Middleware(console.NewHandler(console.Config{
		Store:             store,
		Broadcaster:       broadcaster,
		Policy:            policyRuntime,
		Cache:             artifactCache,
		CacheMaxBytes:     int64(cfg.Cache.Local.MaxSizeGB) << 30,
		Registries:        runningRegistries,
		RegistryStore:     registrySettingsStore{s: settingsStore},
		RunningRegistries: runningRegistries,
		ImageScanEnabled:  cfg.ImageScan.Enabled,
		Health:            healthMon,
		Logger:            logger,
	})))
```

- [ ] **Step 4: Build and run the full test suite**

Run: `go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

Run: `gofmt -w cmd/jo-ei && golangci-lint run ./cmd/...`
Expected: clean.

```bash
git add cmd/jo-ei/main.go
git commit -m "feat(cmd): overlay/seed registries from settings store and wire editable console"
```

---

### Task 6: integration test — settings survive a restart

**Files:**
- Create: `integration/settings_persistence_test.go`

**Interfaces:**
- Consumes: `storage.Open`, `settings.New`, `policy.NewRuntimeWithStore`, the `policySettingsStore` behavior, `console.NewHandler` with `RegistryStore`, `applyStoredRegistries` behavior.

Because the adapters (`policySettingsStore`, `registrySettingsStore`, `applyStoredRegistries`) live in `package main` and aren't importable, this test re-implements the same tiny JSON-over-settings glue locally and asserts the round-trip across two DB opens — exactly mirroring `telemetry_persistence_test.go`.

- [ ] **Step 1: Write the test**

```go
//go:build integration

package integration_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

// policyStore mirrors cmd/jo-ei's policySettingsStore (unexported there).
type policyStore struct{ s *settings.Store }

func (p policyStore) LoadPolicy() (policy.RuntimeParams, bool, error) {
	b, ok, err := p.s.Get("policy")
	if err != nil || !ok {
		return policy.RuntimeParams{}, ok, err
	}
	var rp policy.RuntimeParams
	require := json.Unmarshal(b, &rp)
	return rp, true, require
}
func (p policyStore) SavePolicy(rp policy.RuntimeParams) error {
	b, err := json.Marshal(rp)
	if err != nil {
		return err
	}
	return p.s.Put("policy", b)
}

func scCfg() config.SupplyChainConfig { return config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24} }
func cveCfg() config.CVEConfig        { return config.CVEConfig{Enabled: true, BlockOn: "CRITICAL"} }

func TestPolicyPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jo-ei.db")

	// First process: seed from YAML, then apply an edit.
	{
		db, err := storage.Open(path)
		require.NoError(t, err)
		st, err := settings.New(db)
		require.NoError(t, err)
		r, err := policy.NewRuntimeWithStore(scCfg(), cveCfg(), config.PolicyProfile{CVEBlock: true}, nil, policyStore{st})
		require.NoError(t, err)

		p := r.Current()
		p.Mode = "dry_run"
		p.MinAgeHours = 0
		require.NoError(t, r.Apply(p))
		require.NoError(t, db.Close())
	}

	// Second process: reopen — the edit (not the YAML default) is installed.
	db, err := storage.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	st, err := settings.New(db)
	require.NoError(t, err)
	r, err := policy.NewRuntimeWithStore(scCfg(), cveCfg(), config.PolicyProfile{CVEBlock: true}, nil, policyStore{st})
	require.NoError(t, err)

	assert.Equal(t, "dry_run", r.Current().Mode, "edited mode restored from DB, not YAML")
	assert.Equal(t, 0, r.Current().MinAgeHours)
}

func TestRegistriesPersistAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jo-ei.db")
	edited := []console.RegistryInfo{
		{Ecosystem: "pypi", Enabled: true, Upstreams: []string{"https://pypi.org/simple"}},
		{Ecosystem: "npm", Enabled: true, Upstreams: []string{"https://registry.npmjs.org"}},
		{Ecosystem: "maven", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "rubygems", Enabled: false, Upstreams: []string{}},
		{Ecosystem: "docker", Enabled: false, Upstreams: []string{}},
	}

	// First process: persist an edited registry set.
	{
		db, err := storage.Open(path)
		require.NoError(t, err)
		st, err := settings.New(db)
		require.NoError(t, err)
		b, err := json.Marshal(edited)
		require.NoError(t, err)
		require.NoError(t, st.Put("registries", b))
		require.NoError(t, db.Close())
	}

	// Second process: reopen and overlay onto a fresh (npm-disabled) config.
	db, err := storage.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	st, err := settings.New(db)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.Registries.PyPI = config.RegistryConfig{Enabled: true, Upstreams: []string{"https://pypi.org/simple"}}
	b, ok, err := st.Get("registries")
	require.NoError(t, err)
	require.True(t, ok)
	var stored []console.RegistryInfo
	require.NoError(t, json.Unmarshal(b, &stored))
	for _, ri := range stored {
		if ri.Ecosystem == "npm" {
			cfg.Registries.NPM = config.RegistryConfig{Enabled: ri.Enabled, Upstreams: ri.Upstreams}
		}
	}
	assert.True(t, cfg.Registries.NPM.Enabled, "npm edit restored from DB")
	assert.Equal(t, []string{"https://registry.npmjs.org"}, cfg.Registries.NPM.Upstreams)
}
```

> Note: in `policyStore.LoadPolicy` the variable named `require` shadows the testify import locally inside that method only; rename it to `uerr` to avoid confusion: `uerr := json.Unmarshal(b, &rp); return rp, true, uerr`. Apply that rename when typing the file.

- [ ] **Step 2: Run the integration test to verify it passes**

Run: `go test -tags integration ./integration/ -run 'PersistsAcrossRestart|PersistAcrossRestart' -v`
Expected: PASS (both tests).

- [ ] **Step 3: Lint + commit**

Run: `gofmt -w integration && golangci-lint run --build-tags integration ./integration/...`
Expected: clean.

```bash
git add integration/settings_persistence_test.go
git commit -m "test(integration): policy and registries survive a restart"
```

---

### Task 7: console UI — editable registries + persisted-policy copy

**Files:**
- Modify: `web/console/src/registries.jsx`
- Modify: `web/console/src/policy.jsx`
- Modify: `web/console/src/api.js`
- Modify: `web/console/src/app.jsx`
- Regenerate: `web/console/app.bundle.js` (via `go generate ./...`)
- Test: `web/web_test.go` (add one smoke assertion)

**Interfaces:**
- Consumes: `GET/PUT /api/registries` (Task 4) returning `{registries, pending_restart, warnings}`.
- Produces: `JOEI.saveRegistries(list)` on the API client; an editable `Registries` screen receiving a `notify` prop.

- [ ] **Step 1: Add `saveRegistries` and carry pending/warnings in `api.js`**

In `web/console/src/api.js`, update the `registries` default state and `load()` parsing, drop the policy "runtime" framing, and add `saveRegistries`.

Change the `registries: []` line (line 40) region — leave it, but in `load()` replace the registries assignment (line 131) with:

```js
    J.registries = (registries.registries || []).map((r) => ({ eco: r.eco, enabled: r.enabled, upstreams: r.upstreams || [] }));
    J.registriesPending = !!registries.pending_restart;
    J.registriesWarnings = registries.warnings || [];
```

Add `registriesPending: false, registriesWarnings: [],` to the `J` object literal (near the `registries: []` field, line 40).

In the policy default state (lines 36-39) change `persistence: "runtime"` to `persistence: "database"`.

After `savePolicy` (after line 176), add:

```js
  async function saveRegistries(list) {
    const body = { registries: list.map((r) => ({ eco: r.eco, enabled: r.enabled, upstreams: r.upstreams })) };
    const res = await fetch("/api/registries", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON error body */ }
    if (!res.ok) {
      const err = new Error((data && data.message) || "registries update failed (HTTP " + res.status + ")");
      err.field = data && data.field;
      throw err;
    }
    J.registries = (data.registries || []).map((r) => ({ eco: r.eco, enabled: r.enabled, upstreams: r.upstreams || [] }));
    J.registriesPending = !!data.pending_restart;
    J.registriesWarnings = data.warnings || [];
    fire("joei:data");
    return { pending: J.registriesPending, warnings: J.registriesWarnings };
  }
```

Export it next to the other handlers (after line 202, `J.pageRequests = pageRequests;`):

```js
  J.saveRegistries = saveRegistries;
```

- [ ] **Step 2: Make the `Registries` screen editable**

Replace the whole of `web/console/src/registries.jsx` with an editor. It keeps the cache panel, turns each registry card into a toggle + upstream editor, adds Save and a pending/restart + warnings banner.

```jsx
/* 浄衛 Jōei :: REGISTRIES & CACHE */

const REG_ECOS = ["pypi", "npm", "maven", "rubygems", "docker"];

function UpstreamEditor({ upstreams, onChange }) {
  const [val, setVal] = useState("");
  const add = () => { const v = val.trim(); if (v) { onChange([...upstreams, v]); setVal(""); } };
  const remove = (i) => onChange(upstreams.filter((_, j) => j !== i));
  const move = (i, d) => {
    const j = i + d;
    if (j < 0 || j >= upstreams.length) return;
    const next = upstreams.slice();
    [next[i], next[j]] = [next[j], next[i]];
    onChange(next);
  };
  return (
    <div className="upstream">
      {upstreams.map((u, i) => (
        <div className="upstream-item" key={u + i}>
          <span className="ord">{i + 1}</span>
          <span style={{ flex: 1 }}>{u}</span>
          <span className="pri">{i === 0 ? "primary" : "fallback"}</span>
          <button className="btn sm ghost" disabled={i === 0} onClick={() => move(i, -1)} aria-label="up">↑</button>
          <button className="btn sm ghost" disabled={i === upstreams.length - 1} onClick={() => move(i, 1)} aria-label="down">↓</button>
          <button className="lc-del" onClick={() => remove(i)}><Icons.trash /></button>
        </div>
      ))}
      <div className="upstream-item" style={{ borderStyle: "dashed" }}>
        <Icons.plus />
        <input
          className="lc-val" style={{ background: "none", border: "none", outline: "none", color: "var(--washi)", flex: 1 }}
          placeholder="https://registry.example.org"
          value={val} onChange={(e) => setVal(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add()}
        />
        <button className="btn sm ghost" onClick={add}>Add</button>
      </div>
    </div>
  );
}

function RegistryCard({ reg, onToggle, onUpstreams }) {
  const e = JOEI.ECO[reg.eco] || { name: reg.eco };
  return (
    <div className="card reg-card">
      <div className="reg-head">
        <Eco id={JOEI.ECO[reg.eco] ? reg.eco : "pypi"} size={30} />
        <div className="col">
          <span className="reg-name">{e.name}</span>
          <span className="reg-vol">{reg.enabled ? `${reg.upstreams.length} upstream${reg.upstreams.length === 1 ? "" : "s"}` : "disabled"}</span>
        </div>
        <div className="right row" style={{ gap: 10 }}>
          <span className="muted" style={{ fontSize: 12 }}>{reg.enabled ? "enabled" : "off"}</span>
          <button className={`toggle ${reg.enabled ? "on" : ""}`} onClick={() => onToggle(!reg.enabled)} aria-label="toggle"></button>
        </div>
      </div>
      <UpstreamEditor upstreams={reg.upstreams} onChange={onUpstreams} />
    </div>
  );
}

function Registries({ notify }) {
  useJoeiData();
  const c = JOEI.cache;
  const usedPct = c.max_gb > 0 ? Math.min(100, (c.used_gb / c.max_gb) * 100) : 0;

  // Normalize to all five ecosystems in canonical order for editing.
  const initial = () => REG_ECOS.map((eco) => {
    const found = JOEI.registries.find((r) => r.eco === eco);
    return found ? { ...found, upstreams: [...found.upstreams] } : { eco, enabled: false, upstreams: [] };
  });
  const [draft, setDraft] = useState(initial);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [pending, setPending] = useState(JOEI.registriesPending);

  const dirtyRef = useRef(dirty);
  useEffect(() => { dirtyRef.current = dirty; }, [dirty]);
  useEffect(() => {
    const sync = () => { if (!dirtyRef.current) { setDraft(initial()); setPending(JOEI.registriesPending); } };
    window.addEventListener("joei:data", sync);
    return () => window.removeEventListener("joei:data", sync);
  }, []);

  const patch = (eco, change) => {
    setDraft(draft.map((r) => (r.eco === eco ? { ...r, ...change } : r)));
    setDirty(true);
  };

  const save = () => {
    setSaving(true);
    JOEI.saveRegistries(draft)
      .then(({ pending, warnings }) => {
        setDirty(false);
        setPending(pending);
        notify({ kind: "ok", code: "200 OK", title: "Registries saved",
          msg: <>Saved to the database — changes apply on the next restart.{warnings.length ? " " + warnings[0] : ""}</> });
      })
      .catch((err) => notify({ kind: "block", code: "400 Bad Request", title: "Registries rejected",
        msg: String(err.message || err) }))
      .finally(() => setSaving(false));
  };

  return (
    <div className="content-inner">
      <div className="section-head">
        <span className="head-kanji kanji">蔵</span>
        <div>
          <div className="eyebrow">Upstreams &amp; storage · persisted, applies on restart</div>
          <h2>Registries &amp; cache</h2>
        </div>
        <div className="spacer"></div>
        <button className={`btn ${dirty ? "primary" : ""}`} disabled={!dirty || saving}
          style={!dirty ? { opacity: .5 } : undefined} onClick={save}>
          {saving ? "Saving…" : dirty ? "Save" : "Saved"}
        </button>
      </div>

      {pending && (
        <div className="card" role="status" style={{ padding: 14, marginBottom: 16, borderColor: "var(--gold)" }}>
          <span className="muted">⟳ Registry changes are saved but <b style={{ color: "var(--gold-l)" }}>apply on the next restart</b>.</span>
        </div>
      )}

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
        </div>
        <div className="cache-meter">
          <i className="used" style={{ width: usedPct + "%" }}></i>
        </div>
        <div className="row" style={{ marginTop: 12, gap: 28, fontSize: 12.5 }}>
          <span className="muted">Objects <b className="mono" style={{ color: "var(--washi)" }}>{c.objects}</b></span>
          <span className="muted">Hit rate · since start <b className="mono" style={{ color: "var(--jade-l)" }}>{(c.hit_rate * 100).toFixed(1)}%</b></span>
          <span className="muted">LRU evictions · since start <b className="mono" style={{ color: "var(--gold-l)" }}>{fmtNum(c.evictions)}</b></span>
        </div>
      </div>

      <div className="section-head" style={{ marginBottom: 14 }}>
        <h2 style={{ fontSize: 16 }}>Per-ecosystem upstreams</h2>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        {draft.map((r) => (
          <RegistryCard key={r.eco} reg={r}
            onToggle={(enabled) => patch(r.eco, { enabled })}
            onUpstreams={(upstreams) => patch(r.eco, { upstreams })} />
        ))}
      </div>
    </div>
  );
}

Object.assign(window, { Registries, RegistryCard, UpstreamEditor });
```

- [ ] **Step 2b: Pass `notify` to the screen**

In `web/console/src/app.jsx` change line 190:

```jsx
          {page === "registries" && <Registries notify={notify} />}
```

- [ ] **Step 3: Update the policy copy**

In `web/console/src/policy.jsx`:
- Line 34 comment string: `"# 浄衛 runtime policy — resets to config.yaml on restart"` → `"# 浄衛 runtime policy — persisted to the database"`.
- Line 92-93 success toast: replace `Runtime policy updated — resets to the YAML config on restart.` with `Policy updated and saved to the database.`
- Line 111 eyebrow: `Runtime policy · applies immediately, resets on restart` → `Runtime policy · applies immediately, persisted`.
- Lines 125-128 paragraph: replace the "runtime override … a restart restores the file policy" wording with: `Changes apply to the gate immediately and are <b style={{ color: "var(--jade-l)" }}>saved to the database</b>, so they survive a restart.` (keep the trailing `{fieldError && ...}` span unchanged).

- [ ] **Step 4: Rebuild the bundle**

Run: `go generate ./...`
Expected: `uibuild: wrote console/app.bundle.js (N bytes)` and no esbuild errors.

- [ ] **Step 5: Add a bundle smoke assertion + run web tests**

In `web/web_test.go`, add:

```go
func TestBundleIncludesRegistryEditor(t *testing.T) {
	srv := http.NewServeMux()
	srv.Handle("/console/", ConsoleHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/console/app.bundle.js", nil)
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bundle status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"saveRegistries", "UpstreamEditor"} {
		if !strings.Contains(body, want) {
			t.Errorf("app.bundle.js missing %q — rebuild with `go generate ./...`", want)
		}
	}
}
```

Run: `go test ./web/...`
Expected: PASS (existing web tests + the new smoke test).

- [ ] **Step 6: Full build, test, lint**

Run: `go build ./... && go test ./... && golangci-lint run`
Expected: all PASS / clean.

- [ ] **Step 7: Commit**

```bash
git add web/console/src/registries.jsx web/console/src/policy.jsx web/console/src/api.js web/console/src/app.jsx web/console/app.bundle.js web/web_test.go
git commit -m "feat(console-ui): editable registries screen + persisted-policy copy"
```

---

## Self-Review

**Spec coverage:**
- Generic key→JSON settings store + `settings` migration → Task 1. ✓
- Policy seed-or-load + save→install + 500 on persist failure → Tasks 2, 3. ✓
- Registries overlay/seed at boot (DB wins) → Task 5. ✓
- `PUT /api/registries` + validation rules + docker/image-scan warning → Task 4. ✓
- `GET /api/registries` pending_restart via boot snapshot → Tasks 4, 5. ✓
- `console.Config` gains RegistryStore / RunningRegistries / ImageScanEnabled → Task 4. ✓
- Error envelopes (invalid_registries, persist_failed) → Task 4; policy persist_failed mapping via `PersistError` → Tasks 2, 4-note. ✓
- Fail-fast on corrupt stored value at boot → Task 5 (`applyStoredRegistries`), Task 3 (policy adapter decode error surfaces via NewRuntimeWithStore). ✓
- Restart-survives integration test → Task 6. ✓
- UI: editable registries, policy copy, api.js, bundle rebuild, web smoke → Task 7. ✓
- Out-of-scope items (hot-reload, CVE/cache/health, reset-to-YAML, auth) → not implemented, matching spec. ✓

**Placeholder scan:** No TBD/TODO/"handle edge cases"; every code step shows full code. The two prose `> Note:` callouts (drop `sort` in Task 4; rename shadowed `require` in Task 6) are explicit corrective instructions, not deferrals.

**Type consistency:**
- `policy.SettingsStore { LoadPolicy() (RuntimeParams, bool, error); SavePolicy(RuntimeParams) error }` — used identically in Tasks 2, 3, 6. ✓
- `console.RegistryStore { LoadRegistries() ([]RegistryInfo, bool, error); SaveRegistries([]RegistryInfo) error }` — Tasks 4, 5. ✓
- `console.Config` fields `RegistryStore`, `RunningRegistries`, `ImageScanEnabled` — defined Task 4, set Task 5. ✓
- `settings.New/Get/Put` signatures — defined Task 1, consumed Tasks 3, 5, 6. ✓
- `NewRuntimeWithStore(sc, cve, profile, fileAllow, store) (*Runtime, error)` — defined Task 2, called Tasks 3, 6. ✓
- API client `JOEI.saveRegistries(list)` returning `{pending, warnings}` — defined and consumed in Task 7. ✓

**Note on Task 4 `PersistError` mapping:** Task 2 introduces `policy.PersistError`; the existing `putPolicy` handler (server.go lines 279-289) already falls through non-`ValidationError` errors to a 500. To emit the spec's `persist_failed` body, add this branch in `putPolicy` before the generic 500 (fold into Task 4 Step 3):

```go
		var perr *policy.PersistError
		if errors.As(err, &perr) {
			s.cfg.Logger.Error().Err(err).Msg("console: policy persist")
			s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "persist_failed"})
			return
		}
```

(`errors` and `policy` are already imported in server.go.)

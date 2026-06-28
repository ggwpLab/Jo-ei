# Persistent settings: policy + registries in the database

**Date:** 2026-06-28
**Status:** Approved (design)
**Scope:** Move runtime-editable **policy** and **registry** settings out of
runtime-only / boot-only state into the embedded SQLite database, so console
edits survive a restart. Extend the UI so registries are editable (today they
are read-only) and correct the policy UI copy.

## Problem

Two classes of configuration are lost on restart:

1. **Policy** (`internal/policy/runtime.go`) is editable at runtime via
   `PUT /api/policy` behind an atomic pointer, but edits are runtime-only — the
   YAML config wins again after a restart. The UI says so explicitly
   ("resets to the YAML config on restart").
2. **Registries** (`cmd/jo-ei/main.go`) are read from YAML once at boot to build
   the proxy adapters/mux. They are not editable at runtime at all; the console
   `Registries` screen is read-only with disabled toggles.

We want operator changes to persist. Telemetry already persists to SQLite via
`internal/storage` (a shared `*sql.DB` with per-component migrations), so the
foundation exists.

## Decisions (locked)

- **Source of truth = DB wins, YAML seeds.** On first boot with an empty
  settings store, the YAML-derived values are written to the DB. Thereafter the
  DB is the single source for these fields and YAML edits to them are ignored.
- **Registries: persist + restart-required.** Edits are validated and written to
  the DB; they take effect on the next restart. The live proxy mux is **not**
  rebuilt at runtime (no hot-reload, no atomic mux swap). The UI shows a
  "saved — applies on restart" banner.
- **Scope = policy + registries only.** CVE/scanner, cache-revalidation, and
  health/upstream tuning stay in YAML for now.
- **Policy persist ordering = save → install.** On `PUT /api/policy` we validate,
  then write the DB, then install the atomic swap. If the DB write fails the live
  policy is unchanged and the API returns 500 — DB and runtime never diverge.

## Architecture

### Storage: a generic key→JSON settings store

New package `internal/settings`. One table, owned by a new migration component
`settings`:

```sql
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,   -- JSON
    updated_at INTEGER NOT NULL -- unix seconds
);
```

API (bytes in/out — callers own their JSON shapes, so `policy`/`config` never
import `storage`):

```go
type Store struct { /* wraps *storage.DB */ }
func New(db *storage.DB) (*Store, error)      // runs the migration
func (s *Store) Get(key string) ([]byte, bool, error)
func (s *Store) Put(key string, value []byte) error
```

Keys: `"policy"`, `"registries"`. Rationale for a blob over typed columns: only
two small config groups, schema churns whenever a knob is added, and the DB-wins
model just needs durable load/store — not queryability. Blob keeps migrations to
a single step.

### Policy: seed-or-load + persist-on-apply

`policy` gains a small persistence seam so it does not depend on `storage`:

```go
// SettingsStore persists the runtime policy params. Implemented in cmd/jo-ei
// by an adapter over *settings.Store that marshals/unmarshals RuntimeParams.
type SettingsStore interface {
    LoadPolicy() (RuntimeParams, bool, error)
    SavePolicy(RuntimeParams) error
}
```

- `NewRuntime(...)` gains an optional `store SettingsStore` argument
  (nil keeps today's runtime-only behavior for tests that don't care).
  - On construct: `LoadPolicy()` → found? install those params.
    Not found? compute the YAML-seed params (current `NewRuntime` logic),
    install them, and `SavePolicy()` so the DB is seeded.
- `Apply(p)`: validate (unchanged) → `store.SavePolicy(p)` → on success
  `install(p)`. On save error, return the error **without** installing.
  Concurrency note: `Apply` already serializes via last-writer-wins; we keep that
  and accept that two racing applies persist in call order.

The adapter lives in `cmd/jo-ei` (and a test helper), marshaling `RuntimeParams`
↔ JSON under key `"policy"`.

### Registries: seed-or-load at boot + editable, restart-applied

A small serializable shape (reuse `console.RegistryInfo`-equivalent or a
`settings`-local struct) is stored under key `"registries"`: an ordered list of
`{eco, enabled, upstreams[]}`.

**Boot (`cmd/jo-ei/main.go`):**
1. Build the YAML registry set as today.
2. `store.Get("registries")` → found? overlay the stored set onto
   `cfg.Registries` **before** `buildHandlers`/`registryInfo`/docker wiring.
   Not found? marshal the YAML set and `Put` it (seed).
3. Everything downstream (handlers, mux, revalidation, `registryInfo`) reads the
   effective (overlaid) config — no further changes.

**Console API:**
- `GET /api/registries` (existing): return the stored/effective registries plus
  `pending_restart` (bool). The handler captures a boot-time snapshot of the
  running registry set; `pending_restart` is `stored != running`.
- `PUT /api/registries` (new): accept `{registries:[{eco,enabled,upstreams}]}`,
  validate, `store.Put`, return the same shape as GET with the recomputed
  `pending_restart` (true after any real change).

**Validation rules:**
- `eco` ∈ {pypi, npm, maven, rubygems, docker}; no duplicates; the set must
  cover exactly the known ecosystems (PUT replaces the whole list).
- `enabled == true` ⇒ `len(upstreams) >= 1`; each upstream a non-empty,
  well-formed URL.
- **Docker caveat:** enabling `docker` requires `image_scan` configured in YAML
  (the docker handler is gated on `trivyScanner != nil`, a boot-only dependency).
  If `docker.enabled` is set true but image-scan is not configured, return a
  validation warning so the operator knows the restart won't actually serve
  `/v2/`. (The console learns this via a boot flag passed into its Config.)

`console.Config` gains: the `*settings.Store`-backed registry persister, the
boot-time running snapshot, and an `ImageScanEnabled bool` for the docker caveat.

### UI

- **`registries.jsx`** — read-only → editor:
  - per-ecosystem enable/disable toggle (no longer `disabled`),
  - upstream list: add / remove / reorder (primary = index 0),
  - Save button → `JOEI.saveRegistries(...)`,
  - "saved — applies on restart" banner driven by `pending_restart`,
  - docker row shows the image-scan caveat when relevant.
- **`policy.jsx`** — copy only: replace "resets to the YAML config on restart" /
  "runtime override" wording with "persisted to the database".
- **`api.js`** — add `saveRegistries(list)` (PUT), keep `registries` shape but
  carry `pending_restart`; drop the `persistence:"runtime"` framing for policy.
- Rebuild bundle via `go generate ./...` (esbuild concat, order in
  `internal/uibuild/main.go`).

## Data flow

```
boot:
  YAML ──► cfg.Registries ──┐
                            ├─ settings.Get("registries") found? ─ yes ─► overlay ─► buildHandlers/mux
                            └─ no ─► settings.Put(seed) ───────────────► buildHandlers/mux
  YAML policy params ──► NewRuntime(store):
                            LoadPolicy found? ─ yes ─► install
                                              ─ no  ─► install + SavePolicy(seed)

edit policy (PUT /api/policy):
  validate ─► SavePolicy ─► install (swap)        [save fail ⇒ 500, no swap]

edit registries (PUT /api/registries):
  validate ─► settings.Put ─► pending_restart=true ; live mux unchanged
```

## Error handling

- Policy save failure → 500 `{"error":"persist_failed"}`, live policy unchanged.
- Registry validation failure → 400 `{"error":"invalid_registries","field":...,
  "message":...}` (mirror the policy error envelope).
- Settings store read failure at boot → fail fast (return error from `run`),
  same as telemetry store open failure today.
- Corrupt/unmarshalable stored value → fail fast at boot with a clear message
  (do not silently fall back to YAML — that would mask data loss).

## Testing

- **`internal/settings`**: Get/Put round-trip, missing-key returns `ok=false`,
  overwrite updates `updated_at`, migration is idempotent.
- **`internal/policy`**: seed-from-empty writes the store; load-existing installs
  stored params (not YAML); `Apply` persists then installs; save-failure leaves
  live policy unchanged and returns the error.
- **`internal/console`**: `PUT /api/registries` happy path + each validation
  rule; `pending_restart` flips after a real change; docker-without-image-scan
  warning; error envelope shape.
- **`integration`**: restart-survives test mirroring
  `telemetry_persistence_test.go` — open DB, apply policy + registry edits via the
  handlers, reopen DB, assert the edits are loaded (policy installed, registries
  overlaid).
- **UI**: `web/web_test.go` smoke that the bundle includes the new editor
  symbols; keep it light.

## Out of scope (explicit)

- Hot-reload of registries / live mux rebuild.
- Moving CVE/scanner, cache-revalidation, or health/upstream tuning to the DB.
- A generic "reset this field to YAML default" affordance (DB-wins makes YAML
  inert for these fields after seed; a reset feature can come later).
- Auth/RBAC changes — existing `auth.Middleware` continues to gate `/api/`.

## Migration / compatibility

- First boot after upgrade: empty `settings` table → both keys seeded from the
  existing YAML, so behavior is identical to today until the operator edits
  something. No manual migration step.
- The `settings` migration component is independent of `telemetry`'s, per the
  existing `ApplyMigrations(component, steps)` design.

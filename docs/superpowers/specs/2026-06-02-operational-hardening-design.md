# Operational Hardening — Design

**Date:** 2026-06-02
**Status:** Approved
**Scope:** Operational maturity for Jōei. No major new features. Derived from the
project-wide Go best-practices review.

## Goal

Bring the codebase to operational maturity: a single enforced toolchain gate,
correct process lifecycle, removal of dead configuration, and fixes for memory
growth and unmanaged goroutines. Two dead-config items (`allowlist`,
`logging.output`) are wired up; two (`TLS`, `S3 backend`) are removed so the
configuration no longer advertises behaviour the binary does not perform.

Out of scope: implementing TLS termination and an S3 cache backend. TLS is
removed now (may return as its own future phase). The S3 backend is **not
implemented** in this phase, but its config and the cache backend abstraction
are kept and prepared so a future phase can plug it in without further wiring.

## Workstreams

### WS1 — Toolchain & CI

- Run `gofmt -w .` across the tree (13 currently-unformatted files: import
  ordering and struct-field alignment).
- Add `.golangci.yml` enabling: `gofmt`, `goimports` (local-prefix
  `github.com/ggwpLab/Jo-ei`), `govet`, `errcheck`, `staticcheck`,
  `ineffassign`, `unused`, `misspell`.
- `Makefile`: change `lint` to run `golangci-lint run`; add a `fmt` target
  (`gofmt -w .`).
- Add `.github/workflows/ci.yml`:
  - Go 1.25.
  - Steps: `go build ./...` → `gofmt -l .` (fail if any file listed) →
    `golangci-lint run` → `go test ./... -race`.
  - Separate job/step for integration tests: `go test -tags integration ./...`.
  - Triggers: push and pull_request on `develop` and `main`.

### WS2 — Graceful shutdown & lifecycle

- `cmd/jo-ei/main.go` `runProxy`:
  - Create a root context via `signal.NotifyContext(ctx, os.Interrupt,
    syscall.SIGTERM)`.
  - Run `srv.ListenAndServe()` in a goroutine; on `http.ErrServerClosed` treat
    as clean exit, otherwise return the error.
  - On context cancellation, call `srv.Shutdown(shutdownCtx)` with a 30s timeout.
- Add `LocalCache.Close()` that stops the eviction worker (WS4) and closes the
  SQLite `Index` (`Index.Close()` already exists). Call it via `defer` in
  `runProxy`.
- Stop the OSV janitor (WS4) on shutdown via `OSVScanner.Close()`.

### WS3 — Dead configuration

**Wire up `allowlist` (supply chain):**
- `config.SupplyChainConfig.AllowlistPath` is read at startup.
- When non-empty: load the file, build `supplychain.NewAllowlist(entries)`, and
  pass it to `supplychain.NewFilter(cfg.SupplyChain, allowlist)` in
  `buildHandlers`/`runProxy` (currently passes `nil`).
- File format: one entry per line, `ecosystem/name` or `ecosystem/name@version`;
  blank lines and lines beginning with `#` are ignored; entries are
  whitespace-trimmed.
- **Fail-fast:** if `AllowlistPath` is set and the file cannot be opened/read,
  startup returns an error (do not silently run with an empty allowlist).
- When empty/unset: behaviour unchanged (no allowlist, `nil` is acceptable since
  `Allowlist.Contains` is nil-safe).

**Wire up `logging.output`:**
- Accept `stdout`, `stderr`, or a filesystem path.
- Default (`""` or `stderr`): write to `os.Stderr` (current zerolog default).
- `stdout`: `os.Stdout`.
- Path: open with `O_CREATE|O_WRONLY|O_APPEND`, `0644`; fail-fast on open error.
- Writer is selected before the logger is constructed and applies to both
  `json` and `text` formats. The chosen file handle is closed on shutdown.

**Remove TLS:**
- Delete `ServerConfig.TLS` and `TLSConfig` from `internal/config/config.go`.
- Remove the `server.tls` block from `config.yaml`.
- Remove TLS mentions from README/docs if present.

**Prepare S3 backend (keep config, do not implement):**
- Keep `CacheConfig.Backend`, `CacheConfig.S3`, and `S3Cache` in config.
- Introduce a backend factory `cache.New(cfg) (cache.Cache, error)` that selects
  by `cache.backend`:
  - `local` (or empty → default `local`) → returns a `*LocalCache`.
  - `s3` → returns an explicit `"s3 cache backend not yet implemented"` error
    (fail-fast at startup — no silent fallback to local, which is the current
    bug).
  - unknown value → error listing the valid backends.
- `runProxy` calls the factory instead of `cache.NewLocalCache` directly.
- Make `cacheAdapter` (in `cmd/jo-ei/main.go`) hold the `cache.Cache` interface
  rather than the concrete `*cache.LocalCache`, so the proxy layer is backend-
  agnostic. This is the seam a future S3 backend plugs into: implementing
  `cache.Cache` (and being returned by the factory) is all that a later phase
  needs.
- `config.yaml` keeps `cache.backend: local` and a commented `cache.s3` example
  block documenting the future option.

### WS4 — Correctness fixes

**OSV in-memory cache janitor:**
- `OSVScanner` currently never evicts expired entries (only checks TTL on read),
  so the map grows unbounded across distinct package keys.
- Add a background janitor goroutine started in `NewOSVScanner`: a `time.Ticker`
  with interval equal to the TTL that sweeps and deletes expired entries under
  the existing mutex.
- Add `OSVScanner.Close()` that stops the janitor (via a stop channel /
  context). Called on shutdown (WS2).

**Eviction worker:**
- Replace the fire-and-forget `go lc.evictIfNeeded()` on every `Put` with a
  single long-lived worker started in `NewLocalCache`.
- The worker reads from a buffered, capacity-1 trigger channel; `Put` does a
  non-blocking send (coalescing bursts into a single eviction pass).
- The worker stops when the trigger channel is closed by `LocalCache.Close()`.
- This removes the race between concurrent eviction passes competing over the
  same LRU rows.

### WS5 — Cleanup

- Delete the unused `proxy.BlockedError` type.
- Delete the unreachable `/health` branch in `Handler.ServeHTTP` (the `Mux`
  handles `/health` before dispatch).
- Handle/log previously-ignored ResponseWriter write errors
  (`json.Encoder.Encode`, `w.Write`, `fmt.Fprintf`) where errcheck flags them.
- Add a package doc comment (`// Package <name> ...`) to every package.
- Replace the hardcoded supply-chain reason `"package_version_newer_than_24h"`
  with a value derived from `min_age_hours` (e.g. `"package_younger_than_min_age"`).
  Update any tests and the `FilterResult.Reason` documentation in
  `internal/proxy/adapter.go` accordingly.

## Testing (TDD)

Each fix lands with tests written first:
- allowlist file loading: valid entries, comments/blank lines, missing-file
  fail-fast, nil-safe empty path.
- `logging.output` writer selection: stdout/stderr/path/default; bad-path
  fail-fast.
- graceful shutdown: integration test that a `SIGTERM` drains and the process
  exits cleanly with the DB closed.
- OSV janitor: expired entries are removed after the sweep interval.
- eviction worker: over-limit cache triggers eviction; concurrent `Put`s do not
  spawn racing passes.
- dynamic reason string: filter returns the new reason and tests assert on it.
- cache backend factory: `local`/empty returns a working cache; `s3` and unknown
  values return the expected fail-fast errors.

Completion criteria: `golangci-lint run` clean, `go test ./... -race` green,
integration tests green, CI workflow passing.

## Risk / compatibility notes

- Removing `server.tls` is a config change: with viper not in strict mode the
  key becomes a no-op (no hard break), but it should be dropped from
  `config.yaml` so it no longer advertises unimplemented behaviour.
- `cache.backend: s3` changes from a silent no-op (currently falls back to local)
  to a fail-fast startup error. This is intentional — it surfaces the
  unimplemented backend instead of hiding it. `cache.backend: local` is
  unaffected.
- The dynamic reason string change alters the JSON error body field `reason` for
  supply-chain blocks; any downstream consumer matching the old literal must be
  updated. Documented as an intentional change.

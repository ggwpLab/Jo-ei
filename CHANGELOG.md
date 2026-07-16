# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Go toolchain bumped to 1.26.5 for the crypto/tls Encrypted Client Hello
  privacy-leak fix (GO-2026-5856); `govulncheck` reports no vulnerabilities
  reachable from this codebase.

### Added

- Cache cleanup on demand: `POST /api/cache/cleanup` and a Clean up button on
  the console cache card delete stale entries and report the freed space.
- Revalidation sweep logs an info summary after each pass with entries due
  (`due`/`kept`/`evicted`/`retried`/`skipped`); quiet ticks log at debug level.

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

## [0.1.0] - 2026-07-04

First public release.

### Added

- **Transparent proxy** for PyPI, npm (with a Yarn alias), Maven, and RubyGems
  with multi-upstream failover per ecosystem, and a **Docker Hub pull-through
  registry mirror** (Registry v2 API).
- **Supply-chain min-age gate**: packages younger than a configurable
  threshold (24h default) are held with HTTP 423; `enforce` / `dry_run` /
  `off` modes.
- **CVE gate** backed by osv.dev with a configurable severity threshold and
  TTL-cached scan results; fails closed on scanner errors.
- **Malware gate**: pluggable engines — ClamAV (clamd protocol) and any
  ICAP-speaking scanner (Kaspersky, Dr.Web, …); all engines scan every
  artifact, any detection blocks, verdicts are never allowlisted.
- **Trivy image gate** for Docker pulls (vulnerability + secret scanning,
  client/server mode); the verdict is decided on the manifest request so a
  rejected image is never served.
- **Artifact cache** with LRU eviction and periodic **revalidation** sweeps
  that re-run the gates over cached entries and evict newly failing ones.
- **Policy profiles** (dev/staging/production) with per-gate allowlists and a
  denylist; runtime edits via the console persist to the database and apply
  without restart.
- **Admin console** (embedded React SPA, works offline, no npm toolchain) with
  overview dashboard, live request feed (SSE), quarantine queue, policy
  editor, and registries/cache view — behind HTTP Basic auth (bcrypt,
  fail-closed when unconfigured).
- **Persistent telemetry**: request events, per-day metrics, and lifetime
  counters in embedded SQLite (pure Go) with configurable retention.
- **Scanner health probes** surfaced in the console.
- **Operational hardening**: per-upstream-host concurrency caps, token-bucket
  rate limiting, 429/503 circuit breakers, malware-scan concurrency limits,
  structured JSON logging.
- Distroless non-root Docker image and a compose stack with ClamAV and Trivy
  sidecars.

[Unreleased]: https://github.com/ggwpLab/Jo-ei/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ggwpLab/Jo-ei/releases/tag/v0.1.0

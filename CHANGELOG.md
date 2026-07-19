# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Docker: by-digest pulls with a cached gate verdict are served without
  contacting the upstream registry — repeat pulls are faster and survive
  registry outages (fresh verdict → straight from cache; expired verdict →
  stale fallback when the upstream is unreachable). By-tag pulls still
  require the upstream for resolution.

### Changed

- Concurrent re-checks of one expired cache entry (and concurrent Docker
  evaluations of one image digest) coalesce into a single scan whose verdict
  is shared by all waiting requests.

## [0.2.0] - 2026-07-19

### Security

- Go toolchain bumped to 1.26.5 for the crypto/tls Encrypted Client Hello
  privacy-leak fix (GO-2026-5856); `govulncheck` reports no vulnerabilities
  reachable from this codebase.

### Added

- Cache cleanup on demand: `POST /api/cache/cleanup` and a Clean up button on
  the console cache card delete stale entries and report the freed space.

### Changed

- Cache re-validation is now lazy: per-gate TTLs (`cache.revalidation.cve_ttl_minutes` / `malware_ttl_minutes`, default 24 h, `0` disables) re-run the expired gate on the next cache hit and evict entries that now fail. The background sweep and its keys (`enabled`, `interval_minutes`, `revalidate_after_hours`, `batch_size`) are removed; old keys in existing configs are ignored. Scanner outages serve the previously clean entry and retry on the next hit. Configs that previously set `revalidation.enabled: false` to opt out now get the 24h-TTL default instead — set both `cve_ttl_minutes` and `malware_ttl_minutes` to `0` to keep re-checks off.
- Console: lifetime counters are labeled "total" instead of "since start" —
  they persist in SQLite and survive restarts.
- Console: the local-cache card shows a 30-day hit-rate sparkline, and the
  usage meter marks the reclaimable (stale) slice of used space with a
  hatched segment and legend.

### Removed

- `internal/revalidate` background sweep — replaced by lazy TTL re-checks; re-validation load now scales with traffic instead of cache size.

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

[Unreleased]: https://github.com/ggwpLab/Jo-ei/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ggwpLab/Jo-ei/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ggwpLab/Jo-ei/releases/tag/v0.1.0

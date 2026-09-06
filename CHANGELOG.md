# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The live feed no longer names a gate on successful requests.** A passing
  request used to show the deepest gate it cleared, so a clean package was
  listed as "Malware" next to its green PASS. The GATE column now speaks only
  for blocks (the gate that blocked) and errors (the stage that failed);
  passes and cache hits leave it empty. Docker image-scan errors are labelled
  instead of showing a bare dash.

### Changed

- **Console overview totals now read on a single time base.** The 7d/30d
  toggle is gone and every KPI card — requests, cache hit rate, blocked, and
  the supply-chain/CVE/malware/denylist breakdown — shows the all-time
  counter, which is exactly what the proxy persists. The sparklines stay, now
  captioned "30d trend" so they read as a trend beside the value rather than a
  breakdown of it (daily rows are pruned on their own retention, the counters
  are not). The quarantine card is labelled as the live gauge it always was —
  how many packages are held right now — and no longer carries a sparkline of
  daily supply-chain blocks, a different quantity than the number above it.

## [0.4.0] - 2026-09-06

### Added

- **Trusted CA certificates for upstream registries** (`tls.ca_files`) — PEM
  files listed here are added to the system root pool used for every upstream
  connection, so a mirror presenting a corporate or self-signed certificate can
  be fetched without weakening verification for public registries. An unreadable
  or certificate-less file stops startup with a message naming it.
- **Console session settings** — `console.auth.jwt_secret`
  (`JOEI_CONSOLE_JWT_SECRET`, at least 32 bytes),
  `console.auth.access_ttl_minutes` (default 15) and
  `console.auth.refresh_ttl_hours` (default 168). With no secret configured,
  one is generated on first boot and stored in the database, so sessions
  survive a restart; set it explicitly to share sessions across replicas.

### Changed

- **BREAKING — console and API authentication is now JWT, not HTTP Basic.**
  The console has a real login screen, shows who is signed in, and can sign
  out. Browsers ride HttpOnly, `SameSite=Strict` cookies (`Secure` whenever the
  request arrives over TLS), which is also what lets the live event stream
  authenticate — `EventSource` cannot send an `Authorization` header. Scripts
  obtain a token from `POST /api/auth/login` and send
  `Authorization: Bearer <token>`; **`curl -u` no longer works.** Credentials
  themselves are unchanged: the same bcrypt `console.auth.users` /
  `JOEI_CONSOLE_AUTH_USERS` entries keep working. Tokens are stateless, so
  signing out clears the cookies but an already-issued bearer token stays valid
  until it expires (15 minutes by default); rotating `console.auth.jwt_secret`
  and restarting ends every session at once.
- **`/console/` is now served without authentication** — it is the static UI
  bundle, and its login screen has to render before a session can exist. Every
  byte of data still comes from `/api/`, which stays gated; with no users
  configured `/api/` returns HTTP 503 and nobody can sign in.
- **Every upstream mirror's own error now reaches the log.** A fetch that fails
  across several mirrors used to report only the last mirror's error, so a
  mirror rejected for a TLS or DNS failure was hidden behind another mirror's
  plain 404. Artifact downloads, transparent proxying, npm/PyPI/RubyGems/Go
  metadata fetches, and Docker manifest/blob fetches now log an
  `upstream_attempts` array with each mirror's URL, HTTP status (0 for a
  transport failure), error, and duration. Response statuses are unchanged.
  The `artifact not found on any upstream` and `failed to download artifact`
  log lines no longer carry the old `upstream_urls` field; `upstream_attempts`
  supersedes it.

### Fixed

- **The console no longer burns CPU while it sits idle.** An open overview tab
  cost ~14% CPU doing nothing: the pipeline token was animated through `left`,
  a layout property, so every frame relaid out the page and the 1.1s glide
  never finished before the next step began; gate highlights animated
  `drop-shadow` and `text-shadow`, re-rasterizing the whole arch each frame;
  and the loading overlay, hidden by `opacity` alone, kept running its
  infinite torii animation for the life of the tab. Movement now rides
  `transform`, highlights crossfade pre-rendered glow layers by `opacity`, and
  the overlay is unmounted once its fade-out ends. The animation looks the
  same.
- **The console's 7d/30d control now moves the numbers, not only the charts.**
  The KPI cards and the block breakdown read lifetime counters regardless of
  the selected window. They now sum the daily rows inside it, and the window is
  a UTC date range rather than a count of stored rows — daily rows exist only
  for days that saw traffic, so "7d" could previously span weeks on an
  intermittently used proxy. "In quarantine" stays unwindowed: it is a
  current-state gauge with no daily counter.
- **The live request feed pages 20 rows at a time** in both its live and its
  history listings, behind the same "Show more" button. History filters
  previously fetched 50 per page and the live filters did not page at all.
- **The sidebar's gate badge reports real scan-engine health** instead of a
  hardcoded "healthy": any engine down reads degraded, any engine slow reads
  slow, and an unreachable API reads no connection. Engines that are configured
  but unattached, or not yet probed, are not failures and stay green.

## [0.3.0] - 2026-07-20

### Added

- **Go module registry adapter** — pull Go modules through Jōei
  (`GOPROXY=http://<jo-ei>/go`) so module zips pass the supply-chain, CVE, and
  malware gates. Metadata endpoints (`.info` / `.mod` / `@v/list` / `@latest`)
  are proxied transparently. Disabled by default (`registries.go`).
- **Offline by-digest Docker pulls** — a by-digest pull with a fresh cached
  verdict is served straight from the cache, without contacting the upstream
  registry; an expired verdict falls back to the cached artifact when the
  upstream is unreachable. By-tag pulls still need the upstream to resolve the
  digest.

### Changed

- **Coalesced re-checks** — concurrent lazy re-checks of one expired cache
  entry, and concurrent Docker evaluations of one image digest, now collapse
  into a single scan (singleflight) whose verdict every waiting request shares.

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

[Unreleased]: https://github.com/ggwpLab/Jo-ei/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/ggwpLab/Jo-ei/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ggwpLab/Jo-ei/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ggwpLab/Jo-ei/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ggwpLab/Jo-ei/releases/tag/v0.1.0

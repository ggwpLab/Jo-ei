# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **pip downloads now go through the proxy's gates.** PyPI index pages were
  proxied untouched, and pypi.org links every file by absolute URL on
  `files.pythonhosted.org`, so pip, uv and poetry fetched packages straight
  from the file host: no supply-chain, CVE or malware check ran, and nothing
  was cached or recorded. Simple-index pages (PEP 503 HTML and PEP 691 JSON)
  and the JSON API (`/pypi/<project>/json`) are now served with every
  `/packages/` link rewritten to a relative link to the proxy, hash fragments
  kept. A link to any other host is removed and logged, an index the proxy
  cannot rewrite (unparseable, undecodable, over 64 MB) is answered with
  `502 index_rewrite_failed` instead of being served as-is, and client
  validators are no longer forwarded upstream, so a page cached before the
  upgrade cannot be revalidated back into use. Only links that resolve to
  `/packages/` survive — anything another parser might read differently
  (stray whitespace, backslashes, `https:/host`, duplicate `href`) is dropped.
  The JSON API now carries relative URLs too, so scripts that pass its `url`
  straight to an HTTP client must resolve it against the request URL.
- **Unrecognized PyPI files are refused instead of passed through.** A
  download under `/pypi/packages/` whose filename names no package and version
  was proxied transparently, around every gate; it now gets `403
  unrecognized_artifact`. All sdist formats pip accepts (`.tar.bz2`, `.tgz`,
  `.tar.xz`, …) and upper-case extensions are now recognized and gated.

### Added

- **Readiness endpoint and healthcheck command.** `GET /ready` returns 200
  when the database answers and no attached scanner is down, and 503 with the
  failing components otherwise (`/health` still only reports that the process
  is up). `jo-ei healthcheck [--ready]` probes either endpoint from inside the
  distroless image, and the compose file uses it as the container healthcheck.
- **`server.shutdown_timeout_seconds`** (default 30) bounds how long a stopping
  server drains in-flight requests.
- **`jo-ei backup --output <file>`** writes a consistent online copy of the
  state database (users, signing key, policy, telemetry) while the proxy runs
  (SQLite `VACUUM INTO`); the file is created owner-only and never overwrites
  an existing one. The README documents backup and restore.

### Changed

- **Every config key can be set from the environment.** `JOEI_*` variables
  used to override only keys present in the config file, so setting one for a
  key the file left out (or commented out) was silently ignored. Every scalar
  and string-list key is now settable whether or not the file mentions it
  (lists comma-separated); lists of objects and maps (`malware.scanners`,
  `policy.profiles`) remain file-only. **A `JOEI_*` variable that sets
  nothing now stops startup** with an error naming it — check for leftover
  variables (for example the removed `JOEI_CONSOLE_AUTH_USERS`) before
  upgrading. Kubernetes service-link variables for a Service named `joei` are
  ignored.
- **The compose file is safe to run in production as shipped.** Port 8080 is
  published on `127.0.0.1` only (put a reverse proxy in front); every service
  rotates its logs (50 MB × 5); the Trivy server is pinned to the client
  version in the image (0.76.1, was 0.71.2) and ClamAV to `1.5`; Jō-ei gets a
  healthcheck and a 45 s stop grace period. A `.dockerignore` keeps `.env`,
  `.git` and local tooling out of the build context.
- **ClamAV scans real-world artifacts and images in full.** clamd's defaults
  rejected every stream over 100 MB — the proxy answered 503 for any larger
  artifact — and silently stopped scanning archives past 100 MB per file,
  400 MB per scan, 10,000 files, 17 levels of nesting or 2 minutes, while
  still answering clean. The compose file raises them (2 GB stream and file,
  4 GB scan, 200,000 files, 32 levels, 280 s) and enables `AlertExceedsMax`;
  the ClamAV scanner timeout in `config.yaml` goes from 30 s to 300 s, above
  clamd's own scan-time limit.
- **An incomplete malware scan blocks as `scan_incomplete`, not as malware.**
  When an engine reports that it could not scan an artifact in full (clamd's
  `Heuristics.Limits.Exceeded.*`), the request is refused with `403
  scan_incomplete` and the event carries `blocked_by: scan_incomplete`; it is
  not counted or cached as a malware verdict, so raising the engine's limits
  takes effect on the next request. A real detection by another engine still
  wins, and a lazy re-check that comes back incomplete keeps serving the
  previously clean copy.
- **Antivirus engines scan in parallel.** Every engine in `malware.scanners[]`
  now scans an artifact at the same time, so a first download waits for the
  slowest engine instead of the sum of all of them, and a concurrency slot
  (`malware.max_concurrent_scans`, one per artifact) is held correspondingly
  shorter. Verdicts are unchanged: any detection blocks, an engine error fails
  closed, and when several engines report, the first in config order is shown.
- **Scanner metrics are labelled by name.** `jo_ei_scans_total`,
  `jo_ei_scan_duration_seconds`, `jo_ei_scans_in_flight` and `jo_ei_scanner_up`
  now carry the configured scanner name as `scanner` and the engine type as a
  new `engine` label, so two ICAP servers no longer share one series. Queries
  filtering `scanner=~"clamav|icap"` should filter on `engine` instead; the
  shipped alert rules and Grafana dashboard are updated, and the
  scan-saturation alert now compares the limit with the busiest engine (`max`)
  rather than the sum across engines.

### Fixed

- **`server.trusted_proxies` can be set from the environment.** The key was
  only commented out in `config.yaml`, and environment overrides only reach
  keys the file contains, so `JOEI_SERVER_TRUSTED_PROXIES` was silently
  ignored — behind a reverse proxy, every client then shared the proxy's
  login-throttling bucket. `trusted_proxies` and `client_ip_header` are now
  real keys, the variable accepts comma- or space-separated entries, and the
  README explains which address to trust (and when trusting the compose
  gateway is unsafe).
- **CVE lookups honour `tls.ca_files`.** The OSV scanner used its own HTTP
  client, so behind a TLS-inspecting corporate proxy every lookup failed — and
  the fail-closed CVE gate answered 503 for every uncached download. It now
  trusts the configured CA files and is bounded by the upstream idle timeout,
  but deliberately not by the registry rate limits or circuit breaker (osv.dev
  has no mirror to fail over to). Its traffic is labelled with the OSV host in
  the upstream metrics.
- **`docker pull` works with containerd-based clients.** Docker Desktop's
  default (containerd) image store also fetches an image's BuildKit
  attestation blobs (SBOM/provenance). Their manifests were served
  un-gated, but the blobs were never cached, so every pull of an official
  image failed with "could not fetch content descriptor … not found" right
  after the image itself passed the gate. For an attestation manifest — every
  layer an in-toto statement — the proxy now relays its config and in-toto
  blobs from upstream, unscanned (they are JSON documents, not filesystems):
  capped at 4 MiB, verified against their digest, not cached.
- **Manifests with unrecognised layer types are gated, not passed through.**
  A manifest counted as a pass-through "attestation" whenever any layer had a
  media type outside a short list of tar types, so an image could avoid the
  gate by naming a layer `application/vnd.docker.image.rootfs.diff.tar`, with
  a parameter or in upper case — types containerd still unpacks. Only a
  manifest whose every layer is in-toto passes through now; everything else
  is gated (and fails closed if it cannot be scanned).
- **Stopping the proxy no longer hangs on an open console tab.** The live
  event stream held the graceful shutdown until its 30 s deadline, which then
  failed with an error — and Compose had already killed the container after
  10 s, cutting in-flight downloads. Event streams now end as soon as shutdown
  starts, in-flight requests drain for `server.shutdown_timeout_seconds`, and
  anything still open after that is closed without failing the shutdown.
- **A throttled mirror no longer turns a miss into a 502.** When the other
  upstreams answered 404/410 and one answered 429 (or was skipped by the
  circuit breaker after a 429), the client got `502 upstream_unavailable`,
  which reads like an outage. It now gets `429` (`503` when the throttle was a
  503) with `Retry-After` set to the throttled mirror's remaining cooldown, so
  clients such as Maven back off and retry. Applies to artifact downloads,
  metadata, transparent proxying and Docker manifests (`TOOMANYREQUESTS`); the
  event reason is `upstream_throttled`. Any real failure on a mirror (5xx,
  connection, TLS) still yields 502.
- **Large artifacts and cold Docker pulls no longer time out.** Artifact
  downloads and Docker blobs were capped at 60 s and 120 s in total, and the
  server cut every request at 120 s, so a multi-GB wheel or image layer failed
  on every attempt. Artifact and Docker fetches are now aborted only after 60 s
  without a byte (metadata fetches keep their 30 s cap), the server no longer
  limits how long a gated request may run, and slow clients are bounded by
  progress instead: a request body that sends nothing for 60 s fails, and
  every artifact, blob, manifest and metadata response is written in chunks
  that must each complete within 60 s, so a client that stops reading is
  still dropped. Clients with short read timeouts may need a longer
  one for multi-GB first downloads, since the proxy checks an artifact before
  sending its first byte (for example `pip --timeout 600`).
- **Concurrent first requests for one artifact can no longer corrupt the
  served file.** Cache entries were written in place, so a second request
  storing the same artifact truncated the file a first request was still
  streaming. Entries are now written to a temporary file and renamed into
  place, and cached artifacts and Docker blobs are served with
  `Content-Length`, so a truncated transfer is detectable.
- **Download temp files live on the cache volume.** Artifacts, layers and
  manifests under check were buffered in the container's `/tmp`, on the host's
  root filesystem; they now go to `<cache.local.path>/tmp`, and files left
  there by an interrupted run are removed at startup.

## [0.6.0] - 2026-10-24

### Security

- Go toolchain bumped from 1.26.6 to 1.26.10 for standard-library advisories
  reachable from this codebase (net/http, net/textproto, crypto/tls, fixed in
  1.26.9; crypto/x509 GO-2026-6809, fixed in 1.26.10). `govulncheck` reports no
  vulnerabilities reachable from this codebase.

### Added

- **Prometheus metrics.** A dedicated listener (`metrics.listen`, default
  `:9464`, path `/metrics`; on by default, `metrics.enabled: false` turns it
  off) exposes inbound HTTP, upstream, scanner, verdict and cache metrics plus
  Go runtime and process collectors, all prefixed `jo_ei_` with bounded label
  sets. The port is unauthenticated by design and not published by the compose
  file. `examples/monitoring/` ships a Prometheus scrape config, alert rules and
  a Grafana dashboard; see [docs/metrics.md](docs/metrics.md).

- **Console users and roles.** Users now live in the database with an `admin` or
  `operator` role, managed from a new Users page in the console. Sessions
  are revocable, passwords are 12 characters to 72 bytes, and temporary
  passwords force a change at next sign-in. Sign-in is rate limited (5 failures
  per user and IP, 20 per IP, per 15 minutes; `429` with `Retry-After`). New
  `server.trusted_proxies` and `server.client_ip_header` resolve the real client
  IP behind a reverse proxy. Allow/deny lists get add/remove endpoints. See
  [docs/configuration.md](docs/configuration.md#users-and-roles).

- **Initial admin with a generated password.** On first start with an empty
  users table, Jōei creates the user `admin` (role admin) with a random
  20-character temporary password, logs it once as a `warn` line
  `created initial admin user` (find it with
  `docker compose logs jo-ei | grep "initial admin"`) and requires a change at
  first sign-in. The password is never logged again. Until `admin` changes it,
  the temporary password is readable by anyone with access to the logs.

- **`jo-ei reset-admin-password`.** The recovery command: gives `admin` a new
  temporary password (printed alone on stdout), re-enables it, restores its
  admin role, revokes its sessions and forces a change at next sign-in; it
  recreates `admin` if it was deleted. It works while the server runs and
  refuses to create a database at a wrong `--config` path.

- **Request feed search covers the whole history.** The search box now queries
  the server (`GET /api/requests?q=`, a case-insensitive substring of
  `package@version` or the request ID, combinable with `verdict`, cursor-paged;
  `limit` is now capped at 500) instead of filtering only the rows already
  loaded in the browser. Hovering the time in the feed shows the full date.

### Changed

- **Breaking: config/env console users and `jo-ei hashpw` are removed.**
  `console.auth.users`, the `JOEI_CONSOLE_AUTH_USERS` environment variable and
  the `jo-ei hashpw` command no longer exist and are not read. **Upgrading
  from 0.5.x:** the accounts defined there are not imported. The users table
  is new and starts empty, so the first start of this version creates `admin`
  with a generated password (see above) — take it from the log, sign in, and
  re-create the other people on the Users page. A database that already holds
  users keeps them. Remove the old keys from `config.yaml` and `.env`.

- **Admin-only console mutations.** `PUT /api/policy`, `PUT /api/registries`
  and `POST /api/cache/cleanup` are now admin-only, and `PUT /api/policy` keeps
  allow/deny lists that are absent from the body.

- **One log format across the proxy.** Package downloads, metadata filtering,
  transparent proxying, Docker, the console API, telemetry and startup used to
  log with different field names, message prefixes and only some of them with
  a request ID. Now:
  - every request gets one ID at the server edge, returned in a new
    `X-Request-Id` response header and carried as `request_id` on every log
    line the request produces — including metadata filtering, transparent
    proxying, Docker blobs, the Docker gate and the console API, which had none
    — and in the console request feed and JSON error bodies;
  - every line names its subsystem in a `component` field (`server`, `proxy`,
    `metadata_filter`, `docker`, `console`, `telemetry`, `auth`); message
    prefixes such as `console:`, `telemetry:` and `metadata filter:` are gone;
  - packages are always `ecosystem` + `package` + `version` (the download log's
    combined `package` key, e.g. `pypi/requests@2.32.0`, is split); Docker
    logs `ecosystem=docker`, the repository as `package` and the requested
    reference as `version` instead of `repo`/`ref`;
  - each gated request ends with exactly one `request gated` line mirroring its
    telemetry event (`verdict`, `gate`, `reason`, `status`, `duration_ms` and
    block details). It replaces `serving artifact`, `supply chain filter
    blocked package`, `CVE policy blocked package`, `malware detected`,
    `docker image allowed` and `docker image blocked`, and package downloads now
    log their verdict the way Docker did.

  Log queries keyed on the old messages or fields need updating; see
  [configuration › logging](docs/configuration.md#logging).

- **`server.listen` defaults to `:8080`** and an empty value is rejected at
  startup. The Docker image bundles Trivy 0.76.0 (was 0.74.0) and also
  exposes the metrics port `9464`.

### Fixed

- **Malware engines are reported by name.** Detections, logs and the console
  overview showed only the scanner type, so with several ICAP engines every
  verdict and health row read `icap`. Scanners now take an optional `name`
  (`malware.scanners[].name`); it defaults to the type, or `icap:<service>` for
  ICAP. Names must be unique: a config with two unnamed scanners of the same
  type and service now fails validation until one is given a `name`.
  Prometheus labels are unchanged.

## [0.5.1] - 2026-10-05

### Changed

- **`docker-compose` runs the released image by default.** The compose file
  used to build the proxy from the checkout on every fresh start, so the quick
  start needed a full Go build even though every release is published to
  `ghcr.io/ggwplab/jo-ei`. It now pulls `ghcr.io/ggwplab/jo-ei:latest`; pin a
  release tag for reproducible deployments. To run your checkout — unreleased
  changes or local modifications — use `docker-compose up -d --build`.

### Fixed

- **Docker pulls now log their verdict.** An allowed image manifest — a fresh
  `PASS` or a `CACHE` re-pull — wrote nothing to the proxy log; only blocks
  did. Each gated manifest now logs `docker image allowed` at info level with
  the verdict, reason, digest and tag, matching the package ecosystems.
- **A missing Docker manifest returns 404, not 502.** When every upstream
  answered 404 for a manifest (a mistyped tag, or a client's OCI referrers
  fallback probe), the proxy reported a gate error and answered
  `502 UNAVAILABLE`. It now answers `404 MANIFEST_UNKNOWN` and logs a warning.
  A missing layer of an existing manifest is still a gate failure.

## [0.5.0] - 2026-09-28

### Added

- **npm installs now fall back to an allowed version instead of failing.**
  npm resolves a version range from a package's metadata document before it
  requests any tarball, so a version blocked by the minimum-age rule or the
  denylist used to kill the whole install: it had already committed to that
  version, and `423` gave it nowhere to go. The proxy now hides blocked
  versions from the metadata document itself, so `^1.0.0` resolves to the
  newest version your policy allows and the install simply succeeds. Rewritten
  documents carry the proxy's own `ETag`, so a client cannot revalidate its way
  back into a stale copy once a version matures; documents that were not
  rewritten keep the registry's own validators and the cheap `304` that
  follows. A lockfile-pinned install (`npm ci`) still fails with `423` — there
  is no range left to resolve — and so does a document larger than
  `server.metadata_filter_max_mb` (default 32). Set that to `0` to switch
  filtering off.

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

### Fixed

- **`docker-compose` now passes the whole `.env` to the proxy.** The compose
  file listed environment variables one by one, so a `JOEI_*` override written
  into `.env` reached compose — which reads that file for `${...}`
  substitution — but never reached the container unless someone had also added
  a line for it under `environment:`. The service reads `.env` through
  `env_file` instead: setting a variable there is now enough. The file stays
  optional, so a fresh clone still starts without one.
- **The live feed no longer names a gate on successful requests.** A passing
  request used to show the deepest gate it cleared, so a clean package was
  listed as "Malware" next to its green PASS. The GATE column now speaks only
  for blocks (the gate that blocked) and errors (the stage that failed);
  passes and cache hits leave it empty. Docker image-scan errors are labelled
  instead of showing a bare dash.

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

[Unreleased]: https://github.com/ggwpLab/Jo-ei/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/ggwpLab/Jo-ei/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/ggwpLab/Jo-ei/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/ggwpLab/Jo-ei/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ggwpLab/Jo-ei/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ggwpLab/Jo-ei/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ggwpLab/Jo-ei/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ggwpLab/Jo-ei/releases/tag/v0.1.0

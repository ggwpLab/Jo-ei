# Configuration Reference

Jōei is configured by a single YAML file passed via `--config` (default in the
Docker image: `/etc/jo-ei/config.yaml`). The repository's
[`config.yaml`](../config.yaml) is a fully commented working example.

## Loading & environment overrides

Any config key can be overridden by an environment variable: take the key
path, replace dots with underscores, uppercase it, and prefix `JOEI_`.

| Config key | Environment variable |
|---|---|
| `logging.level` | `JOEI_LOGGING_LEVEL` |
| `cve.block_on` | `JOEI_CVE_BLOCK_ON` |
| `supply_chain.min_age_hours` | `JOEI_SUPPLY_CHAIN_MIN_AGE_HOURS` |

This works for every scalar and string-list key, whether or not the file
contains it. String lists are comma- (or, for `server.trusted_proxies`,
space-) separated, e.g.
`JOEI_REGISTRIES_PYPI_UPSTREAMS=https://pypi.org,https://mirror.example`.
Lists of objects and maps — `malware.scanners` and `policy.profiles` — can
only be set in the file.

A field of a profile the file defines can still be overridden
(`JOEI_POLICY_PROFILES_PRODUCTION_CVE_BLOCK=false` when the file has a
`production` profile).

A non-empty `JOEI_*` variable that sets nothing — a misspelt name, or one
aimed at `malware.scanners` / a profile the file does not define — makes the
server refuse to start with an error naming it, instead of being silently
ignored; the CLI tools (`healthcheck`, `backup`, `reset-admin-password`) only
print a warning, so recovery still works. Empty variables are ignored. Not
configuration, and accepted: `JOEI_CONSOLE_JWT_SECRET` (below), and the
service links Kubernetes injects for Services named `joei` or `joei-…`
(`JOEI_SERVICE_HOST`, `JOEI_METRICS_PORT_9464_TCP`, …) — or switch them off
with `enableServiceLinks: false`.

The config file is still required (`--config`): built-in defaults do not yet
cover everything the shipped `config.yaml` sets, such as registry upstreams
and policy profiles. Policy and registry settings edited in the console are
stored in the database and take precedence over both the file and the
environment after first boot.

One special case is read directly from the environment, not through this
mechanism:

- **`JOEI_CONSOLE_JWT_SECRET`** — the HS256 key that signs console sessions,
  taking precedence over `console.auth.jwt_secret` from the file. Preferred
  over the file so the secret stays out of version control, and required to
  share sessions across replicas (see `console` below).

Console users are not configured through the file or the environment at all —
they live in the database (see [Users and roles](#users-and-roles)).

Validation runs at startup; an invalid config prints the offending key and the
process exits non-zero.

## `server`

| Key | Default | Description |
|---|---|---|
| `listen` | — | Listen address, e.g. `":8080"`. |
| `upstream_max_concurrent` | `6` | Max concurrent in-flight requests **per upstream host** (metadata + transparent proxy + downloads combined). Keeps parallel dependency resolution under registry limits. |
| `upstream_rate_per_second` | `10` | Max request **rate** per upstream host (token bucket, burst = 2×). The primary defense against upstream HTTP 429. Set high to effectively disable. |
| `metadata_filter_max_mb` | `32` | Max decompressed size (MB) of a metadata document the proxy will buffer to filter out policy-blocked versions. `0` disables filtering. |
| `max_artifact_mb` | `2048` | Largest package artifact (MB) the proxy downloads; a larger one is refused with `403 artifact_too_large`. `0` = unlimited. Docker layers use `image_scan.max_layer_bytes`. |
| `shutdown_timeout_seconds` | `30` | How long a stopping server drains in-flight requests before closing the rest. |
| `trusted_proxies` | `[]` | Reverse proxies (CIDRs or bare IPs) whose forwarding header is believed when resolving the client IP. Invalid entries stop startup. |
| `client_ip_header` | `X-Forwarded-For` | Header read from a trusted proxy: `X-Forwarded-For`, `X-Real-IP` or `Forwarded`. |

Upstream responses of 429/503 additionally trip a per-host circuit breaker
with exponential cooldown (1s–20s, honoring `Retry-After`). When the other
mirrors answered 404/410 and only throttled ones remain, the client gets 429
(503 if no throttle was a 429) with `Retry-After` set to the shortest
remaining cooldown, instead of a 502 — the artifact may well exist on the
throttled mirror, so clients such as Maven back off and retry.

npm resolves a version range from a package's metadata document before it ever
requests a tarball, so a version blocked at download time gives it nowhere to
go — it has already committed to that version and does not backtrack. Metadata
filtering hides blocked versions from the document itself, so npm's resolver
lands on a version the policy allows instead. Only the checks that need no
network round-trip take part: the minimum-age rule and the denylist. CVE and
malware verdicts still block at download time, since they can only be decided
once the artifact is in hand. Set `metadata_filter_max_mb` to `0` to disable
the feature entirely; a document larger than the configured cap is also
streamed through untouched rather than buffered. This applies to npm only —
every other registry's metadata is proxied untouched regardless of this
setting. It cannot help a lockfile-pinned install (`npm ci`): there is no
range left to resolve, so a blocked exact version still fails with `423`.

### Behind a reverse proxy

Forwarding headers are believed only when the request's direct peer is listed in
`trusted_proxies`; from any other peer they are ignored, since a client could
forge them. With `trusted_proxies` empty, every client behind nginx or Traefik
appears to come from the proxy's IP, so the per-IP console login limits are shared
by all users. For `X-Forwarded-For` the right-most address that is not a trusted
proxy is the client; client-supplied entries to the left of it are ignored, so a
junk `X-Forwarded-For` sent by the client cannot hide its address. When a
forwarding header arrives from an untrusted peer,
Jō-ei logs a one-time warning mentioning `server.trusted_proxies` with the
offending `peer`; seeing it means the proxy needs to be listed.

Set it to the proxy's own address, or the network the proxy connects from — for
example nginx on the Docker host reaching Jō-ei over the compose network:

```yaml
server:
  trusted_proxies:
    - 172.18.0.1        # the proxy's address as Jō-ei sees it
    # - 172.18.0.0/16   # or the proxy's network, if its address changes
  client_ip_header: X-Forwarded-For
```

> **Warning:** list only proxy addresses, never client ranges. Every peer in a
> trusted range may set the forwarding header to any value, so a broad CIDR
> (say `10.0.0.0/8` when your users also sit in it) lets those clients spoof
> their IP and dodge the login limits.

## `tls`

Trust for outbound connections to upstream registries.

```yaml
tls:
  ca_files:
    - /etc/jo-ei/ca/corp-root.pem
```

| Key | Default | Description |
| --- | --- | --- |
| `ca_files` | empty | List of PEM file paths whose certificates are added to the system root pool |

The listed certificates **supplement** the system roots — they do not replace
them — so an internal mirror signed by a corporate CA and a public registry both
verify through the same pool. A bundle containing several certificates in one
file is fine; all of them are added.

Startup fails, naming the file, when a listed file cannot be read, contains no
certificate (a private key or a DER file with a `.pem` name are the usual
causes), or holds an unparseable certificate. On success the startup log reads:

```
tls: added CA certificates to the upstream trust pool certificates=1 sources=1
```

### Getting a mirror's CA certificate

Dump the chain the mirror presents — each certificate is one PEM block, the
mirror's own certificate first, its issuers after:

```bash
openssl s_client -showcerts -connect mirror.corp:443 </dev/null 2>/dev/null \
  | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > mirror-chain.pem
```

Copy the issuing CA's block out of `mirror-chain.pem` into the file you list in
`ca_files`. Prefer that CA over the mirror's own leaf certificate: a leaf must be
replaced here every time it is rotated, while the CA outlives it. A mirror with a
self-signed certificate presents a single block, and that one certificate is both
the leaf and the trust anchor — list it directly.

## `registries`

Six fixed ecosystems: `pypi`, `npm`, `maven`, `rubygems`, `go`, `docker`. Each:

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Serve this ecosystem. An enabled registry **must** list at least one upstream. |
| `upstreams` | — | Upstream base URLs, tried in order (first success wins; failover on error). |

Client-facing paths: `/pypi/simple/…`, `/npm/…` (alias `/yarn/`),
`/maven/…`, `/rubygems/…`, and the Docker Registry v2 API (`/v2/…`) for use
as a `registry-mirrors` entry. Yarn uses the npm protocol; the `/yarn/` alias
exists so both package managers can be pointed at the proxy independently.

Upstream credentials go in the URL (`https://user:token@nexus.example.org/…`);
the console and `GET /api/registries` show them masked. Requests forwarded
upstream also carry the client's own headers, `Authorization` included, but
that is no isolation boundary: cached artifacts, and metadata documents fetched
for concurrent clients, are shared by every client of the proxy regardless of
who fetched them first. Use one set of upstream credentials that every client
may use.

Docker caveats: multiple `upstreams` are supported as ordered failover
*mirrors of one registry* (e.g. Docker Hub plus a corporate pull-through
mirror of it) — do not mix different registries in one list, since the image
reference passed to Trivy is always built from the first upstream's host.
Also note the Docker daemon applies `registry-mirrors` only to Docker Hub
images; images from another upstream registry must be pulled explicitly as
`docker pull <proxy-host>/<repo>:<tag>`.

## `supply_chain`

The min-age gate: packages published less than `min_age_hours` ago are blocked
with HTTP 423 (Locked) until they age past the threshold.

| Key | Default | Description |
|---|---|---|
| `min_age_hours` | — | Minimum package age. `24` blocks day-old poisoning attacks. |
| `mode` | — | `enforce` (block), `dry_run` (log what would block, allow), `off`. |
| `allowlist_path` | — | Optional file of packages exempt from this gate (format below). |

Allowlist file format — one entry per line, `#` comments and blank lines
ignored:

```
# ecosystem/name         → all versions
pypi/requests
# ecosystem/name@version → one version
npm/lodash@4.17.21
```

Where the publish date comes from:

| Ecosystem | Publish date |
|---|---|
| PyPI | upload time of the requested file (a file added to an old release is as new as its upload) |
| npm | the packument's `time` entry for the version |
| RubyGems | `created_at` of the version and platform |
| Maven | the artifact's `Last-Modified` header; a missing header counts as old |
| Go | the `Time` in the module proxy's `.info` document, which is the commit time of the version — set by the author, so a module author can backdate it past the minimum age |
| Docker | the image config's `created` time — set at build, so it can predate the push; reproducible builds often fix it to an old date |

The file seeds the **supply-chain** allowlist at first boot; after that the
per-gate allowlists (supply-chain and CVE) are edited in the console and
persist in the database.

## `cve`

Known-vulnerability gate backed by [osv.dev](https://osv.dev). Runs before the
artifact download; fails closed on scanner errors (HTTP 503).

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Query osv.dev for each package version. |
| `base_url` | `https://api.osv.dev` | OSV-compatible API endpoint. |
| `block_on` | — | Minimum severity that blocks: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. The active policy profile's `cve_min_severity` overrides this when set. |
| `cache_ttl_minutes` | `1440` | How long CVE scan results are cached in memory before re-querying osv.dev. Keep it at or below `cache.revalidation.cve_ttl_minutes` so lazy CVE re-checks see fresh data. |

## `image_scan`

Trivy is the engine behind the **CVE gate for Docker images** — the same gate
that osv.dev implements for package ecosystems, applied to a different
artifact type. The verdict is returned on the **manifest** request, so a
rejected image never reaches the client. Severity threshold and denylist come
from the same active policy profile as package CVE decisions.

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Scan images pulled through the Docker proxy. Requires `trivy_server`. |
| `trivy_server` | — | Trivy server URL, e.g. `http://trivy:4954`. |
| `timeout_seconds` | `120` | Per-scan timeout. |
| `scanners` | `vuln,secret` | Passed to Trivy `--scanners`. |
| `max_layer_bytes` | `0` (no limit) | Layers larger than this fail closed (block the image). The example config uses 2 GiB. |
| `client_wait_seconds` | `25` | How long a manifest request waits for a first scan before answering `503` + `Retry-After` while the scan continues (containerd gives up after 30 s). `0` = wait for the verdict. |

## `malware`

Post-download antivirus gate. Zero scanners is valid — the gate is skipped.

| Key | Default | Description |
|---|---|---|
| `max_concurrent_scans` | `8` | Cap on artifacts scanned at once (backpressure; roughly clamd's default worker pool). Each artifact runs every engine in parallel, so each engine sees at most this many simultaneous scans. |
| `scanners` | `[]` | List of engines, each: |

Per scanner:

| Key | Default | Description |
|---|---|---|
| `type` | — | `clamav` (clamd protocol) or `icap` (RFC 3507 — Kaspersky, Dr.Web, …). |
| `name` | type, or `icap:<service>` | Name the engine is reported under in detections, logs and the console overview. Must be unique across scanners, so give several engines of one type distinct names. `osv`, `osv.dev` and `trivy` are reserved for the CVE engines. |
| `address` | — | `tcp:host:port` or `unix:///path/to/socket`. |
| `timeout_seconds` | `30` | Per-scan timeout. |
| `service` | — | ICAP service name (required for `icap`). |

All configured engines scan every artifact in parallel, so a scan takes as long
as the slowest engine; any single detection blocks, and an engine error fails
closed. Prometheus scanner metrics carry the name as `scanner` and the type
(`clamav`, `icap`) as `engine`.
Malware verdicts cannot be allowlisted.

## `health`

Background liveness probes for socket scanners (clamd/ICAP), surfaced in the
console overview.

| Key | Default | Description |
|---|---|---|
| `probe_interval_seconds` | `30` | Probe frequency. |
| `slow_threshold_ms` | `2000` | Latency above this shows the scanner as "warn". |

## `cache`

| Key | Default | Description |
|---|---|---|
| `backend` | — | `local`. (`s3` is reserved and currently fails fast at startup.) |
| `local.path` | — | Directory for cached artifacts. |
| `local.max_size_gb` | — | Size cap; least-recently-used entries are evicted. |
| `local.stale_after_days` | `30` | Entries idle this long are stale: shown as reclaimable in the console and deleted by its Clean up button (`POST /api/cache/cleanup`). |

### `cache.revalidation`

Lazy per-gate re-validation. A cache hit whose CVE or malware check is older
than its TTL re-runs **only that gate** before serving — CVE against current
osv.dev data, malware by re-scanning the cached bytes; Docker re-runs the full
image gate when its verdict is older than the smaller enabled TTL. An entry
that now fails is blocked and evicted (index entry and binary). A temporarily
unreachable scanner (or scan infrastructure — Trivy, ClamAV, the verdict
store) serves the previously clean entry and retries on the next hit. For Docker, scan-infrastructure outages (Trivy, ClamAV) serve the stale
verdict. An unreachable upstream registry fails **by-tag** pulls (tag
resolution needs the upstream), but **by-digest** repeat pulls are served
from the cache: a fresh cached verdict is served without contacting the
upstream at all, and an expired one degrades to the stale verdict (when the
cached manifest body itself is servable; a body without a detectable media
type falls back to requiring the upstream). Load is proportional to traffic,
not cache size.

| Key | Default | Description |
|---|---|---|
| `cve_ttl_minutes` | `1440` | Re-run the CVE gate on hits older than this. `0` disables. |
| `malware_ttl_minutes` | `1440` | Re-scan cached bytes on hits older than this. `0` disables. |

Note: the CVE scanner keeps its own in-memory result cache
(`cve.cache_ttl_minutes`). A newly published CVE becomes visible only after
both TTLs lapse, so keep `cve.cache_ttl_minutes` ≤ `cve_ttl_minutes`.

## `database`

Embedded SQLite (pure Go, no cgo). **Required** — telemetry, runtime policy
edits, and registry toggles persist here and survive restarts.

| Key | Default | Description |
|---|---|---|
| `path` | — (required) | Database file path. The parent directory is created if missing. |
| `event_retention_days` | `30` | Prune request events older than this. |
| `daily_retention_days` | `365` | Prune per-day metric rows older than this. |

## `policy`

Named profiles; `active_profile` selects one at boot.

| Key (per profile) | Description |
|---|---|
| `cve_block` | Enforce the CVE gate. |
| `cve_min_severity` | Blocking threshold; overrides `cve.block_on` when non-empty. |
| `supply_chain_block` | Enforce the min-age gate. |
| `malware_block` | Enforce the malware gate. |
| `allowlist` | Entries (`eco/name` or `eco/name@version`) that seed **both** per-gate allowlists (supply-chain and CVE). |
| `denylist` | Always-blocked packages, same entry format. |

The profile seeds the runtime policy on **first boot only**; after that the
console's policy editor is the source of truth (persisted in the database,
applied atomically without restart).

## `logging`

| Key | Default | Description |
|---|---|---|
| `level` | `info` (unknown values warn and fall back) | zerolog level: `trace`…`error`. |
| `format` | `json` | `json` or `text` (human-readable console writer). |
| `output` | `stderr` | `stdout`, `stderr`, or a file path (opened append). |

**Log line shape.** Every line names the subsystem that wrote it in
`component` (`server`, `proxy`, `metadata_filter`, `docker`, `console`,
`telemetry`, `auth`), and every line written while serving a request carries
that request's `request_id`. The same ID is returned to the client in the
`X-Request-Id` response header, appears in JSON error bodies and in the
console's request feed, so one ID finds everything a request left behind.
Packages are identified by `ecosystem`, `package` and `version` (Docker:
`ecosystem=docker`, `package` = repository, `version` = tag or digest as
requested, plus `digest`).

Each gated request — a package download or a Docker manifest — ends with exactly
one `request gated` line mirroring its telemetry event: `verdict`
(`PASS`/`CACHE`/`BLOCK`/`ERROR`), `gate`, `reason`, `status`, `duration_ms`, and
for blocks `blocked_by`, `cves`, `engine`/`signature` or
`published_at`/`block_until`. It logs at `info` for `PASS`/`CACHE`, `warn` for
`BLOCK` and client-side (4xx) errors, `error` otherwise; diagnostic lines (scanner
errors, per-mirror `upstream_attempts`) precede it.

```json
{"level":"warn","component":"proxy","request_id":"6f1c…","ecosystem":"npm","package":"left-pad","version":"1.3.0","verdict":"BLOCK","gate":"supply","reason":"package_younger_than_min_age","status":423,"duration_ms":41,"blocked_by":["supply_chain"],"published_at":"2026-10-15T09:00:00Z","block_until":"2026-10-16T09:00:00Z","message":"request gated"}
```

## `metrics`

Prometheus metrics, served on their own listener. See
[`docs/metrics.md`](metrics.md) for the catalogue and monitoring setup.

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Serve metrics (`JOEI_METRICS_ENABLED`). |
| `listen` | `:9464` | Metrics listen address (`JOEI_METRICS_LISTEN`). Must differ from `server.listen`; a bind failure stops startup with an error naming `metrics.listen`. |
| `path` | `/metrics` | URL path (`JOEI_METRICS_PATH`). |

The metrics port is unauthenticated by design. Keep it on an internal network:
the compose file does not publish it, and outside compose bind to `127.0.0.1` or
an internal interface.

## `console`

| Key | Default | Description |
|---|---|---|
| `auth.jwt_secret` | generated | HS256 key signing console sessions, at least 32 bytes. Prefer `JOEI_CONSOLE_JWT_SECRET`. Unset, Jōei generates one on first boot and stores it in the database, so sessions survive a restart; set it explicitly to share sessions across replicas. |
| `auth.access_ttl_minutes` | `15` | Access-token lifetime. |
| `auth.refresh_ttl_hours` | `168` | Refresh-token lifetime (7 days). |

### Users and roles

Console users are stored in the database and managed from the console's Users
page (admins only): creating users, changing roles, resetting passwords and
disabling, enabling or deleting users all happen there (or through the same
API). The only CLI is the recovery command `jo-ei reset-admin-password`
(below). There are two roles:

| | `operator` | `admin` |
|---|---|---|
| View overview, requests, cache, policy, registries | yes | yes |
| Add or remove allow/deny list entries | yes | yes |
| Change policy mode, minimum age or CVE threshold (`PUT /api/policy`) | no | yes |
| Change registries (`PUT /api/registries`) | no | yes |
| Purge the cache (`POST /api/cache/cleanup`) | no | yes |
| Manage users | no | yes |
| Change own password | yes | yes |

A forbidden call returns `403 {"error":"forbidden"}`. The last enabled admin
cannot be disabled, demoted or deleted, and nobody can disable, demote or delete
themselves.

**First start.** When the users table is completely empty, Jōei creates the
user `admin` (role admin) with a random 20-character temporary password
(`A–Z a–z 0–9`) and logs it exactly once, as a `warn` line:

```json
{"level":"warn","component":"server","user":"admin","password":"<temporary>","hint":"temporary password: change it at first sign-in; lost it? run jo-ei reset-admin-password","time":"2026-10-24T10:00:00Z","message":"created initial admin user"}
```

Find it with:

```sh
docker compose logs jo-ei | grep "initial admin"
```

Sign in as `admin` with that password; the console makes you choose a new one
before anything else. The line is written only when the user is created — later
restarts never print a password. Once the table holds any user (even only
disabled ones) nothing is created automatically. A `logging.level` of `error`
hides the line; use `jo-ei reset-admin-password` then.

> **Security:** the temporary password is in the logs, and in any log
> aggregator they are shipped to, and it stays valid until `admin` signs in and
> changes it. Sign in right after the first start; if the logs may have been
> read by others before that, run `jo-ei reset-admin-password`.

**Recovery.** `jo-ei reset-admin-password` gives `admin` a new temporary
password and prints it — and only it — on stdout (messages go to stderr). It
also re-enables `admin`, restores its admin role if it was demoted, revokes its
sessions and requires a password change at next sign-in. If `admin` was deleted
it is recreated as an admin. It opens the database directly, so it works while
the server is running, and it refuses to run if the database file does not
exist (a wrong `--config` would otherwise silently create an empty one).

```sh
jo-ei --config /etc/jo-ei/config.yaml reset-admin-password
```

In the Docker image the binary is `/jo-ei` (not on `PATH`; the image has no
shell) and `--config` defaults to `config.yaml` in the working directory, so
name both:

```sh
docker compose exec -T jo-ei /jo-ei --config /etc/jo-ei/config.yaml reset-admin-password
```

With no enabled users at all the console is locked (`/api/` answers 503) and
the startup log points at this command.

**Passwords** are 12 characters to 72 bytes (bcrypt's limit; longer is rejected,
never truncated) and must not equal the username. There are no composition
rules. An admin-created or reset password is temporary: the user must change it
at next sign-in, and until then every other API call returns
`403 {"error":"password_change_required"}`.

**Sessions** are database-backed. Disabling a user, changing their role or
resetting or changing their password revokes their sessions.

**Login limits.** Per process and in memory: 5 failures per (username, client IP)
per 15 minutes and 20 failures per client IP per 15 minutes. A blocked attempt
gets `429` with `Retry-After` (seconds) even with the correct password; success
resets that pair. The client IP is resolved as described in
[Behind a reverse proxy](#behind-a-reverse-proxy) — set `server.trusted_proxies`
or all users share one IP's budget. With several replicas the limits and the
counters are per replica, not shared.

**Sessions.** The console signs in at `POST /api/auth/login` and rides two
HttpOnly, `SameSite=Strict` cookies (`joei_at`, `joei_rt`); the browser never
sees the token in JavaScript. `Secure` is set when the request arrives over TLS
— terminate TLS in front of Jōei in any deployment that leaves a trusted
network.

**Behind a reverse proxy**, Jōei decides "was this request over TLS" from
`X-Forwarded-Proto` (see `isTLS` in `internal/auth`), not from its own
transport — it always speaks plain HTTP to the proxy. The proxy **must** set
`X-Forwarded-Proto: https`, or `Secure` never gets set on the session cookies
even though the browser sees a padlock. It should also pass through the
browser's original `Host` header rather than substituting its own upstream
address (nginx's default `proxy_set_header Host $proxy_host` does the latter),
because the same-origin check on cookie-authenticated mutations compares
`Origin` against the request's `Host`. In practice modern browsers send
`Sec-Fetch-Site`, which is checked first and does not depend on `Host`, so a
wrong `Host` is a belt-and-braces gap rather than something that breaks a
current browser.

**Scripts and CI** use the same endpoint and read the token from the response
body:

```bash
TOKEN=$(curl -sX POST "$JOEI/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"ops","password":"…"}' | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" "$JOEI/api/overview"
```

**Fail-closed:** with no enabled users, `/api/` returns HTTP 503 and no
one can sign in; the console shell still loads (it is static UI), and the proxy
data path and `/health` stay open.

**Signing out** clears the cookies and revokes the session. To end every
session at once, change `auth.jwt_secret` and restart.

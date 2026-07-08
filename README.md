# Jōei

[![CI](https://github.com/ggwpLab/Jo-ei/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ggwpLab/Jo-ei/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ggwpLab/Jo-ei)](https://goreportcard.com/report/github.com/ggwpLab/Jo-ei)
[![Go Reference](https://pkg.go.dev/badge/github.com/ggwpLab/Jo-ei.svg)](https://pkg.go.dev/github.com/ggwpLab/Jo-ei)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A transparent supply chain security proxy for package registries and Docker images.
Supports PyPI, npm, Maven, and Docker Hub (Go support ships in a later phase).
Point your package manager at Jōei instead of the upstream registry — it intercepts
every download and enforces four layers of protection before serving the artifact.
Docker images are additionally gated by Trivy vulnerability and secret scanning.

```
Developer (pip/npm/mvn/docker pull)
        │
        ▼
  ┌──────────────────────────────────────────────────┐
  │                   Jōei :8080                     │
  │  1. Cache lookup (HIT served immediately)        │
  │  2. Supply Chain Filter (24h rule)               │
  │  3. CVE Scanner (osv.dev)                        │
  │  4. Malware Scanner (ClamAV / ICAP)              │
  │  5. Image Scanner (Trivy — Docker images only)   │
  └──────────────────────────────────────────────────┘
        │
        ▼
   Upstream registry (PyPI / npm / Maven / Docker Hub)
```

**What gets blocked:**
- Packages published less than 24 hours ago (supply chain poisoning protection)
- Packages with CVE severity ≥ configured threshold (`HIGH` by default)
- Packages whose artifact matches a malware signature detected by any configured scanner
- Docker images with vulnerabilities or embedded secrets detected by Trivy
- Packages on the explicit `denylist`

**What gets cached:** Approved artifacts are stored locally; repeat requests are served
from cache without contacting the upstream registry.

## Quick Start

**Prerequisites:** Docker and Docker Compose (no Go installation required for this path).

**1. Start the proxy**

```bash
git clone https://github.com/ggwpLab/Jo-ei.git && cd Jo-ei
```

**Configure secrets** — copy the example env file and fill it in:

```bash
cp .env.example .env
```

**Create a console user** (the console is fail-closed until you do). bcrypt-hash a
password and write the `username:hash` pair into `.env`:

```bash
# Generate a hash (pick your own strong password)
HASH=$(printf '%s' 'change-me' | docker-compose run --rm -T jo-ei hashpw)

# Put it in .env as JOEI_CONSOLE_AUTH_USERS, then start the proxy
echo "JOEI_CONSOLE_AUTH_USERS=admin:$HASH" > .env
docker-compose up -d
```

`docker-compose` reads `.env` automatically. `.env` is gitignored — your secrets
stay out of git. Then open the console and log in as `admin`.

The proxy starts on `http://localhost:8080`. ClamAV runs as a sidecar in the compose file;
malware scanning is active when the selected policy profile sets `malware_block: true`.

**2. Point your package manager at the proxy**

pip:
```bash
pip install requests \
  --index-url http://localhost:8080/pypi/simple/ \
  --trusted-host localhost
```

Or persist it in `~/.pip/pip.conf`:
```ini
[global]
index-url = http://localhost:8080/pypi/simple/
trusted-host = localhost
```

**Maven**:
Add Jōei mirror for your repositories, configured on either project `pom.xml`:
```xml
<project>
  ...
  <repositories>
    <repository>
      <id>central</id>
      <url>http://localhost:8080/maven/</url>
    </repository>
  </repositories>

  <pluginRepositories>
    <pluginRepository>
      <id>central</id>
      <url>http://localhost:8080/maven/</url>
    </pluginRepository>
  </pluginRepositories>
</project>
```
or global level (`~/.m2/settings.xml`):
```xml
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0
                              https://maven.apache.org/xsd/settings-1.2.0.xsd">
   <mirrors>
      <mirror>
         <id>jo-ei</id>
         <name>Jōei supply-chain proxy</name>
         <url>http://localhost:8080/maven/</url>
         <mirrorOf>central</mirrorOf>
      </mirror>
   </mirrors>
</settings>
```

**npm**:
```bash
npm install lodash --registry http://localhost:8080/npm/
```

Or persist it globally:
```bash
npm config set registry http://localhost:8080/npm/
```

**yarn** (uses the npm registry protocol via the `/yarn/` alias):
```bash
# Yarn Berry (v2+)
yarn config set npmRegistryServer http://localhost:8080/yarn/
# Yarn Classic (v1)
yarn config set registry http://localhost:8080/yarn/
```

**RubyGems / Bundler:**
```bash
# bundler
bundle config mirror.https://rubygems.org http://localhost:8080/rubygems
# or set the source in a Gemfile:
#   source "http://localhost:8080/rubygems"
```

**Docker (registry mirror):**

Jōei can act as a pull-through proxy for Docker Hub. Point the Docker daemon at
Jōei by adding it as a registry mirror in `/etc/docker/daemon.json`:

```json
{
  "registry-mirrors": ["http://localhost:8080"]
}
```

Restart the Docker daemon, then `docker pull` fetches images through Jōei:

```bash
sudo systemctl restart docker
docker pull library/alpine:3.21
```

**Caveats:**
- Only Docker Hub (`registry-1.docker.io`) is supported as an upstream. Private
  registries and other OCI registries are not proxied.
- Images are gated by Trivy (vulnerability + secret scanning) and by every
  configured malware engine in `malware.scanners[]` (ClamAV and/or ICAP), which
  scan the image config blob and each layer. The verdict is returned on the
  **manifest** request, so a rejected image is never served to the client.
- Enable the Docker registry in `config.yaml` by setting
  `registries.docker.enabled: true` and `image_scan.enabled: true`.

**3. Smoke test**

```bash
# Health check
curl -s http://localhost:8080/health
# Expected: {"status":"ok"}

# Install a well-known package (should pass)
pip install requests==2.31.0 --index-url http://localhost:8080/pypi/simple/ --trusted-host localhost
```

## Admin Console

Jōei ships an embedded admin console — 浄衛 *The Purification Gate* — served at
[`http://localhost:8080/console/`](http://localhost:8080/console/). It is a single-page
app baked into the binary (no extra files at runtime), and renders the four-gate
pipeline (Cache → 衛 Supply Chain → 浄 CVE → 浄 Malware) along with an overview dashboard,
a live request feed, the min-age quarantine queue, a threat-detail drawer, a policy editor,
and a registries & cache view.

The console reads live proxy state via the JSON API described below. React and the
console UI are compiled to a single bundle baked into the binary — it needs no CDN
and works fully offline.

### Admin console & API

The embedded console at `/console/` shows live proxy state and lets you edit
the effective policy at runtime. It is backed by a JSON API under `/api/`:

| Endpoint | Method | Description |
|---|---|---|
| `/api/overview` | GET | KPIs, per-gate counters, cache stats, configured scanners (since process start) |
| `/api/requests?limit=N` | GET | recent request events, newest first (SQLite-backed, cursor pagination) |
| `/api/events` | GET | Server-Sent Events stream of new request events |
| `/api/quarantine` | GET | active supply-chain holds (derived from recent block events) |
| `/api/policy` | GET / PUT | effective policy; PUT validates and applies atomically |
| `/api/registries` | GET | configured registries and upstreams |

Policy edits made through the console apply immediately without restart and
are **persisted to the database**: they survive restarts, and the YAML policy
values only seed the very first boot. Event history and telemetry are also
persistent (SQLite, with configurable retention).

### Console authentication

The console and `/api/` require HTTP Basic authentication. Configure one or more
operator accounts; the proxy data path (`/pypi/`, `/npm/`, …) and `/health`
stay open.

**Fail-closed:** with no users configured, `/console/` and `/api/` return
**HTTP 503** until you add at least one user. The proxy keeps serving.

Generate a bcrypt hash:

```bash
printf '%s' 'choose-a-strong-password' | jo-ei hashpw
# -> $2a$10$... (copy this)
```

(Docker users: `printf '%s' 'choose-a-strong-password' | docker-compose run --rm -T jo-ei hashpw`)

Configure users in `config.yaml`:

```yaml
console:
  auth:
    users:
      - username: admin
        password_hash: "$2a$10$...."
```

Or inject them via the environment (preferred for secrets — keeps hashes out of
committed config). Entries are `username:hash`, separated by `;`:

```bash
export JOEI_CONSOLE_AUTH_USERS='admin:$2a$10$...;alice:$2a$10$...'
```

Env entries override file entries with the same username.

**With Docker Compose**, set the same variable in `.env` (see
[`.env.example`](./.env.example)) instead of exporting it — Compose loads `.env`
automatically and substitutes it into `docker-compose.yaml`:

```dotenv
JOEI_CONSOLE_AUTH_USERS=admin:$2a$10$...;alice:$2a$10$...
```

Write the hash **literally** in `.env` — values there are not interpolated. Only
when you hardcode a hash *inline* in `docker-compose.yaml` must each `$` be
doubled to `$$` to escape Compose variable substitution.

> **TLS:** Jōei serves plain HTTP. Basic credentials are only as private as the
> transport — for any non-loopback or public deployment, terminate TLS at a
> reverse proxy (nginx, Traefik, Caddy) in front of Jōei. In-binary TLS is not
> provided.

### Scanner health

The console overview shows live health for each scan engine:

- **ClamAV / ICAP** are actively probed (clamd `PING`, ICAP `OPTIONS`) every
  `health.probe_interval_seconds` (default 30s).
- **Trivy** (Docker image scanner) is actively probed via its `/healthz`
  endpoint on the same interval.
- **osv.dev** health is derived passively from real scan traffic — no extra
  requests are sent to the public API.

Status is `ok` (reachable, fast), `warn` (reachable but slower than
`health.slow_threshold_ms`, default 2000ms), `down` (last check failed),
`unknown` (no data yet), or `off` (configured but not attached by the active
profile).

### Persistent telemetry

The request feed, KPI counters, quarantine list and **per-calendar-day metrics**
are stored in an embedded SQLite database and are the single source of truth.
`database.path` is **required** — the proxy fails to start if it is empty or the
database cannot be opened. Daily metrics are exposed at
`GET /api/metrics/daily?days=N` (default 30, max 365, newest first).

The console **Overview** renders these daily metrics as sparklines on the
Requests, Cache-hit and Blocked KPI cards, with a 7-day / 30-day window toggle.

Each proxied request records its telemetry event in one synchronous local SQLite
transaction, so state is durable the moment it is written and survives restarts
and crashes with no flush window. Old rows are pruned hourly in the background.

Retention is configurable via `database.event_retention_days` (default 30) and
`database.daily_retention_days` (default 365).

## How it Works

Every package download goes through this pipeline:

1. **Cache lookup** — if the artifact was previously approved and cached, it is served
   immediately with `X-Joei-Cache: HIT`. No upstream contact.

2. **Supply Chain Filter** — fetches version metadata from the upstream registry and checks
   `upload_time`. Packages published less than `supply_chain.min_age_hours` ago are rejected
   with HTTP **423 Locked**.

3. **CVE Scan** — queries [osv.dev](https://osv.dev) with the package name and version.
   If any finding meets or exceeds `cve.block_on` severity, the package is rejected with
   HTTP **403 Forbidden**. Results are cached in memory for `cve.cache_ttl_minutes`.

4. **Malware Scan** — the artifact is downloaded to a temp file and scanned by
   every configured engine in `malware.scanners[]` (native ClamAV `INSTREAM`, or
   any ICAP server such as Kaspersky / Dr.Web). If any engine reports a signature,
   the package is rejected with HTTP **403 Forbidden** (`reason: malware_found`)
   and the artifact is not cached.

5. **Cache + Serve** — a clean artifact is stored in the local cache and served to
   the client.

If any scanner is unreachable, the request is rejected (fail-closed). The proxy never serves
an artifact that has not been approved.

Index and metadata requests (e.g. `/simple/requests/` for pip) are proxied transparently
to the upstream registry without scanning or caching.

### Multiple upstreams per provider

Each provider accepts an ordered list of `upstreams`. For every request the proxy tries
them in order and uses the first that serves the artifact (Nexus-style sequential
fallback). Any failure — 404/410, 5xx, timeout, or connection refused — advances to the
next upstream. If every upstream returns 404/410 the client gets a 404; any other failure
mix yields a 502.

```yaml
registries:
  maven:
    enabled: true
    upstreams:
      - "https://repo1.maven.org/maven2"
      - "https://repo.spring.io/release"
  rubygems:
    enabled: true
    upstreams:
      - "https://rubygems.org"
```

## Configuration

The proxy reads `config.yaml` (default path, overridable with `--config`).
All values can be overridden with environment variables using the prefix `JOEI_`
and `_` as separator (e.g. `JOEI_SUPPLY_CHAIN_MODE=dry_run`).

| Key | Default | Description |
|-----|---------|-------------|
| `server.listen` | `:8080` | TCP address to listen on |
| `supply_chain.min_age_hours` | `24` | Minimum package age in hours before serving |
| `supply_chain.mode` | `enforce` | `enforce` blocks; `dry_run` logs only; `off` disables the filter |
| `cve.enabled` | `true` | Enable CVE scanning via osv.dev |
| `cve.block_on` | `HIGH` | Minimum severity to block: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `cve.cache_ttl_minutes` | `1440` | How long CVE scan results are cached in memory (minutes) |
| `image_scan.enabled` | `false` | Enable Trivy-based image scanning for Docker pulls |
| `image_scan.trivy_server` | `http://trivy:4954` | Address of the Trivy server sidecar |
| `image_scan.timeout_seconds` | `120` | Timeout for a single image scan |
| `image_scan.scanners` | `vuln,secret` | Comma-separated Trivy scanner types |
| `image_scan.max_layer_bytes` | `2147483648` | Maximum layer size (bytes); larger layers fail closed |
| `policy.active_profile` | `production` | Name of the active policy profile |
| `policy.profiles.<name>.allowlist` | `[]` | Packages that bypass CVE and age checks at boot (seeds both per-gate runtime allowlists). Format: `pypi/requests` (all versions) or `pypi/requests@2.31.0` (exact version) |
| `policy.profiles.<name>.denylist` | `[]` | Packages always blocked regardless of scan results. Same format as `allowlist` |
| `cache.local.path` | `/var/cache/jo-ei` | Directory for cached artifacts |
| `cache.local.max_size_gb` | `100` | Maximum cache size; oldest entries evicted when exceeded (LRU) |

The table above covers the most common keys. The complete reference — every
key, default, and the environment-variable override rules — is in
[`docs/configuration.md`](docs/configuration.md); the full commented default
configuration is in [`config.yaml`](./config.yaml).

Ready-made client configs (pip, npm, Yarn, Maven, Gradle, Bundler, Docker)
live in [`examples/`](examples/), and the package/dependency layout is
documented in [`docs/architecture.md`](docs/architecture.md).

## Understanding Block Responses

When the proxy rejects a request, it returns a structured JSON body. The `reason` field
tells you exactly why.

### 423 Locked — Supply Chain Filter

The package was published too recently.

```json
{
  "error": "package_blocked",
  "reason": "package_version_newer_than_24h",
  "package": "requests",
  "version": "2.32.0",
  "published_at": "2026-05-31T10:00:00Z",
  "block_until": "2026-06-01T10:00:00Z",
  "blocked_by": ["supply_chain_filter"],
  "request_id": "req_abc123"
}
```

**What to do:**
- Wait until `block_until` and retry.
- Or add the package to the supply-chain allowlist (console → Policy → Allowlist · supply-chain, or `policy.profiles.<name>.allowlist` in YAML) to bypass the age check for
  trusted packages (e.g. internal packages, approved hotfixes).

### 403 Forbidden — CVE found

A known vulnerability meets or exceeds the configured severity threshold.

```json
{
  "error": "package_blocked",
  "reason": "cve_found",
  "package": "requests",
  "version": "2.28.0",
  "cves": [
    {
      "id": "CVE-2024-35195",
      "severity": "HIGH",
      "summary": "Requests Session object does not verify requests after making first request with verify=False"
    }
  ],
  "blocked_by": ["cve_scanner"],
  "request_id": "req_def456"
}
```

**What to do:**
- Upgrade to a version with no CVEs at or above the threshold.
- Or add the package+version to the CVE allowlist (console → Policy → Allowlist · CVE) if the CVE has been reviewed and accepted
  as a known risk.

### 403 Forbidden — Denylist

```json
{
  "error": "package_blocked",
  "reason": "denylisted",
  "package": "evil-pkg",
  "version": "1.0.0",
  "blocked_by": ["policy_engine"],
  "request_id": "req_ghi789"
}
```

**What to do:** Remove the package from `policy.profiles.<name>.denylist` if it was added
in error, or use a different package.

### 403 Forbidden — Malware detected

The downloaded artifact matched a malware signature.

```json
{
  "error": "package_blocked",
  "reason": "malware_found",
  "package": "evil-pkg",
  "version": "1.0.0",
  "engine": "clamav",
  "signature": "Win.Trojan.Agent-123456",
  "blocked_by": ["malware_scanner"],
  "request_id": "req_jkl012"
}
```

**What to do:** Do not install this artifact. If you believe it is a false
positive, verify the package out-of-band and report the signature to your
security team. Malware verdicts cannot be allowlisted — the scan runs on
every download regardless of policy.

## Installing a Release

Prebuilt binaries for Linux, macOS, and Windows (amd64/arm64) with checksums
are published on the [releases page](https://github.com/ggwpLab/Jo-ei/releases).
The container image ships on GHCR:

```bash
docker pull ghcr.io/ggwplab/jo-ei:latest
jo-ei --version   # prints version, commit, and build date
```

## Building from Source

**Prerequisites:** Go 1.25+ (see [go.dev/dl](https://go.dev/dl/) for downloads)

```bash
# Download the latest stable Go from https://go.dev/dl/ and follow the install instructions.
# On Linux amd64 (adjust version as needed):
#   curl -fsSL https://go.dev/dl/go1.25.10.linux-amd64.tar.gz -o /tmp/go.tar.gz
#   mkdir -p ~/go-sdk && tar -C ~/go-sdk -xzf /tmp/go.tar.gz
#   export PATH="$HOME/go-sdk/go/bin:$PATH"

# Build
go build -o bin/jo-ei ./cmd/jo-ei

# Run
./bin/jo-ei --config config.yaml

# Unit tests
go test ./...

# Integration tests (use in-process mocks; no external services required)
go test ./integration/... -tags integration
```

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup, testing requirements, and PR workflow. This project follows
a [Code of Conduct](CODE_OF_CONDUCT.md).

Found a security vulnerability? Please report it privately — see
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)

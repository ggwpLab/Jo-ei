# Docker Registry Support — Design

**Date:** 2026-06-23
**Status:** Approved (brainstorming complete)
**Scope:** Pull-through proxy for public Docker images (Docker Hub first), gated by
Trivy (CVE/secrets) and ClamAV (signature malware), reusing Jōei's existing
telemetry, policy, cache, and health subsystems.

## Goal

Let developers pull public container images (Docker Hub / GHCR / Quay) through Jōei
the same way they already pull PyPI/npm/Maven/RubyGems packages: intercept, enforce
protection layers, cache, serve. **Pull only** — no push / private-registry storage.

## Why the usual approach does not work

Jōei's existing pipeline (`proxy.Handler.ServeHTTP`) assumes **one HTTP request → one
artifact file**: `NormalizeRequest` yields `name@version`, then supply-chain (24h
rule), CVE via osv.dev keyed on `name@version`, download one file to a temp path,
ClamAV scans that single file, cache, serve.

Docker Registry HTTP API V2 breaks every one of those assumptions:

1. **Pull is a sequence of requests**, not one download:
   `GET /v2/` (ping) → `GET /v2/<repo>/manifests/<tag|digest>` →
   `GET /v2/<repo>/blobs/<digest>` for the config blob and **each layer**.
2. **An image is not one file** — it is a manifest + config blob + N layers
   (gzip tarballs). Layers are addressed by digest and **shared/deduplicated**
   across images.
3. **CVE scanning via osv.dev is inapplicable.** osv.dev finds vulnerabilities in
   *language ecosystem packages* by `name@version`. An image has no such version;
   you must inventory OS packages (apk/deb/rpm) and language dependencies *inside the
   layers*. That is Trivy/Grype's job, not osv.dev's.
4. **Antivirus over a single temp file does not fit.** The artifact is a set of
   layers; ClamAV must scan layer contents, not "one file".
5. **No honest publish date.** The registry API has no real publication timestamp;
   the closest signal is `created` in the config blob (a build date).

## Decisions (from brainstorming)

- **Scenario:** pull-through proxy of public images. Docker Hub as the primary
  `registry-mirror` target; GHCR/Quay are a future extension (the Docker daemon's
  `registry-mirrors` only mirrors Docker Hub).
- **CVE engine:** Trivy.
- **Antivirus:** both Trivy *and* ClamAV from the start (Trivy for CVE/secrets,
  ClamAV for signature malware over layers).
- **24h rule:** apply using `config.created` from the image config blob.
- **Integration approach:** a dedicated `DockerHandler` in a new package that reuses
  Jōei's shared interfaces; the existing `proxy.Handler` is left untouched.
- **Trivy deployment:** sidecar `trivy server` (holds the vuln DB + matching); the
  `trivy` CLI ships inside the Jōei image and runs in client/server mode.
- **multi-arch:** scan only the platform the client requested (MVP).
- **Oversized layer:** layer larger than `max_layer_bytes` → fail-closed (block).

## Architecture

### Components — `internal/proxy/dockerproxy`

New package, isolated from `proxy.Handler` (which does not change):

- `Handler` — implements the Docker Registry V2 flow; satisfies `http.Handler`.
- `Adapter` — upstream selection (default `https://registry-1.docker.io` + Docker Hub
  token auth), resolution of `repo` and `reference`.
- `manifestGate` — orchestrates the checks (supply-chain → Trivy → ClamAV → policy)
  and caches the verdict by image-digest.
- `ImageScanner` interface — image CVE scanner, with a `TrivyScanner` implementation
  (mirrors the role of `proxy.CVEScanner`).
- `BlobStore` — narrow digest-keyed store (Get/Put/Has by `sha256:<digest>`) layered
  over the existing `cache` package's local disk backend.

### Routing

`Mux` registers prefix `v2` → `dockerproxy.Handler`. `splitPrefix("/v2/library/nginx/
manifests/latest")` already yields `prefix="v2"` and the Docker handler parses the
rest. Only the registration is added to `Mux`; shared routing logic is unchanged.
Enabled via `registries.docker.enabled` in config, wired in `buildHandlers`.

**Note on the `/v2/` constraint:** the Docker client always talks to `/v2/` and cannot
be given a `/docker/` prefix; and `registry-mirrors` in `daemon.json` only mirrors
Docker Hub. MVP therefore targets Docker Hub as a mirror, with headroom for other
registries later.

### Reused unchanged

`Recorder`/telemetry (new `Ecosystem:"docker"` events), `policy` (severity threshold +
denylist by image name), config patterns, and the health monitor.

## Flow — single gate on the manifest

1. `GET /v2/` → respond `200` with `Docker-Distribution-API-Version: registry/2.0`.
2. `GET`/`HEAD /v2/<repo>/manifests/<ref>`:
   - Resolve `<ref>` (tag or digest) to the **canonical image digest** (HEAD upstream).
   - If a cached verdict exists for that digest → serve the manifest (clean) or `403`
     (blocked) immediately.
   - Otherwise run `manifestGate`: supply-chain (`config.created` vs 24h) → Trivy
     (CVE/secrets) → ClamAV over layers → policy. Cache the verdict by digest.
   - **multi-arch index** (`application/vnd.oci.image.index...` / `manifest.list`):
     resolve to the **client-requested platform's** manifest and scan only that one.
3. `GET /v2/<repo>/blobs/<digest>`: served only if the image it belongs to passed the
   gate. Serve from cache or proxy upstream. Layers cached by blob-digest (dedup).

Blocking on the manifest means the client gets a clear error **before** any layer is
downloaded.

## Scanning model

### Trivy (client/server)

The Trivy **client** analyses the image (pulls layers, builds the SBOM); the sidecar
`trivy server` holds the vuln DB and does matching. The `trivy` CLI ships in the Jōei
image and is invoked via `os/exec` with a context timeout:

```
trivy image --server http://trivy:4954 --format json --quiet \
            --scanners vuln,secret <repo>@<digest>
```

JSON output is parsed (`Results[].Vulnerabilities[]`) and mapped to the existing
`proxy.CVEFinding`/`proxy.Severity` (`MODERATE`→Medium already handled by
`ParseSeverity`). `TrivyScanner` exposes a health probe (`trivy version --server ...`)
for the console, mirroring the osv health pattern.

### ClamAV over layers

An image is approved only if **all layers are clean**:

- For each layer-blob not already cached, download it to a temp file and run it through
  the existing `AVScanner` (`MultiScanner` → ClamAV/ICAP). ClamAV unpacks gzip/tar and
  scans contents itself. The `AVScanner.Scan(ctx, filePath)` interface is reused as-is.
- The ClamAV verdict is cached **by blob-digest** — each layer is scanned once and
  reused across images (dedup).
- A layer larger than `max_layer_bytes` → **fail-closed** (block the image).

### Verdict combination

`manifestGate` produces the per-image verdict: supply-chain (`config.created`) → Trivy
findings vs `policy` (severity threshold, denylist) → ClamAV over all layers. Any block
→ negative verdict, cached by image-digest with its reason
(`cve_found` / `malware_found` / `package_younger_than_min_age` / `denylisted`).

## Configuration

```yaml
registries:
  docker:
    upstreams:
      - "https://registry-1.docker.io"   # Docker Hub
    enabled: true

image_scan:                  # image CVE scanning (Trivy)
  enabled: true
  trivy_server: "http://trivy:4954"
  timeout_seconds: 120
  scanners: "vuln,secret"
  max_layer_bytes: 2147483648   # 2 GB; a larger layer → fail-closed (block)
```

- `image_scan` is separate from `cve` (osv.dev): different engine and model.
- Severity threshold and denylist come from the **existing** active policy profile
  (`cve_min_severity`, `denylist`) — no separate policy is introduced.
- ClamAV/ICAP use the same `malware.scanners`, attached when the profile sets
  `malware_block: true`, as today.
- `docker-compose.yaml`: add a `trivy` sidecar (`aquasec/trivy server`) with a volume
  for its DB cache. The Jōei `Dockerfile` installs the `trivy` binary.
- Health: the Trivy scanner is added to the health monitor (active probe
  `trivy version --server`).

## Cache by digest

- **Layers (blobs)** cached by `sha256:<digest>` — immutable, deduplicated across
  images, carry the reused ClamAV verdict.
- **Manifests** cached by their digest; the gate verdict (clean/blocked + reason +
  findings) stored by **image-digest**.
- **Tags are mutable**, so tag→digest is not cached long: each pull does a HEAD
  upstream to resolve the current digest (short TTL, ~60s, to avoid hammering upstream
  across the blob requests of one pull). The verdict is bound to the digest, so a tag
  moving to a new image automatically triggers a fresh gate.
- Storage reuses the existing `cache` local disk backend (size accounting / LRU) under
  digest-shaped keys `docker/blobs/<digest>` and `docker/manifests/<digest>` via the
  new `BlobStore`. The existing `ArtifactCache` interface is **not** changed.

## Error handling & telemetry

- **Fail-closed everywhere**, as in the existing pipeline: a Trivy/ClamAV/digest-resolve
  error blocks the request; the image is not served.
- Responses use the Docker Registry error envelope (the Docker client parses these):
  - CVE/malware/supply-chain block → `403 Forbidden`,
    `{"errors":[{"code":"DENIED","message":...}]}`.
  - upstream unavailable → `502`; not found → `404`
    (`{"errors":[{"code":"MANIFEST_UNKNOWN",...}]}`).
- **Telemetry:** one event per gate (`Ecosystem:"docker"`, `Package:<repo>`,
  `Version:<tag-or-digest>`); `BlockedBy` = `cve`/`malware`/`supply_chain`/`denylist`;
  findings/engine/signature fields reused. The console renders Docker events with no
  schema change.
- A `GateImageScan` constant is added alongside `GateCVE`/`GateMalware`.

## Testing (TDD)

- **Unit, `dockerproxy`:** V2 path parsing; tag→digest resolution; multi-arch index
  unwrap with platform selection; verdict cache by digest; Trivy JSON→`CVEFinding`
  mapping; verdict combination; fail-closed on errors and on oversized layers. Trivy
  and ClamAV are mocked behind interfaces.
- **`TrivyScanner`:** mock `os/exec` (command-substitution pattern); parse a real Trivy
  JSON fixture; severity mapping; health probe.
- **Integration (`integration/`):** stand up a fake upstream Docker registry
  (`httptest`) and run the full pull flow — ping → manifest gate (clean → served;
  CVE-hit → 403; malware-hit → 403) → blob serve from cache; assert layer dedup and the
  Docker error envelope. Modeled on `phase*_test.go`.
- Real ClamAV/Trivy tests are gated behind a build tag / skip, like the existing
  scanner tests.

## Out of scope (future)

- Push / private-registry storage.
- Mirroring registries other than Docker Hub (GHCR/Quay) via the daemon.
- Scanning all platforms of a multi-arch index.
- Per-tag publish-date sourcing via registry-specific APIs (e.g. Docker Hub
  `last_updated`).

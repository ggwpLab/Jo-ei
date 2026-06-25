# Docker proxy polish: Trivy health, supply-chain quarantine, AV docs

- **Date:** 2026-06-25
- **Status:** approved
- **Scope:** three independent fixes to the Docker pull-through proxy and console.

## Problem

Three shortcomings in the Docker proxying surfaced after the stage-1 bugfix merge:

1. **Trivy health is misleading.** The console scanner strip shows Trivy, but its
   status/ping do not reflect whether the Trivy *server* is reachable.
2. **Supply-chain-blocked Docker images never appear in the Quarantine screen**,
   even though equivalent package (SCA) holds do.
3. **README says Docker layers are scanned only by ClamAV**, while the code already
   runs every configured malware engine.

## 1. Trivy health probe tests the server

### Current behaviour
`TrivyScanner.Probe` (`internal/proxy/dockerproxy/trivy.go:131`) runs
`trivy version --server <url> --format json`. `trivy version` is essentially a
local/client command: it can exit 0 even when the Trivy server is down. The health
`Monitor` therefore reports a misleading `ok` and a meaningless latency.

### Change
Replace the probe with an HTTP `GET <trivy_server>/healthz`, expecting HTTP `200`.
`/healthz` is Trivy server's documented, auth-free health endpoint (returns `ok`),
so the round-trip reflects real server availability and yields a real ping latency
for the scanner strip.

- Add an unexported `httpClient *http.Client` field to `TrivyScanner`, defaulted to
  a client with a short timeout. The health `Monitor` already bounds each probe with
  a context deadline (`probeTimeout`, ≤ 10s); the probe must use that context.
- Build the URL as `strings.TrimRight(serverURL, "/") + "/healthz"`.
- A non-2xx status or a transport error is a probe failure (scanner shows `down`).

### Testability
`trivy_test.go` is in `package dockerproxy`, so a test can set the unexported
`httpClient` and point `serverURL` at an `httptest.Server`:
- handler returns `200 ok` on `/healthz` → `Probe` returns nil.
- handler returns `503` (or the server is closed) → `Probe` returns an error.

### Rejected alternative
Keep shelling out to the `trivy` CLI (e.g. a trivial scan): slower, spawns a process
per probe, and still does not cleanly isolate "server reachable". The `/healthz` GET
is lighter and accurate.

## 2. Supply-chain-blocked Docker images appear in Quarantine

### Current behaviour
`/api/quarantine` returns only telemetry events whose `block_until` is in the future
(`internal/telemetry/sqlite.go:381`). The package proxy sets `PublishedAt` and
`BlockUntil` on supply-chain holds (`internal/proxy/handler.go:149-152`). The Docker
gate does not: `GateVerdict` carries `PublishedAt` but never `BlockUntil`, and
`Handler.record` never sets either field on the event. The filter already returns both
(`proxy.FilterResult.PublishedAt` / `.BlockUntil`); they are discarded.

Consequence: Docker min-age holds are counted in the `supply_blocked` KPI (the gate is
recorded as `GateSupply`) but never listed on the Quarantine screen.

### Change
- Add `BlockUntil time.Time` to `GateVerdict`
  (`internal/proxy/dockerproxy/gate.go`).
- In the supply-chain branch of `manifestGate.Evaluate` (`gate.go:119-124`), populate
  `v.PublishedAt = fr.PublishedAt` and `v.BlockUntil = fr.BlockUntil` from the filter
  result.
- In `Handler.serveManifest` block path (`handler.go:69-73`), set
  `ev.PublishedAt = v.PublishedAt` and `ev.BlockUntil = v.BlockUntil` in the event
  modifier. For non-supply blocks (cve / malware / denylist) these stay zero, which is
  correct — only supply-chain holds are quarantined.

### Decision: do not cache supply-chain blocks
The quarantine query (`sqlite.go:354-387`) deduplicates by `eco/pkg@ver` and keeps the
**newest** event **before** applying the `block_until > now` filter. The Docker verdict
store persists only `clean` + a `reason` string (`blobcache.go:51`), not the timestamps.
If a supply-chain block were cached, the next pull would hit the cache and record a
newer event with `block_until = 0`, which would shadow the original and drop the image
from quarantine.

Therefore the supply-chain branch must **stop caching its verdict** (remove the
`g.cacheVerdict(...)` call there). Supply-chain blocks are time-based and must be
re-evaluated on every pull: the gate re-fetches the manifest + config blob (cheap — no
layers are fetched, since the block happens before layer scanning) and re-runs the
filter, producing a fresh block event with a current `block_until` each time. This also
fixes a latent bug where a cached "younger than min-age" block was never re-checked
after the image matured. CVE / malware / denylist blocks remain cached — they are
deterministic and do not expire.

**Stale cache from older builds.** The verdict store is on-disk and survives a binary
upgrade, so a supply-chain block cached by a pre-fix build would still be *read* by the
cache-restore branch in `Evaluate` and returned with `block_until = 0` (the store never
persisted the timestamp) — blocked but never quarantined, and never released after
maturity. Because the current gate never *writes* a supply-chain block, any such cached
entry is necessarily stale. The cache-restore branch therefore skips it
(`isStaleSupplyBlock`) and falls through to a fresh evaluation. End-to-end tests cover
the single-arch, multi-arch, and stale-cache paths through the real supply-chain filter
and the real SQLite telemetry store.

### Decision: keep HTTP 403
The Docker block path returns HTTP **403** for every block reason. The package proxy
returns **423 Locked** for supply holds. We keep **403** for Docker: registry V2
clients expect 401/403/404, and 423 is unusual for the protocol. The Quarantine
listing is driven by the telemetry `block_until` field, not the HTTP status, so it
works regardless. The Quarantine card badge ("423 LOCKED") is static UI text and
renders correctly either way.

## 3. README: Docker layers scanned by all configured AV engines

### Current behaviour
The gate scans the image config blob and every layer through `g.av`, which is wired to
`scanner.NewMultiScanner(all configured engines)` (`cmd/jo-ei/main.go:214,268`).
`MultiScanner.Scan` runs every engine on a clean file. So all configured engines
(ClamAV and any ICAP engines) already scan Docker layers.

The README, however, mentions only ClamAV for Docker images
(`README.md:133-134`, pipeline diagram `:18`, malware section `:283`).

### Change (docs only)
Update the README so the Docker section states that image layers (config blob + each
layer) are scanned by **every configured `malware.scanners[]` engine (ClamAV and/or
ICAP)**, consistent with the package path. No code change.

## Testing summary

- **(1)** Unit-test `TrivyScanner.Probe` against an `httptest.Server`: 200 → ok;
  503 / closed server → error.
- **(2)** Gate test: a supply-chain Docker block yields a `GateVerdict` with non-zero
  `BlockUntil`/`PublishedAt` and is **not** written to the verdict store (re-evaluated
  each pull). Handler test: such a block records an event carrying `BlockUntil` so the
  quarantine query returns it, and two consecutive pulls both produce block events with
  a non-zero `BlockUntil` (no cache shadowing).
- **(3)** None (documentation).

## Out of scope

- Switching the Docker supply-chain block to HTTP 423.
- Per-engine attribution of which AV engine flagged an image.
- Any change to the package (non-Docker) proxy.

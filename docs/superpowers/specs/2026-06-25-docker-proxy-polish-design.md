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
  `BlockUntil`. Handler/telemetry test: such a block produces an event that the
  quarantine query returns.
- **(3)** None (documentation).

## Out of scope

- Switching the Docker supply-chain block to HTTP 423.
- Per-engine attribution of which AV engine flagged an image.
- Any change to the package (non-Docker) proxy.

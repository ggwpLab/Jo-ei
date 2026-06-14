# Scanner Health-Probes — Design

**Date:** 2026-06-14
**Status:** Approved
**Stage:** Production-readiness (task 3 of 4)

## Problem

The console overview lists configured scan engines (osv.dev, ClamAV, ICAP) but
their status is **static**: `cmd/jo-ei.scannerInfo()` computes a slice once at
startup and reports each engine as `enabled` or not. An operator cannot tell from
the console whether clamd is actually reachable or whether osv.dev is responding —
only whether it was *configured*. The frontend already anticipated live data: the
scanner strip has health-dot CSS (`ok` green / `warn` gold / `down` red) and a
`latency` field placeholder in `api.js`; it just receives the static `enabled`
flag today.

## Goal

Surface **live availability + latency** for each scan engine in
`GET /api/overview`, driving the existing health dots and showing a latency
figure operators can watch.

Non-goals (YAGNI): historical health timelines, alerting/notifications,
signature-database freshness, per-engine error-rate tracking.

## Health model

Health is determined differently per scanner type (the **hybrid** model):

- **ClamAV / ICAP** are local/internal socket services with cheap, file-free
  liveness commands. They are **actively probed** on a background timer.
- **osv.dev** is a remote third-party HTTP API with no health endpoint. Its
  health is derived **passively** from real scan outcomes (last success/error +
  observed latency), so we add **zero** extra traffic to the third party.

## Architecture

### New package `internal/health`

A small, dependency-light monitor that owns scanner liveness state. It knows
nothing about the clamd/ICAP/osv wire protocols — probes are injected as
closures, so `health` does **not** import `scanner` (avoids an import cycle;
`scanner` already imports `proxy`, and `console` will import `health`).

```go
type Status string

const (
    StatusOK      Status = "ok"
    StatusWarn    Status = "warn"
    StatusDown    Status = "down"
    StatusUnknown Status = "unknown"
    StatusOff     Status = "off"
)

// ScannerHealth is the per-engine record surfaced in the overview.
type ScannerHealth struct {
    Name      string `json:"name"`
    Detail    string `json:"detail"`
    Enabled   bool   `json:"enabled"`
    Status    Status `json:"status"`
    LatencyMS int64  `json:"latency_ms"`
}

type Monitor struct { /* entries, last results, background goroutine */ }

func (m *Monitor) Snapshot() []ScannerHealth
func (m *Monitor) Close() error
```

**Entry kinds** (registered at construction; order is preserved in `Snapshot`):

- **Active** — carries `probe func(ctx) error`. The Monitor's background
  goroutine calls it every `interval` and **measures the latency itself** around
  the call (uniform measurement, not each scanner's job), then stores the latest
  `Result` (status + latency, derived via the status rules below). `Snapshot`
  returns the stored result.
- **Passive** — carries `report func() ScannerHealth`. The Monitor calls it live
  at `Snapshot` time; the underlying scanner tracks its own last outcome. Passive
  entries are never touched by the background goroutine.
- **Disabled** — a configured scanner that the active policy profile did not
  attach. Reported as `status:"off"`, `latency_ms:0`, never probed.

The background goroutine probes all active entries once immediately on start,
then every `interval`. Each probe is bounded by its own context timeout
(derived from `interval`, capped) so a hung scanner cannot stall the loop or
later probes. `Close()` cancels the goroutine and waits for it to exit (mirrors
`OSVScanner.Close`).

### Status rules

Given a configurable `slowThreshold`:

| Condition (active probe)                    | Status    |
|---------------------------------------------|-----------|
| probe ok, latency ≤ threshold               | `ok`      |
| probe ok, latency > threshold               | `warn`    |
| probe returns error / times out             | `down`    |
| not probed yet (before first cycle returns) | `unknown` |

| Condition (passive / osv.dev)               | Status    |
|---------------------------------------------|-----------|
| last scan ok, latency ≤ threshold           | `ok`      |
| last scan ok, latency > threshold           | `warn`    |
| last scan errored                           | `down`    |
| no scan traffic yet                          | `unknown` |

A disabled (not-attached) scanner is always `off` regardless of probes.

### Scanner-package additions (`internal/scanner`)

- `(*ClamAVScanner).Ping(ctx) error` — dials clamd, sends `zPING\x00`, expects a
  `PONG` reply. Reuses the existing dial/deadline pattern from `Scan`.
- `(*ICAPScanner).Options(ctx) error` — sends
  `OPTIONS icap://<addr>/<service> ICAP/1.0` with the standard headers, expects a
  2xx ICAP status. This is the canonical ICAP capability/health probe; no file
  body is sent.
- `(*OSVScanner)` — records `lastLatency time.Duration`, `lastErr error`,
  `lastAt time.Time` (guarded by the existing mutex or a dedicated one) on each
  `Scan` call. Exposes `Health() health.ScannerHealth` translating those fields
  via the passive status rules. (osv import of `health` is fine — no cycle.)

### Wiring (`cmd/jo-ei/main.go`)

`scannerInfo()` is replaced by `buildHealthMonitor()`, which assembles the
Monitor from config + the live scanner instances:

- If `cfg.CVE.Enabled`: register the `OSVScanner` as a passive entry
  (`name:"osv.dev"`, detail = base URL).
- For each `cfg.Malware.Scanners` entry: if the profile attaches it
  (`profile.MalwareBlock`), register an active entry whose probe closes over the
  concrete scanner's `Ping`/`Options`; otherwise register a disabled (`off`)
  entry. (The concrete scanner instances built for the proxy are reused; the
  factory must surface the concrete type or a `Prober` so main can wire the
  closure.)
- Start the monitor; `defer monitor.Close()`.

The monitor is passed to the console as the `Health` provider.

### Console (`internal/console`)

- `Config.Scanners []ScannerInfo` is replaced by
  `Config.Health ScannerHealthProvider`, an interface:
  ```go
  type ScannerHealthProvider interface { Snapshot() []health.ScannerHealth }
  ```
  (`*health.Monitor` satisfies it; tests pass a stub.) The now-unused
  `ScannerInfo` type is removed.
- `overview` emits `"scanners"` as the live shape
  `[{name, detail, enabled, status, latency_ms}]` from `cfg.Health.Snapshot()`.
  A nil provider yields an empty array (defensive, matches existing nil-guards).

### Frontend (minimal — UI already exists)

- `api.js`: map the real `status` field through instead of deriving it from
  `enabled`; carry `latency_ms` into `J.scanners[].latency`.
- `hero.jsx`: render the latency (e.g. `42ms`) next to each scanner name in the
  strip; `unknown`/`off` render without a coloured dot.

## Configuration

New optional `health:` block (sensible defaults, override-friendly):

```yaml
health:
  probe_interval_seconds: 30   # how often active scanners are probed
  slow_threshold_ms: 2000      # latency above which status is "warn"
```

Defaults apply when the block or a field is omitted/zero. Added to
`config.yaml` (commented) and documented in the README scanner section.

## Testing

- **`scanner`**: fake clamd/ICAP TCP servers exercising `Ping`/`Options` for
  success and error/timeout; `OSVScanner.Health()` transitions across
  no-traffic → ok → slow(warn) → error(down).
- **`health`**: `Monitor` with injected fake probes — verify ok/warn/down/
  unknown/off mapping, timer-driven refresh updates the snapshot, passive entries
  read live, `Close()` stops the goroutine (no leak; `-race` clean).
- **`console`**: `overview` JSON carries `status` + `latency_ms` from a stub
  provider; nil provider → empty array.
- **`integration`**: overview reflects a `down` scanner end-to-end.

## Risks / notes

- **Probe timeout discipline**: a probe must never outlive its budget; each gets
  a bounded context so the loop cadence holds even against a black-holed socket.
- **Goroutine lifecycle**: `Close()` must be deferred in `main` and join the
  goroutine, matching the `OSVScanner` janitor pattern, to keep `-race` and
  shutdown clean.
- **Factory exposure**: wiring active probes requires `scanner.New` to return (or
  allow asserting) the concrete `*ClamAVScanner`/`*ICAPScanner` so `main` can
  close over `Ping`/`Options`. An optional `Prober` interface
  (`Probe(ctx) error`) implemented by both keeps the wiring uniform and testable.

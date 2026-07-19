# Re-check Coalescing + Offline By-digest Serving — Design

**Date:** 2026-07-19
**Status:** Approved
**Stage:** Post-v0.2.0 iteration (PR #61 follow-ups)

## Problem

Two gaps left by the lazy TTL re-validation work
(`2026-07-18-lazy-ttl-revalidation-design.md`, shipped in v0.2.0):

1. **Thundering herd on re-checks.** Concurrent requests for the same expired
   cache entry each independently re-run the expired gate: N parallel hits on
   one hot package fan out N identical CVE/AV scans once per TTL. Docker is
   worse — N parallel pulls of one image (first pull *or* expired verdict)
   run N full Trivy+ClamAV pipelines.
2. **Repeat docker pulls die with the upstream.** `Evaluate` always calls
   `FetchManifest` before consulting the verdict store, so an unreachable
   upstream registry fails even a by-digest repeat pull whose verdict and
   manifest body are sitting in the cache.

## Goal

- Coalesce concurrent identical re-checks (packages) and gate evaluations
  (docker) so one scan serves all waiters — same verdict, same guarantees.
- Serve by-digest docker pulls with a **fresh** cached verdict entirely from
  the cache (no upstream round-trip), and fall back to the stale cached
  verdict when the verdict is expired and the upstream is unreachable.

Decisions fixed during brainstorming:

1. Coalescing covers **both** the package re-check path and the whole docker
   scan pipeline (keyed by digest, so it also collapses first-pull herds).
2. By-digest fast path serves from cache **whenever the verdict is fresh** —
   not only as an error fallback. Tag resolution still requires the upstream.
3. Dependency: `golang.org/x/sync/singleflight` (new module dependency).

Non-goals: coalescing across processes (single-instance proxy); tag-ref
offline serving (resolution needs the upstream); persisting Content-Type in
the verdict store (schema unchanged — sniffed from the stored body instead).

## Architecture

### 1. Package re-check coalescing (`internal/proxy/handler.go`)

`Handler` gains `recheckGroup singleflight.Group`.

The response-writing `recheckExpired` splits into:

- **`runRechecks(ctx, ref, entry) *recheckOutcome`** — pure decision +
  side-effects function, executed once per flight by the singleflight leader.
  Runs the expired gates in the existing order (CVE → malware), performs the
  eviction (`Cache.Invalidate`) on a block and the `Mark*Checked` bumps on a
  pass. Returns:

  ```go
  // recheckOutcome is the shared result of one coalesced re-check flight.
  // nil means "serve from cache" (all checks passed or were skipped/stale).
  type recheckOutcome struct {
      gate      string             // gate.GateCVE | gate.GateMalware
      blockedBy string             // "cve" | "denylist" | "malware"
      decision  gate.PolicyDecision // CVE block details (findings, reason)
      av        *gate.AVResult      // malware block details (engine, signature)
  }
  ```

- **The per-request wrapper** in the cache-hit branch:

  ```go
  out, _, _ := h.recheckGroup.Do(ref.Key(), func() (any, error) {
      return h.runRechecks(ctx, ref, entry), nil
  })
  ```

  Every waiter (leader and followers) maps the shared outcome to its own
  response and its own telemetry event (own `request_id`; the scan ran once):
  blocked → 403 via the existing `writeCVEBlockedResponse` /
  `writeMalwareBlockedResponse` + `BLOCK` event; nil → serve from cache +
  `CACHE` event (unchanged).

Semantics preserved:

- **Blocking guarantee** — followers wait on the flight; nobody serves bytes
  past an expired TTL without the fresh verdict.
- **Scanner outage → serve stale** — `runRechecks` returns nil without
  bumping timestamps; every waiter serves stale; the next hit retries.
- Flight lifetime is one `Do` call — singleflight forgets the key when the
  leader returns, so consecutive (non-overlapping) requests are not
  accidentally coalesced across TTL windows. No `Forget` calls needed.
- The fresh-hit path (`TTL not expired`) never enters the group — zero
  overhead when nothing is due.

Edge: two racing requests where the leader evicts (block) — followers share
the block outcome directly instead of falling through to a cache miss and
re-downloading, which is exactly the waste the shared outcome avoids.

### 2. Docker evaluation coalescing (`internal/proxy/dockerproxy/gate.go`)

`manifestGate` gains `flights singleflight.Group`.

Placement: around the **scan pipeline** — everything after `FetchManifest`
and after the index/attestation passthrough branches (supply-chain check,
Trivy, ClamAV, verdict store write, blob cascade), keyed
`repo + "@" + digest`:

```go
res, err, _ := g.flights.Do(repo+"@"+digest, func() (any, error) { … })
```

- The flight body returns the computed `GateVerdict`; all waiters share it.
- Both herds collapse: N first pulls of one image → one pipeline run; N pulls
  of one expired verdict → one re-evaluation.
- `FetchManifest` and the passthrough branches stay outside the flight —
  cheap, and tag-keyed requests have no stable digest before the fetch.
- The stale-on-error fallback stays per-request: the flight returns the error,
  and each waiter applies its own `staleOr` with its own captured
  `staleVerdict` (identical values in practice; keeps the flight body free of
  per-request state).
- `evictBlobs` cascade and `cacheVerdict` run inside the flight (once).

### 3. By-digest fast path (`internal/proxy/dockerproxy/gate.go`)

At the top of `Evaluate`, before `FetchManifest`, **only** for
`isDigestRef(ref)` (digest == canonical key, no resolution needed):

```
GetImageVerdict(repo, ref):
  fresh (age ≤ recheckTTL, or TTL disabled):
      clean   → GateVerdict{Allowed, FromCache:true}; ManifestPath from
                GetManifestBody; ContentType sniffed from the stored body's
                top-level "mediaType" JSON field. If the field is absent
                (some OCI manifests omit it), SKIP the fast path and fall
                through to the normal fetch — never serve with a guessed
                Content-Type.
      blocked → GateVerdict{!Allowed, BlockedBy…, FromCache:true} → 403,
                no upstream round-trip (same decision the post-fetch check
                makes today).
      (isStaleSupplyBlock entries are ignored here exactly as in the
      post-fetch check — fall through to a fresh evaluation.)
  expired:
      capture staleVerdict BEFORE FetchManifest. FetchManifest error →
      staleOr(staleVerdict) — a by-digest repeat pull now survives an
      unreachable upstream. FetchManifest ok → normal re-eval (through the
      §2 flight).
  not found:
      current behavior — FetchManifest, fail closed on error.
```

Tag refs are untouched: resolution requires the upstream, and
`tags.rememberChildren` is fed only by by-tag index fetches, which the fast
path never handles.

Telemetry: a fast-path serve carries `FromCache: true` → recorded as `CACHE`,
same as today's post-fetch short-circuit. A fast-path 403 records `BLOCK`
with the stored reason.

The post-fetch cached-verdict check remains for tag refs and for digest refs
that fell through (no verdict / missing mediaType / expired).

### 4. Dependency

`golang.org/x/sync` added to go.mod (singleflight only; no transitive deps).

## Error handling

| Situation | Outcome |
|-----------|---------|
| Concurrent hits on one expired package entry | one scan; shared outcome; each request writes its own response + event |
| Leader's scanner errors mid-flight | outcome nil, no bumps → every waiter serves stale; next hit retries |
| Concurrent pulls of one docker digest (first or expired) | one pipeline run; shared verdict |
| Flight returns infra error (docker) | each waiter applies staleOr with its own staleVerdict; first pull (no stale) fails closed as today |
| By-digest, fresh clean verdict, upstream down | served from cache — upstream never contacted |
| By-digest, fresh blocked verdict | 403 from cache — upstream never contacted |
| By-digest, expired verdict, upstream down | stale verdict served (was: fail closed) |
| By-digest, no cached verdict, upstream down | fail closed (unchanged) |
| By-tag, upstream down | fail closed (unchanged — resolution needs upstream) |
| Stored manifest body lacks top-level mediaType | fast path skipped; normal fetch path |

## Documentation changes

- `docs/configuration.md` — `cache.revalidation` section: replace "an
  unreachable upstream registry still fails the pull" with the split rule:
  by-digest repeat pulls are served from the cache (fresh verdict → straight
  from cache; expired → stale fallback); by-tag pulls still require the
  upstream for resolution.
- `docs/superpowers/specs/2026-07-18-lazy-ttl-revalidation-design.md` — same
  sentence updated with a pointer to this spec.
- `CHANGELOG.md` (Unreleased): Added — by-digest docker pulls with a cached
  verdict are served without contacting the upstream (and survive registry
  outages); Changed — concurrent re-checks/evaluations of one entry are
  coalesced into a single scan.

## Testing

- **Handler (unit):** N parallel GETs on one expired entry with a gated stub
  scanner (blocks until released) → scanner called exactly once; all
  responses identical (block variant: all 403, entry+file gone, N BLOCK
  events with distinct request_ids; clean variant: all 200, timestamp bumped
  once). Scanner-error variant: all 200 (stale), no bump.
- **Docker gate (unit):** parallel `Evaluate` of one digest with a gated
  `countingScanner` → `ScanImage` called once, shared verdict. Fast path:
  fresh clean verdict → zero adapter requests (counting fake registry);
  fresh blocked verdict → 403, zero requests; expired verdict + dead
  upstream → stale verdict served; no verdict + dead upstream → error;
  stored body without `mediaType` → falls through to fetch.
- **Integration (`-tags=integration`):** seed a clean by-digest pull through
  the fake registry, shut the registry down, pull the same digest again →
  200, manifest bytes served, correct Content-Type and Docker-Content-Digest.

## Files touched

- `go.mod` / `go.sum` — golang.org/x/sync
- `internal/proxy/handler.go` — runRechecks split, singleflight wrapper
- `internal/proxy/handler_recheck_test.go` — concurrency tests
- `internal/proxy/dockerproxy/gate.go` — fast path, flight around the pipeline
- `internal/proxy/dockerproxy/gate_recheck_test.go` (+ helpers) — tests
- `integration/lazy_recheck_test.go` — offline by-digest test
- `docs/configuration.md`, `docs/superpowers/specs/2026-07-18-…-design.md`, `CHANGELOG.md`

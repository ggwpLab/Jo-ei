# PERF-01: reduce npm metadata JSON serialization

Date: 2026-11-05. Status: implemented, validated, and independently reviewed.

## Intent and scope

Reduce CPU time and allocated bytes per npm metadata request without changing
filtering or response semantics. The owner selected PERF-01 as the next task.
The implementation starts from `4d7427f` on `perf/npm-metadata-json`.

The saved vite/gzip CPU profile attributes 69.81% cumulative CPU to
`FilterVersions`, including 37.39% to JSON marshaling and 32.42% to unmarshaling.
These are nested costs, not independent percentages. The current code marshals
each dist object, each version, the versions map, and the top-level document.
Embedding those results as `json.RawMessage` causes repeated validation,
compaction, and copying of the same large payloads.

## Approaches

1. **Keep raw unknown fields; marshal the modified object tree once.** Continue
   using the standard library to decode raw fields. Represent modified objects
   as nested maps whose leaves are raw JSON or replacement strings, and perform
   one final document marshal. This removes intermediate encodings while
   preserving numeric precision and deterministic map ordering. It introduces
   small map conversions; benchmarks must establish the net allocation benefit.
   This is the proposed first change.
2. **Use a custom JSON scanner or a different JSON implementation.** This could
   also avoid repeated decoding and raw-field copies, but expands parser and
   compatibility work. Defer unless measurements show the first change is
   insufficient.
3. **Cache rewritten responses or tune gzip.** These address other costs, but
   cache invalidation changes require a separate design, and gzip was the
   smaller measured CPU consumer. Keep both outside this change.

## Implementation boundary

Change the npm adapter's private rewriting helpers and `FilterVersions` in
`internal/proxy/adapters/npm.go`. Keep its public `MetadataFilterer` contract.
Build the rewritten version/dist objects in memory and attach them to the
filtered document before final serialization. Reuse the same rewriting logic
for single-version manifests. Avoid a general JSON framework, new dependencies,
configuration options, pools, or custom parsers.

Keep unknown values as `json.RawMessage`, rather than decoding arbitrary JSON
numbers into `float64`. Continue using `encoding/json` escaping and sorted map
keys. Do not change the publish-date parser or policy evaluation order as part
of removing intermediate encodings.

Preserve these behaviors:

- Full and abbreviated packuments, scoped names, and single-version manifests.
- Canonical proxy tarball URLs, including the existing validation of versions.
- Unknown top-level, version, and dist fields, including large numbers, nested
  values, and JSON nulls.
- Versions without tarball links; malformed/unmappable versions and their time
  entries; empty or absent versions; and the all-rejected fallback.
- Sorted `Removed`/`Unmappable` results, unchanged dist-tags, publish dates,
  denylist decisions, and supply-chain filtering.
- Input bytes remain unmodified: concurrent callers can share fetched bytes.
- Deterministic response bytes, gzip behavior, and ETag/304 revalidation. Compare
  response bytes with baseline where possible, in addition to semantic JSON
  equality; investigate any differences before accepting them.

## Validation and acceptance

1. Run the unmodified unit and integration suites with `-race` in Docker using
   Go 1.26.10 and the existing `joei-gomod`/`joei-gocache` volumes.
2. Add focused compatibility cases for raw unknown values, malformed/null
   objects, and input reuse where the existing tests leave gaps. Establish a
   pre-change benchmark with allocation reporting before changing production
   code. Functional characterization tests should pass before and after.
3. Run focused tests during implementation, then the full unit/integration
   suites with `-race`, gofmt, and golangci-lint.
4. Repeat the saved microbenchmarks and the 39-case HTTP matrix with the exact
   saved lodash/typescript/vite fixtures and the original CPU/memory limits.
   Run performance measurements without race instrumentation. Compare
   CPU-ms/request, allocated bytes/request, throughput, p95, and RSS; collect a
   new CPU/allocation profile. Do not claim a predetermined numerical gain.
5. Require a repeatable reduction in CPU cost and allocated bytes on the saved
   workloads, with behavior checks passing. If the map conversions erase the
   benefit, revisit the implementation before marking PERF-01 complete.

Store all measurement harnesses, fixtures, outputs, and reports in a new
directory under Codex project memory, outside the checkout. Preserve the
original baseline. Note time-sensitive policy differences when comparing old
and new HTTP runs: a version can age out of the 24-hour hold between runs.
Record any limitations and update the Codex task status only after verification.

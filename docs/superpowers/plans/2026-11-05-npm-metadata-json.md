# npm Metadata JSON Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Reduce npm metadata CPU cost and allocated bytes while preserving filtering, download links, response bytes, and HTTP behavior.

**Architecture:** Keep unknown JSON values as `json.RawMessage`. Replace intermediate encodings of modified dist/version/versions objects with nested maps, then marshal the complete document once. Reuse the private tarball helper for packuments and single-version manifests; keep the handler and policy unchanged.

**Tech Stack:** Go 1.26.10, standard `encoding/json`, existing testify tests, Docker, golangci-lint v2.12.2 as in CI.

**Spec:** [Approved design](../specs/2026-11-05-npm-metadata-json-design.md).

## Global Constraints

- Work on `perf/npm-metadata-json`, starting at `4d7427f`; changes reach `main` through a PR.
- Keep the public `MetadataFilterer` contract.
- Keep unknown values as `json.RawMessage`, rather than decoding arbitrary JSON numbers into `float64`.
- Continue using `encoding/json` escaping and sorted map keys.
- Do not change the publish-date parser or policy evaluation order as part of removing intermediate encodings.
- Avoid a general JSON framework, new dependencies, configuration options, pools, or custom parsers.
- Keep cache invalidation, gzip tuning, and review findings R01–R13 outside this change.
- Run every Go test and benchmark in Docker using Go 1.26.10 and volumes `joei-gomod` and `joei-gocache`; performance runs omit `-race`.
- Store all measurement harnesses, fixtures, outputs, and reports in a new directory under Codex project memory, outside the checkout. Preserve the original baseline.
- No predetermined numerical gain is agreed. Require repeatable reductions in CPU cost and allocated bytes; investigate regressions in latency, throughput, or RSS.

## Review Focus

1. Unknown large numbers, nested values, and HTML-sensitive strings must retain their values and baseline encoding (Task 1).
2. Missing, null, and empty objects must retain their distinct behavior; a null tarball field is still rewritten (Task 1).
3. Malformed versions mixed with policy rejection must not restore unmappable links or lose the all-rejected fallback/time semantics (Task 1).
4. Callers sharing the same input bytes but using different proxy addresses must receive independent, deterministic rewrites (Task 1).
5. Manifest version/tag handling, duplicate keys, and invalid publish-date shapes must retain standard-library parsing behavior (Task 1).

## Files and Commands

Repository changes:

- `internal/proxy/adapters/npm.go`: only the private JSON helpers and serialization in `FilterVersions`/`rewriteNPMManifest`.
- `internal/proxy/adapters/npm_test.go`: focused public-contract characterization tests, alongside existing fixtures and helpers.
- This plan: execution checkboxes and verification status.

Reuse `internal/proxy/metadata_test.go` and `integration/npm_metadata_filter_test.go` unchanged unless verification exposes a specific missing assertion. Do not restructure other adapters or edit generated console assets.

Measurement locations are logical names, resolved when executing the plan:

- `REPOSITORY_ROOT`: the checkout containing this plan.
- `BASELINE_ROOT`: the saved `2026-11-05-metadata` experiment in the external Codex project measurement archive.
- `RUN_ROOT`: a new `2026-11-05-metadata-json` experiment directory in that same archive.

Create `RUN_ROOT` only if it does not exist; otherwise select a new suffix. Use the relocated baseline `README.md`; the archived instructions and HTTP runner require their measurement locations to be updated before reuse. Host-specific paths and launch scripts are execution details outside this plan.

In Docker commands, replace `<repository-root>` with `REPOSITORY_ROOT`. Mount it read-only at `/src`, use `/src` as the working directory, and reuse the named Go cache volumes. Mount `RUN_ROOT` at `/bench` for measurements; `/work` is a disposable container directory. These are container paths, independent of the host environment.

Focused tests:

```text
docker run --rm --mount "type=bind,source=<repository-root>,target=/src,readonly" -w /src -v joei-gomod:/go/pkg/mod -v joei-gocache:/root/.cache/go-build golang:1.26.10 go test ./internal/proxy/adapters ./internal/proxy -run 'NPM|Metadata|ETag' -race -count=1
```

## Task 1: Pin Behavior and Establish the Before Measurement

**Files:** Modify `internal/proxy/adapters/npm_test.go`; create measurement copies only under `RUN_ROOT`.

**Interfaces:** Consume existing `(*adapters.NPMAdapter).FilterVersions(doc []byte, ref *gate.MetadataRef, decide gate.VersionDecider, linkBase string) (gate.FilteredDocument, error)`, `fullPackument`, `packumentRef`, `linkBase`, and `rejectVersions`. Produce passing characterization cases and immutable before-results for Task 2. No new production API.

- [x] **Step 1: Confirm the starting state.** Inspect branch/diff and read the spec, `npm.go:276–450`, and existing npm tests. The earlier unmodified unit/integration race run passed; rerun if source or environment changed. Do not overwrite user changes.
- [x] **Step 2: Add `TestNPMAdapter_FilterVersions_PreservesRawValues`.** Exercise both a packument and a manifest with unknown fields at top/version/dist levels: `9007199254740993`, `1e+09`, nested arrays/objects, nulls, and strings containing `<`, `>`, `&`, quotes, and Unicode. Decode assertions into `json.RawMessage` or use `Decoder.UseNumber`; ordinary `JSONEq` alone can hide precision loss. Include these checks:

  ```go
  assert.Equal(t, "9007199254740993", string(unknown["large"]))
  assert.Equal(t, "1e+09", string(unknown["exponent"]))
  assert.Equal(t, "null", string(unknown["nullable"]))
  assert.Equal(t, "https://reg.example/npm/left-pad/-/left-pad-1.3.0.tgz", dist.Tarball)
  ```

  Record complete baseline response strings for compact representative fixtures as literal expected values before changing production code. Assert byte equality as well as field values; this pins sorting/escaping and therefore synthetic ETag inputs.
- [x] **Step 3: Add `TestNPMAdapter_FilterVersions_ObjectShapes`.** Table-test absent `versions` (original bytes), `versions:null` (still null), `versions:{}` (still object), null version entries (retained), absent/null/empty `dist` (unchanged), `dist.tarball:null` (canonical URL), and non-object version/dist values (unmappable). A lone unmappable version must satisfy `require.ErrorIs(t, err, gate.ErrNoServableVersions)`; `versions:[]` must return a decoding error. Include `time:null` versus `time:{}`.
- [x] **Step 4: Add `TestNPMAdapter_FilterVersions_MixedRejections`.** Supply `1.0.0` with malformed dist, `1.2.0` with a valid tarball, and both time entries; reject `1.2.0`. Assert `Unmappable == []string{"1.0.0"}`, `Removed == []string{"1.2.0"}`, and `AllRejected == true`. Only `1.2.0` remains, rewritten, with its time entry; `1.0.0` and its time disappear. The decider must never see `1.0.0`. Add a case with two unmappable versions inserted in reverse lexical order and assert sorted `Unmappable`. Retain existing partial-rejection, scoped-name, abbreviated, and sorted-removed coverage.
- [x] **Step 5: Add `TestNPMAdapter_FilterVersions_SharedInput`.** Invoke the same adapter concurrently on one shared input slice with bases `https://a.example/npm` and `https://b.example/npm`, using pure deciders. Collect results before assertions. Assert input bytes equal an original copy, each output contains only its own canonical links, and repeated calls for one base return identical bytes. Run under `-race`.
- [x] **Step 6: Add `TestNPMAdapter_FilterVersions_ParsingCompatibility`.** Pin single-manifest `version` string/tag behavior, case-insensitive `VERSION` matching, duplicate string-valued version keys (last value wins), and numeric manifest versions (decoding error). For a time map containing one valid timestamp and one numeric value, assert all decider dates are zero, as in the existing `npmPublishDates`; preserve the numeric time field. Derive expected results on unmodified code, not from the proposed implementation.
- [x] **Step 7: Run the focused Docker command.** All characterization cases must pass on the original implementation. This optimization adds no functional behavior: the before-performance result is the improvement baseline, while these tests protect compatibility. If an expected assertion disagrees with current code, investigate and correct the characterization before refactoring; do not silently fix behavior.
- [x] **Step 8: Prepare the measurement directory.** Copy `artifacts/harness.go`, `artifacts/config.yaml`, `artifacts/micro/metadata_bench_test.go`, the archived HTTP runner, and the saved fixtures from `BASELINE_ROOT` into `RUN_ROOT`; create separate `before/` and `after/` result/profile directories. Verify every JSON fixture SHA-256 against `artifacts/fixtures/manifest.json`. Do not fetch fresh registry data or modify baseline files. Record HEAD and the source diff used for each build.
- [x] **Step 9: Measure the unmodified adapter and handler.** In an 8 CPU / 6 GiB Docker container, copy `/src/go.mod`, `/src/go.sum`, and `/src/internal` into `/work`, place the external benchmark in `/work/micro`, then run the following with `RUN_ROOT` mounted as `/bench` and `BENCH_FIXTURES=/bench/fixtures`:

  ```sh
  cd /work
  go test ./micro -run '^$' -bench 'Benchmark(FilterRewrite|Handler)$' -benchmem -benchtime 1s -count 3 > /bench/before/microbench.txt
  ```

  Require PASS and results for lodash, typescript, and vite, including handler identity/gzip/304. Preserve raw output. Use this same benchmark source, toolchain, limits, and repetition count after the change.
- [x] **Step 10: Save baseline response evidence.** From the same external harness, call the adapter at fixed base `http://metadata-app:8080/npm` with deterministic accept-all, partial-reject (reject only the lexicographically smallest version key), and reject-all predicates; save body bytes and the `Removed`/`Unmappable`/`AllRejected` values for each fixture under `before/`. This differential check avoids wall-clock age changes and large fixtures in the repository.
- [x] **Step 11: Commit characterization tests.** Stage only `internal/proxy/adapters/npm_test.go`; commit as `test: pin npm metadata rewrite compatibility` after formatting and focused verification. Measurement files remain outside Git.

## Task 2: Marshal the Rewritten Document Once

**Files:** Modify `internal/proxy/adapters/npm.go`; consume Task 1 tests and baseline outputs.

**Interfaces:** Keep the public method signature unchanged. Add private `npmJSONFields(fields map[string]json.RawMessage) map[string]any`. Change private `rewriteNPMTarball(raw json.RawMessage, linkBase, name, version string) (any, error)` to return a serializable tree on success, or the original raw value plus `errNoTarballLink` when no link exists. Existing callers are only `FilterVersions` and `rewriteNPMManifest`; update them together.

- [x] **Step 1: Implement `npmJSONFields`.** Copy raw field values into a shallow `map[string]any`; preserve a nil input as a nil output, so null objects do not become empty objects. Do not unmarshal arbitrary unknown values into interfaces or floats.
- [x] **Step 2: Change `rewriteNPMTarball` to defer encoding.** Keep current decoding, link-presence checks, version validation, errors, and raw no-link return. Convert modified dist/version maps using `npmJSONFields`, store the canonical link as a string, and return the nested map. Remove the intermediate marshals of the URL, dist, and version.
- [x] **Step 3: Adapt `FilterVersions`.** Keep raw top-level/version decoding. Initialize the serializable versions map from the raw versions, replace successful rewrites, and remove unmappable/rejected entries from that map. Preserve the existing order: establish unmappable versions, then evaluate policy for servable versions, then apply the all-rejected fallback. Preserve nil versus empty versions, sorted result lists, and `ErrNoServableVersions`.
- [x] **Step 4: Assemble the final packument.** Convert the top-level map, attach the filtered versions map, and attach the existing raw time map after its current deletions when decoding succeeds. Preserve malformed time values unchanged. Retain `npmPublishDates` unchanged. Call `json.Marshal` once for the complete response; remove the intermediate versions/time marshals and their obsolete error branches. Keep error context for final encoding.
- [x] **Step 5: Adapt `rewriteNPMManifest`.** Keep its current `head.Version` decoding and no-link passthrough. Marshal the returned tree once on success; retain `gate.ErrNoServableVersions` wrapping for rewrite failures and return a contextual error if final encoding fails.
- [x] **Step 6: Format only changed Go files and run focused Docker tests.** Require PASS, including byte-exact cases and shared-input race checks. Inspect the diff for unrelated changes; do not format the whole repository.
- [x] **Step 7: Compare the large-fixture outputs.** Repeat Task 1 Step 10 under `after/`; require byte-for-byte bodies and equal result metadata for every fixed predicate/base pair. Investigate differences before acceptance. Repeat Task 1 Step 9 under `after/`; require lower CPU-related benchmark time and B/op across repeated samples, rather than accepting one favorable run. If costs regress, simplify the maps within this design and rerun; do not substitute a parser/cache redesign.
- [x] **Step 8: Commit the adapter change.** Stage only `internal/proxy/adapters/npm.go` and any justified test corrections; commit as `perf: avoid intermediate npm metadata serialization` after focused tests and lint pass.

## Task 3: Verify the Complete Change and Repeat the HTTP Matrix

**Files:** External `RUN_ROOT` scripts/results/profiles/report; Codex `MEMORY.md` and `metadata-optimization.md`; this plan's checkboxes. Existing repository test files are verification inputs.

**Interfaces:** Consume Task 2's unchanged adapter contract and before/after benchmark data. Produce reproducible HTTP/profile evidence and a task status supported by that evidence.

- [x] **Step 1: Run fresh full correctness checks.** Execute in Docker:

  ```text
  docker run --rm --mount "type=bind,source=<repository-root>,target=/src,readonly" -w /src -v joei-gomod:/go/pkg/mod -v joei-gocache:/root/.cache/go-build golang:1.26.10 sh -c 'go test ./... -race -count=1 && go test -tags integration ./integration/... -race -count=1 && go build ./...'
  ```

  Require exit 0. Existing integration cases must continue to cover min-age filtering, all-rejected fallback, canonical npm/Yarn links, trusted forwarding addresses, gzip/identity, single manifests, ETag revalidation, concurrent fetches, and credential separation. Record failures by name, including unrelated ones.
- [x] **Step 2: Run formatting and lint checks.** `gofmt -l internal/proxy/adapters/npm.go internal/proxy/adapters/npm_test.go` must print nothing. `golangci-lint run --timeout 5m` must exit 0 with no issues. Inspect `git diff --check` and the final source diff. Native Go tests remain prohibited; native formatting/lint are permitted.
- [x] **Step 3: Adapt the copied HTTP runner.** Use the new `RUN_ROOT`, an unused isolated network such as `joei-metadata-json-20261105`, and unique container names. Keep the hostnames `metadata-app`/`metadata-upstream` as network aliases for the archived config/harness and fixed rewritten base. Check for existing names before creation; track and clean up only resources this run created, including a running load container on failure. Do not stop working services or expose ports.
- [x] **Step 4: Build the real binaries and run the same 39 scenarios.** Build `/bench/loadtool` from the external harness and `/bench/jo-ei` from `./cmd/jo-ei`, with source mounted read-only. Keep application limits 8 CPU/6 GiB, upstream 2 CPU/1 GiB, generator 4 CPU/2 GiB, original config, ten-second start windows plus in-flight drain, warmup, and fresh app/temporary database between proxy cases. Use lodash/typescript VUs 1/10/50 and vite VUs 1/5/10; run direct/transparent/identity/gzip at each level plus 304 at the highest level. Save under `after/http/`.
- [x] **Step 5: Validate the HTTP results.** Require 39 completed scenarios, only expected 200 or 304, zero transport/read failures, valid warmup JSON, and rewritten-link counts matching remaining versions for every rewrite warmup. Note age-dependent version-count changes relative to the historical report. Compare each case with the saved original matrix, including controls. Recheck original/current binaries back-to-back for representative identity/gzip cases if controls or policy ages make attribution uncertain.
- [x] **Step 6: Collect matching profiles.** In the same external benchmark container, run `go test ./micro -run '^$' -bench '^BenchmarkHandler$/^vite$/^gzip$' -benchtime 5x -count 1 -cpuprofile /bench/after/profiles/cpu.pprof -memprofile /bench/after/profiles/heap.pprof -o /bench/after/profiles/micro.test`. Require PASS. Save `go tool pprof` CPU flat/cumulative and alloc_space summaries in `after/profiles/`, then compare removed marshal/compaction costs with the original profile; cumulative costs overlap.
- [x] **Step 7: Write `RUN_ROOT/report.md`.** Report before/after CPU-ms/request (`1000 * cpu_cores / requests_per_second`), allocated MiB/request, rps, p95, and sampled RSS for matching cases, plus repeated ns/op/B/op/allocs/op microbenchmarks. Include fixture hashes, commands, source revision/diff, limits, policy/time differences, correctness results, and limitations. Do not treat allocation churn as live memory or local results as production SLOs.
- [x] **Step 8: Apply the acceptance gate.** Require repeatable reductions in CPU cost and allocated bytes with compatibility/tests passing. Explain any mixed results; do not mark the task complete solely because tests pass. If successful, update Codex `metadata-optimization.md`, `MEMORY.md`, and any roadmap status references with the result/report path; otherwise record the unresolved measurement or regression.
- [x] **Step 9: Prepare the branch handoff.** Mark only verified plan steps complete, inspect Git status/diff, and report changed behavior, validation, measured gains, and limitations. Follow the chosen execution workflow for final review and PR preparation; merging/publishing is a separate action.

## Planning Verification

The owner approved the spec on 2026-11-05. This plan was checked against the current helper signatures/callers, existing adapter and integration tests, CI lint version, the relocated harness instructions, fixture manifest, and original HTTP runner. All five review-focus items have explicit tests in Task 1. Functional and performance commands above are execution steps, not claims that the optimization has already been implemented or measured.

## Execution Results

All three tasks completed on 2026-11-05. Production change: 72bc7cb. Full Docker unit/integration race suites, build, lint, and formatting passed. All 18 differential response files are byte-identical. The repeated 39-case HTTP matrix completed 604984 requests with only expected 200/304 and no transport/read failures; its containers and network were removed. Report, raw results, repeated benchmarks, and profiles are in RUN_ROOT outside the checkout. Final independent branch review is the remaining handoff gate.

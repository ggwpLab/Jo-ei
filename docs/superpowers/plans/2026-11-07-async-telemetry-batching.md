# Asynchronous Telemetry and Cache-Usage Batching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce synchronous SQLite work per cached-artifact request while retaining audit events under normal operation and preserving all enforcement decisions.

**Architecture:** Implement two component-owned writers: FIFO telemetry batches with atomic event/counter/day persistence, and cache-usage deltas coalesced by existing cache row ID. A stable batch token and one receipt per component make retries idempotent. Flush barriers protect destructive cache selection; a shared shutdown deadline drains or explicitly aborts both writers.

**Tech Stack:** Go 1.26.10 as currently specified by go.mod, database/sql, existing modernc SQLite and Prometheus dependencies, standard synchronization/context primitives, existing testify tests, Docker.

**Spec:** [Approved design](../specs/2026-11-07-async-telemetry-batching-design.md). The owner approved the complete design, including forced-stop behavior, on 2026-11-07.

## Global Constraints

- Work on `perf/async-telemetry-batching`, based on `0b5e669`; publish through a PR into main.
- Preserve every individual telemetry event. Aggregate counter deltas, not audit history.
- Losing unflushed observations on process crash is accepted; bounded-buffer overflow blocks producers and never drops events.
- Normal console visibility delay must remain within 30 seconds. This is not a timeout for discarding work.
- Defaults: telemetry queue 1024 events / batch 128; usage pending 4096 distinct row IDs / batch 256; both flush after 10 seconds or earlier on size/blocked producers. Retry failed batches after one second. Limits count items, not payload bytes or total HTTP memory.
- Keep policy, scanners, artifact publication, clean/block verdicts, security check timestamps and invalidation on their current enforcement path. Do not change R01-R13, REL-01 or SQLite synchronous settings.
- Healthy shutdown flushes. At the configured shared shutdown deadline (default 30 seconds), explicitly report an unsuccessful drain and unsaved work, unblock producers and terminate; never claim a clean flush after timeout.
- Single application instance per database/cache directory. No broker, durable outbox, new dependencies, new public tuning options or general batching framework.
- Every Go test/build/benchmark runs in Docker with the go.mod toolchain and `joei-gomod`/`joei-gocache`. Correctness tests use `-race`; performance measurements omit it. Local gofmt and golangci-lint are allowed.
- Store harnesses, measurement fixtures, before/after results, profiles and reports in a new external Codex measurement directory; preserve previous experiments. Documentation contains no personal host paths or host-shell assumptions.

## Review Focus

1. An acknowledged-on-disk batch whose COMMIT response fails must be retried without duplicate events or counters, even after pruning (Task 1/2).
2. Backpressure, client cancellation and shutdown racing with admission must not silently lose events, deadlock or leave producers behind (Task 2/4/5).
3. Midnight, zero event time, caller-owned nested slices and SSE/read ordering must not corrupt historical data (Task 1/2).
4. Deletion/reinsertion, UPSERT and an in-flight usage batch must not update another cache row or falsely select hot entries as stale (Task 1/3).
5. Storage failure must leave queue pressure observable and shutdown bounded, without making an unchecked/blocked artifact servable (Task 4/5).

## File Map and Verification Commands

- `internal/telemetry/{repo.go,sqlite.go,aggregate.go}`: atomic batch persistence; add `batch_test.go`.
- `internal/telemetry/{store.go,broadcaster.go}` plus new `writer.go` / `writer_test.go`: owned FIFO admission, retry, flush, shutdown and post-commit publication.
- `internal/cache/{index.go,local.go}` plus new `usage_writer.go` / `usage_writer_test.go`: row-guarded deltas, coalescing, barriers and lifecycle. Update `index_test.go` and `local_internal_test.go` where needed.
- New `internal/storage/writer_stats.go`: snapshot DTO only; no shared queue implementation. Test its behavior through writers/metrics, not mirror tests of fields.
- New `internal/metrics/async_writes.go` / `async_writes_test.go`: bounded-label collectors; existing cache stats reads must have a deadline.
- `cmd/jo-ei/{main.go,state.go,serve.go,serve_test.go}` and new `shutdown.go` / `shutdown_test.go`: constructor wiring and a shared shutdown deadline.
- `internal/gate/recorder.go`: correct the obsolete nonblocking comment without changing its signature.
- Existing telemetry/console tests and integration fixtures: explicit flushes for committed-read assertions; new `integration/async_telemetry_test.go` for combined acceptance cases.

All `go` commands below run inside the Go Docker container at `/src`. A portable launch template is:

```text
docker run --rm --mount "type=bind,source=<repository-root>,target=/src,readonly" -w /src -v joei-gomod:/go/pkg/mod -v joei-gocache:/root/.cache/go-build golang:1.26.10 go test <packages> -race -count=1
```

Resolve `<repository-root>` at execution time. For performance work, also mount the external measurement directory at `/bench`, set the stated CPU/memory limits, and copy sources into disposable `/work` when adding external benchmark helpers. Record exact invocations privately; do not put environment-specific paths in this plan.

## Task 1: Establish the Baseline and Atomic Batch Persistence

**Files:** Modify telemetry repo/sqlite code and cache index; create telemetry `batch_test.go`, cache batch cases in `index_test.go`, and storage `writer_stats.go`. Baseline artifacts are external.

**Interfaces produced:**

- `telemetry.BatchEvent{Event gate.Event; Day string}`; `Repo.RecordBatch(ctx context.Context, token string, events []BatchEvent) error`.
- Keep `Repo.RecordEvent(gate.Event) error` as a synchronous compatibility entry point, sharing transaction helpers but not replacing the async writer receipt. It is not the production Store recording path after Task 2.
- `cache.UsageDelta{RowID int64; Hits int64; LastHit int64}`; `(*Index).ApplyUsageBatch(ctx context.Context, token string, deltas []UsageDelta) error`.
- `(*Index).GetWithID(ref *gate.PackageRef) (*CacheEntry, int64, bool)`; existing `Get` delegates and discards the ID.
- `storage.WriterStats` snapshot fields: `Capacity`, `Queued`, `InFlight`, `BlockedProducers`, `UnsavedItems`, `LastBatchSize` as int64; `CommittedItems`, `Batches`, `Failures`, `Retries` as uint64; `OldestAge`, `LastSuccessAge`, `EnqueueWaitTotal`, `CommitTimeTotal`, `LastCommitDuration` as time.Duration. Values come from memory only. `CommittedItems` counts acknowledged original events/hits; batch size counts event rows/distinct usage rows. Retired cache rows are acknowledged no-ops.

- [ ] **Step 1: Verify the baseline before editing production code.** Inspect branch/status/toolchain and run `go test ./... -race -count=1` and `go test -tags integration ./integration/... -race -count=1` in Docker. Save the source revision/diff, test output and a real baseline application binary externally. A failed baseline is a finding to investigate and report, not evidence against new code.
- [ ] **Step 2: Record the before workload.** Build an external helper that seeds known-clean 8-KiB fixture artifacts through `LocalCache.Put`, closes it, then starts the real application with telemetry and Prometheus enabled. Run 60-second closed-loop HTTP cases at 1/10/50 clients for one repeated key and 256 uniformly selected distinct keys (six cases). Verify body hashes and CACHE/200 outcomes; assert zero upstream calls. Exclude seeded/warmup counts using before snapshots. Keep identical configuration, logging, timestamps, resource limits and files for the after run; app limit 8 CPU/6 GiB, generator 4 CPU/2 GiB, isolated network, no published ports/public-registry traffic. Fixed cache revalidation settings and known-clean fixtures isolate bookkeeping; security is tested separately in Task 5.
- [ ] **Step 3: Add atomic/replay tests.** `TestSQLiteRepo_RecordBatchAtomicCountersAndDays` submits a CACHE at `2026-11-06T23:59:59Z` and a BLOCK@supply at `2026-11-07T00:00:00Z`; assert 2 events, Requests=2, CacheHits=1, Blocked=1, two UTC daily rows each Requests=1. Replay the same token and assert unchanged totals. `TestSQLiteRepo_BatchReceiptSurvivesPrune` removes an old batch's event rows through existing retention, then replays its last token; counters must remain unchanged and rows must not reappear. `TestSQLiteRepo_BatchRollback` injects an INSERT trigger failure on the second event; assert zero inserted rows/deltas/receipt advancement, then remove the trigger and retry successfully. Use real SQLite; no broad production fault framework.

  ```go
  require.Len(t, events, 2)
  assert.Equal(t, uint64(2), snapshot.Requests)
  assert.Equal(t, uint64(1), snapshot.CacheHits)
  assert.Equal(t, uint64(1), snapshot.Blocked)
  require.Len(t, daily, 2)
  ```

- [ ] **Step 4: Add row-identity tests.** `TestIndex_UsageBatchReplayAndRowIdentity` adds deltas 3 and 2 to one row and verifies HitCount=5 after the relevant batch acknowledgements; replay the last token and assert 5. Delete/reinsert the same coordinates and apply the old ID's pending delta: the new row remains unchanged. `TestIndex_UsageBatchUpsertKeepsIdentity` verifies UPSERT preserves ID/count continuity and `MAX(last_hit, observed_time)` cannot move time backwards. Include two classifier variants and a failed transaction with no partial updates.
- [ ] **Step 5: Run red.** `go test ./internal/telemetry ./internal/cache -run 'RecordBatch|BatchReceipt|BatchRollback|UsageBatch' -race -count=1`. Require the new tests to expose the missing batch contract, then inspect failures for the intended cause.
- [ ] **Step 6: Implement the produced interfaces.** Append a forward-only telemetry migration and create the same small `async_write_state(component TEXT PRIMARY KEY, last_batch_token TEXT NOT NULL)` table during cache index initialization. Inside each batch transaction check the component's token first; a match is an acknowledged no-op. Otherwise apply the data and receipt atomically using Context SQL calls. Telemetry inserts every event and reads/upserts lifetime counters once and each supplied Day once. Usage changes only hit_count/last_hit by existing AUTOINCREMENT ID. No per-event receipt table or coordinate-only replay. Tokens are nonempty, unique and stable per active batch; callers may retry only the unresolved latest batch, never arbitrary older tokens after advancing.
- [ ] **Step 7: Preserve timestamp semantics.** Store-provided BatchEvent.Day is computed once from event.Time, or from a captured Record-call timestamp if Time is zero. Do not replace the original Event.Time or recompute Day on retry/flush. Legacy RecordEvent computes its fallback day at its own call, preserving current synchronous behavior.
- [ ] **Step 8: Verify and commit.** Run the full telemetry/cache package tests with race, format changed Go files and inspect the diff. Preserve the existing synchronous IncrementHit until Task 3 switches its caller. Commit as `feat: add idempotent telemetry and usage batch transactions`.

## Task 2: Add Owned Telemetry Admission, Retry and Publication

**Files:** telemetry `writer.go`, `writer_test.go`, store/hub code; `internal/gate/recorder.go`; main's Hub construction; existing telemetry/console/integration fixtures that construct a Hub or require immediate committed data.

**Consumes:** Task 1 BatchEvent, RecordBatch and WriterStats.

**Interfaces produced:**

- Preserve `(*Store).Record(gate.Event)`, `New`, `Open` and existing read signatures.
- Add `(*Store).RequestFlush()`, `Flush(ctx context.Context) error`, `Shutdown(ctx context.Context) error`, `WriterStats() storage.WriterStats`.
- `func NewHub(store *Store, b *Broadcaster) *Hub` binds post-commit publication before traffic; Hub.Record delegates to Store.Record. Replace all literal Hub constructions.
- Private `writerOptions{QueueCapacity int; BatchSize int; FlushInterval time.Duration; RetryInterval time.Duration}` and `newWithWriterOptions(repo Repo, logger zerolog.Logger, opts writerOptions) *Store` permit small deterministic internal tests; production New uses the approved defaults, without new public tuning options.

- [ ] **Step 1: Write behavioral tests first.** `TestWriter_RecordDoesNotWaitForCommit` blocks a real/fake batch sink and verifies a Record fitting the queue returns before commit. `TestWriter_FullQueueBlocksWithoutLoss` uses capacity2/batch1: hold 1 event in flight, enqueue 2, then assert the fourth producer is blocked and `BlockedProducers==1`; releasing the sink and Flush must persist all 4. Cancel a caller's request context while its producer waits and verify the event is still admitted/committed. Use channel handshakes; timeouts are hang guards, not sleeps proving ordering.

  ```go
  assert.Equal(t, int64(2), stats.Queued)
  assert.Equal(t, int64(1), stats.InFlight)
  assert.Equal(t, int64(1), stats.BlockedProducers)
  // After releasing the sink and flushing:
  require.Len(t, persisted, 4)
  ```

- [ ] **Step 2: Pin ownership, day and publication.** `TestWriter_OwnsNestedEventData` mutates BlockedBy, CVEs and each finding's Aliases after Record returns; the persisted event retains original values under race instrumentation. `TestWriter_DayFixedBeforeFlush` covers midnight and zero-Time enqueue/retry with the Day rule from Task 1. `TestHub_PublishesOnlyAfterCommit` asserts no SSE event while commit is held, then one event after confirmed commit and visible SQLite history; FIFO follows admission order.
- [ ] **Step 3: Pin retry/barrier semantics.** A narrow Repo decorator commits through the real RecordBatch, then returns an acknowledgement error once. `TestWriter_AmbiguousCommitRetriesSameToken` must produce one stored event and one set of deltas, one SSE publication and a recorded retry. Test a pre-commit failure, timer-triggered flush, an explicit Flush, and concurrent producers advancing past a captured flush watermark.
- [ ] **Step 4: Run red.** `go test ./internal/telemetry -run 'Writer|Hub_' -race -count=1`; inspect the missing asynchronous behavior before implementing it.
- [ ] **Step 5: Implement the writer and Hub.** Reserve bounded queue capacity before allocating an owned event copy. Capture the zero-time fallback day at Record entry, copy nested slices, enqueue, then return. Keep one writer and immutable in-flight batch/token; retry it before advancing. Flush forces all admissions up to its captured watermark and waits through confirmed commit/publication; cancellation stops only the wait, never consumes queued work. Snapshot statistics include queued/in-flight work and blocked producers. Never hold a DB connection or producer lock while awaiting capacity. Public reads query committed data and never trigger an implicit Flush.
- [ ] **Step 6: Add bounded shutdown.** Shutdown stops new admission after producer drain, flushes promptly, and on context expiry cancels writer SQL, reports unsaved plus blocked counts, releases waiters and joins its worker. Record attempts racing with a forced stop must be reported, not silently claimed persisted. Close remains idempotent and delegates with a bounded default when no application shutdown has run. Implement writer-local lifecycle now; the shared app deadline arrives in Task 4.
- [ ] **Step 7: Adapt affected consumers/tests surgically.** Replace Hub literals in `cmd/jo-ei/main.go`, telemetry broadcaster tests, `internal/console/server_test.go`, `integration/console_test.go`, and `integration/console_auth_test.go` with NewHub. Add explicit `require.NoError(t, store.Flush(ctx))` in tests before assertions that require committed history/counters; update write-failure doubles to implement RecordBatch. In failure/logging tests use a short Shutdown context and join the writer before reading log buffers, rather than waiting for the default drain or racing a background write. Healthy Close still establishes restart durability in `integration/telemetry_persistence_test.go`. Correct the gate.Recorder comment to acknowledge bounded-capacity waiting without permission changes. Update source comments describing recording as immediately durable.
- [ ] **Step 8: Verify and commit.** Run `go test ./internal/telemetry ./internal/console ./cmd/jo-ei -race -count=1` and affected tagged console/telemetry integration tests. Require no send-on-closed-channel, duplicate SSE, failed immediate-read assumptions or race reports. Commit as `feat: batch telemetry with bounded backpressure`.

## Task 3: Coalesce Cache Usage and Protect Cleanup

**Files:** cache `usage_writer.go`, `usage_writer_test.go`, local/index code and related tests; define the optional capability in `cache.go`.

**Consumes:** UsageDelta, GetWithID, ApplyUsageBatch and WriterStats from Task 1.

**Interfaces produced:**

- `(*LocalCache).RequestUsageFlush()`, `FlushUsage(ctx context.Context) error`, `Shutdown(ctx context.Context) error`, `UsageWriterStats() storage.WriterStats`.
- `cache.UsageBatcher` contains those four methods. Keep the existing Cache and gate.ArtifactCache method sets unchanged; application wiring may type-assert this capability.
- Private `usageWriterOptions{PendingCapacity int; BatchSize int; FlushInterval time.Duration; RetryInterval time.Duration}` and `newUsageWriter(apply func(context.Context, string, []UsageDelta) error, opts usageWriterOptions) *usageWriter`.
- `(*usageWriter).record(rowID int64, at time.Time)`, `requestFlush()`, `flush(ctx context.Context) error`, `shutdown(ctx context.Context) error`, `stats() storage.WriterStats`.

- [ ] **Step 1: Write coalescing/pressure tests.** `TestUsageWriter_CoalescesHits` admits 100 hits for one row, flushes, and verifies one row delta with Hits=100 and maximum observed time. `TestUsageWriter_DistinctKeyBackpressure` uses two pending-key slots plus a held active batch; a new key blocks, while hits on an existing pending key continue coalescing. Release and verify every hit accounted once, bounded pending keys and no worker-per-hit behavior.

  ```go
  require.Len(t, deltas, 1)
  assert.Equal(t, int64(100), deltas[0].Hits)
  assert.Equal(t, latestHit.Unix(), deltas[0].LastHit)
  ```

- [ ] **Step 2: Write retry/watermark tests.** Cover a same-row hit arriving while its previous delta is in flight, pre-commit failures and commit-then-error retry. Assert the immutable active delta/token is reused and new hits become a subsequent delta. A flush watermark covers all earlier admitted hits without requiring an ongoing stream of later hits to stop.
- [ ] **Step 3: Write cleanup integration tests in the cache package.** `TestLocalCache_PurgeFlushesPendingHits` makes an entry stale in SQLite, records a current pending hit and verifies PurgeStale preserves it after flushing. Add LRU selection and newer-hit-time cases. `TestLocalCache_CleanupAbortsOnFlushFailure` requires no destructive selection/deletion when the barrier fails or its context is cancelled; admitted deltas remain. Pin Get→delete→reinsert isolation, classifier keys and UPSERT identity against real Index transactions from Task 1.
- [ ] **Step 4: Run red.** `go test ./internal/cache -run 'UsageWriter|PurgeFlushes|CleanupAborts|UsageBatch' -race -count=1`; inspect the expected missing behavior.
- [ ] **Step 5: Implement usage admission and barriers.** LocalCache.Get obtains the existing ID and entry from GetWithID, performs the current file check, then records usage instead of calling IncrementHit. Coalesce by ID with one immutable in-flight batch, retry receipt protection and a service-owned admission wait. On forced shutdown, report rejected usage without changing the already-read ScanClean/security fields. FlushUsage fences earlier admissions; invoke it before each destructive LRU/stale candidate-selection round, outside locks/connections. Abort that cleanup attempt on barrier error. Remove the now-orphaned IncrementHit and replace its old direct tests with the batch tests covering the same behavior.
- [ ] **Step 6: Bound read-only statistics and lifecycle.** Keep Stats reads independent of flush barriers and bound the whole read with a shared one-second context. Change Index.Count to `Count(ctx context.Context)` and StaleSizeBytes to `StaleSizeBytes(ctx context.Context, cutoff int64)`; update their direct callers/tests. Queue metrics never query SQLite. Stop eviction, resolve/abort usage admissions and writer work, then close the index; Close is idempotent and bounded. Do not enqueue or defer Insert/Delete/MarkCVEChecked/MarkMalwareChecked.
- [ ] **Step 7: Verify and commit.** Run `go test ./internal/cache ./internal/proxy ./internal/proxy/dockerproxy -race -count=1`, covering healthy and failed shutdown, row-ID replay and cleanup cancellation. Commit as `perf: coalesce cache-hit usage writes`.

## Task 4: Expose Pressure and Coordinate One Shutdown Budget

**Files:** metrics async writer collector/tests; `cmd/jo-ei/shutdown.go`, shutdown/serve tests, main/state wiring. Existing app closer ordering remains the final fallback.

**Consumes:** Task 2 Store control/snapshots; Task 3 UsageBatcher; Task 1 WriterStats.

**Interfaces produced:**

- `(*metrics.Metrics).RegisterAsyncWriter(component string, snapshot func() storage.WriterStats)` accepts only `telemetry` and `cache_usage`; nil metrics is a no-op. Callback snapshots never perform SQL or flush.
- Private `shutdownGroup` in `cmd/jo-ei/shutdown.go`; `newShutdownGroup(budget time.Duration, requestFlush func()) *shutdownGroup`, `(*shutdownGroup).Begin() context.Context` creates one deadline once and issues nonblocking flush requests; `(*shutdownGroup).Close()` releases its timer.
- Private server signatures become `serveListener(ctx context.Context, srv *http.Server, ln net.Listener, drain time.Duration, log zerolog.Logger, group *shutdownGroup) error`, `serveWith(ctx context.Context, srv *http.Server, drain time.Duration, log zerolog.Logger, run func() error, group *shutdownGroup) error`, and `serveAll(ctx context.Context, group *shutdownGroup, servers ...boundServer) error`. Update existing callers/tests. A nil group creates a local bounded drain for standalone tests; production uses one shared group, closed by its creator rather than individual listeners.
- `(*state).requestWriterFlush()` and `(*state).shutdownWriters(ctx context.Context, logger zerolog.Logger) error`; the latter stops both components concurrently under the same deadline and logs failed-drain statistics before generic closers run.

- [ ] **Step 1: Write metrics tests.** `TestAsyncWriterMetrics_LabelsAndValues` checks occupancy/capacity/in-flight/blocked/unsaved gauges, oldest and last-success ages, committed-items/batches/failures/retries totals, cumulative enqueue-wait/commit seconds and last batch size/duration. All series use only component labels; avoid package/request-ID cardinality. `TestAsyncWriterMetrics_ObservableWithFailedStorage` holds the DB connection and a failed in-flight batch; Gathering must still finish within the bounded cache-stat read deadline and return pressure/error series. Verify collector callbacks are concurrent-safe and never flush.
- [ ] **Step 2: Write coordinated-drain tests.** `TestShutdown_HealthyDrainsBothWriters` queues both kinds of work, begins shutdown before a normal timer, and asserts they commit before their databases close. `TestShutdown_OneDeadlineForHTTPAndWriters` supplies a short test budget, blocks HTTP and DB writes, and verifies elapsed shutdown is one budget plus bounded scheduling/cleanup overhead, not three budgets. Check explicit unsuccessful-drain logs and exact queued/in-flight/blocked counts, and prove every blocked producer returns after forced stop.

  ```go
  assert.Equal(t, primaryHTTPDeadline, telemetryDeadline)
  assert.Equal(t, primaryHTTPDeadline, cacheUsageDeadline)
  require.ErrorIs(t, drainErr, context.DeadlineExceeded)
  ```

  Capture actual contexts received by the blocked components; equal deadlines prove the shared budget without relying on a tight wall-clock scheduling assertion. A generous timeout guards joining all test goroutines.

- [ ] **Step 3: Cover startup and failure paths.** Preserve current listener-bind/first-server-failure tests with the new group. Inject failure after Store/cache initialization but before serving; no workers or resources may leak. Repeated shutdown/Close calls remain safe. Shutdown caused by either parent cancellation or a server error must use the same sequence/deadline. Use `enableLogs(t)` in cmd tests that assert logs.
- [ ] **Step 4: Run red.** `go test ./internal/metrics ./cmd/jo-ei -run 'AsyncWriter|Shutdown|Serve|App_' -race -count=1`; inspect missing metrics/lifecycle behavior.
- [ ] **Step 5: Implement metrics wiring.** Register Store.WriterStats and optional UsageBatcher.UsageWriterStats after state construction. Export bounded component series named `jo_ei_async_write_*`: capacity, queue_depth, inflight_items, blocked_producers, unsaved_items, oldest_age_seconds, last_success_age_seconds, committed_items_total, batches_total, failures_total, retries_total, enqueue_wait_seconds_total, commit_seconds_total, last_batch_size and last_commit_seconds. Age is computed at snapshot time; before the first successful commit, last-success age is time since writer start. Document item units: events for telemetry, original hit deltas for committed/unsaved usage and distinct rows for usage queue/batch size.
- [ ] **Step 6: Implement shared shutdown.** main creates the group from the configured primary drain budget and passes it into serveAll. On cancellation/server termination, Begin fixes the shared deadline and requests both flushes. Each HTTP Shutdown uses the earlier of its existing server-specific drain and that deadline; preserve forced socket close on timeout and immediate SSE closure. After HTTP producers drain or their deadline expires, shut down both writers under the remaining shared context, join them, log unsaved/blocked work on error, then allow app.close to release DBs/logging. Generic Close must not create a second wait after explicit shutdown. SQL cancellation and producer-abort signals must make expired-context shutdown finite. Return/report drain errors; do not let app.close's error-dropping loop hide them.
- [ ] **Step 7: Verify and commit.** Run full affected package tests with race and tagged telemetry/console integration tests; require readable metrics during failure and no goroutine leak/deadlock. Commit as `feat: observe batch writers and coordinate shutdown`.

## Task 5: Prove Enforcement and Audit Behavior End to End

**Files:** New `integration/async_telemetry_test.go`; targeted additions to existing proxy/cache/Docker tests and persistence fixtures where private fault seams are needed. No new product feature in this task.

**Consumes:** The integrated writers/flush/lifecycle contracts from Tasks 1-4. Produces regression evidence that accounting faults cannot grant access.

- [ ] **Step 1: Add `TestAsyncTelemetry_RejectedArtifactNeverServed`.** Run ordinary artifact requests with independent supply-chain, CVE, AV-error and infected outcomes while telemetry persistence is held/failed. Use component fault tests for tiny-buffer saturation; for the integrated path use the real production buffer. Once a blocked audit admission is released, expect the same blocking status/body as baseline, zero bytes of the denied artifact, and no clean cache publication. Cancel the waiting client and later flush: its produced rejection event must remain in history. A lost/failed event must never create a clean verdict.

  ```go
  // CVE-block subtest; supply-chain and scanner-error cases use their own statuses.
  assert.Equal(t, http.StatusForbidden, response.StatusCode)
  assert.Zero(t, servedArtifactBytes)
  assert.False(t, cleanVerdict)
  ```

- [ ] **Step 2: Add `TestAsyncTelemetry_DockerVerdictsRemainSynchronous`.** Hold telemetry writes while Docker scanning is incomplete or returns a block; assert no allowed manifest/blob verdict is published through the telemetry path. Exercise the real Docker verdict store with existing scanner test doubles. Separate known R01-R13 behavior from regressions; do not broaden this task to fix unrelated findings.
- [ ] **Step 3: Add restart/crash coverage.** Extend `TestTelemetryPersistsAcrossRestart` to exercise healthy draining of pending telemetry/usage. Add `TestAsyncTelemetry_CrashTailDoesNotAuthorizeArtifact` using a controlled child of the Docker test binary: signal readiness, leave work uncommitted, terminate the child without Close, reopen its files and verify persisted accounting remains consistent and an unchecked temporary file has no clean index/verdict. A subsequent request must execute the required checks; accepted tail loss is not an authorization record. Use handshakes, not sleep-to-crash timing.
- [ ] **Step 4: Add console consistency checks.** Before an explicit healthy flush, committed views may lag. After flush, history/counters/day totals and post-commit SSE agree. Verify queue pressure still appears in Prometheus while SQLite writes fail; fill/release flows retain all admitted audit events, including BLOCK/ERROR events.
- [ ] **Step 5: Run and address failures.** `go test -tags integration ./integration/... -race -count=1` plus relevant proxy/Docker/cache package tests. New tests should expose any missing integration; if they already pass, keep them as security regression coverage and do not manufacture functional changes. Any real fix gets its own observed red→green test. Commit as `test: verify batched accounting preserves enforcement`.

## Task 6: Measure Sustainable Gains and Finish Verification

**Files:** External measurement harness/results/profiles/report; focused source comments/docs describing async visibility; this plan's checkboxes and Codex task records. No measurement artifacts in the checkout.

**Consumes:** Task 1 before artifacts and Tasks 2-5 completed behavior. Produces the performance acceptance result and branch-review handoff.

- [ ] **Step 1: Run fresh full checks.** In Docker run `go test ./... -race -count=1`, `go test -tags integration ./integration/... -race -count=1`, and `go build ./...`. Run gofmt on changed files, `golangci-lint run --timeout 5m` and `git diff --check`. Require exit0/no formatting findings. Console source is unchanged, so do not hand-edit its generated bundle. Record all failures by name.
- [ ] **Step 2: Repeat Task 1's six cases.** Build the real after binary, restore equivalent seeded state and run the exact same fixture/configuration/resource/concurrency/duration matrix, without race instrumentation. Repeat before/after cases if noise obscures the result. Capture sustainable rps, latency percentiles, CPU/request, allocations, DB connection waits, operations/commits, queue age/depth/unsaved work, RSS and final flush time. Include cold/slow-scanner control cases to identify workloads with little benefit; avoid public upstream load.
- [ ] **Step 3: Reconcile every request.** After the load stops, drain HTTP and both writers, then read persisted files/counters and compare event/request IDs, cache-hit totals and per-day counts with successful measured requests after subtracting warmup. Include persistence drain in elapsed throughput and CPU accounting. Fail the measurement if backlog grows without recovery, final unsaved work is nonzero, audit/counts disagree or non-200/cache-hit behavior appears in the warm-cache matrix. Validate oldest committed visibility within30 seconds in healthy cases; pressure/outage cases must be identified separately.
- [ ] **Step 4: Profile both bookkeeping components.** Preserve CPU/allocation profiles and transaction/connection-wait evidence for matching repeated-key and many-key cases. Report total memory and variable event sizes, not only queue slot counts. Show whether commits/aggregated SQL work actually fell; separate queue admission speed from persistence capacity. Run any code-level benchmarks three times per variant and keep raw samples.
- [ ] **Step 5: Write the external acceptance report.** Include exact revisions, toolchain, fixture hashes, resource limits, commands, per-case before/after numbers, counts after drain, visibility age, shutdown/fault results and adverse cases. Require repeatably lower write/transaction cost and useful sustainable throughput or latency improvement, unchanged enforcement and acceptable measured memory. There is no agreed numeric speedup target. If the criteria are not met, record that rather than declaring success from faster enqueueing.
- [ ] **Step 6: Update current-behavior documentation and task status.** Describe batching/visibility, full-queue backpressure, failure observability and the approved finite forced-stop exception. Preserve historical benchmark statements as historical. Update Codex telemetry-batching.md/MEMORY.md/roadmap status with evidence, not predictions; record any remaining uncertainty. Commit relevant repository documentation as `docs: document batched accounting behavior and validation`.
- [ ] **Step 7: Prepare final review.** Inspect the entire branch against the approved spec, attach the five Review Focus classes and execution rulings, and follow the selected execution workflow's fresh whole-branch review gate. Resolve important findings with regression tests before handoff. Only verified steps become checked. PR publishing/merging requires its own user instruction.

## Plan Self-Review

Checked against the approved spec, current Repo/Store/Cache/Hub interfaces, SQLite schema and row IDs, metrics collector behavior, server/closer lifecycle, gate.Recorder's obsolete comment, existing console/persistence tests and CI commands. Each Review Focus class has explicit owning tests. Shared data types/method names above are the contracts between tasks; existing gate/cache interfaces remain unchanged. This document specifies future execution and makes no claim that implementation, fault tests or new measurements have already run.

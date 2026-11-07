# Asynchronous Telemetry and Cache-Usage Batching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce synchronous SQLite work per cached-artifact request with best-effort, nonblocking observation admission and unchanged enforcement decisions.

**Architecture:** Implement two component-owned writers: FIFO telemetry batches with atomic event/counter/day persistence, and cache-usage deltas coalesced by existing cache row ID. A stable batch token and one receipt per component make retries idempotent. Flush barriers protect destructive cache selection; a shared shutdown deadline drains or explicitly aborts both writers.

**Tech Stack:** Go 1.26.10 as currently specified by go.mod, database/sql, existing modernc SQLite and Prometheus dependencies, standard synchronization/context primitives, existing testify tests, Docker.

**Spec:** [Design](../specs/2026-11-07-async-telemetry-batching-design.md). The owner approved the full scope/forced-stop behavior and subsequently replaced blocking overflow with drop-on-full admission on 2026-11-07. This revised plan follows that latest instruction.

## Global Constraints

- Work on `perf/async-telemetry-batching`, based on `0b5e669`; publish through a PR into main.
- Preserve every admitted telemetry event. Aggregate counter deltas, not admitted audit history.
- Losing unflushed observations on process crash is accepted. Full/closed buffers drop and count incoming observations without waiting; keep previously admitted work. This applies to telemetry and cache usage, including PASS/CACHE/BLOCK/ERROR events.
- Observation admission must not wait for capacity, SQL, a flush, retry or synchronous logging. No synchronous persistence fallback, producer-spawned goroutine or eviction of an older queued event. Required verification/cache operations keep their existing behavior.
- Normal console visibility delay must remain within 30 seconds. This is not a timeout for discarding work.
- Defaults: telemetry queue 1024 events / batch 128; usage pending 4096 distinct row IDs / batch 256; both flush after 10 seconds or earlier on size/overflow signals. Retry failed admitted batches after one second without holding admission locks. Limits count items, not payload bytes or total HTTP memory.
- Keep policy, scanners, artifact publication, clean/block verdicts, security check timestamps and invalidation on their current enforcement path. Do not change R01-R13, REL-01 or SQLite synchronous settings.
- Healthy shutdown flushes admitted work. At the configured shared shutdown deadline (default 30 seconds), explicitly report an unsuccessful drain/unsaved work and stop workers; never claim a clean flush after timeout. New observations while closing are counted rejections, not waits.
- Single application instance per database/cache directory. No broker, durable outbox, new dependencies, new public tuning options or general batching framework.
- Every Go test/build/benchmark runs in Docker with the go.mod toolchain and `joei-gomod`/`joei-gocache`. Correctness tests use `-race`; performance measurements omit it. Local gofmt and golangci-lint are allowed.
- Store harnesses, measurement fixtures, before/after results, profiles and reports in a new external Codex measurement directory; preserve previous experiments. Documentation contains no personal host paths or host-shell assumptions.

## Review Focus

1. An acknowledged-on-disk batch whose COMMIT response fails must be retried without duplicate events or counters, even after pruning (Task 1/2).
2. Full buffers, client cancellation and shutdown racing with admission must not make package handlers wait; reject/count excess items while keeping admitted work and avoiding deadlock (Task 2/4/5).
3. Midnight, zero event time, caller-owned nested slices and SSE/read ordering must not corrupt historical data (Task 1/2).
4. Deletion/reinsertion, UPSERT and an in-flight usage batch must not update another cache row; maintenance barriers cover accepted hits, while dropped hits may leave eviction hints stale (Task 1/3).
5. Storage failure must leave loss/pressure observable, requests independent of writer recovery and shutdown bounded, without making an unchecked/blocked artifact servable (Task 4/5).

## File Map and Verification Commands

- `internal/telemetry/{repo.go,sqlite.go,aggregate.go}`: atomic batch persistence; add `batch_test.go`.
- `internal/telemetry/{store.go,broadcaster.go}` plus new `writer.go` / `writer_test.go`: owned FIFO admission, retry, flush, shutdown and post-commit publication.
- `internal/cache/{index.go,local.go}` plus new `usage_writer.go` / `usage_writer_test.go`: row-guarded deltas, coalescing, barriers and lifecycle. Update `index_test.go` and `local_internal_test.go` where needed.
- New `internal/storage/writer_stats.go`: snapshot DTO only; no shared queue implementation. Test its behavior through writers/metrics, not mirror tests of fields.
- New `internal/metrics/async_writes.go` / `async_writes_test.go`: bounded-label collectors; existing cache stats reads must have a deadline.
- `cmd/jo-ei/{main.go,state.go,serve.go,serve_test.go}` and new `shutdown.go` / `shutdown_test.go`: constructor wiring and a shared shutdown deadline.
- `internal/gate/recorder.go`: document best-effort admission and counted drops consistently with the nonblocking contract, without changing its signature.
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
- `storage.WriterStats` snapshot fields: `Capacity`, `Queued`, `InFlight`, `UnsavedItems`, `LastBatchSize` as int64; `AttemptedItems`, `AcceptedItems`, `DroppedFullItems`, `DroppedClosedItems`, `AbandonedItems`, `CommittedItems`, `Batches`, `Failures`, `Retries` as uint64; `OldestAge`, `LastSuccessAge`, `CommitTimeTotal`, `LastCommitDuration` as time.Duration. Values come from memory only. `CommittedItems` counts acknowledged admitted events/hits; batch size counts event rows/distinct usage rows. Retired cache rows are acknowledged no-ops. Unsaved excludes rejected work; Abandoned counts admitted work lost at a forced stop.

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

- [ ] **Step 1: Write behavioral tests first.** `TestWriter_RecordDoesNotWaitForCommit` holds the batch sink and verifies an admitted Record returns before commit. `TestWriter_FullQueueDropsIncomingWithoutWaiting` uses capacity2/batch1: hold 1 event in flight, enqueue 2, then require a fourth Record to return while the sink remains held. It increments DroppedFullItems and is not persisted or published; releasing/Flush persists the 3 accepted events in order. Repeat for PASS/CACHE/BLOCK/ERROR and assert no priority-specific wait. A cancelled caller cannot remove an already admitted event. Use channel handshakes; timeouts only guard hangs. Detect any producer-side SQL, synchronous log call, copy of a rejected payload or fallback goroutine.

  ```go
  assert.Equal(t, int64(2), stats.Queued)
  assert.Equal(t, int64(1), stats.InFlight)
  assert.Equal(t, uint64(1), stats.DroppedFullItems)
  // After releasing the sink and flushing:
  require.Len(t, persisted, 3)
  ```

- [ ] **Step 2: Pin ownership, day and publication.** `TestWriter_OwnsNestedEventData` mutates BlockedBy, CVEs and each finding's Aliases after Record returns; the persisted event retains original values under race instrumentation. `TestWriter_DayFixedBeforeFlush` covers midnight and zero-Time enqueue/retry with the Day rule from Task 1. `TestHub_PublishesOnlyAfterCommit` asserts no SSE event while commit is held, then one event after confirmed commit and visible SQLite history; FIFO follows admission order.
- [ ] **Step 3: Pin retry/barrier semantics.** A narrow Repo decorator commits through the real RecordBatch, then returns an acknowledgement error once. `TestWriter_AmbiguousCommitRetriesSameToken` must produce one stored event and one set of deltas, one SSE publication and a recorded retry. Test a pre-commit failure, timer-triggered flush, an explicit Flush, and concurrent producers advancing past a captured flush watermark.
- [ ] **Step 4: Run red.** `go test ./internal/telemetry -run 'Writer|Hub_' -race -count=1`; inspect the missing asynchronous behavior before implementing it.
- [ ] **Step 5: Implement the writer and Hub.** Try to reserve bounded queue capacity without waiting before allocating an owned copy. On full/closed admission increment the appropriate loss counter, optionally signal the writer without waiting, and return. On success capture the stable fallback day, copy nested slices, enqueue and return. Keep one writer and immutable in-flight batch/token; retry admitted work before advancing, without an admission lock across I/O. Flush fences accepted admissions only and waits through confirmed commit/publication; cancellation stops only that maintenance/test wait. Snapshots expose attempted/accepted/committed/dropped/unsaved work. Public reads query committed data and never flush. No SQL, flush, blocking logger or worker completion is awaited in Record.
- [ ] **Step 6: Add bounded shutdown.** Shutdown stops new admission, flushes accepted work promptly and, on expiry, cancels writer SQL, counts abandoned work and joins its worker. Record racing with close returns immediately and increments DroppedClosedItems; it never waits for shutdown. Close remains idempotent and delegates with a bounded default when no application shutdown has run. Implement writer-local lifecycle now; the shared app deadline arrives in Task 4.
- [ ] **Step 7: Adapt affected consumers/tests surgically.** Replace Hub literals in `cmd/jo-ei/main.go`, telemetry broadcaster tests, `internal/console/server_test.go`, `integration/console_test.go`, and `integration/console_auth_test.go` with NewHub. Add explicit `require.NoError(t, store.Flush(ctx))` before assertions that require committed history/counters; update write-failure doubles to implement RecordBatch. In failure/logging tests use a short Shutdown context and join the writer before reading log buffers. Drop paths update memory counters only; optional aggregate warnings run in the background. Healthy Close establishes restart durability in `integration/telemetry_persistence_test.go`. Document counted drop-on-full/closed behavior in gate.Recorder; preserve its nonblocking admission requirement and signature. Update comments describing recording as immediately durable or lossless.
- [ ] **Step 8: Verify and commit.** Run `go test ./internal/telemetry ./internal/console ./cmd/jo-ei -race -count=1` and affected tagged console/telemetry integration tests. Require no full/closed-queue wait, send-on-closed-channel, duplicate SSE or race reports. Commit as `feat: batch telemetry with nonblocking overflow`.

## Task 3: Coalesce Cache Usage and Protect Cleanup

**Files:** cache `usage_writer.go`, `usage_writer_test.go`, local/index code and related tests; define the optional capability in `cache.go`.

**Consumes:** UsageDelta, GetWithID, ApplyUsageBatch and WriterStats from Task 1.

**Interfaces produced:**

- `(*LocalCache).RequestUsageFlush()`, `FlushUsage(ctx context.Context) error`, `Shutdown(ctx context.Context) error`, `UsageWriterStats() storage.WriterStats`.
- `cache.UsageBatcher` contains those four methods. Keep the existing Cache and gate.ArtifactCache method sets unchanged; application wiring may type-assert this capability.
- Private `usageWriterOptions{PendingCapacity int; BatchSize int; FlushInterval time.Duration; RetryInterval time.Duration}` and `newUsageWriter(apply func(context.Context, string, []UsageDelta) error, opts usageWriterOptions) *usageWriter`.
- `(*usageWriter).record(rowID int64, at time.Time)`, `requestFlush()`, `flush(ctx context.Context) error`, `shutdown(ctx context.Context) error`, `stats() storage.WriterStats`.

- [ ] **Step 1: Write coalescing/pressure tests.** `TestUsageWriter_CoalescesHits` admits 100 hits for one row, flushes and verifies one row delta with Hits=100 and maximum observed time. `TestUsageWriter_FullMapDropsNewKeyWithoutWaiting` uses two pending-key slots plus a held active batch: a new row's incoming hit is counted/dropped and returns while the sink stays held; an existing pending row continues coalescing. Verify admitted hits exactly once, rejected hits absent, bounded pending keys and no synchronous UPDATE/flush/log or worker-per-hit fallback. A real LocalCache.Get must still return its unchanged entry/ScanClean while usage admission is saturated.

  ```go
  require.Len(t, deltas, 1)
  assert.Equal(t, int64(100), deltas[0].Hits)
  assert.Equal(t, latestHit.Unix(), deltas[0].LastHit)
  ```

- [ ] **Step 2: Write retry/watermark tests.** Cover a same-row hit arriving while its previous delta is in flight, pre-commit failures and commit-then-error retry. Assert the immutable active delta/token is reused and new hits become a subsequent delta. A flush watermark covers all earlier admitted hits without requiring an ongoing stream of later hits to stop.
- [ ] **Step 3: Write cleanup integration tests in the cache package.** `TestLocalCache_PurgeFlushesPendingHits` makes an entry stale in SQLite, records a current pending hit and verifies PurgeStale preserves it after flushing. Add LRU selection and newer-hit-time cases. `TestLocalCache_CleanupAbortsOnFlushFailure` requires no destructive selection/deletion when the barrier fails or its context is cancelled; admitted deltas remain. Pin Get→delete→reinsert isolation, classifier keys and UPSERT identity against real Index transactions from Task 1.
- [ ] **Step 4: Run red.** `go test ./internal/cache -run 'UsageWriter|PurgeFlushes|CleanupAborts|UsageBatch' -race -count=1`; inspect the expected missing behavior.
- [ ] **Step 5: Implement usage admission and maintenance barriers.** LocalCache.Get obtains the existing ID/entry, performs the current file check and attempts usage admission instead of IncrementHit. Coalesce existing pending IDs; when a new ID cannot fit, drop/count only that incoming hit and return the unchanged cache entry. Closed admission also returns/counts immediately. Keep one immutable in-flight batch and idempotent retry. FlushUsage fences accepted hits only, before destructive LRU/stale selection outside the package path; abort that cleanup attempt on error. Never call FlushUsage from Get, Put or verification. Dropped usage can reduce eviction accuracy; it must not change security fields. Remove the orphaned IncrementHit and replace its direct tests with batch coverage.
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

- [ ] **Step 1: Write metrics tests.** `TestAsyncWriterMetrics_LabelsAndValues` checks occupancy/capacity/in-flight/unsaved gauges, oldest/last-success ages, attempted/accepted/committed items, drops by full/closed reason, abandoned items, batches/failures/retries, commit seconds and last batch size/duration. Labels are only component and the bounded drop reason; never package/request ID. `TestAsyncWriterMetrics_ObservableWithFailedStorage` holds the DB connection and a failed batch; Gathering must finish within the cache-stat read deadline and return loss/pressure/error series. Verify collectors never flush or write telemetry themselves, including during drop storms.
- [ ] **Step 2: Write coordinated-drain tests.** `TestShutdown_HealthyDrainsBothWriters` queues both kinds of work, begins shutdown before a normal timer and asserts admitted work commits before DB close. `TestShutdown_OneDeadlineForHTTPAndWriters` blocks HTTP and DB work under a short budget and verifies one shared deadline. Check unsuccessful-drain logs and queued/in-flight/abandoned counts. Concurrent Record/Get usage calls while closing must return immediately and increment the closed-loss count, never wait for a worker or SQL.

  ```go
  assert.Equal(t, primaryHTTPDeadline, telemetryDeadline)
  assert.Equal(t, primaryHTTPDeadline, cacheUsageDeadline)
  require.ErrorIs(t, drainErr, context.DeadlineExceeded)
  ```

  Capture actual contexts received by the blocked components; equal deadlines prove the shared budget without relying on a tight wall-clock scheduling assertion. A generous timeout guards joining all test goroutines.

- [ ] **Step 3: Cover startup and failure paths.** Preserve current listener-bind/first-server-failure tests with the new group. Inject failure after Store/cache initialization but before serving; no workers or resources may leak. Repeated shutdown/Close calls remain safe. Shutdown caused by either parent cancellation or a server error must use the same sequence/deadline. Use `enableLogs(t)` in cmd tests that assert logs.
- [ ] **Step 4: Run red.** `go test ./internal/metrics ./cmd/jo-ei -run 'AsyncWriter|Shutdown|Serve|App_' -race -count=1`; inspect missing metrics/lifecycle behavior.
- [ ] **Step 5: Implement metrics wiring.** Register Store.WriterStats and optional UsageBatcher.UsageWriterStats. Export `jo_ei_async_write_*`: capacity, queue_depth, inflight_items, unsaved_items, oldest_age_seconds, last_success_age_seconds, attempted_items_total, accepted_items_total, committed_items_total, dropped_items_total with reason `queue_full`/`closed`, abandoned_items_total, batches_total, failures_total, retries_total, commit_seconds_total, last_batch_size and last_commit_seconds. Other series have only the bounded component label. Age is computed at snapshot time; before first success it is time since writer start. Document events versus original hit-delta units and distinct usage row occupancy. No per-drop synchronous warning; any rate-limited summary runs off the request path.
- [ ] **Step 6: Implement shared shutdown.** main creates the group from the configured primary budget and passes it into serveAll. Begin fixes the deadline and requests both flushes. Each HTTP Shutdown uses the earlier existing server-specific drain or shared deadline; preserve forced socket close and immediate SSE closure. After HTTP handlers drain or their deadline expires, close observation admission and shut down both writers under the remaining context. New observations are counted/dropped immediately while admitted work drains. Join workers, log admitted-unsaved/abandoned work on error, then let app.close release DBs/logging. No second default wait after explicit shutdown; SQL cancellation makes expiry finite. Return/report drain errors before the generic closer loop can hide them.
- [ ] **Step 7: Verify and commit.** Run full affected package tests with race and tagged telemetry/console integration tests; require readable metrics during failure and no goroutine leak/deadlock. Commit as `feat: observe batch writers and coordinate shutdown`.

## Task 5: Prove Enforcement and Audit Behavior End to End

**Files:** New `integration/async_telemetry_test.go`; targeted additions to existing proxy/cache/Docker tests and persistence fixtures where private fault seams are needed. No new product feature in this task.

**Consumes:** The integrated writers/flush/lifecycle contracts from Tasks 1-4. Produces regression evidence that accounting faults cannot grant access.

- [ ] **Step 1: Add `TestAsyncTelemetry_OverflowDoesNotWaitOrChangeEnforcement`.** Hold the telemetry writer, fill its production buffer and keep it held throughout HTTP assertions. Allowed warm-cache requests must still complete correctly; independently verify supply-chain/CVE/AV-error/infected outcomes return their original blocking status/body, zero denied artifact bytes and no clean publication. Excess events are dropped/counted, including BLOCK/ERROR, without waiting for the sink. A separate cancelled-client case verifies already admitted work persists later; a dropped event must remain absent from committed history/SSE and must not change permission.

  ```go
  // CVE-block subtest; supply-chain and scanner-error cases use their own statuses.
  assert.Equal(t, http.StatusForbidden, response.StatusCode)
  assert.Zero(t, servedArtifactBytes)
  assert.False(t, cleanVerdict)
  ```

- [ ] **Step 2: Add `TestAsyncTelemetry_DockerVerdictsRemainSynchronous`.** Hold telemetry writes while Docker scanning is incomplete or returns a block; assert no allowed manifest/blob verdict is published through the telemetry path. Exercise the real Docker verdict store with existing scanner test doubles. Separate known R01-R13 behavior from regressions; do not broaden this task to fix unrelated findings.
- [ ] **Step 3: Add restart/crash coverage.** Extend `TestTelemetryPersistsAcrossRestart` to exercise healthy draining of pending telemetry/usage. Add `TestAsyncTelemetry_CrashTailDoesNotAuthorizeArtifact` using a controlled child of the Docker test binary: signal readiness, leave work uncommitted, terminate the child without Close, reopen its files and verify persisted accounting remains consistent and an unchecked temporary file has no clean index/verdict. A subsequent request must execute the required checks; accepted tail loss is not an authorization record. Use handshakes, not sleep-to-crash timing.
- [ ] **Step 4: Add console consistency checks.** Before healthy flush, committed views may lag; afterward admitted history/counters/day totals/SSE agree. During saturation history intentionally omits dropped events while immediate verdict counters and separate loss counters expose the gap. Hold the writer during assertions to prove requests do not wait for recovery; release and ensure every accepted event is committed once. Queue/drop/error metrics remain readable throughout.
- [ ] **Step 5: Run and address failures.** `go test -tags integration ./integration/... -race -count=1` plus relevant proxy/Docker/cache package tests. New tests should expose any missing integration; if they already pass, keep them as security regression coverage and do not manufacture functional changes. Any real fix gets its own observed red→green test. Commit as `test: verify batched accounting preserves enforcement`.

## Task 6: Measure Sustainable Gains and Finish Verification

**Files:** External measurement harness/results/profiles/report; focused source comments/docs describing async visibility; this plan's checkboxes and Codex task records. No measurement artifacts in the checkout.

**Consumes:** Task 1 before artifacts and Tasks 2-5 completed behavior. Produces the performance acceptance result and branch-review handoff.

- [ ] **Step 1: Run fresh full checks.** In Docker run `go test ./... -race -count=1`, `go test -tags integration ./integration/... -race -count=1`, and `go build ./...`. Run gofmt on changed files, `golangci-lint run --timeout 5m` and `git diff --check`. Require exit0/no formatting findings. Console source is unchanged, so do not hand-edit its generated bundle. Record all failures by name.
- [ ] **Step 2: Repeat Task 1's six cases.** Build the real after binary, restore equivalent seeded state and run the exact same fixture/configuration/resource/concurrency/duration matrix, without race instrumentation. Repeat before/after cases if noise obscures the result. Capture sustainable rps, latency percentiles, CPU/request, allocations, DB connection waits, operations/commits, queue age/depth/unsaved work, RSS and final flush time. Include cold/slow-scanner control cases to identify workloads with little benefit; avoid public upstream load.
- [ ] **Step 3: Reconcile admitted and dropped observations.** After load, drain HTTP/writers and compare persisted IDs/totals/day counts with accepted telemetry, and hit deltas with accepted usage, after subtracting warmup. In stable completed runs attempted = accepted + full/closed drops; accepted = committed + remaining admitted work + reported forced abandonment. Include persistence drain in throughput/CPU accounting. Healthy headline batching cases require zero drops/abandonment and zero final unsaved work, with counts matching all requests. Classify overload/drop cases separately and report request throughput, persistence throughput, dropped fraction and history coverage; never label omitted accounting as a batching gain. Fail on unexplained discrepancies or changed HTTP enforcement. Validate normal visibility within30 seconds for admitted work.
- [ ] **Step 4: Profile both bookkeeping components.** Preserve CPU/allocation profiles and transaction/connection-wait evidence for matching repeated-key and many-key cases. Report total memory and variable event sizes, not only queue slot counts. Show whether commits/aggregated SQL work actually fell; separate queue admission speed from persistence capacity. Run any code-level benchmarks three times per variant and keep raw samples.
- [ ] **Step 5: Write the external acceptance report.** Include exact revisions, toolchain, fixture hashes, resource limits, commands, per-case before/after numbers, counts after drain, visibility age, shutdown/fault results and adverse cases. Require repeatably lower write/transaction cost and useful sustainable throughput or latency improvement, unchanged enforcement and acceptable measured memory. There is no agreed numeric speedup target. If the criteria are not met, record that rather than declaring success from faster enqueueing.
- [ ] **Step 6: Update current-behavior documentation and task status.** Describe batching/visibility, nonblocking drop-on-full/closed observation admission, loss counters, admitted-work retries and the finite forced-stop exception. State that dropped hit hints may affect eviction efficiency but never security validity. Preserve historical benchmarks as historical. Update Codex task records with evidence rather than predictions and commit repository documentation as `docs: document batched accounting behavior and validation`.
- [ ] **Step 7: Prepare final review.** Inspect the entire branch against the approved spec, attach the five Review Focus classes and execution rulings, and follow the selected execution workflow's fresh whole-branch review gate. Resolve important findings with regression tests before handoff. Only verified steps become checked. PR publishing/merging requires its own user instruction.

## Plan Self-Review

Checked against the latest owner-directed spec, current Repo/Store/Cache/Hub interfaces, SQLite row IDs, metrics, lifecycle, gate.Recorder's nonblocking contract, existing tests and CI commands. This revision supersedes all prior capacity-wait requirements and tests. All five Review Focus classes have owning tests; gate/cache interfaces remain unchanged. Product implementation, fault tests and new measurements have not run.

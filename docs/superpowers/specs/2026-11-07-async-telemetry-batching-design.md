# PERF-02: asynchronous telemetry and cache-usage batching

Date: 2026-11-07. Status: design and plan updated for the owner's nonblocking-overflow decision; implementation not started.
Starting source: `0b5e669`. Design branch: `perf/async-telemetry-batching`.

## Intent

Reduce per-request SQLite work and connection waiting when serving cached
artifacts. The full option combines telemetry batching with coalescing cache
usage updates. This is a new performance task; PERF-01 remains completed.

Current telemetry recording performs an event INSERT, counter read/upsert,
daily read/upsert, and COMMIT for every event. Cache hits separately execute an
UPDATE of `hit_count` and `last_hit` in the cache index. Each database has one
open connection. WAL and `synchronous=NORMAL` are already enabled.

No measured gain is assigned to this change yet. The earlier 118-to-1853 rps
result belongs to changing SQLite synchronous mode, not this design.

## Owner decisions

- Select the full option: telemetry plus cache-usage counters.
- Losing the most recent unflushed events on process crash is acceptable.
- Telemetry loss must not alter checks or permit serving an unchecked artifact.
- Latest owner decision supersedes the earlier blocking policy: telemetry must
  never make package handling wait for queue capacity, a flush or persistence.
  If its bounded queue is full, discard the incoming observation and return.
  Apply the same rule to cache-usage admission so it cannot remain a hidden
  bookkeeping wait on the package path. Count all such losses in metrics.
- Up to 30 seconds of normal-operation console event/statistics delay is
  acceptable. This is not an event-dropping timeout or a bound during outages.

## Goals and boundaries

- Retain every admitted telemetry event; batch transactions and aggregate
  counter deltas rather than merging the admitted audit history. Admission is
  best effort under saturation for PASS, CACHE, BLOCK and ERROR alike.
- Coalesce usage updates for the same cache entry into a count delta and the
  maximum observed hit time.
- Bound pending work, shed incoming observations instead of waiting on overflow,
  expose losses/pressure/write failures, and drain on healthy orderly shutdown.
- Preserve security decisions, cache validity, counter correctness, daily UTC
  attribution, concurrent ownership, and safe cache cleanup.

Policy evaluation, scanner execution, clean/block verdicts, security check
timestamps, artifact publication and invalidation remain on the existing
enforcement path. In particular, do not queue `Cache.Put`, `Invalidate`,
`MarkCVEChecked`, `MarkMalwareChecked`, or Docker image/blob verdict writes.
Only usage metadata (`hit_count`, `last_hit`) is deferred in the cache index.

No changes to scanners, npm metadata rewriting, artifact delivery semantics,
REL-01, R01-R13, S3/HA, or SQLite synchronous settings. Use existing dependencies;
do not add a message broker, durable outbox, or general task framework. The
deployment remains one application instance per database/cache directory.

## Approaches

1. **Telemetry only:** a smaller change, but the synchronous cache-hit UPDATE
   still remains on every hit. Discussed and not selected.
2. **Telemetry and cache usage:** separate writers for the two existing SQLite
   databases, with common behavioral rules but component-owned queues. This is
   the owner-selected option and the recommendation because it addresses both
   sources of write work.

The selection does not require a shared batching abstraction. Keep the two
implementations small and local; their payloads and read/cleanup semantics differ.

## Proposed defaults (implementation choices for review)

| Component | Pending capacity | Maximum active batch | Time trigger |
|---|---:|---:|---:|
| Telemetry | 1024 events | 128 events | 10 seconds |
| Cache usage | 4096 distinct cache row IDs | 256 row deltas | 10 seconds |

Flush on size or timer, whichever comes first; signal a prompt flush on overflow
without waiting for it. These internal defaults leave room under the accepted
30-second normal visibility target; validate actual oldest-event age before
acceptance. Tune them only from the recorded workload, without new public
configuration unless a concrete requirement appears.

An in-flight batch is additional bounded storage. Failed batches remain owned
by their writer. Queue limits are counts, not a fixed byte-memory guarantee:
events have variable-sized findings. Measure representative large events and
peak memory; do not claim bounded total application memory from queue length.
There is one background writer per component, not a goroutine per event/key.

## Telemetry path

`Recorder.Record` tries to reserve a queue slot without waiting. When full or
closed, increment the corresponding in-memory loss counter and return without
copying, synchronous logging, SQL, flush waits or spawning a goroutine. Drop
the incoming event; keep already admitted events in order. After successful
reservation, take an immutable owned snapshot, including mutable nested
findings/slices, before returning. Synchronization must be short and must never
be held across writer I/O or callbacks. Ordinary snapshot/counter work remains
local CPU/memory work; this does not promise a hard real-time execution bound.

The writer processes FIFO batches. For each batch, a single transaction:

1. Checks the stable batch token described below.
2. Inserts every event, retaining its original timestamp, request ID and fields.
3. Sums deltas in memory, reads/upserts lifetime counters once, and reads/upserts
   each affected UTC-day row once. Use event time rather than flush time; a batch
   spanning midnight has multiple daily deltas.
4. Stores the successful batch token and commits atomically.

Console queries continue reading committed SQLite data. Publish SSE events in
batch order only after commit has been confirmed; enqueueing is not publication.
Preserve the broadcaster's existing slow-subscriber behavior: durable event
history is authoritative, while an SSE connection is not a durable queue.
Prometheus request/verdict counters can continue updating immediately, so a
short difference from committed console totals is expected. Under saturation,
dropped events cause a permanent history/counter gap until retention/reset;
expose its size, and do not publish dropped events as committed SSE history.

## Cache-usage path

Keep the existing synchronous cache lookup, file-existence check and all
security information. The internal index lookup also returns the existing
`artifacts.id` (`INTEGER PRIMARY KEY AUTOINCREMENT`). The usage accumulator keys
by that ID and combines count deltas and maximum hit time. All classifier/name
coordinates remain correct; public artifact-gate interfaces need no new field.

Admission never waits for accumulator capacity. An existing pending row can
continue coalescing while the map is full; a new row with no free slot loses
only that incoming hit and increments the usage-loss counter. Do not remove
another row or fall back to a synchronous UPDATE/flush. Admission while closing
is likewise rejected and counted. Cache lookup/security data remains unchanged.

Use one index transaction per usage batch. Each row update changes only
`hit_count = hit_count + delta` and `last_hit = MAX(last_hit, observed_time)`,
guarded by its row ID. A deleted entry's delayed update must not recreate it or
affect a newly inserted entry at the same coordinates. Existing UPSERTs retain
row ID/hit-count continuity; delayed older timestamps must not regress last_hit.
Retired row IDs can resolve to zero updated rows without a new artifact entry.
The telemetry event for the request is still preserved separately.

Cache counters exposed to callers may reflect committed data with the accepted
normal lag. Security check timestamps and verdicts never use this accumulator.
Dropped usage may leave a valid entry with an older last_hit, changing eviction
efficiency; it cannot grant permission or renew a security check timestamp.

### Cache cleanup consistency

Before LRU selection for size eviction or stale selection for destructive
cleanup, request a usage-writer flush barrier. It waits for all usage admitted
before the barrier to be committed before the selection query executes. On
barrier failure/cancellation, abort that cleanup attempt rather than selecting
from known-stale last_hit values. The wait must not hold the index connection
or accumulator lock. Concurrent hits after the barrier retain the existing
concurrent-cleanup semantics; no stronger global snapshot is introduced.

These barriers belong only to maintenance selection. Package handlers must not
call them from Get, Put, verification, or observational admission. Lost usage
cannot be reconstructed by a barrier; cleanup can therefore evict a recently
used entry whose hit was dropped. This is an efficiency tradeoff, not permission
to serve an unchecked entry. Required cache/security SQL keeps its own existing
semantics; nonblocking observation admission does not eliminate ordinary CPU,
lock or storage contention, which must be bounded/measured separately.

Read-only stale-size/statistics displays may use committed values and lag within
the normal target. Do not make statistics/metrics collection wait indefinitely
for a failed writer. Bound its database reads; pressure metrics use in-memory
state and must remain observable during storage failure.

## Write failures and idempotent retry

Normal-operation write failure must not silently discard the active batch.
Keep it, expose the error, and retry in order with a one-second delay while the
service is running. Repeated warnings should be rate-limited, with error counts
and time since successful commit visible in metrics. When the pending queue
fills, discard/count new incoming observations and return immediately. Retrying
the active batch must never hold an admission lock or cause a synchronous
fallback. Caller cancellation must not remove an already admitted event; a
full/closed-buffer rejection is an explicitly counted loss, not an admission.

Retry must not double-count a commit whose acknowledgement was ambiguous.
Add a small `async_write_state` table in each database, keyed by component, with
one `last_batch_token` row. A token is unique to the writer incarnation/batch,
generated once and reused for every attempt. Read it inside the transaction:
if it already matches, treat the batch as committed without replaying changes;
otherwise apply the batch and store the token in the same transaction. The
single writer never advances to another batch until this one is resolved.
Other settings/security transactions do not touch that component's token.

This receipt survives event retention pruning and avoids per-event receipt
growth or a new durable queue. It relies on the already-stated single-instance
deployment; supporting competing application writers is outside this task.
Use cancellable SQL operations so an unresponsive database cannot prevent
shutdown control. Database-read timeouts must not consume or discard queued work.

## Lifecycle and shutdown

Healthy shutdown stops accepting new HTTP work, drains existing producers,
flushes both writers without waiting for the normal timer, then closes each
database. Preserve startup-failure cleanup and idempotent Close behavior.

Make admitted work and writers service-owned rather than tied to the client's
request context. Closing sockets does not mean an event was committed. New
observations rejected during close are counted without waiting.
Coordinate the queues with the existing HTTP shutdown path: no send-on-closed
channel, premature database close, admission race or infinite Close.

**Approved failure boundary:** keep shutdown bounded by the
configured service shutdown budget (30 seconds by default). If storage remains
unwritable and the budget expires, report an explicit unsuccessful drain and
the remaining event/usage counts, stop workers, and terminate. Treat
this forced stop like the accepted crash-loss case; do not report it as a clean,
fully flushed shutdown. The owner approved this forced-stop exception together
with the design on 2026-11-07.

The budget must be coordinated across HTTP drain and the two writers, rather
than giving every closer a new full budget. Keep logging available until the
writers have stopped; log drain failures before the existing generic closer
loop can discard returned errors.

## Observability

Expose queue occupancy/capacity, oldest pending age, attempted/admitted/dropped
items, batch sizes/commit duration, failures/retries and last successful commit
age separately for telemetry and cache usage. Loss reasons are bounded to
`queue_full` and `closed`; forced-stop abandonment of admitted work is reported
separately. Do not log synchronously for each dropped observation: use in-memory
counters and optional rate-limited background summaries. Use bounded component
labels, not package/request-ID labels. Include in-flight work when reporting
unsaved counts. Saturation and write failures must be visible without waiting
for those same telemetry events to reach SQLite. No new console dashboard is
required; existing operational logs and Prometheus are sufficient for this task.

## Validation and performance acceptance

1. Establish a current-source baseline before production changes. Repeat the
   small cached-artifact workload with 1/10/50 clients, telemetry enabled, using
   both repeated and many-distinct artifact keys. Include the recorded 50-client
   cache-hit scenario where reproducible; do not reuse the older 1853 rps as an
   interchangeable baseline.
2. Measure sustainable rps, p50/p95/p99, CPU/request, allocation bytes/count,
   SQLite operations/commits and connection waits, queue age/occupancy,
   outstanding events, drop coverage and sampled RSS. Include serialization/writer CPU and
   drain queued work before claiming throughput: accepting events faster than
   the writer can persist them is not a sustainable gain.
3. Verify per-request events and counter totals after flush, UTC midnight,
   repeated keys/classifiers, FIFO publication and immutability under race
   checks. Inject pre-commit failures and ambiguous commit acknowledgements;
   retries must not duplicate events or either set of counters.
4. Fill each buffer deliberately. Hold the writer stalled and prove package
   handling and observation admission return without releasing it: excess
   incoming items are dropped and counted, admitted items remain in order,
   no synchronous logging/SQL fallback or per-item goroutines are created,
   and pressure metrics remain readable. Test nested event ownership only for
   successfully reserved slots; do not allocate copies for rejected events.
5. Exercise healthy and failed shutdown with concurrent admissions, pending work,
   DB failure and expired budget. Assert no worker/handler leaks or use-after-
   close; verify the final-drain outcome is reported truthfully.
6. Pin cache deletion/reinsertion, UPSERT, in-flight usage, stale/LRU barriers,
   failed flush, concurrent hits and row-ID isolation.
7. Test security separation for ordinary artifacts and Docker: rejecting or
   unfinished checks must remain rejecting/unservable regardless of queued,
   failed or lost telemetry. Restarting with missing events must not create a
   clean verdict; lost hit counts may cause extra eviction, never permission.
8. Run focused and full unit/integration tests with race instrumentation in
   Docker, using the toolchain in go.mod and existing Go cache volumes; run
   gofmt and golangci-lint. Performance runs also use Docker and omit race
   instrumentation. Record event sizes, limits and all commands/results in the
   external Codex measurement archive, preserving previous experiment data.

Reconcile persisted accounting against admitted observations, with rejected
items and forced abandonment reported separately. Ordinary headline benchmark
gains must use healthy no-drop cases; do not present faster responses obtained
by silently omitting accounting as a batching speedup. Report overloaded/drop
cases separately, including the fraction of requests represented in history.

Require repeatable lower write/transaction cost and useful sustainable
throughput or latency improvement on the target cache-hit workload, correct
persisted accounting, acceptable measured memory, normal visibility within
30 seconds, and unchanged enforcement. No numerical speedup is promised before
measurement. Record adverse cases explicitly and revisit the design if batching
only moves the bottleneck or grows a continuously draining backlog.

## Implementation boundaries

Expected changes are concentrated in telemetry repo/store/hub, cache index/local
usage handling, metrics instrumentation and app shutdown wiring, with focused
unit/integration tests and forward-only database migrations. Preserve existing
public gate/cache behavior. The implementation plan will define precise helper
signatures and test cases after design approval.

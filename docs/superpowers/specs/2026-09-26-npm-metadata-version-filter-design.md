# npm Metadata Version Filtering — Design

**Date:** 2026-09-26
**Status:** Approved
**Stage:** Post-v0.4.0 iteration

## Problem

When the supply-chain gate blocks an npm package the proxy answers the tarball
request with `423 Locked`. npm treats that as terminal: it has already resolved
the version range client-side from the packument, so the install fails outright
instead of falling back to a version the policy would allow.

No HTTP status code changes this. Resolution finishes before the tarball is
ever requested, and npm has no backtracking at download time:

- `429`/`5xx`/`408` — `make-fetch-happen` retries the *same* URL and the same
  version, then fails, so the only effect is a threefold delay.
- `404` — `E404`, also fatal.
- `403`/`423` — fatal immediately. Today's behaviour is the most honest of the
  three.

The lever is the packument, not the response code: a version that is absent
from the metadata document is never picked, so `^1.0.0` resolves to the newest
*allowed* version and the install succeeds with no error at all.

## Goal

Hide versions the gate would block from npm metadata documents, so that range
resolution lands on an allowed version instead of failing, while keeping the
artifact gate as the enforcement boundary.

Decisions fixed during brainstorming:

1. **Scope:** an optional `RegistryAdapter` capability in `internal/gate`,
   implemented for npm only. The other five adapters are untouched and keep
   returning `423`.
2. **Gates that filter:** min-age and denylist — both decidable without a
   network call. CVE is excluded: it needs a scan per version (typescript has
   ~2000), which would move packument latency by orders of magnitude.
3. **Enablement:** no new on/off flag. Filtering follows whatever the gate
   would have decided at the tarball, which makes `supply_chain.mode` the
   switch it already is. The size cap doubles as an emergency off switch; see
   decision 7.
4. **Memory:** a size cap on the buffered document. A document over the cap is
   streamed through unfiltered and blocked at download time as today.
5. **Validators:** a synthetic `ETag` on rewritten documents only. Untouched
   documents keep upstream's validators, so the common case keeps its `304`
   economics (see §4).
6. **Telemetry:** a structured log line. No new `gate.Event` verdict —
   `aggregate.record` increments `requests` for every event
   (`internal/telemetry/aggregate.go:42`), so feeding filtering through it
   would corrupt the KPI counters just repaired in PR #80. See §9 for why the
   counter this decision originally paired with the log line has no home yet.
7. **Kill switch:** `server.metadata_filter_max_mb: 0` disables filtering. The
   default comes from `v.SetDefault`, not from the zero value.

Non-goals: filtering on CVE verdicts; caching filtered documents (§9); a
publish-date index (§9); ecosystems other than npm; changing `npm ci`
behaviour.

## Evidence

Measured against npm 10.9.2 and `registry.npmjs.org` with a throwaway
filtering proxy. These results are the reason the design looks the way it does.

| Scenario | Result |
|---|---|
| `left-pad@^1.0.0`, 1.3.0 removed from the packument | installs **1.2.0**, exit 0, silent |
| same, with `dist-tags.latest` left dangling at 1.3.0 | installs **1.2.0**, exit 0 |
| exact pin `left-pad@1.3.0`, 1.3.0 removed | `ETARGET` |
| `npm ci` with a lockfile pinning 1.3.0 | packument **never requested**; straight to the tarball |
| plain `npm install`, and an 8-package transitive tree | every packument requested as `Accept: application/json` (**full**, not abbreviated) |
| revalidation after a filtered response | npm sends back `If-None-Match` with whatever ETag it was given |

Two consequences worth stating plainly:

- npm tolerates a `dist-tags` entry pointing at a version that is not in
  `versions`, and falls back to the highest available. **Tags are therefore
  left untouched**, which also avoids adding a semver dependency to a
  deliberately lean `go.mod`.
- An exact pin degrades from `423` with reason `package_younger_than_min_age`
  to a misleading `ETARGET` (reported as a version that does not exist). A
  packument request carries no range information, so a pin cannot be
  distinguished from a range. This is accepted.

Document sizes, for the caps and trade-offs below (gzip / decompressed):

| Package | full | abbreviated |
|---|---|---|
| `@types/node` | 1.42 MB / 11.2 MB | 1.10 MB / 2.3 MB |
| `typescript` | 2.01 MB / 15.7 MB | 1.64 MB / 8.7 MB |
| `react` | 1.37 MB / 7.0 MB | 1.16 MB / 2.9 MB |

Packuments are served **chunked, with no `Content-Length`**, so the cap in §5
cannot be short-circuited from a header.

## Architecture

### 1. The adapter capability (`internal/gate/gate.go`)

Modelled on the existing `DownloadMetadataExtractor` (`gate.go:65`): an
optional interface that one adapter implements and the handler type-asserts.

```go
// MetadataFilterer is an optional RegistryAdapter capability: rewriting a
// metadata document so that versions policy will not serve are absent from it,
// letting the client's own resolver pick an allowed version instead of failing
// on a blocked download. npm implements it; adapters whose clients resolve
// server-side do not.
type MetadataFilterer interface {
	// NormalizeMetadataRequest reports whether r asks for a filterable
	// metadata document, and names the package it describes.
	NormalizeMetadataRequest(r *http.Request) (*MetadataRef, bool)

	// FilterVersions rewrites doc, dropping every version decide rejects. It
	// returns the rewritten document and the versions it removed. When nothing
	// is removed it returns doc itself, unmodified, so callers can forward the
	// upstream bytes verbatim.
	FilterVersions(doc []byte, decide VersionDecider) ([]byte, []string, error)
}

// VersionDecider reports whether one version of a package may be served.
// publishedAt is the zero time when the document carries no publish date for
// that version, which leaves any age-based rule mute.
type VersionDecider func(version string, publishedAt time.Time) bool

// MetadataRef names the package a metadata document describes. It is a
// PackageRef without a version, because the document covers every version.
type MetadataRef struct {
	Ecosystem string
	Name      string
}
```

The adapter knows only the document shape; it never imports policy. The
handler owns the decision.

### 2. Which requests qualify (`internal/proxy/adapters/npm.go`)

`NormalizeMetadataRequest` matches a `GET` for a package name only:
`/left-pad`, `/@types%2fnode`, `/@types/node`.

It rejects, deliberately:

- anything containing `/-/` — tarballs, `/-/v1/search`, `/-/npm/v1/*`,
  `/-/whoami`;
- `/left-pad/1.3.0` — a single-version manifest has nothing to hide; it is
  proxied as-is and the tarball gate still answers `423`;
- any method other than `GET`, so publishes are never rewritten.

### 3. Handler wiring (`internal/proxy/metadata.go`, new file)

`ServeHTTP` gains a third branch between "is a tarball" and "proxy
transparently" (`handler.go:74`):

```
GET /left-pad   Accept: application/json
      |
  NormalizeRequest -> (nil, false)            not a tarball
      |
      +- adapter implements MetadataFilterer?   no -> proxyTransparent
      +- NormalizeMetadataRequest(r) -> ok?     no -> proxyTransparent
      | yes
  proxyMetadata
      1. forwardUpstream(r) -> first response < 400
      2. gunzip when Content-Encoding: gzip
      3. LimitReader(body, cap+1) -> buffer
           +- over cap -> write the prefix, stream the rest, unfiltered
      4. FilterVersions(doc, decide)
           +- removed == 0   -> write doc unchanged, no re-encode
           +- removed == every version -> write the ORIGINAL document
           +- otherwise      -> write the filtered document, log + counter
      5. headers per section 4
```

`proxyMetadata` needs the same ordered-upstream failover that
`proxyTransparent` already implements (`handler.go:441-480`). Rather than
duplicate the loop, its middle is extracted:

```go
// forwardUpstream tries each configured upstream in order and returns the
// first response with status < 400. The caller owns the body. When every
// upstream fails, the returned Attempts carries each mirror's own outcome.
func (h *Handler) forwardUpstream(r *http.Request, body []byte) (*http.Response, upstream.Attempts)
```

`proxyTransparent` becomes `forwardUpstream` plus header copying plus
`io.Copy` — byte-identical behaviour to today. The new code lands in
`internal/proxy/metadata.go`; `handler.go` is already 652 lines and should not
grow by this feature.

A `metadataGroup singleflight.Group` joins the existing `recheckGroup`
(`handler.go:56`) so concurrent clients asking for the same packument collapse
into one upstream fetch.

Removing *every* version deliberately serves the original document: an empty
`versions` map would turn every install of that package into `ETARGET`,
whereas the unfiltered document lets the tarball gate state the real reason.

### 4. Validators and the synthetic ETag

Upstream serves packuments with `ETag`, `Last-Modified`,
`Cache-Control: public, max-age=300` and `Vary: accept-encoding, accept`.
Forwarding upstream's `ETag` alongside a *rewritten* body is a trap:

1. npm caches the filtered document under upstream's ETag.
2. min-age elapses; the hidden version becomes legitimate.
3. npm revalidates with that ETag; upstream has not changed the document and
   answers `304`.
4. Relaying the `304` leaves npm on its filtered copy — the version never
   comes back. Worse, a `304` gives *us* no body to filter either.

So the proxy mints its own validator, but **only for documents it rewrote**.
The routing decision is made from the request alone, before any work:

```
If-None-Match from the client:
  empty                    -> forward upstream unchanged
  an upstream tag          -> forward upstream unchanged
  contains our prefix      -> strip If-None-Match and If-Modified-Since,
                              fetch the full body
```

Three response paths follow:

| Path | Condition | Upstream traffic | Parse | To the client |
|---|---|---|---|---|
| **Relay** | client sent an upstream tag and upstream answered `304` | headers only | no | `304` |
| **Clean** | upstream `200`, filter removed nothing | body | yes | body + **upstream** `ETag`/`Last-Modified` |
| **Filtered** | filter removed at least one version | body | yes | body + **our** `ETag`; or `304` when the filtering is unchanged |

```go
// syntheticETagPrefix marks an ETag this proxy minted for a rewritten metadata
// document. A client revalidating with such a tag must be served from a freshly
// filtered document: forwarding its If-None-Match upstream would earn a 304
// with no body to filter, pinning the client to a stale rewrite forever.
const syntheticETagPrefix = `"joei.`
```

The tag's value is a hash of the **filtered** body, which makes it a strong
validator and lets unchanged filtering answer `304` — so even the slow path
keeps the client hop cheap.

`If-None-Match` is a list: if *any* element carries the prefix the tag counts
as ours. `*` does not count as ours and is forwarded. An upstream that happens
to mint a tag starting with `joei.` only causes one redundant body fetch.

Header handling per path:

| | `ETag` to client | `Last-Modified` to client | `INM`/`IMS` upstream |
|---|---|---|---|
| Relay | upstream's | upstream's | forwarded |
| Clean | upstream's | upstream's | forwarded |
| Filtered | ours | **dropped** | **stripped** |

Dropping `Last-Modified` on the filtered path closes the date side-channel:
verified with a real npm, which then stops sending `If-Modified-Since` too.
`Cache-Control` and `Vary` are always forwarded — the body genuinely varies by
`Accept`, so `Vary: accept-encoding, accept` stays truthful.

Parsing therefore happens only on an upstream `200`: a stable package that
nobody filters lives on relayed `304`s and costs nothing after the first
fetch.

Residual gap, accepted: a client holding an upstream tag will not learn about a
**newly added denylist entry** until upstream changes the document, because the
`304` is relayed without looking at a body. min-age cannot cause this — it only
ever moves toward "allowed", and an unchanged document gains no versions. See
§7.

### 5. Size cap and configuration

The cap applies to the **decompressed** document, enforced with
`io.LimitReader(gz, cap+1)`. On overflow the body is already partly consumed
and cannot be rewound, so the overflow path writes the buffered prefix, then
`io.Copy`s the rest: response chunked, no `Content-Length`, `Content-Encoding`
dropped. Slightly more CPU than today, degrading into today's behaviour rather
than into an error.

```go
// MetadataFilterMaxMB caps the decompressed size of a metadata document the
// proxy will buffer in order to hide blocked versions. A document over the cap
// is streamed through unfiltered and the artifact gate blocks it at download
// time instead. Zero disables metadata filtering entirely.
MetadataFilterMaxMB int `mapstructure:"metadata_filter_max_mb"`
```

Lives in `ServerConfig`, next to the existing proxy-behaviour knobs. The
default is `v.SetDefault("server.metadata_filter_max_mb", 32)` — the same
mechanism already used for `cache.revalidation.*_ttl_minutes`
(`config.go:305`) — rather than the sibling "zero or negative selects the
default" convention, precisely so that an explicit `0` can serve as the kill
switch. A negative value is a validation error.

32 MB is double the largest document measured (typescript, 15.7 MB).

### 6. The decision function

```go
decide := func(version string, publishedAt time.Time) bool {
	ref := &gate.PackageRef{Ecosystem: mref.Ecosystem, Name: mref.Name, Version: version}

	// An empty ScanResult means "not scanned", not "clean": only the denylist
	// verdict is trustworthy here, so no other reason may hide a version.
	if d := h.cfg.Policy.Evaluate(ref, &gate.ScanResult{}); !d.Allowed && d.Reason == gate.ReasonDenylisted {
		return false
	}
	// Document shapes without per-version publish dates leave min-age mute.
	if publishedAt.IsZero() {
		return true
	}
	return h.cfg.SCFilter.Check(ctx, ref, &gate.PackageMetadata{PublishedAt: publishedAt}).Allowed
}
```

There is no branch on `supply_chain.mode`, and none is needed:
`supplychain.Filter.Check` already returns `Allowed: true` with reason `off` or
`dry_run` (`filter.go:74-80`). The rule reduces to one sentence — *the filter
hides exactly what the gate would have blocked at the tarball* — so `dry_run`
hides nothing, and the denylist applies regardless of `supply_chain.mode`,
matching how both behave at download time today.

### 7. Enforcement invariant

**Metadata filtering is a UX layer; the artifact gate is the enforcement
layer.** Every degradation in this design lands on the same fallback — the
client resolves a blocked version and receives `423` at download:

- a document over the size cap (§5);
- `npm ci` and any lockfile-pinned install, which never fetch a packument;
- a single-version manifest request (§2);
- a client on a relayed `304` after a denylist addition (§4);
- documents without per-version publish dates, for min-age (§8).

This invariant is what makes those trade-offs acceptable. It must hold in
tests, not just in prose — see scenarios E, G and J under Testing.

### 8. Documents without publish dates

The abbreviated packument (`Accept: application/vnd.npm.install-v1+json`) has
top-level keys `name`, `dist-tags`, `versions`, `modified` — **no `time`** —
and its per-version objects carry no date either. `modified` describes the
document, not a version.

Detection is by document, not by header: clients send `Accept` listing all
three media types, so the header cannot predict the shape of the response. A
version missing from `time` yields the zero time, and §6 leaves min-age mute
for it. The denylist still applies, since it needs only name and version.

For abbreviated documents the result is therefore today's behaviour, with no
regression: min-age is enforced at the tarball. A once-per-document log line
records that min-age was mute, so "why does pnpm still get 423" has an answer
in the logs.

npm itself is unaffected: it requests full documents for every dependency
(measured). pnpm and yarn were **not** verified — neither is installed on the
development machine.

### 9. Telemetry

One structured log line per rewritten document, naming the package, the
versions removed, the count, and the rule that removed each one. That log line
is the whole mechanism, and it is what answers "why did an old version arrive".

Nothing enters `gate.Event`: `aggregate.record` increments `requests` for every
event (`aggregate.go:42`), so a filtering event would inflate the request count
and skew the blocked ratio — the KPIs just repaired in PR #80.

A process counter was planned alongside the log line, and is dropped for now
because there is nowhere to read it from: the project exposes no Prometheus or
`expvar` surface, `/health` answers a fixed `{"status":"ok"}`
(`internal/proxy/mux.go:28`) and should keep that contract, and the telemetry
store is excluded above. Aggregation is therefore a job for whatever consumes
the logs. A real metrics surface is follow-up 5.

## Follow-ups (not in this change)

Each is named here so it is not re-derived later:

1. **Filtered-document cache.** Key `(path, Accept, upstream ETag, policy
   generation)`, TTL 300 s from upstream's `Cache-Control`. Would let a client
   revalidation be answered by revalidating upstream with the *stored* upstream
   ETag: `304` upstream means `304` to the client with no body transferred at
   all, and the policy generation in the key closes the residual gap in §4.
   Not needed for correctness — an optimisation for many sequential clients on
   a heavily filtered package.
2. **Full document in answer to an abbreviated request.** Legal negotiation —
   npm itself advertises `application/json; q=0.8` — and would give min-age to
   abbreviated clients. Rejected for now because the decision to fetch the
   bigger document must be made *before* knowing whether anything needs
   hiding, so the cost lands on every request rather than on the filtered
   minority. Trigger to revisit: pnpm or yarn users reporting that min-age does
   not apply. Would ship behind a knob.
3. **Publish-date index.** `NPMAdapter.FetchMetadata` already fetches full
   documents on the download path (`npm.go:130`); persisting per-version dates
   would serve abbreviated clients without extra upstream traffic. A new store
   with its own invalidation — its own change.
4. **`DenylistEmpty()` fast path.** Would skip buffering entirely when nothing
   could possibly be filtered. Declined: it widens `policy.Runtime`'s API to
   save work on a path npm does not take.
5. **A metrics surface.** The proxy has no Prometheus or `expvar` endpoint, so
   any counter added by this change would be unreadable (§9). Exposing counters
   properly is worth doing, for far more than this feature, and belongs in its
   own change.

## Testing

Project conventions: external test packages (`adapters_test`), testify,
`TestType_Method_Case`, integration tests behind `//go:build integration` with
an `httptest` upstream mock.

### Unit — `internal/proxy/adapters/npm_test.go`

`NormalizeMetadataRequest`, as a table. The negative cases matter more than the
positive ones:

| Path | Method | Expect |
|---|---|---|
| `/left-pad` | GET | accepted |
| `/@types%2fnode`, `/@types/node` | GET | accepted |
| `/left-pad/1.3.0` | GET | rejected — single-version manifest |
| `/left-pad/-/left-pad-1.3.0.tgz` | GET | rejected — tarball |
| `/-/v1/search?text=x`, `/-/npm/v1/user`, `/-/whoami` | GET | rejected |
| `/left-pad` | PUT, POST | rejected — publish |
| `/` | GET | rejected |

`FilterVersions` against a packument fixture:

- removes exactly what `decide` rejects, and clears their `time` entries;
- returns the list of what it removed;
- leaves `dist-tags` untouched even when a tag targets a removed version —
  this pins the decision recorded in the Evidence section, so nobody later
  "fixes" it by adding a semver dependency;
- a version present in `versions` but absent from `time` yields the zero time,
  not an error;
- an abbreviated fixture (no `time` at all) filters on the denylist only;
- malformed JSON returns an error, and the caller falls back to passthrough;
- **removing nothing returns the original byte slice, not a re-marshalled
  one.** This is not cosmetic: Go marshals maps with sorted keys, so
  re-marshalling would reorder the document and break the byte-identity the
  Clean path relies on when it forwards upstream's ETag. The test compares
  bytes.

### Unit — `internal/proxy/metadata_test.go`

- The `If-None-Match` classifier: empty, an upstream tag, our tag, a list with
  ours second, `*`, garbage.
- The synthetic tag: stable for identical filtered output, different when the
  filtering changes.
- `decide` construction: a denylisted version is rejected; a too-fresh version
  is rejected; `dry_run` and `off` reject nothing; and — as an explicit
  regression guard — an empty `ScanResult` never rejects for a CVE reason.

### Integration — `integration/npm_metadata_filter_test.go`

A mock registry in the style of `newTestRegistry`: a packument with two
versions (one old, one fresh, dated relative to `time.Now()`) plus tarball
endpoints. The mock records what it received and what it served; several
assertions are about that record.

| # | Scenario | Expect |
|---|---|---|
| A | GET packument, min-age enforce | the fresh version is absent from `versions`; `ETag` carries our prefix; no `Last-Modified` |
| B | revalidate with our tag | `304`, **and the upstream saw no `If-None-Match`** |
| C | fixture aged so nothing is filtered | `200`, `ETag` equals upstream's, body byte-identical to upstream's |
| D | client sends an upstream tag, upstream answers `304` | `304` relayed; the mock confirms it served no body |
| E | tiny `metadata_filter_max_mb` | document passes unfiltered with upstream's `ETag`; the fresh version's tarball still returns `423` |
| F | `mode: dry_run` | document untouched, upstream's `ETag` |
| G | **every** version blocked | the original document is served, not an empty `versions`; the tarball returns `423` |
| H | upstream answers `Content-Encoding: gzip` | the client can gunzip and parse the filtered body |
| I | `metadata_filter_max_mb: 0` | pure passthrough, byte-identical |
| J | GET `/left-pad/1.3.0` for a blocked version | `200` with upstream's body; the tarball returns `423` |

E, G and J catch the most expensive class of regression. G especially: without
it, "the filter ate every version" surfaces in production as `ETARGET` on every
install of that package rather than as one failing test.

### Not in CI

A live npm client. CI has no Node (the console is bundled by Go's esbuild), and
adding it for this is not worth it. The manual recipe below covers it and is
run before merge.

### Manual verification recipe

Against `registry.npmjs.org`, with a `min_age_hours` high enough that the
newest version of a chosen package is blocked. All four steps were performed
during the spike; their expected outcomes are the ones recorded in Evidence.

1. `npm install <pkg>@<range>` — an allowed older version installs, exit 0,
   and the response carries a `joei.` ETag.
2. `npm install --prefer-online` again — the proxy answers `304`; verify the
   upstream log shows no forwarded `If-None-Match`.
3. Lower `min_age_hours` so nothing is blocked, then
   `npm install --prefer-online` — the newest version installs and the response
   carries upstream's ETag.
4. `npm install --prefer-online` once more — the upstream `304` is relayed and
   no document body is parsed.

### Order of work

Test-first: the `NormalizeMetadataRequest` table (cheap, catches the endpoint
shapes immediately), then `FilterVersions`, then the ETag classifier, and only
then the handler wiring under integration scenarios A–J.

Before pushing: `make test` and **golangci-lint** locally. The lint gate is
golangci-lint, not `go vet`, and CRLF checkouts can mask gofmt findings.

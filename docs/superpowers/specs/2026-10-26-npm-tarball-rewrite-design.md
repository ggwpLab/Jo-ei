# npm tarball URL rewrite — design

Date: 2026-10-26
Status: draft, awaiting owner approval of the full document

## Why

An npm packument links every version's tarball by absolute URL
(`versions.<v>.dist.tarball`, e.g. `https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz`).
Jō-ei serves that URL untouched today. An E2E run in the second-wave review
(PR #115) showed:

- pnpm 9.15.0 and Yarn 1.22.22 download the tarball from that URL directly,
  around the proxy, even with the default npmjs upstream. No gate (min-age,
  CVE, malware) sees the artifact.
- npm 10.9.9 goes through the proxy only because its
  `replace-registry-host=npmjs` default swaps the `registry.npmjs.org` host for
  the configured registry. With a non-npmjs upstream (Nexus, Verdaccio,
  Artifactory) npm bypasses the proxy too.

README and `docs/configuration.md` currently document this as a known
limitation. This work removes it: every tarball link a client receives points
at Jō-ei.

## Goals

- Every npm metadata document served with status 200 (full and abbreviated
  packument, and the single-version manifest `/<pkg>/<version-or-tag>`) has
  each `dist.tarball` pointing at the Jō-ei npm route, under the
  address the client used to reach Jō-ei.
- Fail closed: if the proxy cannot rewrite a document, the client gets an
  error, never the original document. Owner decision: "мимо гейтов не пускаем".
- Works both for clients reaching Jō-ei directly (`http://joei:8080/npm/`) and
  behind a reverse proxy / ingress with an external HTTPS domain, with no
  configuration in the common case. Owner decision: derive the address from
  request headers, like Nexus.

## Non-goals

- Lockfiles that already pin tarball URLs (`yarn.lock` `resolved`, possibly
  `package-lock.json`): the client never asks for a packument, so the server
  cannot intervene. Owner decision: document it ("regenerate the lockfile after
  moving to Jō-ei; block direct egress to registry.npmjs.org"), no rewriting
  utility.
- Other ecosystems. PyPI already rewrites via `gate.IndexRewriter`; RubyGems,
  Maven, Go and Docker clients fetch artifacts relative to the configured
  registry.
- `GET` with a query string (npm's `?write=true` read before a publish
  `PUT`): passed through untouched, since rewriting it would push Jō-ei URLs
  upstream on the `PUT`. It is not an install path; the docs name it.
  *(My call.)*
- Version filtering of the single-version manifest: it is rewritten only; the
  tarball gate still rules on the download. *(My call.)*
- Rewriting any field other than `dist.tarball` (`_resolved`, `repository`,
  `homepage` etc. are not download links clients follow during install).

## Anti-goals

- A path where an unrewritten packument reaches a client in any mode or error
  case. This includes 304 responses that let a client keep a copy cached
  before this change.
- One client's address leaking into another client's response (via coalescing
  or ETags).
- Trusting forwarding headers from arbitrary peers.

## Decisions

### Public base address (owner: headers, like Nexus)

Resolved per request, in this order:

1. `server.public_url` (new, optional, e.g. `https://registry.example.com/joei`).
   When set, headers are ignored. *(My call — Nexus has the same override, and
   it is the escape hatch for setups the header logic misreads.)*
2. When the TCP peer is in `server.trusted_proxies`: scheme from
   `X-Forwarded-Proto`, host from `X-Forwarded-Host` (port included, or
   `X-Forwarded-Port` if the host has none), path prefix from
   `X-Forwarded-Prefix`; `Forwarded` (`proto=`, `host=`) is read when the
   `X-Forwarded-*` pair is absent. Any value not supplied falls back to step 3.
   *(My call on the exact header set; it matches what nginx, Traefik and
   Kubernetes ingress-nginx send.)*
3. Otherwise: scheme `https` if the connection is TLS else `http`, host from
   the request `Host`.

Headers from a peer outside `trusted_proxies` are ignored, the same rule the
client-IP resolution in `internal/httpx/clientip.go` already applies. A host or
proto value that does not parse as a URL authority / `http|https` makes the
request fail with 400 rather than be echoed into JSON. The npm route prefix
(the registry name the mux strips, e.g. `npm`) is appended after the base.

An untrusted client can still choose its own `Host`; this only affects the
links in that client's own response, which it could rewrite itself anyway.

### Rewritten URL shape

Owner decision: the canonical npm path, built from the package name and the
version key, never parsed out of the original URL:
`<base>/<npm-prefix>/<name>/-/<unscoped-name>-<version>.tgz` (scoped names as
`@scope/name`, e.g. `/npm/@babel/core/-/core-7.26.0.tgz`). The original
`dist.tarball` host, upstream base path (Nexus `/repository/npm-proxy/`) and
filename are discarded; the tarball handler forwards the canonical path to the
configured upstreams, which npmjs, Verdaccio and Nexus serve (Artifactory
expected to, unverified). Upstreams that only serve tarballs elsewhere (GitHub
Packages: `/download/@scope/name/<version>/<hash>`) are unsupported and
documented as such.

The rewritten link must be one the npm adapter's `NormalizeRequest` /
`parseNPMVersion` resolves back to the same name and version. A version for
which that round trip fails (e.g. a version key with characters that cannot
form that filename) is dropped from the document and logged, the way PyPI drops
links it cannot rewrite. *(My call: a version the client cannot see is the
safe failure; the others stay installable.)* A version with no `dist` object
has no link to rewrite and is left as is. If dropping leaves no versions, the
request fails (502).

### Fail-closed cases (owner: return an error)

| Case | Today | After |
|---|---|---|
| 200 document over `metadata_filter_max_mb` | streamed verbatim | 502, `reason` logged *(log only: no metadata metric exists today; adding one is separate work — my call)* |
| Content-Encoding the proxy cannot decode | streamed verbatim | 502 |
| 200 body that is not a parseable packument | served unfiltered | 502 |
| 3xx from upstream | relayed | 502 *(my call: a redirect can lead the client to a document the proxy never saw)* |
| 4xx/5xx from upstream | relayed | relayed unchanged (no tarball links) |
| every version rejected by policy (`AllRejected`) | original served | original served **rewritten** |
| no version rejected | original bytes served | rewritten document served |

`server.metadata_filter_max_mb: 0` changes meaning from "filtering disabled"
to "no size cap" (owner decision). Filtering and rewriting have no off switch.
CHANGELOG records the meaning change.

### Caching, coalescing, ETags

- The coalesced upstream flight still shares the raw upstream document; the
  version filter and the rewrite run per caller after the flight, as the
  filter does today. The base address is never part of shared state.
- Every 200 document is now rewritten, so every one carries a synthetic
  `"joei.` ETag computed from the final body (which includes the base
  address), so two addresses never share a tag.
- A client presenting a non-synthetic validator (`If-None-Match` with an
  upstream ETag, or `If-Modified-Since`) holds a copy served before this
  change, which is unrewritten. Those validators are stripped before the
  upstream request, so the client gets a full rewritten document instead of a
  304 that would keep its old copy alive. Upstream 304s therefore no longer
  reach clients; the synthetic-ETag 304 path (`clientHoldsOurTag`) remains.
  *(Consequence I accept: every packument revalidation is a full upstream
  fetch. Acceptable because the coalescing flight already collapses
  concurrent ones; flag for the builder if a cheap safe alternative appears.)*

### Shape in code

Left to the builder, with these constraints:

- The rewrite lives in the npm adapter (next to `FilterVersions`); it needs
  the base address as an input, so the `gate.MetadataFilterer` contract grows
  to take it (or a sibling optional interface is added). Base-address
  resolution lives in the HTTP layer (`internal/httpx` or `internal/proxy`),
  not in the adapter.
- Reuse the trusted-proxy matcher that `clientip.go` already builds; do not
  parse `trusted_proxies` twice.
- Document decoding stays one level deep with raw JSON for unknown fields, as
  `FilterVersions` does now; only `versions.*.dist.tarball` changes.
- Relay reasons stay a closed set; new outcomes (e.g. `rewrite_failed`) are
  added to it. Upstream requests force `Accept-Encoding: gzip`, as
  `internal/proxy/index.go` does for PyPI, so a client asking for `br` does
  not turn into a 502.

## Verification

- Unit tests: base-address resolution (direct, trusted proxy with each header,
  untrusted proxy ignored, `public_url` override, malformed header → 400);
  rewrite of full and abbreviated packuments, scoped names, Nexus-style
  upstream path, unmappable tarball dropped, all-dropped → error; every
  fail-closed row of the table above; non-synthetic validators stripped;
  ETag differs per base address.
- Integration test through the handler with a fake upstream.
- E2E on an `--internal` Docker network (same harness as the PR #115 review):
  npm, pnpm 9, Yarn 1 and Yarn Berry install a package with the default npmjs
  upstream and with Verdaccio (and Nexus if it can be stood up) as upstream, and the fake upstream's log shows no
  direct tarball fetch by the client. Also confirm the pnpm v9 lockfile and
  Yarn Berry lockfile do not pin tarball hosts (affects the lockfile docs).
- All Go tests in the `golang:1.26.10` container with `-race`; golangci-lint
  clean.

## Docs

- README / `docs/configuration.md`: replace the "Known limitation — tarballs
  can bypass the gates" block with how tarball links are rewritten; document
  `server.public_url`, the forwarding headers read from `trusted_proxies`, the
  new meaning of `metadata_filter_max_mb: 0`, and the lockfile caveat
  (regenerate; block direct egress), unsupported upstreams (GitHub Packages)
  and the `?write=true` pass-through.
- CHANGELOG Unreleased: Security (bypass closed), Changed (`0` = unlimited,
  fail-closed npm metadata, upstream 304s not relayed).

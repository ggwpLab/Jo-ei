# Yarn and RubyGems Support — Design

**Date:** 2026-06-01
**Branch:** `feature/yarn-rubygems-support` (off `develop`, which already has multi-upstream)
**Status:** Approved (brainstorming complete)

## Problem

The proxy supports PyPI, npm, and Maven. Add two more clients/ecosystems:
- **Yarn** — a JavaScript package manager that speaks the npm registry protocol.
- **RubyGems** — a genuinely new ecosystem (gems from rubygems.org).

Both must flow through the existing four-layer pipeline (cache → supply-chain age
→ CVE → malware). New adapters implement the current `RegistryAdapter` interface
(`Name / NormalizeRequest / FetchMetadata / UpstreamURLs`) and therefore inherit
the multi-upstream sequential fallback already in `develop`.

## Decisions

| Topic | Decision |
|---|---|
| Yarn scope | **Docs + `/yarn/` route alias** to the existing npm handler. No new adapter, no separate upstream config. Relies on the yarn client rewriting tarball origins (same assumption as npm). |
| RubyGems metadata source | **`GET <base>/api/v1/versions/<gem>.json`** (rich: `number`, `created_at`, `licenses[]`, `sha` SHA256, `platform`). |
| Platform gems (native ext.) | **Full support** — parse the optional platform suffix; match the API entry by `number` + `platform`. |
| Platform encoding in pipeline | **Encode in `PackageRef.Version`**: `"1.15.0"` (ruby) or `"1.15.0-x86_64-linux"` (platform). No new `PackageRef` field. Cache key stays unique per platform. |
| OSV / CVE version | OSV scanner strips the platform suffix for the `rubygems` ecosystem (gem versions contain no hyphens), so CVE lookups use the pure `number`. |
| Scope / decomposition | **One spec/plan** covering both: RubyGems is the bulk; Yarn is one small task. |
| Branch base | `develop` (multi-upstream already merged via PR #4, commit `4d40bd3`). |

## Yarn

Yarn (classic and berry) uses the npm registry protocol: it fetches the package
document (`GET /<pkg>`) and tarballs (`/-/<file>.tgz`). The npm adapter already
handles both shapes, so yarn needs no new adapter.

- **Routing:** in `cmd/sca-proxy/main.go`, when `registries.npm.enabled`, register
  the same `*proxy.Handler` instance under both prefixes `"npm"` and `"yarn"`.
- **Tarball interception:** a yarn configured with
  `npmRegistryServer = http://localhost:8080/yarn/` rewrites tarball origins to
  that base, so tarball requests arrive at `/yarn/<pkg>/-/<file>.tgz`; the mux
  strips the `/yarn/` prefix and the npm adapter intercepts `.tgz` and scans it.
- **CVE ecosystem** stays `npm` (yarn packages are npm packages). No OSV change.
- **Docs:** README "Using with Yarn" — `yarn config set npmRegistryServer http://localhost:8080/yarn/` (berry) and `yarn config set registry http://localhost:8080/yarn/` (classic v1).

No change to the npm adapter or the OSV ecosystem map for yarn.

## RubyGems

### Config & routing

Add `RubyGems RegistryConfig` to `RegistriesConfig` (`mapstructure:"rubygems"`),
identical shape to the others (`upstreams: []`, `enabled`). Default upstream
`https://rubygems.org`. Routing prefix `rubygems`. `main.go` registers the handler
when enabled; the existing `Validate()` already enforces "enabled ⇒ ≥1 upstream".

### Adapter — `internal/proxy/adapters/rubygems.go`

Implements `RegistryAdapter`:

- **`Name()`** → `"rubygems"`.
- **`NormalizeRequest`** — intercepts only gem downloads: path `/gems/<file>.gem`.
  Parse `<name>-<version>[-<platform>]`:
  - strip `.gem`; split on `-`;
  - the first hyphen-separated segment that begins with a digit starts the version
    (gem versions contain no hyphens — they use dots: `1.2.3`, `1.0.0.beta1`);
    everything before it is `name`; that segment is `version`; everything after
    (if any) is `platform`, re-joined with `-`.
  - examples: `rails-7.0.4` → (rails, 7.0.4, ""); `aws-sdk-s3-1.0.0` →
    (aws-sdk-s3, 1.0.0, ""); `nokogiri-1.15.0-x86_64-linux` →
    (nokogiri, 1.15.0, x86_64-linux).
  - returns `PackageRef{Ecosystem:"rubygems", Name:name, Version:<encoded>}` where
    `<encoded>` = `version` or `version + "-" + platform`. Non-`.gem` paths and
    unparseable names return `(nil, false)` (transparent proxy).
- **`FetchMetadata`** — sequential fallback over `upstreams`:
  - decode `ref.Version`: `number, rest := SplitN(version, "-", 2)`; `platform`
    = `rest` if present else `"ruby"`.
  - `GET <base>/api/v1/versions/<name>.json`; on each upstream, first success wins.
  - find the array entry with `number == number` AND `platform == platform`.
  - map: `PublishedAt = parse(created_at)` (RFC3339, UTC); `License =` join of
    `licenses` with `", "` ("" if absent); `Checksum = sha`.
  - error if the upstream list is exhausted or no entry matches.
- **`UpstreamURLs`** — `base + r.URL.RequestURI()` for each upstream, in order.

Transparent (not intercepted): `/api/...`, `/info/<gem>`, `/versions`,
`/quick/Marshal.4.8/...`, `/specs.4.8.gz`, `/latest_specs.4.8.gz`.

### CVE / OSV — `internal/scanner/osv.go`

- Add `"rubygems": "RubyGems"` to `ecosystemMap`.
- Before building the OSV query, normalize the version for the `rubygems`
  ecosystem by stripping any platform suffix: `version = SplitN(version, "-", 2)[0]`.
  Gem versions never contain a hyphen, so this is safe and yields the pure number
  OSV expects. Other ecosystems are unaffected.

## Testing (TDD)

- **config_test.go:** parse `registries.rubygems.upstreams`; enabled+empty fails.
- **rubygems_test.go:**
  - `NormalizeRequest`: `/gems/rails-7.0.4.gem` → (rails, 7.0.4); `aws-sdk-s3-1.0.0.gem`
    (hyphenated name); platform gem `nokogiri-1.15.0-x86_64-linux.gem` → version
    `1.15.0-x86_64-linux`; non-`.gem` paths (`/api/...`, `/info/...`) not intercepted.
  - `FetchMetadata`: mock `/api/v1/versions/<gem>.json`; ruby-version match;
    platform-version match by `number`+`platform`; fallback to the second upstream
    on first-upstream 404; error when version/platform not found.
  - `UpstreamURLs`: one URL per upstream.
- **osv_test.go:** `rubygems` OSV query uses the platform-stripped version; ecosystem
  maps to `"RubyGems"`.
- **mux_test.go (or main wiring):** `/yarn/...` dispatches to the npm handler (the
  same handler object as `/npm/`); a `.tgz` via `/yarn/` is intercepted as npm.
- **integration (`integration/`, `integration` build tag):** end-to-end RubyGems
  scenario with two httptest upstreams — first 404s, second serves `versions.json`
  (old `created_at`) + the `.gem` → 200.

Tests are written before implementation, one failing test at a time.

## Out of scope (future phases)

- Tarball/`dist.tarball` URL rewriting for guaranteed npm/yarn interception
  (current design relies on client-side origin rewrite).
- RubyGems compact-index merging across upstreams (listings use first-hit fallback).
- Go and other ecosystems.

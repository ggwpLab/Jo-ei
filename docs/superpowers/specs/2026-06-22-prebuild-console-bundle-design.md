# Design: Prebuild console bundle

**Date:** 2026-06-22
**Status:** Approved

## Problem

The admin console (`/console/`, 浄衛 — The Purification Gate) is a React SPA whose
UI is currently rendered entirely in the browser at load time:

- `.jsx` files are shipped as `<script type="text/babel">` and **compiled by Babel
  in the browser** on every page load.
- React, ReactDOM and Babel are loaded **from a CDN (unpkg.com)** — the console
  will not open without outbound internet access, and trusts a third-party CDN.
- The 10 source files load sequentially, unminified.

For a supply-chain security proxy, depending on an external CDN to render its own
admin console is both an availability risk (no offline use) and ironic. In-browser
Babel compilation (`babel.min.js` ≈ 3 MB) also slows first paint.

## Goal

Move the UI to a **prebuilt bundle**: compile JSX to plain JS at build time, drop
in-browser Babel, and serve React locally. Rendering stays client-side React; only
the *compilation* moves from runtime (browser) to build time. No CDN, works offline.

## Decisions

| Question | Decision |
|---|---|
| Approach | Build-time bundling with esbuild (not SSR, not local-Babel) |
| Tooling | Pure Go: esbuild as a Go library via `//go:generate go run`. No Node. |
| React source | Vendor `react.production.min.js` + `react-dom.production.min.js` (UMD globals) locally |
| Artifact | Commit `app.bundle.js` to the repo; CI verifies it is up to date |
| Minification | Minified bundle (review the `src/` sources, not the artifact) |

## Architecture

```
Development:                          Runtime (unchanged shape):
  src/*.jsx ──┐                         browser
  src/api.js ─┤  go generate             │ GET /console/
              ▼  (esbuild Transform       ▼
        app.bundle.js  ──► go:embed ──►  index.html
        (minified, committed)            + react UMD (local)
                                         + app.bundle.js
```

### Bundling strategy (global-scope aware)

The source files are **not** ES modules — they share one global lexical scope:
`shared.jsx` declares `const { useState } = React` and top-level
`const`/`function` components plus `Object.assign(window, …)`; the other files
reference `Icons`, `JOEI`, `Spark`, `useState` from that shared global scope (how
classic `<script>` tags work). A plain `esbuild bundle:true` (which expects
`import`/`export`) would break these links.

Therefore the generator does **not** use `bundle:true`. Instead it:

1. Runs each source file through **esbuild Transform** (JSX→JS, minify
   whitespace/syntax, **`MinifyIdentifiers: false`** so top-level globals are not
   renamed and cross-file references keep resolving).
2. **Concatenates** the results in dependency order (the same order as the current
   `index.html`: `api.js` → `shared.jsx` → `hero.jsx` → `overview.jsx` →
   `feed.jsx` → `quarantine.jsx` → `drawer.jsx` → `policy.jsx` → `registries.jsx`
   → `app.jsx`) into a single `app.bundle.js`.

This preserves the current semantics 1:1 — the component code is not edited. React
and ReactDOM remain globals provided by the vendored UMD scripts.

### React/ReactDOM — local

Vendor the **production** UMD builds (current dev builds are swapped for prod) at
the same pinned version (18.3.1) into `web/console/vendor/`. They are embedded in
the binary and loaded before `app.bundle.js`.

## File layout

```
web/console/
  index.html              # edited: drop CDN+Babel; load vendor + app.bundle.js
  src/                    # sources — NOT embedded
    api.js, shared.jsx, hero.jsx, overview.jsx, feed.jsx,
    quarantine.jsx, drawer.jsx, policy.jsx, registries.jsx, app.jsx
  vendor/
    react.production.min.js
    react-dom.production.min.js
  app.bundle.js           # GENERATED, committed
  styles.css, screens.css, favicon-*.png
web/generate.go           # //go:generate directive + esbuild Transform/concat
```

`//go:embed` is adjusted so `src/` is **not** embedded (drop the `all:` prefix,
which would otherwise pull in everything; the bare `console` embed naturally
excludes a `_`-prefixed dir, or list members explicitly). Only the built artifact,
vendored React, CSS and favicons ship in the binary. (Exact mechanism — rename
`src` to `_src` vs. explicit embed list — is an implementation detail for the plan;
the requirement is: sources out of the binary, artifact + assets in.)

### index.html changes

Remove:
- the three `<script src="https://unpkg.com/...">` tags (React, ReactDOM, Babel);
- the per-file `<script type="text/babel" src="*.jsx">` tags and the `api.js` tag.

Add (in order):
```html
<script src="vendor/react.production.min.js"></script>
<script src="vendor/react-dom.production.min.js"></script>
<script src="app.bundle.js"></script>
```
The `<link>` to Google Fonts is left as-is (separate concern; out of scope).

## The generator

`web/generate.go` holds a `//go:generate go run` directive that builds the bundle.
It reads the ordered source list, runs `api.Transform` per file with:
- `Loader: api.LoaderJSX` (`.jsx`) / `LoaderJS` (`api.js`),
- `JSX: api.JSXTransform` with classic runtime (React global),
- `MinifyWhitespace: true`, `MinifySyntax: true`, `MinifyIdentifiers: false`,
- `Target: api.ES2017` (matches current browser assumptions).

It concatenates the outputs (each separated by a newline and a `// <file>` banner
comment for traceability) and writes `web/console/app.bundle.js`. A build error in
any file aborts generation with a non-zero exit.

esbuild is added to `go.mod` as `github.com/evanw/esbuild`. Because the generator
is invoked via `go run` it is a normal module dependency, not a separate install.

## CI gate

Add a step to `ci.yml` (`build-test` job), before the build, that ensures the
committed bundle matches the sources:

```yaml
- name: Verify console bundle is up to date
  run: |
    go generate ./...
    git diff --exit-code -- web/console/app.bundle.js
```

If `go generate` produces a different bundle than the committed one, the diff is
non-empty and the job fails, forcing the developer to regenerate and commit.

## Tests

`web/web_test.go`:
- Replace the `app.jsx` asset check with `app.bundle.js`.
- Add `vendor/react.production.min.js` and `vendor/react-dom.production.min.js` to
  the served-assets check.
- New test: `GET /console/` body does **not** contain `unpkg.com` or
  `text/babel` (regression guard against re-introducing the CDN/in-browser path).
- New test: `GET /console/` body **does** reference `app.bundle.js` and the
  vendored React.
- Confirm the `src/` directory is not served (e.g. `GET /console/src/app.jsx`
  returns 404), proving sources are not embedded.

## Documentation

- `web/web.go` package doc + `ConsoleHandler` comment: replace "React + Babel
  loaded in the browser … driven by client-side mock data" with the prebuilt-bundle
  description (compiled at build time, React vendored locally, no CDN).
- `README.md`: update the Admin Console paragraph that says "It loads React + Babel
  from a CDN, so the browser needs outbound internet access the first time it is
  opened." to state the console is fully self-contained and works offline.

## Out of scope (YAGNI)

- SSR / hydration / server-rendered HTML.
- Rewriting components to ES modules.
- CSS minification.
- Changes to the JSON API or SSE stream.
- Self-hosting Google Fonts.

## Risks

- **Top-level identifier collisions after concat.** Mitigated by
  `MinifyIdentifiers: false` (globals keep their names) and by the fact the same
  files already coexist in one global scope today.
- **Stale committed bundle.** Mitigated by the CI `git diff --exit-code` gate.
- **esbuild version drift changing output.** Pin esbuild in `go.mod`; the CI gate
  catches any unintended regeneration diff.
```
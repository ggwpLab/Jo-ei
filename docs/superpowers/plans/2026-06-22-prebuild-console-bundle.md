# Prebuild Console Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the admin console UI off in-browser Babel + CDN React onto a build-time esbuild bundle with vendored React, so the console renders client-side React with no runtime compilation and works offline.

**Architecture:** A pure-Go generator (`internal/uibuild`, esbuild as a library) transforms each `.jsx`/`.js` source (JSX→JS, minified) and concatenates them in dependency order into a single committed `app.bundle.js`. React/ReactDOM ship as vendored production UMD files. `index.html` loads the vendored React then the bundle. Sources move out of the embedded asset tree; only built artifacts are baked into the binary. CI regenerates and `git diff --exit-code`s the bundle to keep it in sync.

**Tech Stack:** Go 1.25, `github.com/evanw/esbuild` (Go library), React 18.3.1 (vendored UMD), `go:embed`, GitHub Actions.

## Global Constraints

- Go version floor: **1.25** (`go.mod`, CI `setup-go` 1.25).
- **No Node/npm** tooling: esbuild is used as a Go library via `go run` / `//go:generate`.
- React/ReactDOM pinned at **18.3.1**, **production** UMD builds (current dev builds are replaced).
- Bundling uses esbuild **Transform** (not `bundle:true`); **`MinifyIdentifiers: false`** so top-level globals are not renamed and cross-file references keep resolving.
- JSX uses the **classic runtime** (`React.createElement` global) — no automatic runtime, no import injection.
- The generated `app.bundle.js` is **committed**; CI fails if it is stale.
- Final state: console **sources are NOT embedded** in the binary — only `index.html`, `app.bundle.js`, `vendor/`, CSS and favicons.
- `gofmt`-clean and `golangci-lint`-clean (CI enforces both).

---

### Task 1: Vendor production React/ReactDOM locally

Bring React in-tree so the console no longer fetches it from a CDN. Sources are still embedded via the existing `all:console` directive, so the new `vendor/` files are served automatically.

**Files:**
- Create: `web/console/vendor/react.production.min.js` (downloaded)
- Create: `web/console/vendor/react-dom.production.min.js` (downloaded)
- Test: `web/web_test.go`

**Interfaces:**
- Consumes: existing `ConsoleHandler()` from `web/web.go`.
- Produces: vendored assets served at `/console/vendor/react.production.min.js` and `/console/vendor/react-dom.production.min.js`.

- [ ] **Step 1: Write the failing test**

Add to `web/web_test.go`:

```go
func TestConsoleServesVendoredReact(t *testing.T) {
	srv := http.NewServeMux()
	srv.Handle("/console/", ConsoleHandler())

	for _, asset := range []string{
		"vendor/react.production.min.js",
		"vendor/react-dom.production.min.js",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/console/"+asset, nil)
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET /console/%s status = %d, want 200", asset, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("GET /console/%s returned empty body", asset)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./web/ -run TestConsoleServesVendoredReact -v`
Expected: FAIL — both assets return 404 (files do not exist yet).

- [ ] **Step 3: Download the production UMD builds**

Run (creates the dir and fetches the pinned 18.3.1 production files):

```bash
mkdir -p web/console/vendor
curl -fsSL https://unpkg.com/react@18.3.1/umd/react.production.min.js \
  -o web/console/vendor/react.production.min.js
curl -fsSL https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js \
  -o web/console/vendor/react-dom.production.min.js
```

Verify they are real JS, not an error page:

```bash
head -c 80 web/console/vendor/react.production.min.js
# Expected: starts with a license banner like "/** @license React v18.3.1 ..."
wc -c web/console/vendor/*.js
# Expected: react ~ 10 KB, react-dom ~ 130 KB (non-trivial sizes)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./web/ -run TestConsoleServesVendoredReact -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add web/console/vendor/ web/web_test.go
git commit -m "feat(console): vendor production React/ReactDOM locally"
```

---

### Task 2: Add esbuild generator and switch the console to the prebuilt bundle

Create the pure-Go generator, produce `app.bundle.js`, and rewrite `index.html` to load vendored React + the bundle instead of CDN React/Babel and per-file `text/babel` scripts. Sources stay in `web/console/` for now (still embedded); Task 3 relocates them out of the binary.

**Files:**
- Create: `internal/uibuild/main.go`
- Create: `web/console/app.bundle.js` (generated, committed)
- Create: `.gitattributes`
- Modify: `web/web.go` (add `//go:generate` directive)
- Modify: `web/console/index.html`
- Modify: `web/web_test.go`
- Modify: `go.mod` / `go.sum` (esbuild dependency)

**Interfaces:**
- Consumes: source files `web/console/{api.js,shared.jsx,hero.jsx,overview.jsx,feed.jsx,quarantine.jsx,drawer.jsx,policy.jsx,registries.jsx,app.jsx}`.
- Produces: `web/console/app.bundle.js`; `go generate ./...` (re)builds it; `index.html` references `vendor/react.production.min.js`, `vendor/react-dom.production.min.js`, `app.bundle.js`.

- [ ] **Step 1: Write the failing tests**

In `web/web_test.go`, change the asset list in `TestConsoleHandlerServesAssets` from `"app.jsx"` to `"app.bundle.js"`:

```go
	for _, asset := range []string{"styles.css", "screens.css", "app.bundle.js", "favicon-32.png", "favicon-180.png"} {
```

Then add a regression-guard test:

```go
func TestConsoleIndexIsPrebuilt(t *testing.T) {
	srv := http.NewServeMux()
	srv.Handle("/console/", ConsoleHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/console/", nil)
	srv.ServeHTTP(rec, req)
	body := rec.Body.String()

	// No CDN, no in-browser compilation.
	for _, banned := range []string{"unpkg.com", "text/babel", "babel"} {
		if strings.Contains(body, banned) {
			t.Errorf("index.html still references %q; console must be prebuilt and self-hosted", banned)
		}
	}
	// Loads the prebuilt bundle and the vendored React.
	for _, want := range []string{"app.bundle.js", "vendor/react.production.min.js", "vendor/react-dom.production.min.js"} {
		if !strings.Contains(body, want) {
			t.Errorf("index.html does not reference %q", want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./web/ -run 'TestConsoleHandlerServesAssets|TestConsoleIndexIsPrebuilt' -v`
Expected: FAIL — `app.bundle.js` is 404 and `index.html` still contains `unpkg.com`/`text/babel`.

- [ ] **Step 3: Add the esbuild dependency**

Run:

```bash
go get github.com/evanw/esbuild@latest
```

Expected: `go.mod` gains a `github.com/evanw/esbuild vX.Y.Z` require line (a pinned version).

- [ ] **Step 4: Write the generator**

Create `internal/uibuild/main.go`:

```go
// Command uibuild compiles the Jōei console sources into a single minified
// app.bundle.js using esbuild, run via `go generate ./...`.
//
// The console files are NOT ES modules: they share one global lexical scope
// (shared.jsx declares top-level globals; the others reference them). So this
// does not module-bundle. Each file is transformed (JSX->JS, minified) and
// concatenated in dependency order, preserving the global-scope semantics. The
// working directory under `go generate` is the package dir of the directive
// (web/), so paths are relative to web/.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/evanw/esbuild/pkg/api"
)

// Concatenation order mirrors the historical <script> load order and encodes
// the dependency chain: api/shared first, the app shell last.
var sources = []string{
	"api.js",
	"shared.jsx",
	"hero.jsx",
	"overview.jsx",
	"feed.jsx",
	"quarantine.jsx",
	"drawer.jsx",
	"policy.jsx",
	"registries.jsx",
	"app.jsx",
}

const (
	srcDir  = "console" // Task 3 moves sources to "console/src".
	outFile = "console/app.bundle.js"
)

func main() {
	var b strings.Builder
	b.WriteString("/* GENERATED by internal/uibuild — do not edit. Run `go generate ./...`. */\n")
	for _, name := range sources {
		code, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			fail(err)
		}
		loader := api.LoaderJS
		if strings.HasSuffix(name, ".jsx") {
			loader = api.LoaderJSX
		}
		res := api.Transform(string(code), api.TransformOptions{
			Loader:            loader,
			JSX:               api.JSXTransform, // classic React.createElement
			Target:            api.ES2017,
			MinifyWhitespace:  true,
			MinifySyntax:      true,
			MinifyIdentifiers: false, // keep top-level globals stable across files
		})
		if len(res.Errors) > 0 {
			for _, e := range res.Errors {
				fmt.Fprintf(os.Stderr, "uibuild: %s: %s\n", name, e.Text)
			}
			os.Exit(1)
		}
		b.WriteString("\n/* " + name + " */\n")
		b.Write(res.Code)
	}
	if err := os.WriteFile(outFile, []byte(b.String()), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("uibuild: wrote %s (%d bytes)\n", outFile, b.Len())
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "uibuild:", err)
	os.Exit(1)
}
```

- [ ] **Step 5: Add the `//go:generate` directive**

In `web/web.go`, add the directive directly above the `//go:embed all:console` line:

```go
//go:generate go run github.com/ggwpLab/Jo-ei/internal/uibuild
//go:embed all:console
var consoleFiles embed.FS
```

- [ ] **Step 6: Generate the bundle**

Run:

```bash
go generate ./...
```

Expected: prints `uibuild: wrote console/app.bundle.js (NNNN bytes)` and creates `web/console/app.bundle.js`. Sanity-check it contains compiled output:

```bash
grep -c "createElement\|createRoot" web/console/app.bundle.js
# Expected: a non-zero count (JSX compiled to React.createElement; app mounts with createRoot)
```

- [ ] **Step 7: Pin bundle line endings**

Create `.gitattributes` so the committed bundle has stable LF endings on every platform (keeps the CI `git diff` gate deterministic):

```gitattributes
web/console/app.bundle.js text eol=lf
```

- [ ] **Step 8: Rewrite index.html to load the prebuilt assets**

In `web/console/index.html`, replace the entire block from the `<!-- React + Babel (pinned) -->` comment through the final `<script ... src="app.jsx"></script>` line with:

```html
  <!-- React (vendored, production) + prebuilt console bundle -->
  <script src="vendor/react.production.min.js"></script>
  <script src="vendor/react-dom.production.min.js"></script>
  <script src="app.bundle.js"></script>
```

Leave the `<div id="root"></div>`, the `<head>` (favicons, fonts, stylesheets) and everything else unchanged.

- [ ] **Step 9: Run tests and build to verify they pass**

Run:

```bash
go test ./web/ -run 'TestConsoleHandlerServesAssets|TestConsoleIndexIsPrebuilt|TestConsoleServesVendoredReact' -v
go build ./...
gofmt -l internal/uibuild/main.go web/web.go
```

Expected: tests PASS; build succeeds; `gofmt -l` prints nothing.

- [ ] **Step 10: Commit**

```bash
git add internal/uibuild/main.go web/web.go web/console/index.html web/console/app.bundle.js .gitattributes web/web_test.go go.mod go.sum
git commit -m "feat(console): prebuild the UI bundle with esbuild, drop CDN/Babel"
```

---

### Task 3: Move sources out of the embedded asset tree

Relocate the 10 source files into `web/console/src/` and narrow `//go:embed` so sources are not baked into the binary — only `index.html`, `app.bundle.js`, `vendor/`, CSS and favicons ship.

**Files:**
- Move: `web/console/{api.js,*.jsx}` → `web/console/src/`
- Modify: `internal/uibuild/main.go` (`srcDir`)
- Modify: `web/web.go` (`//go:embed` directives)
- Modify: `web/web_test.go`

**Interfaces:**
- Consumes: the generator and embed handler from Task 2.
- Produces: identical served `app.bundle.js`; sources unreachable at `/console/src/*` and absent from the binary.

- [ ] **Step 1: Write the failing test**

Add to `web/web_test.go`:

```go
func TestConsoleSourcesNotEmbedded(t *testing.T) {
	srv := http.NewServeMux()
	srv.Handle("/console/", ConsoleHandler())

	for _, src := range []string{"src/app.jsx", "src/api.js", "app.jsx"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/console/"+src, nil)
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET /console/%s status = %d, want 404 (sources must not ship in the binary)", src, rec.Code)
		}
	}
}
```

- [ ] **Step 2: Move the sources**

Run:

```bash
mkdir -p web/console/src
git mv web/console/api.js web/console/src/api.js
for f in shared hero overview feed quarantine drawer policy registries app; do
  git mv "web/console/$f.jsx" "web/console/src/$f.jsx"
done
```

- [ ] **Step 3: Point the generator at the new source dir**

In `internal/uibuild/main.go`, change:

```go
	srcDir  = "console" // Task 3 moves sources to "console/src".
```

to:

```go
	srcDir  = "console/src"
```

- [ ] **Step 4: Narrow the embed directives**

In `web/web.go`, replace:

```go
//go:embed all:console
var consoleFiles embed.FS
```

with (drop `all:`; list only shipped assets so `console/src` is excluded):

```go
//go:embed console/index.html console/app.bundle.js console/styles.css console/screens.css
//go:embed console/favicon-16.png console/favicon-32.png console/favicon-48.png console/favicon-180.png console/favicon-512.png
//go:embed console/vendor
var consoleFiles embed.FS
```

`fs.Sub(consoleFiles, "console")` in `ConsoleHandler()` is unchanged.

- [ ] **Step 5: Regenerate and verify nothing changed in the bundle**

Run:

```bash
go generate ./...
git diff --exit-code -- web/console/app.bundle.js
```

Expected: exit code 0 — relocating sources must not alter the bundle bytes (same inputs, same order).

- [ ] **Step 6: Run tests and build**

Run:

```bash
go test ./web/ -v
go build ./...
```

Expected: all `web` tests PASS (including `TestConsoleSourcesNotEmbedded`); build succeeds.

- [ ] **Step 7: Commit**

```bash
git add web/console/ internal/uibuild/main.go web/web.go web/web_test.go
git commit -m "refactor(console): keep UI sources out of the embedded binary"
```

---

### Task 4: Add the CI bundle-freshness gate

Make CI regenerate the bundle and fail if the committed artifact is stale, so the bundle can never drift from its sources.

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `go generate ./...` from Tasks 2–3.
- Produces: a CI step that fails on a stale `app.bundle.js`.

- [ ] **Step 1: Verify the gate passes locally first**

Run:

```bash
go generate ./...
git diff --exit-code -- web/console/app.bundle.js
```

Expected: exit code 0 (clean) — the committed bundle already matches the sources.

- [ ] **Step 2: Add the CI step**

In `.github/workflows/ci.yml`, inside the `build-test` job, insert a step between `gofmt` and `Build`:

```yaml
      - name: Verify console bundle is up to date
        run: |
          go generate ./...
          if ! git diff --exit-code -- web/console/app.bundle.js; then
            echo "app.bundle.js is stale: run 'go generate ./...' and commit the result"; exit 1
          fi
```

- [ ] **Step 3: Validate the workflow YAML**

Run:

```bash
python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml OK')"
```

Expected: `ci.yml OK` (no YAML syntax error).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(console): fail the build when the prebuilt bundle is stale"
```

---

### Task 5: Update documentation

Correct the package doc and README, which still describe the CDN/in-browser-Babel model.

**Files:**
- Modify: `web/web.go` (package doc + `ConsoleHandler` comment)
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: documentation consistent with the prebuilt-bundle architecture.

- [ ] **Step 1: Update the package doc in web/web.go**

Replace the package comment:

```go
// Package web embeds the Jōei admin console (浄衛 — The Purification Gate) and
// serves it as static assets. The console is a self-contained React single-page
// app (React + Babel loaded in the browser) driven by client-side mock data; it
// is baked into the binary via go:embed so it ships inside the distroless image
// with no extra files at runtime.
package web
```

with:

```go
// Package web embeds the Jōei admin console (浄衛 — The Purification Gate) and
// serves it as static assets. The console is a self-contained React single-page
// app: its JSX sources are compiled to a single minified app.bundle.js at build
// time (see internal/uibuild, run via `go generate`), and React/ReactDOM are
// vendored locally. No CDN and no in-browser compilation, so the console works
// offline. The built assets are baked into the binary via go:embed so it ships
// inside the distroless image with no extra files at runtime.
package web
```

- [ ] **Step 2: Update the README console paragraph**

In `README.md`, find the paragraph under "## Admin Console" containing:

```
The console reads live proxy state via the JSON API described below. It loads React + Babel
from a CDN, so the browser needs outbound internet access the first time it is opened.
```

Replace it with:

```
The console reads live proxy state via the JSON API described below. React and the
console UI are compiled to a single bundle baked into the binary — it needs no CDN
and works fully offline.
```

This is the only paragraph in `README.md` that mentions the CDN; the "single-page app baked into the binary (no extra files at runtime)" sentence above it is already accurate — leave it unchanged.

- [ ] **Step 3: Verify the CDN claim is gone**

Run:

```bash
grep -rn "from a CDN\|React + Babel" README.md web/web.go
```

Expected: no matches (the stale claims are removed).

- [ ] **Step 4: Build to confirm the doc comment still compiles**

Run: `go build ./...`
Expected: success.

- [ ] **Step 5: Commit**

```bash
git add web/web.go README.md
git commit -m "docs(console): describe the prebuilt offline bundle"
```

---

## Notes for the implementer

- **Offline caveat:** Task 1 Step 3 downloads React from unpkg once. If the build host is offline, fetch the two files on a connected machine and copy them in — they are the only network step in the whole plan.
- **esbuild output stability:** the bundle bytes depend on the pinned esbuild version. Do not bump `github.com/evanw/esbuild` without regenerating and committing `app.bundle.js` in the same change, or CI (Task 4) will fail.
- **Why concatenation, not `bundle:true`:** the sources rely on a shared global scope, not `import`/`export`. Module bundling would wrap each file in its own scope and break cross-file references (`Icons`, `JOEI`, `useState`, …). Keep `MinifyIdentifiers: false`.

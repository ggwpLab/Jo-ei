# Open Source Release Preparation Plan

Status: **completed** (phases 1–6 executed in PRs #37–#42, 2026-07-04/05) ·
Scope: audit of the repository as of 2026-07-04 and the roadmap to a public
open source release. Kept as a historical record; the findings below describe
the pre-release state. Outcomes beyond the plan: the `JOEI_*` env-override
mechanism turned out to be broken and was fixed (PR #40), and a Windows
test flake was root-caused to SQLite handle release timing (PR #37).
Remaining follow-ups: config-struct decoupling (assessed low-value, skipped),
goreleaser `dockers_v2` migration when the old syntax is removed, README
console screenshot.

---

## 1. Current State

Jōei is a supply-chain security proxy for package registries (PyPI, npm, Maven,
RubyGems) and Docker images. Single Go module (`github.com/ggwpLab/Jo-ei`),
~8.5k lines of production Go, ~10k lines of tests, plus an embedded React
admin console compiled with esbuild (no npm toolchain).

```
cmd/jo-ei/            CLI entrypoint + composition root (cobra)
internal/
  auth/               console HTTP Basic auth (bcrypt users)
  cache/              artifact cache (index + local store + revalidation hooks)
  config/             viper config loading & validation
  console/            admin console REST API + SSE events
  health/             scanner health probes & registry
  httpx/              upstream rate limiting, concurrency, circuit breaker
  policy/             policy engine + runtime settings (persisted)
  proxy/              domain types & ports + HTTP gate handler + mux
    adapters/         PyPI / npm / Maven / RubyGems registry adapters
    dockerproxy/      Docker Registry v2 pull-through proxy + Trivy gate
  revalidate/         cache revalidation sweeper
  scanner/            CVE (osv.dev), ClamAV, ICAP scanners + concurrency limits
  settings/           SQLite-backed settings store
  storage/            SQLite bootstrap
  supplychain/        min-age (24h) filter + allowlists
  telemetry/          event log, aggregates, SSE broadcaster (SQLite)
  uibuild/            esbuild bundler for the console (go:generate)
web/                  embedded console assets (JSX sources + prebuilt bundle)
integration/          black-box integration tests (build tag `integration`)
docs/superpowers/     internal design specs & implementation plans
```

### What is already in good shape

- **Tests**: 70–98% statement coverage per package; integration suite runs
  in-process with no external services; CI runs everything with `-race`.
- **Lint**: `golangci-lint` (errcheck, govet, staticcheck, unused, misspell,
  gofmt, goimports) passes with zero issues.
- **No dead code**: `deadcode ./...` flags only two exported test helpers
  (`policy.NewRuntime`, `Sweeper.SweepOnceForTest`), both used by tests.
- **No dependency cycles**; `internal/` is used correctly (nothing internal is
  importable from outside the module).
- **Idiomatic Go**: `context.Context` first-arg throughout, `%w` error
  wrapping (100+ sites), structured logging via zerolog, interfaces defined at
  the consumer side.
- **Ops story**: distroless non-root Docker image, docker-compose with ClamAV
  and Trivy sidecars, `.env.example` with documented secrets flow,
  `.gitattributes` for cross-platform line endings.
- **README**: thorough — quick start, per-ecosystem client config, console
  auth, block-response reference, build-from-source.

## 2. Findings

### 2.1 Architecture

The codebase is pragmatic hexagonal, not textbook Clean Architecture — and at
this size that is the right call. The dependency direction is correct:

```
cmd/jo-ei ──► everything (composition root)
internal/proxy ──► (nothing internal)        ← de facto domain package
all other packages ──► internal/proxy        ← ports defined here
```

`internal/proxy/adapter.go` holds the domain vocabulary (`PackageRef`,
`Severity`, `ScanResult`, `PolicyDecision`) and the ports (`RegistryAdapter`,
`CVEScanner`, `AVScanner`, `PolicyDecider`, `SCFilter`). Every implementation
package (scanner, supplychain, policy, adapters) depends inward on it. That is
dependency inversion working as intended.

Violations / friction points:

| # | Finding | Severity |
|---|---------|----------|
| A1 | **`internal/proxy` mixes layers**: domain types + ports live in the same package as the HTTP gate handler, mux, and response recorder. 11 packages import it just for the types, dragging `net/http` handler code into their dependency surface. | Medium |
| A2 | **`internal/config` leaks into business logic**: `cache`, `scanner`, `supplychain`, `policy` accept viper-shaped config structs instead of plain parameters. Business packages are coupled to the config-file schema. | Low–Medium |
| A3 | **`cmd/jo-ei/main.go` is a 599-line composition root.** Acceptable for a single binary, but wiring for scanners / registries / console could move to named helpers or an `internal/app` bootstrap package. | Low |
| A4 | **Framework independence is otherwise good**: cobra/viper stop at `cmd` + `config`; zerolog is the only cross-cutting framework dependency. | — |

**Verdict**: no full Clean Architecture restructuring is warranted. One
targeted extraction (A1) removes the only real leak.

### 2.2 Go best practices

| # | Finding | Severity |
|---|---------|----------|
| G1 | **Direct dependencies are stale.** `golang.org/x/crypto` v0.21.0 (bcrypt lives here — security-relevant), `testify` v1.9.0, `viper` v1.19.0, `fsnotify` v1.7.0 and the whole transitive tree are 1.5+ years behind. No `replace` directives (good). | High |
| G2 | **Flaky test on Windows**: `internal/console` intermittently fails with `TempDir … empty` during parallel `go test ./...` (SQLite file handle not closed before `t.TempDir()` cleanup). Passes in isolation. | Medium |
| G3 | Package layout is clean; no god-packages by size (largest non-main file is `console/server.go` at 555 lines, cohesive). `proxy` is a god-package only in the A1 sense. | Low |
| G4 | Test-only exported helpers (`NewRuntime`, `SweepOnceForTest`) are documented as such; acceptable, keep. | Info |

### 2.3 Open source readiness

| Item | Status | Notes |
|------|--------|-------|
| README.md | ✅ Strong | Add badges (CI, Go Report Card, license), a screenshot of the console, and a "Contributing" pointer. Replace `git clone <repo-url>` placeholder with the real URL. |
| LICENSE | ✅ MIT | — |
| .gitignore | ⚠️ Minimal | Missing `.superpowers/` (currently untracked but not ignored), coverage artifacts (`*.out`). |
| Makefile | ✅ | Add `integration`, `generate`, `cover` targets for parity with CI. |
| CI | ⚠️ | Solid pipeline (fmt, bundle freshness, build, unit+integration `-race`, golangci-lint) but still triggers on the deleted `develop` branch. No release job. |
| CONTRIBUTING.md | ❌ Missing | Dev setup, test/lint commands, branch+PR workflow, `go generate` for the console bundle. |
| CODE_OF_CONDUCT.md | ❌ Missing | Contributor Covenant 2.1. |
| SECURITY.md | ❌ Missing | Essential for a *security* product: private disclosure channel, supported versions. |
| CHANGELOG.md | ❌ Missing | Start at v0.1.0; Keep a Changelog format. |
| Issue / PR templates | ❌ Missing | `.github/ISSUE_TEMPLATE/`, `PULL_REQUEST_TEMPLATE.md`. |
| docs/ | ⚠️ Internal only | Contains only internal design specs/plans (`docs/superpowers/`). Fine to keep as engineering history, but user-facing docs (configuration reference, architecture overview) should exist at `docs/` top level. |
| examples/ | ❌ Missing | Per-ecosystem client configs (pip.conf, .npmrc, settings.xml, Gemfile, daemon.json) + a copy-paste compose setup. |
| Releases | ❌ Missing | No version embedding (`-ldflags -X`), no tags, no goreleaser, no published Docker image (`ghcr.io`). |

### 2.4 Frontend / backend separation

Already separated correctly, no mixing found:

- Backend API: `internal/console` (REST + SSE), auth in `internal/auth`.
- Frontend: `web/console/` — self-contained React SPA, JSX sources compiled by
  `internal/uibuild` (esbuild via Go, run through `go generate`), vendored
  React, output embedded with `go:embed`.

**Recommendation: keep the monorepo `/web` layout.** Rationale:

1. The product ships as a **single binary / distroless image** with the console
   baked in — a separate frontend repo would break that and add a release
   coordination problem.
2. There is **no npm toolchain** to isolate: the bundler is a Go program, so
   the frontend imposes zero extra contributor setup.
3. CI already enforces bundle freshness (`go generate` + diff check), so the
   committed bundle cannot drift from sources.
4. The console is small (9 JSX files) and versioned in lockstep with the API
   it talks to.

Splitting into `/web` (assets) vs `internal/console` (API) is exactly the
"structure it inside the repo" option — it is already done.

## 3. Target Architecture

One structural change (extract the domain package), plus additive
documentation directories. Renames are deliberately avoided where the churn
outweighs the benefit.

```
Jo-ei/
├── cmd/jo-ei/                  # CLI + composition root (slimmed via internal/app helpers — optional)
├── internal/
│   ├── gate/                   # ★ NEW: domain types & ports (moved from internal/proxy/adapter.go)
│   │   └── gate.go             #   PackageRef, Severity, ScanResult, PolicyDecision,
│   │                           #   RegistryAdapter, CVEScanner, AVScanner, PolicyDecider, SCFilter
│   ├── proxy/                  # HTTP gate handler + mux + recorder (imports gate)
│   │   ├── adapters/           # registry adapters (import gate, not proxy)
│   │   └── dockerproxy/        # Docker v2 proxy (imports gate, cache, health)
│   ├── auth/ cache/ config/ console/ health/ httpx/ policy/
│   ├── revalidate/ scanner/ settings/ storage/ supplychain/ telemetry/
│   └── uibuild/
├── web/                        # embedded console (unchanged)
├── integration/                # integration tests (unchanged)
├── examples/                   # ★ NEW: client configuration per ecosystem
├── docs/
│   ├── architecture.md         # ★ NEW: package map + dependency rules
│   ├── configuration.md        # ★ NEW: full config.yaml reference
│   ├── release-preparation-plan.md
│   └── superpowers/            # internal design history (kept)
├── CONTRIBUTING.md  CODE_OF_CONDUCT.md  SECURITY.md  CHANGELOG.md   # ★ NEW
└── .github/ISSUE_TEMPLATE/  PULL_REQUEST_TEMPLATE.md  workflows/release.yml  # ★ NEW
```

After the `gate` extraction the import graph becomes strictly layered:

```
cmd ──► proxy/console/… ──► gate ◄── scanner/supplychain/policy/adapters
                             ▲
                    (gate imports only stdlib)
```

Packages to **merge/split/rename/move**:

| Action | What | Why |
|--------|------|-----|
| Split | `internal/proxy/adapter.go` → `internal/gate` | A1: domain/ports out of the HTTP layer; type aliases in `proxy` keep the diff mechanical |
| Keep | `internal/proxy` name | It genuinely is the proxy HTTP layer once types move out |
| Keep | everything else | Cohesive, well-tested, correctly layered |
| Optional (post-release) | narrow `config.*Config` params in `cache`/`scanner`/`supplychain`/`policy` constructors | A2; low value relative to churn, do opportunistically |

## 4. Cleanup List

- **Dead code**: none to remove (deadcode + `unused` linter both clean).
- **Dependencies**: `go get -u ./... && go mod tidy` — priority on
  `golang.org/x/crypto` (bcrypt), then re-run full test suite. Consider
  enabling Dependabot/Renovate for `gomod` + `github-actions`.
- **CI**: drop `develop` from trigger branches (branch deleted 2026-06-14).
- **.gitignore**: add `.superpowers/`, `*.out`.
- **README**: replace `<repo-url>` placeholder; add badges + contributing link.
- **Flaky test**: fix `internal/console` Windows TempDir teardown (close the
  SQLite store before test end; likely a missing `defer store.Close()` or
  `t.Cleanup` ordering).

## 5. Roadmap

### Phase 1 — Hygiene & security (High, ~1 day)

1. Update dependencies (`x/crypto` first), `go mod tidy`, full test run.
2. Fix the flaky `internal/console` Windows test.
3. CI: remove `develop` triggers; add Go build cache; pin golangci-lint version.
4. `.gitignore` additions; README placeholder fix.
5. Add **SECURITY.md** (disclosure policy — non-negotiable for a security tool).

### Phase 2 — Community files (High, ~1 day)

6. CONTRIBUTING.md (setup, `make test` / `make lint` / `go generate`, branch+PR
   workflow, integration-test tag).
7. CODE_OF_CONDUCT.md (Contributor Covenant 2.1).
8. Issue templates (bug / feature) + PR template.
9. README badges + console screenshot.

### Phase 3 — Refactor (Medium, 1–2 days)

10. Extract `internal/gate` from `internal/proxy/adapter.go`; update imports
    mechanically (compiler-driven); keep temporary type aliases if needed.
11. Optional: split `cmd/jo-ei/main.go` wiring into named build helpers.
12. Full test + lint + integration pass.

### Phase 4 — Docs & examples (Medium, 1–2 days)

13. `docs/configuration.md` — every config key, env override, default.
14. `docs/architecture.md` — package map, dependency rule, gate pipeline
    diagram.
15. `examples/` — pip.conf, .npmrc, Maven settings.xml, bundler config, Docker
    daemon.json / registry mirror setup, compose quick-start.

### Phase 5 — Release engineering (Medium, ~1 day)

16. Version embedding via `-ldflags "-X main.version=..."` + `--version` flag.
17. goreleaser (or a release workflow): multi-platform binaries, checksums,
    Docker image publish to `ghcr.io/ggwplab/jo-ei`, triggered on tags.
18. CHANGELOG.md; tag **v0.1.0**.

### Phase 6 — Nice-to-have (Low, post-release)

19. Config-struct decoupling (A2) done opportunistically.
20. Dependabot/Renovate; CodeQL / govulncheck CI job.
21. Go Report Card, pkg.go.dev badge, `golangci-lint` strictness bump
    (e.g. `revive`, `gosec`).

**Total estimated effort: 5–7 working days.**

---

*Generated as part of the open source release preparation audit, 2026-07-04.*

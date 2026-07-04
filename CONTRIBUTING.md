# Contributing to Jōei

Thanks for your interest in improving Jōei! This document covers everything you
need to get a change from idea to merged PR.

## Development Setup

**Prerequisites:** Go 1.25+ and git. That's it — the admin console is built by
a Go program ([`internal/uibuild`](internal/uibuild/main.go), esbuild via its
Go API), so there is **no Node/npm toolchain** to install.

```bash
git clone https://github.com/ggwpLab/Jo-ei.git
cd Jo-ei
go build ./...           # or: make build
go test ./...            # unit tests
```

Optional, for exercising the full stack locally: Docker + Docker Compose
(ClamAV and Trivy sidecars). See the [README quick start](README.md#quick-start).

### Line endings

The repository stores all text as **LF** and `.gitattributes` enforces it —
works out of the box on Linux, macOS, and Windows regardless of
`core.autocrlf`. Don't fight it; gofmt and CI both assume LF.

## Making Changes

### Workflow

1. Fork (or branch, if you have write access) off `main`.
2. Use a descriptive branch name: `fix/docker-cache-verdict`,
   `feat/gomod-adapter`, `docs/config-reference`.
3. Keep PRs focused — one logical change per PR.
4. Open the PR against `main`.

### Commit messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): imperative summary` — e.g. `fix(console): report database
persistence when policy store is wired`. Types in use: `feat`, `fix`, `test`,
`refactor`, `docs`, `build`, `ci`, `chore`, `perf`. Add a body when the *why*
isn't obvious from the diff.

### Tests

Every behavior change needs a test. The project is heavily test-driven
(test code outnumbers production code):

```bash
go test ./...                                  # unit tests
go test -tags integration ./integration/...   # integration tests (in-process mocks, no external services)
go test ./... -race                            # what CI runs (needs cgo; skip -race on Windows without a C toolchain)
```

Test helpers worth knowing:

- `internal/storage/storagetest.TempDir(t)` — use instead of `t.TempDir()`
  whenever the test creates a SQLite database in a temp dir (Windows handle
  release is slightly asynchronous; this helper's cleanup retries).

### The console bundle

`web/console/app.bundle.js` is a **generated, committed** artifact. If you
touch anything under `web/console/src/`, regenerate and commit the bundle:

```bash
go generate ./...
```

CI fails the build if the bundle is stale.

### Lint & format

CI runs [golangci-lint](https://golangci-lint.run/) v2 (see
[.golangci.yml](.golangci.yml)) and a strict `gofmt` check:

```bash
make lint     # golangci-lint run
make fmt      # gofmt -w .
```

Run both before pushing — the lint gate is more than `go vet` (staticcheck,
unused, ineffassign, errcheck, misspell, goimports).

## Before You Open a PR

- [ ] `go build ./...` passes
- [ ] `go test ./...` and `go test -tags integration ./integration/...` pass
- [ ] `make lint` reports 0 issues
- [ ] `go generate ./...` produces no diff (if you touched the console)
- [ ] Commits follow Conventional Commits

## Reporting Issues

- **Bugs / feature requests** — use the issue templates.
- **Security vulnerabilities** — do **not** open a public issue; follow
  [SECURITY.md](SECURITY.md).

## Architecture Orientation

Start with [docs/release-preparation-plan.md](docs/release-preparation-plan.md)
for a package map. The short version: `internal/proxy` holds the domain types
and ports (`RegistryAdapter`, `CVEScanner`, `AVScanner`, …); scanners,
registry adapters, the policy engine, and the cache all implement or consume
those interfaces; `cmd/jo-ei` wires everything together. Design documents for
every shipped feature live under `docs/superpowers/`.

## Code of Conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).

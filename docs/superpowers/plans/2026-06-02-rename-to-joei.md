# Rename `sca-proxy` → `Jōei` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace every live occurrence of the old working name `sca-proxy` / `SCA Proxy` with the new project name **Jōei** (macron form in display text, ASCII fallbacks in import paths, env vars, headers, and filesystem paths).

**Architecture:** A pure rename refactor. No behavior changes. The Go module path is rewritten in one mechanical sweep; the command directory is moved with `git mv`; remaining machine identifiers and display strings are edited file-by-file. The existing test suite plus a final repo-wide `grep` are the verification harness.

**Tech Stack:** Go 1.25, cobra (CLI), viper (config), zerolog (logging), testify (tests).

**Spec:** `docs/superpowers/specs/2026-06-02-rename-to-joei-design.md`

**Name mapping (reference):**

| Context | Old | New |
|---|---|---|
| Module path | `github.com/sca-proxy/sca-proxy` | `github.com/ggwpLab/Jo-ei` |
| Command dir | `cmd/sca-proxy/` | `cmd/jo-ei/` |
| Binary / build slug | `sca-proxy` | `jo-ei` |
| Display name | `SCA Proxy` | `Jōei` |
| Env prefix | `SCAPROXY_` | `JOEI_` |
| HTTP header | `X-SCA-Proxy-Cache` | `X-Joei-Cache` |
| Filesystem paths | `/var/cache/sca-proxy`, `/etc/sca-proxy` | `/var/cache/jo-ei`, `/etc/jo-ei` |

---

### Task 1: Rewrite the Go module path

**Files:**
- Modify: `go.mod` (line 1, `module` directive)
- Modify: all `.go` files importing `github.com/sca-proxy/sca-proxy/...` (38 files)

- [ ] **Step 1: Run a build to confirm the starting state is green**

Run: `go build ./...`
Expected: builds with no errors (baseline).

- [ ] **Step 2: Rewrite the module path in `go.mod` and every `.go` file**

```bash
sed -i 's#github.com/sca-proxy/sca-proxy#github.com/ggwpLab/Jo-ei#g' go.mod
grep -rl 'github.com/sca-proxy/sca-proxy' --include='*.go' . \
  | xargs sed -i 's#github.com/sca-proxy/sca-proxy#github.com/ggwpLab/Jo-ei#g'
```

- [ ] **Step 3: Confirm zero import-path occurrences remain**

Run: `grep -rn 'github.com/sca-proxy/sca-proxy' . | grep -v '/.git/'`
Expected: no output.

- [ ] **Step 4: Verify the module still builds**

Run: `go build ./...`
Expected: builds with no errors (the `cmd/sca-proxy` directory still exists at this point — that is fine, package paths are derived from the module path, not the folder name).

- [ ] **Step 5: Commit**

```bash
git add go.mod $(git diff --name-only)
git commit -m "refactor: rename Go module path to github.com/ggwpLab/Jo-ei"
```

---

### Task 2: Move the command directory and update its display strings

**Files:**
- Move: `cmd/sca-proxy/` → `cmd/jo-ei/`
- Modify: `cmd/jo-ei/main.go` (lines 24, 25, 142)
- Modify: `.claude/settings.local.json` (lines 26-27 path references)

- [ ] **Step 1: Move the directory with git (preserves history)**

```bash
git mv cmd/sca-proxy cmd/jo-ei
```

- [ ] **Step 2: Update the cobra command name, short description, and startup log**

In `cmd/jo-ei/main.go`, make these three exact edits:

Replace:
```go
	Use:   "sca-proxy",
	Short: "SCA Proxy — transparent supply chain security proxy for package registries",
```
with:
```go
	Use:   "jo-ei",
	Short: "Jōei — transparent supply chain security proxy for package registries",
```

Replace:
```go
		Msg("SCA Proxy starting")
```
with:
```go
		Msg("Jōei starting")
```

- [ ] **Step 3: Update the stale path references in `.claude/settings.local.json`**

Replace `cmd/sca-proxy/main.go` with `cmd/jo-ei/main.go` on both lines:
```bash
sed -i 's#cmd/sca-proxy/main.go#cmd/jo-ei/main.go#g' .claude/settings.local.json
```

- [ ] **Step 4: Verify the build still works from the new path**

Run: `go build ./...`
Expected: builds with no errors.

- [ ] **Step 5: Verify the binary reports the new name**

Run: `go run ./cmd/jo-ei --help 2>&1 | head -3`
Expected: output contains `Jōei — transparent supply chain security proxy` and usage line `jo-ei`.

- [ ] **Step 6: Commit**

```bash
git add cmd .claude/settings.local.json
git commit -m "refactor: move cmd dir to cmd/jo-ei and update CLI display name to Jōei"
```

---

### Task 3: Rename the HTTP cache header

**Files:**
- Modify: `internal/proxy/handler.go:337`
- Test: `internal/proxy/handler_test.go:223`, `integration/phase1_test.go:164`

- [ ] **Step 1: Run the existing handler test to confirm it passes with the old header**

Run: `go test ./internal/proxy/ -run TestHandler -count=1`
Expected: PASS (baseline; exact test names may vary — the suite is green).

- [ ] **Step 2: Rename the header in the handler and both tests**

```bash
sed -i 's/X-SCA-Proxy-Cache/X-Joei-Cache/g' \
  internal/proxy/handler.go internal/proxy/handler_test.go integration/phase1_test.go
```

- [ ] **Step 3: Confirm no old header name remains**

Run: `grep -rn 'X-SCA-Proxy-Cache' . | grep -v '/.git/'`
Expected: no output.

- [ ] **Step 4: Run the proxy unit tests**

Run: `go test ./internal/proxy/ -count=1`
Expected: PASS (the cache-HIT test now asserts `X-Joei-Cache`).

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/handler.go internal/proxy/handler_test.go integration/phase1_test.go
git commit -m "refactor: rename cache header to X-Joei-Cache"
```

---

### Task 4: Rename the environment variable prefix in config

**Files:**
- Modify: `internal/config/config.go:140` (comment), `:144` (`SetEnvPrefix`)

- [ ] **Step 1: Update the prefix and its doc comment**

In `internal/config/config.go`, replace:
```go
// Environment variables prefixed with SCAPROXY_ override file values.
```
with:
```go
// Environment variables prefixed with JOEI_ override file values.
```

Replace:
```go
	v.SetEnvPrefix("SCAPROXY")
```
with:
```go
	v.SetEnvPrefix("JOEI")
```

- [ ] **Step 2: Confirm no `SCAPROXY` remains in the config package**

Run: `grep -rn 'SCAPROXY' internal/`
Expected: no output.

- [ ] **Step 3: Run the config tests**

Run: `go test ./internal/config/ -count=1`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/config/config.go
git commit -m "refactor: rename env var prefix to JOEI_"
```

---

### Task 5: Rename the cache path in `config.yaml`

**Files:**
- Modify: `config.yaml:49`

- [ ] **Step 1: Update the default cache directory**

Replace:
```yaml
    path: "/var/cache/sca-proxy"
```
with:
```yaml
    path: "/var/cache/jo-ei"
```

- [ ] **Step 2: Confirm the config still loads**

Run: `go run ./cmd/jo-ei --config config.yaml --help >/dev/null 2>&1; echo "exit: $?"`
Expected: `exit: 0` (config parses; `--help` exits cleanly).

- [ ] **Step 3: Commit**

```bash
git add config.yaml
git commit -m "refactor: rename default cache path to /var/cache/jo-ei"
```

---

### Task 6: Sweep build and deploy files

**Files:**
- Modify: `Makefile`, `Dockerfile`, `docker-compose.yaml`, `.gitignore`

These files use the lowercase `sca-proxy` slug for the binary, service name, and
filesystem paths (`/etc/sca-proxy`, `/var/cache/sca-proxy`), plus the uppercase
`SCAPROXY_` env prefix in compose. Replace both forms.

- [ ] **Step 1: Replace the lowercase slug and the env prefix across all four files**

```bash
sed -i -e 's#sca-proxy#jo-ei#g' -e 's#SCAPROXY_#JOEI_#g' \
  Makefile Dockerfile docker-compose.yaml .gitignore
```

- [ ] **Step 2: Confirm no old name remains in these files**

Run: `grep -niE 'sca[-_]?proxy' Makefile Dockerfile docker-compose.yaml .gitignore`
Expected: no output.

- [ ] **Step 3: Verify the Makefile build target works**

Run: `make build && ls -la bin/jo-ei`
Expected: build succeeds and `bin/jo-ei` exists.

- [ ] **Step 4: Verify the Dockerfile and compose file still parse**

Run: `docker compose -f docker-compose.yaml config >/dev/null && echo OK`
Expected: `OK` (or skip this step if Docker is unavailable in the environment — the `grep` in Step 2 is the gate).

- [ ] **Step 5: Commit**

```bash
git add Makefile Dockerfile docker-compose.yaml .gitignore
git commit -m "refactor: rename binary, paths, and env prefix in build/deploy files"
```

---

### Task 7: Sweep the README

**Files:**
- Modify: `README.md`

The README mixes display name (header, prose, ASCII box), the HTTP header, the
env prefix, the cache path, the clone directory, and build commands.

- [ ] **Step 1: Replace machine identifiers (header, env prefix, cache path, binary slug)**

```bash
sed -i \
  -e 's#X-SCA-Proxy-Cache#X-Joei-Cache#g' \
  -e 's#SCAPROXY_#JOEI_#g' \
  -e 's#/var/cache/sca-proxy#/var/cache/jo-ei#g' \
  -e 's#bin/sca-proxy#bin/jo-ei#g' \
  -e 's#./cmd/sca-proxy#./cmd/jo-ei#g' \
  README.md
```

- [ ] **Step 2: Fix the clone directory line**

The clone line `git clone <repo-url> && cd sca-proxy` should point at the repo
folder `Jo-ei`. Replace:
```bash
sed -i 's#&& cd sca-proxy#\&\& cd Jo-ei#g' README.md
```

- [ ] **Step 3: Update the display-name header and intro prose (macron form)**

Replace the H1:
```markdown
# sca-proxy
```
with:
```markdown
# Jōei
```

Replace in the intro paragraph:
```markdown
Point your package manager at sca-proxy instead of the upstream registry — it intercepts
```
with:
```markdown
Point your package manager at Jōei instead of the upstream registry — it intercepts
```

- [ ] **Step 4: Re-pad the ASCII diagram box line**

The box has 45 inner columns between the `│` borders. `SCA Proxy :8080` (15 cols)
becomes `Jōei :8080` (10 cols), so it must be re-centered to keep the right border
aligned (17 leading spaces + `Jōei :8080` + 18 trailing spaces).

Replace this exact line:
```
  │               SCA Proxy :8080               │
```
with this exact line:
```
  │                 Jōei :8080                  │
```

(`ō` renders as one monospace column, so the right `│` stays aligned with the box.)

- [ ] **Step 5: Confirm no old name remains in the README**

Run: `grep -niE 'sca[-_ ]?proxy|SCAPROXY' README.md`
Expected: no output.

- [ ] **Step 6: Visually verify the ASCII box border alignment**

Run: `sed -n '10,18p' README.md`
Expected: the `┌`, content lines, and `└` rows all end their right border `│`/`┐`/`┘` in the same column.

- [ ] **Step 7: Commit**

```bash
git add README.md
git commit -m "docs: rename README to Jōei (display name, header, paths, env prefix)"
```

---

### Task 8: Final repo-wide verification

**Files:** none (verification only)

- [ ] **Step 1: Build the whole module**

Run: `go build ./...`
Expected: no errors.

- [ ] **Step 2: Vet**

Run: `go vet ./...`
Expected: no errors.

- [ ] **Step 3: Run all unit tests**

Run: `go test ./... -count=1`
Expected: all PASS.

- [ ] **Step 4: Run integration tests (if the environment supports them)**

Run: `go test -tags integration ./integration/... -count=1`
Expected: all PASS. (Integration tests require the `integration` build tag and may
need network/ClamAV; if the environment cannot run them, note it and rely on the
unit suite + grep gate.)

- [ ] **Step 5: Confirm zero `sca-proxy` references remain in live files**

Run:
```bash
grep -rniE 'sca[-_ ]?proxy|SCAPROXY' . \
  | grep -v '/.git/' | grep -v '/docs/'
```
Expected: no output. (Historical files under `docs/` are intentionally untouched
per the spec; the new `2026-06-02-rename-to-joei*` files reference the old name
only inside mapping tables, which is correct.)

- [ ] **Step 6: Confirm the new module path is consistent**

Run: `grep '^module' go.mod`
Expected: `module github.com/ggwpLab/Jo-ei`.

---

## Notes for the executor

- This branch is `refactor/rename-to-joei`, based on `develop`. Per the project
  workflow, the final PR targets `develop` and is opened by the user (this
  environment cannot push or open PRs).
- Do not modify files under `docs/superpowers/specs/` or `docs/superpowers/plans/`
  other than this plan and its spec — they are historical records (spec decision).

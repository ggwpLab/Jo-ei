# Rename `sca-proxy` → `Jōei` — Design

**Date:** 2026-06-02
**Status:** Approved
**Branch:** `refactor/rename-to-joei` (off `develop`)

## Goal

Replace the old working name `sca-proxy` / `SCA Proxy` everywhere in live code,
build files, and configuration with the new project name **Jōei**. Use the
macron form `Jōei` in display text, and ASCII fallbacks where special characters
are not allowed (import paths, env vars, headers, filesystem paths).

## Replacement mapping

| Context | Old | New |
|---|---|---|
| Go module path | `github.com/sca-proxy/sca-proxy` | `github.com/ggwpLab/Jo-ei` |
| Command directory | `cmd/sca-proxy/` | `cmd/jo-ei/` |
| Binary name (build output) | `sca-proxy` | `jo-ei` |
| Cobra `Use:` | `sca-proxy` | `jo-ei` |
| Display name (README header + prose, ASCII box, CLI `Short`, startup log) | `SCA Proxy` / `sca-proxy` | `Jōei` |
| Environment variable prefix | `SCAPROXY_` | `JOEI_` |
| HTTP cache header | `X-SCA-Proxy-Cache` | `X-Joei-Cache` |
| Cache directory path | `/var/cache/sca-proxy` | `/var/cache/jo-ei` |
| `.claude/settings.local.json` path refs | `cmd/sca-proxy/main.go` | `cmd/jo-ei/main.go` |

### Rationale for ASCII fallbacks

- **Module path** must be ASCII and follow `host/owner/repo`; the macron and a
  display name cannot live there. Owner/repo confirmed as `ggwpLab/Jo-ei`.
- **Env prefix** cannot be `JO_EI_` because viper uses `_` as the key separator,
  which would collide with config keys. Use `JOEI_` (e.g. `JOEI_SUPPLY_CHAIN_MODE`).
- **HTTP header** uses `X-Joei-Cache` — title-cased ASCII, no awkward mid-word
  hyphen.
- **Binary / cache path** use the hyphenated `jo-ei` slug to match the repo name.

## Execution strategy

1. **Module path rewrite** — global, mechanical replace of
   `github.com/sca-proxy/sca-proxy` → `github.com/ggwpLab/Jo-ei` across all `.go`
   files and `go.mod` (38 Go files affected).
2. **`git mv cmd/sca-proxy cmd/jo-ei`** — preserves file history.
3. **Targeted identifier replacements** (per table) in: `Makefile`, `Dockerfile`,
   `docker-compose.yaml`, `config.yaml`, `.gitignore`, `cmd/jo-ei/main.go`,
   `internal/config/config.go`, `internal/proxy/handler.go`,
   `internal/proxy/handler_test.go`, `integration/phase1_test.go`,
   `.claude/settings.local.json`, and `README.md`.
4. **Display-text edits** — README header/prose/ASCII box, CLI `Short`, and the
   startup log line use the macron form `Jōei`.

## Out of scope

- `docs/superpowers/specs/` and `docs/superpowers/plans/` — historical design
  records left untouched (contents and filenames), by decision. Stale `sca-proxy`
  references there are an accurate record of past work. (This new spec file is the
  one exception, as a forward-looking artifact.)

## Verification

1. `go build ./...`
2. `go vet ./...`
3. `go test ./...` (unit tests)
4. `go test -tags integration ./integration/...` (if the environment supports it)
5. `grep -rniE "sca[-_ ]?proxy"` across live files (excluding `docs/` and `.git/`)
   returns **zero** matches.

## Risks / notes

- Uppercase in the Go module path (`Jo-ei`) is valid; the module cache escapes it
  (`!jo-ei`). Imports become `github.com/ggwpLab/Jo-ei/internal/...`.
- The HTTP header rename is observable by clients; any external consumer reading
  `X-SCA-Proxy-Cache` must switch to `X-Joei-Cache`. Acceptable — pre-release.
- The env-prefix rename is a breaking change for anyone setting `SCAPROXY_*`
  variables; documented in README.

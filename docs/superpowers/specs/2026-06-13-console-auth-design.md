# Console & API Authentication Design

**Date:** 2026-06-13
**Status:** Approved
**Scope:** Add HTTP Basic authentication to the admin console (`/console/`) and JSON API (`/api/`), closing the documented "no auth" risk. Registry traffic and `/health` stay open.

## Goals

- Anonymous access to `/console/` and `/api/` (including `PUT /api/policy`) is rejected.
- Multiple, individually-named operator accounts — the authenticated username is available to handlers so a future phase can attribute actions (audit log).
- The proxy data path (`/pypi/`, `/npm/`, `/maven/`, `/rubygems/`, `/yarn/`) and `/health` remain unauthenticated — package managers and health checks never present credentials.
- No JavaScript build step, no SPA login page, no new runtime services this phase.

## Decisions (settled during brainstorming)

| Question | Decision |
|---|---|
| Scheme | **HTTP Basic Auth** with a per-user credential list. Chosen over bearer tokens (break `EventSource`, which cannot set custom headers) and over cookie sessions (more code: session store, login page, CSRF). |
| Phasing | Basic Auth + named accounts **now**. Cookie sessions, login form, logout, session expiry, lockout/rate-limit, and a persistent audit log + view are a **later phase**. |
| Users | Multiple named accounts (`username` + bcrypt `password_hash`), not a single shared secret — required so future audit can attribute who changed policy. |
| Default behavior | **Fail-closed.** With no users configured, `/console/` and `/api/` return `503`; the proxy and `/health` keep working. A loud startup warning explains how to enable. |
| Password hashing | **bcrypt** via `golang.org/x/crypto/bcrypt`. A deliberate departure from the project's stdlib-only stance — the stdlib has no password KDF, and rolling a weak hash for a security product is unacceptable. Hashes are generated with a new `jo-ei hashpw` subcommand. |
| TLS / public exposure | Jōei stays **HTTP-only**; TLS is terminated by a reverse proxy. README documents "public = behind a TLS-terminating reverse proxy." In-binary TLS remains a separate deferred phase. |
| Attribution this phase | Minimal: the authenticated username is placed in the request context and added to the existing `PUT /api/policy` log line. No persistent audit store yet. |
| Frontend | **Unchanged.** `/console/index.html` is itself behind auth, so the browser's native Basic dialog gates entry; same-origin `fetch` and `EventSource` reuse the browser-cached credentials automatically. |

## Architecture

```
                        ┌─────────────────────────── root mux (cmd/jo-ei) ───────────────────────────┐
client (browser) ──────▶│  auth.Middleware ─▶ /console/  (web.ConsoleHandler, go:embed SPA)           │
                        │  auth.Middleware ─▶ /api/      (console.NewHandler: JSON + SSE)             │
package manager ───────▶│  (no middleware)  ─▶ /         (proxy mux: registry prefixes, /health)      │
                        └────────────────────────────────────────────────────────────────────────────┘

internal/auth
  Users           parsed + validated credential set (from config list + JOEI_CONSOLE_AUTH_USERS)
  Verify(u,p)     constant-time bcrypt check; dummy compare for unknown user (no timing oracle)
  Middleware      Basic challenge → 401 / 503 (locked) / pass-through with username in context
  UserFromContext handler-side accessor for the authenticated username
```

### New package: `internal/auth`

- **`User`** — `{ Username string; PasswordHash string }`.
- **`Users`** — the validated credential set built at startup. Construction merges the config-file list with the `JOEI_CONSOLE_AUTH_USERS` env entries (env entries override/append by username). Empty result ⇒ the middleware is in the **locked** (fail-closed) state.
  - Parse/validation errors (malformed env entry, blank username, non-bcrypt hash) are returned at startup and abort the process (fail-fast), consistent with the existing `allowlist_path` handling.
- **`Verify(username, password) bool`** — looks up the user and runs `bcrypt.CompareHashAndPassword`. For an unknown username it still runs a compare against a fixed dummy hash so response time does not reveal whether a username exists.
- **`Middleware(next http.Handler) http.Handler`**:
  - **Locked** (no users): respond `503 Service Unavailable`, body `{"error":"auth_not_configured"}`. Does not call `next`.
  - Missing/!Basic `Authorization`, or `Verify` fails: respond `401 Unauthorized` with `WWW-Authenticate: Basic realm="Jōei Console", charset="UTF-8"`.
  - Success: store the username in the request context (`auth.UserFromContext`) and call `next`.
- **`UserFromContext(ctx) (string, bool)`** — accessor used by the console handler for log attribution.

The middleware is independent of the console and proxy packages — it depends only on `net/http` and `golang.org/x/crypto/bcrypt`.

### Credentials configuration

New `config` block:

```yaml
console:
  auth:
    users:
      - username: admin
        password_hash: "$2a$12$<bcrypt>"
```

- `config.Config` gains `Console ConsoleConfig` with `Auth.Users []AuthUser` (`username`, `password_hash`).
- **Env injection (preferred for secrets):** `JOEI_CONSOLE_AUTH_USERS="admin:$2a$...;alice:$2a$..."` — semicolon-separated `username:hash` pairs, parsed by `internal/auth`. Because bcrypt hashes contain no semicolons and the username cannot contain `:`, the split is unambiguous (`username = before first ':'`, `hash = remainder`). Env entries merge with the file list, overriding any file entry with the same username. This keeps committed config free of secret material.
- The existing `JOEI_`-prefixed viper override path covers the file shape too, but the dedicated env var is the documented secret-injection mechanism.

### `jo-ei hashpw` subcommand

- A new cobra subcommand alongside the existing root command.
- Reads a password from **stdin** (one line; supports both interactive entry and piping, e.g. `printf '%s' "$PW" | jo-ei hashpw`), generates a bcrypt hash at the default cost, and prints the bare hash on its own line to stdout (copy-paste ready for `password_hash:` or the env var).
- The password is never echoed back and nothing secret is logged.
- Stdin (rather than a CLI flag) avoids leaking the password into shell history / process listings.

### Wiring (`cmd/jo-ei/main.go`)

- After config load, build `auth.Users` (file list + env). On parse error → fail-fast.
- Wrap the console and API handlers only:
  ```go
  mw := authUsers.Middleware
  root.Handle("/console/", mw(web.ConsoleHandler()))
  root.Handle("/api/", mw(console.NewHandler(consoleCfg)))
  root.Handle("/", mux) // proxy + /health, unauthenticated
  ```
- If `authUsers` is empty, log a single loud `WARN`: console & API are disabled (locked) until users are configured; the proxy continues to serve.
- `console.putPolicy` reads `auth.UserFromContext` and includes `user` in its existing "runtime policy updated via console" log line. When the username is absent (only possible in tests without the middleware) the field is omitted.

## Error handling

| Condition | Response |
|---|---|
| No users configured (locked) | `503` `{"error":"auth_not_configured"}` on `/console/` and `/api/` |
| Missing / non-Basic `Authorization` | `401` + `WWW-Authenticate: Basic realm="Jōei Console", charset="UTF-8"` |
| Wrong username or password | `401` (same as above; no distinction between unknown user and bad password) |
| Malformed `JOEI_CONSOLE_AUTH_USERS` / blank username / non-bcrypt hash | startup error, process aborts (fail-fast) |
| Authenticated request | passes through; username in context |

## Testing

- **`internal/auth` unit tests:**
  - User-set construction: file list only, env only, merge with env override, empty ⇒ locked.
  - Validation: blank username, non-bcrypt hash, malformed env entry → error.
  - `Verify`: correct password, wrong password, unknown username all behave correctly; unknown-user path still performs a compare.
  - Middleware: locked → 503; no header → 401 with `WWW-Authenticate`; bad creds → 401; good creds → 200 and username present in context via a probe handler.
- **Integration (`integration/console_test.go`, extended):**
  - Configured user: `/api/overview` without credentials → 401; with correct Basic creds → 200; with wrong creds → 401.
  - `/health` and a registry path return their normal responses **without** credentials (auth does not leak onto the proxy).
  - Locked (no users): `/api/overview` → 503, `/health` → 200.
- **`hashpw`:** a hash it produces verifies against the original password via `bcrypt.CompareHashAndPassword`.

## Documentation

- **README:** remove the ⚠️ "no authentication" known-risk note; add a "Console authentication" section covering the `console.auth` config, the `JOEI_CONSOLE_AUTH_USERS` env var, `jo-ei hashpw`, fail-closed behavior, and the "public = behind a TLS-terminating reverse proxy" guidance. Update the Quick Start to create a user before opening the console.
- **`config.yaml`:** add a commented `console.auth.users` example.
- **`docker-compose.yaml`:** add an example `JOEI_CONSOLE_AUTH_USERS` entry with a prominent "CHANGE THIS / example only" comment so the demo console works out of the box without shipping a silently-insecure default.

## Out of scope (later phases)

- Cookie sessions, login form, logout, session expiry.
- Brute-force lockout / rate limiting.
- Persistent audit log and an audit view in the console.
- In-binary TLS termination.
- Per-user roles / authorization (all authenticated users have full access this phase).

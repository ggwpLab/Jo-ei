# JWT console authentication — design

Date: 2026-09-05
Status: approved, ready for planning

## Problem

The console and API are protected by HTTP Basic authentication
(`internal/auth/middleware.go`), wired at `cmd/jo-ei/main.go:386` (`/console/`)
and `:397` (`/api/`). Basic works, but it is the wrong shape for the product:

- **No session.** Every request re-runs bcrypt against the supplied password.
  The browser caches the credentials for the origin and replays them forever;
  there is no logout — the only way out is closing the browser or clearing
  credentials for the host.
- **Browser-native login only.** The username/password dialog is the browser's,
  not the console's, so the product has no login screen, no error copy, no
  branding, and no way to show *who* is signed in. The sidebar today renders a
  hardcoded fake identity ("S. Kurosawa · DevSecOps · admin",
  `web/console/src/app.jsx:177-181`) because no real one is available to it.
- **Password on every hop.** The password itself travels on every request to
  every endpoint, including the long-lived SSE stream, rather than a
  short-lived credential that can expire.

The credential source itself is fine: bcrypt hashes from `console.auth.users`
and `JOEI_CONSOLE_AUTH_USERS`, validated at startup, with a fail-closed locked
state when the set is empty. That part stays.

## Scope

In scope:

- JWT (HS256) session tokens replacing Basic for both browser and machine
  clients.
- Login / refresh / logout / whoami endpoints under `/api/auth/`.
- Signing-secret configuration, generation and persistence.
- Console login screen, authenticated fetch wrapper, real identity and logout
  in the sidebar.
- Making `/console/` static assets publicly servable so the login screen can
  load before a session exists.
- Documentation and the docker-compose example.

Out of scope, decided explicitly:

- **Server-side revocation** (a token denylist or a sessions table). Tokens are
  stateless; logout clears cookies but an already-issued bearer token stays
  valid until it expires. Mitigated by the 15-minute access TTL. See Risks.
- **Long-lived API tokens** issued from the console (an issue/revoke UI plus a
  tokens table). Machines log in with the same credentials instead.
- **OIDC / SSO.** Tracked separately in the backlog; this design does not
  preclude it — the middleware becomes the single place a second identity
  provider would attach.
- **Roles and permissions.** Every authenticated user keeps today's full
  access.
- **Rate limiting login attempts.** bcrypt's cost is the throttle, as it is
  today for Basic.

## Design

### Token format

HS256 JWTs, signed and verified in a new `internal/auth/token.go` on the
standard library (`crypto/hmac`, `crypto/sha256`, `encoding/base64`,
`encoding/json`). No new module dependency: the whole format is a signed,
base64url-encoded JSON pair, roughly eighty lines including verification, and a
supply-chain gate should not take a dependency it can avoid. The implementation
accepts **only** `alg: HS256` — the `alg: none` and algorithm-confusion classes
of bug come from libraries that honour the header's choice; this one ignores it
except to reject anything else.

Claims:

| Claim | Meaning |
|---|---|
| `sub` | username |
| `iat` | issued-at (Unix seconds) |
| `exp` | expiry (Unix seconds) |
| `jti` | random 128-bit id, hex — distinguishes otherwise identical tokens |
| `typ` | `access` or `refresh` — a refresh token is not accepted as an access token, and vice versa |

Verification checks the signature in constant time (`hmac.Equal`), then `exp`,
then `typ` against what the caller expects. Clock skew is not accommodated;
issuer and audience claims are omitted (single-issuer, single-audience system).

### Endpoints

All four live under `/api/auth/` and are mounted **outside** the authenticating
middleware.

**`POST /api/auth/login`** — body `{"username":"…","password":"…"}`.
On success, 200 with:

```json
{"username":"ops","access_token":"eyJ…","expires_in":900}
```

and two `Set-Cookie` headers:

| Cookie | TTL | Attributes |
|---|---|---|
| `joei_at` | `access_ttl` (15m) | `HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` when the request arrived over TLS |
| `joei_rt` | `refresh_ttl` (168h) | `HttpOnly`, `SameSite=Strict`, `Path=/api/auth`, `Secure` when the request arrived over TLS |

The browser ignores the body and rides on the cookies; curl/CI ignore the
cookies and use `access_token` as a bearer. One endpoint, two clients, no
divergent code path.

On failure, 401 `{"error":"invalid_credentials"}` — the same response for an
unknown username and a wrong password, and `Users.Verify` already burns a
bcrypt comparison against a dummy hash so timing does not separate the two.

**`POST /api/auth/refresh`** — reads `joei_rt` (cookie only; refresh is a
browser-session concern and machines re-login instead). Issues a new access
cookie and a **rotated** refresh cookie, so a browser in continuous use never
hits the 7-day wall. Returns `{"username":…,"expires_in":900}`. A missing,
expired, or wrong-`typ` refresh token is 401 `{"error":"unauthorized"}`.

**`POST /api/auth/logout`** — clears both cookies (`Max-Age=0`, same
`Path`/attributes as when set, or the browser keeps them). Always 204 for a
same-origin request, whether or not a session existed — a cross-origin logout
is rejected like any other cookie-authenticated mutation (403).

**`GET /api/auth/me`** — returns `{"username":"ops"}`. It sits outside the
middleware with its siblings, so it resolves and validates the access
credential itself using the same helper the middleware uses (cookie or bearer),
answering 401 `{"error":"unauthorized"}` when there is none and 503 when the
user set is locked. This is the SPA's "am I signed in" probe on boot.

### Middleware

`Users.Middleware` becomes a session middleware over the same `Users` set:

1. Locked (no users configured) → 503 `{"error":"auth_not_configured"}`.
   Unchanged behaviour, unchanged fail-closed guarantee.
2. Credential resolution, in order: `Authorization: Bearer <jwt>`, then the
   `joei_at` cookie. First one present wins; a malformed bearer header is not
   retried as a cookie.
3. Invalid, expired, missing, or wrong-`typ` token → 401
   `{"error":"unauthorized"}`. **No `WWW-Authenticate` header** — that is what
   makes the browser stop popping the native Basic dialog and lets the SPA
   render its own login screen.
4. Valid → username into the request context exactly as today
   (`auth.UserFromContext` keeps its signature, so console logging and
   attribution are untouched).

For state-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`) authenticated by
**cookie**, the middleware additionally requires the request to be same-origin:
`Sec-Fetch-Site: same-origin` when present, else an `Origin` header matching the
request's own host. Bearer-authenticated requests skip the check — a cross-site
page cannot set an `Authorization` header, so there is nothing to forge.
`SameSite=Strict` already blocks the cross-site cookie ride; this is the second
layer for browsers or proxies that drop the attribute.

### Signing secret

Resolution order at startup:

1. `JOEI_CONSOLE_JWT_SECRET` (env).
2. `console.auth.jwt_secret` (config file).
3. The `auth.jwt_secret` key in the settings store (`internal/settings`), which
   already backs runtime policy and registry persistence.
4. None of the above → generate 32 bytes from `crypto/rand`, persist them under
   `auth.jwt_secret`, and log at info that a secret was generated.

Consequences worth stating plainly: a configured secret shared across replicas
makes sessions portable between them; a generated one is per-database, so
sessions survive a restart but not a wipe of the SQLite file. `cmd/jo-ei` always
opens the database and the settings store before wiring auth, so there is no
storeless branch to design for — a deployment that discards its database simply
logs everyone out on the next boot.

An explicitly configured secret shorter than 32 bytes is a startup error, in the
same style as every other config validation failure.

### Configuration

New keys under `console.auth`:

| Key | Env | Default | Meaning |
|---|---|---|---|
| `jwt_secret` | `JOEI_CONSOLE_JWT_SECRET` | generated | HS256 signing key, ≥32 bytes |
| `access_ttl_minutes` | — | `15` | Access token lifetime |
| `refresh_ttl_hours` | — | `168` | Refresh token lifetime |

TTLs are integer minutes/hours rather than duration strings, matching the
existing `cache.revalidation.*_ttl_minutes` keys. The secret is read from the
environment with `os.Getenv` in `cmd/jo-ei`, the way `JOEI_CONSOLE_AUTH_USERS`
already is — viper's `AutomaticEnv` only overrides keys present in the file, so
an env-only secret would silently not apply.

`console.auth.users` and `JOEI_CONSOLE_AUTH_USERS` keep their current meaning,
format, precedence, and validation. No migration of stored credentials: the
bcrypt hashes an operator already has keep working.

### Mount changes in `cmd/jo-ei`

- `/console/` is served **unauthenticated**. The bundle is static UI code with
  no secrets in it, and the login screen has to render before a session can
  exist. Every byte of data still comes from `/api/`, which stays gated.
- `/api/auth/` mounts before `/api/`, outside the middleware. Go's
  `http.ServeMux` prefers the longer pattern, so `/api/auth/login` reaches the
  public handler while `/api/overview` reaches the gated one.
- The locked-state warning at startup is reworded: the console shell now loads,
  but the API returns 503, so the log line should say that rather than claiming
  `/console/` is disabled.

### Console (SPA)

`web/console/src/api.js`:

- A single `authFetch(path, opts)` wrapper used by every call. On 401 it makes
  one `POST /api/auth/refresh` attempt; on success it replays the original
  request once, on failure it fires a new `joei:auth` event carrying
  `{authenticated:false}`.
- Boot calls `GET /api/auth/me` before `load()`. 401 means "show the login
  screen" rather than "no connection" — the existing connection banner must not
  be reused for an unauthenticated state.
- `login(username, password)` / `logout()` are added to the `JOEI` object.
- The `EventSource` for `/api/events` carries the access cookie automatically.
  Its `onerror` path already probes the API; that probe now distinguishes 401
  (session lapsed → refresh, then reconnect the stream) from a transport error
  (existing reconnect behaviour).
- The 15-second poll and the `visibilitychange` refresh go through the same
  wrapper, so a session that lapses in a backgrounded tab surfaces the login
  screen on return rather than a connection error.

`web/console/src/app.jsx`:

- A new `LoginScreen` component — centred torii card matching the existing
  `PurifyLoader` styling, username + password fields, inline error copy for
  401 (`invalid credentials`) and for 503 (`authentication is not configured on
  this server`), submit disabled while in flight.
- `App` renders `LoginScreen` instead of the shell whenever the auth state is
  unauthenticated; the purify loader covers the initial `me` probe so there is
  no flash of the login screen for an already-signed-in operator.
- The sidebar's hardcoded identity block is replaced by the real username (from
  `me`/`login`), its initials in the avatar square, and a logout button that
  calls `JOEI.logout()` and drops back to `LoginScreen`.

The bundle is rebuilt with `go generate ./web` (esbuild via `internal/uibuild`);
`web/console/app.bundle.js` is committed, as it is today.

## Testing

Go, table-driven where it fits, alongside the existing package tests:

- `internal/auth/token_test.go` — round-trip sign/verify; expired token; wrong
  `typ`; tampered payload; tampered signature; wrong secret; a token whose
  header declares a different `alg` (must be rejected); malformed input
  (missing segments, non-base64, non-JSON).
- `internal/auth/middleware_test.go` (extended) — valid cookie; valid bearer;
  both present; neither; expired; refresh token presented as access; locked
  state → 503; 401 body shape and the absence of `WWW-Authenticate`; the
  same-origin requirement on cookie-authenticated mutations and its absence for
  bearer ones; context username propagation.
- `internal/auth/handlers_test.go` — login success (cookie attributes: name,
  `HttpOnly`, `SameSite`, `Path`, `Max-Age`, `Secure` on and off TLS; body
  shape); login with a wrong password and an unknown user (identical
  responses); malformed body; refresh rotation; refresh with an access token;
  logout clearing both cookies; `me`.
- `internal/config/config_test.go` (extended) — TTL defaults, env precedence for
  the secret, a too-short configured secret failing validation.
- `cmd/jo-ei` — secret resolution order, including generate-and-persist and the
  in-memory fallback when no database is configured.
- `integration/console_auth_test.go` — rewritten end to end: unauthenticated
  `/api/overview` is 401 while `/console/` is 200; login then cookie-driven
  access; login then bearer-driven access; refresh after access expiry;
  logout; the locked stack returning 503.

The console changes have no test runner in this repository — there is no npm
toolchain by design. They are verified by `go generate ./web` producing a
bundle, the Go handler tests above, and a manual pass over the login → session
→ refresh → logout flow. This is stated rather than papered over.

## Documentation

- `README.md` — the console section and any `curl` example using Basic.
- `docs/configuration.md` — the `console` table gains the three keys; the
  fail-closed note is corrected (shell public, API 503).
- `docs/architecture.md` — the `internal/auth` row.
- `.env.example` — `JOEI_CONSOLE_JWT_SECRET` in the example environment.
- `config.yaml` — the commented-out `console.auth` example gains the three new
  keys.
- `CHANGELOG.md` — an Unreleased entry flagged as a **breaking change** for
  anyone scripting the API with Basic, with the two-line curl migration.

## Risks

**No revocation.** A leaked access token is valid until it expires (15
minutes); a leaked refresh token is valid for 7 days and rotation does not
invalidate the copy an attacker holds. Changing `jwt_secret` and restarting
invalidates every session at once, which is the documented break-glass. Real
revocation needs the sessions table this design excludes.

**Breaking change for API clients.** Basic stops working. Scripts must log in
and send a bearer token. This is a deliberate choice, and the migration is two
lines of curl, but it lands in the changelog as breaking.

**Public console shell.** `/console/` becomes reachable without credentials.
The exposure is the UI bundle itself: markup, styles, and the endpoint paths it
calls — no data, no configuration, no hashes. Anyone who can reach the port can
already see those paths in the 401 responses.

**Cookie and TLS.** `Secure` is set only when the request arrived over TLS, so a
plain-HTTP deployment still works. On plain HTTP the cookie travels in the
clear, exactly as the Basic password does today — no regression, but no
improvement either, and the docs should keep recommending TLS in front.

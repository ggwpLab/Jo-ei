# Console Users and Roles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace env/config console credentials with database-backed users managed in the console, with two roles (admin, operator), immediate revocation, login rate limiting keyed on the real client IP, and atomic allow/deny list endpoints.

**Architecture:** A new `internal/users` package owns the `users` table (store, validation, last-admin guard). `internal/auth` stops holding credentials in memory: `Sessions` looks the user up on every request through a small interface, puts an `Identity` (username, role, must-change flag) in the context, and adds a login limiter plus a self-service password endpoint. `internal/console` declares a role per route (default admin-only), gains list endpoints and the users API; `policy.Runtime` serialises edits behind a mutex. `internal/httpx` resolves the client IP from trusted proxies. `cmd/jo-ei` bootstraps the table from the old config/env users once and adds `jo-ei user …`.

**Tech Stack:** Go 1.26 (`net/http` ServeMux patterns, `net/netip`), modernc SQLite via `internal/storage`, bcrypt (`golang.org/x/crypto/bcrypt`), cobra, zerolog/`internal/logx`, React console built by `go generate ./web` (esbuild).

**Spec:** `docs/superpowers/specs/2026-10-24-console-users-and-roles-design.md`

## Global Constraints

- Roles are exactly `admin` and `operator`; no other values accepted anywhere.
- Username: 1–64 chars of `[A-Za-z0-9._@-]`; uniqueness and lookup case-insensitive; stored as entered.
- Password: at least 12 characters (runes), at most 72 **bytes** (bcrypt limit; reject, never truncate), must not equal the username (case-insensitive), no composition rules. *(Plan decision: the spec says "12–72 bytes"; counting the minimum in runes stops a 6-letter Cyrillic password passing as 12 bytes.)*
- Login limits: 5 failures per (username, client IP) per 15 min; 20 failures per client IP per 15 min; blocked attempts → `429` + `Retry-After` (seconds), even with the correct password; success resets the pair.
- `server.trusted_proxies` default empty; `server.client_ip_header` ∈ `X-Forwarded-For` (default) | `X-Real-IP` | `Forwarded`.
- Error bodies: `403 {"error":"forbidden"}`, `403 {"error":"password_change_required"}`, `409 {"error":"last_admin"}`, `409 {"error":"self"}`, `409 {"error":"user_exists"}`, `404 {"error":"user_not_found"}`, `400 {"error":"invalid_user","field":…,"message":…}`, `429 {"error":"too_many_attempts"}`.
- Log messages (exact): `policy list updated` (fields `user`, `list`, `entry`, `action`=`add`|`remove`), `user management` (fields `user`, `target`, `action`=`create`|`role`|`disable`|`enable`|`reset_password`|`delete`, `role` when relevant), `login succeeded` / `login failed` / `login rate limited` (fields `user`, `client_ip`), `password changed` (field `user`), `imported N console users from config`. Never log passwords or hashes.
- Every change that revokes sessions increments the user's `token_version`. *(Plan decision: the spec's `tokens_valid_after` timestamp is implemented as an integer version carried in the JWT `ver` claim — same behaviour, no same-second clock edge.)*
- Go gates: `gofmt -l .` empty, `golangci-lint run` clean, `go test ./...` green; race run via the Docker recipe (memory `docker-race-tests`) before the final review. Console bundle regenerated with `go generate ./...` and committed whenever `web/console/src` changes (CI checks it).
- Work on branch `feat/console-users-roles`; commit after every task; messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Username case.** Creating `Anna` when `anna` exists → 409 `user_exists`; logging in as `ANNA` with anna's password works and the token subject is the stored `anna`. Tests: Task 2 (`TestStore_CaseInsensitive`), Task 4 (`TestLogin_CaseInsensitiveUsername`).
2. **Admin settings save during operator list edits.** Operator adds an allowlist entry, then admin PUTs settings without list fields → entry still present. Test: Task 6 (`TestPutPolicy_AbsentListsUnchanged`).
3. **Bootstrap users that break the new username rule** (e.g. `ivan petrov` or `ops+ci` in `JOEI_CONSOLE_AUTH_USERS`) → startup fails with a message naming the user and the rule, nothing half-imported. Test: Task 2 (`TestImportIfEmpty_InvalidNameImportsNothing`), Task 8 (`TestBootstrapUsers_InvalidName`).
4. **Multibyte passwords.** 12 Cyrillic letters (24 bytes) accepted; 11 rejected; 36 Cyrillic letters (72 bytes) accepted; 37 (74 bytes) rejected. Test: Task 2 (`TestValidatePassword`).
5. **Role change mid-session.** Admin demotes a signed-in admin → that user's next API call with the old access token is 401 and their refresh cookie no longer refreshes (they sign in again and are operator). Test: Task 4 (`TestMiddleware_VersionBumpRevokes`), Task 7 (`TestUsersAPI_RoleChangeRevokesSessions`).

---

### Task 1: Client IP resolution behind trusted proxies

**Files:**
- Create: `internal/httpx/clientip.go`, `internal/httpx/clientip_test.go`
- Modify: `internal/config/config.go` (`ServerConfig`, `Validate`), `internal/config/config_test.go`, `config.yaml` (server section comments), `docs/configuration.md` (server table + a "Behind a reverse proxy" note), `docker-compose.yaml` (commented `trusted_proxies` hint only if the file has a proxy example; otherwise docs only)

**Interfaces:**
- Produces:
  - `config.ServerConfig.TrustedProxies []string` (`mapstructure:"trusted_proxies"`), `config.ServerConfig.ClientIPHeader string` (`mapstructure:"client_ip_header"`)
  - `const httpx.HeaderXForwardedFor = "X-Forwarded-For"`, `HeaderXRealIP = "X-Real-IP"`, `HeaderForwarded = "Forwarded"`
  - `func httpx.NewClientIPResolver(trusted []string, header string, log zerolog.Logger) (*httpx.ClientIPResolver, error)` — empty header ⇒ `X-Forwarded-For`; entries may be CIDRs or bare IPs.
  - `func (c *httpx.ClientIPResolver) ClientIP(r *http.Request) string` — returns an IP string without port.

- [ ] **Step 1: Write failing tests** in `clientip_test.go`:
  - `TestClientIP_UntrustedPeerIgnoresHeaders`: trusted `nil`, `RemoteAddr="203.0.113.7:5555"`, `X-Forwarded-For: 1.2.3.4` → `"203.0.113.7"`.
  - `TestClientIP_TrustedPeerRightmostUntrusted`: trusted `["10.0.0.0/8"]`, `RemoteAddr="10.0.0.2:1"`, `X-Forwarded-For: 6.6.6.6, 198.51.100.9, 10.0.0.5` → `"198.51.100.9"` (spoofed left-most ignored).
  - `TestClientIP_AllHopsTrustedTakesLeftmost`: `X-Forwarded-For: 10.0.0.9, 10.0.0.5` from trusted peer → `"10.0.0.9"`.
  - `TestClientIP_XRealIP`: header `X-Real-IP`, value `198.51.100.9` from trusted peer → that value.
  - `TestClientIP_Forwarded`: header `Forwarded`, value `for=192.0.2.60;proto=https, for="[2001:db8::1]:4711"` from trusted peer → `"2001:db8::1"`.
  - `TestClientIP_MalformedFallsBackToPeer`: trusted peer, `X-Forwarded-For: garbage` → peer IP.
  - `TestClientIP_WarnsOncePerProcess`: untrusted peer sending `X-Forwarded-For` twice → logger buffer contains exactly one `warn` line whose message mentions `server.trusted_proxies` and has field `peer`.
  - `TestNewClientIPResolver_Errors`: `["not-an-ip"]` → error; header `"X-Foo"` → error.
  - In `config_test.go`: `TestValidate_TrustedProxies` — `["10.0.0.0/8","192.0.2.1"]` ok; `["10.0.0.0/33"]` → error containing `server.trusted_proxies[0]`; `ClientIPHeader:"X-Foo"` → error containing `server.client_ip_header`.
- [ ] **Step 2: Run** `go test ./internal/httpx/ ./internal/config/ -run 'ClientIP|TrustedProxies'` — Expected: FAIL (undefined).
- [ ] **Step 3: Implement** the resolver with `net/netip` (`netip.ParsePrefix`, bare IPs as /32 or /128); the warn-once flag is a `sync.Once` or `atomic.Bool` on the resolver. Config validation parses the same way with `net/netip` (no import of `httpx` from `config`).
- [ ] **Step 4: Run** the same command — Expected: PASS. Then `go test ./...`.
- [ ] **Step 5: Docs.** `config.yaml`: commented `trusted_proxies: []` and `client_ip_header: X-Forwarded-For` under `server:` with one-line explanation. `docs/configuration.md`: rows for both keys + a short paragraph: headers trusted only from listed peers; without it, behind nginx/Traefik all clients share the proxy IP for login limits; the warning to look for.
- [ ] **Step 6: Commit** `feat(httpx): resolve client IP through trusted proxies`.

### Task 2: Users store

**Files:**
- Create: `internal/users/users.go` (types, validation, hashing), `internal/users/store.go` (SQLite), `internal/users/users_test.go`, `internal/users/store_test.go`

**Interfaces:**
- Consumes: `storage.DB.ApplyMigrations(component string, steps []string) error`, `storage.DB.SQL()`; tests open a DB via `storage.Open(filepath.Join(t.TempDir(), "t.db"))`.
- Produces:
  - `type users.Role string`; `const users.RoleAdmin Role = "admin"`, `users.RoleOperator Role = "operator"`; `func (r Role) Valid() bool`
  - `type users.User struct { Username, PasswordHash string; Role Role; Disabled, MustChangePassword bool; TokenVersion int64; CreatedAt time.Time; LastLoginAt *time.Time }`
  - `var users.ErrNotFound, users.ErrExists, users.ErrLastAdmin error`
  - `type users.ValidationError struct{ Field, Message string }` (implements `error`)
  - `func users.ValidateUsername(name string) error`, `func users.ValidatePassword(username, password string) error`, `func users.HashPassword(password string) (string, error)` (bcrypt `DefaultCost`), `func users.CheckPassword(hash, password string) bool`
  - `func users.New(db *storage.DB) (*users.Store, error)` (runs migration component `"users"`)
  - Store methods: `Get(username string) (User, error)`; `List() ([]User, error)` (ordered by username, case-insensitive); `HasEnabledUsers() (bool, error)`; `Create(u User) error`; `SetRole(username string, r Role) error`; `SetDisabled(username string, disabled bool) error`; `SetPassword(username, hash string, mustChange bool) error`; `Delete(username string) error`; `TouchLogin(username string, at time.Time) error`; `ImportIfEmpty(us []User) (int, error)`.

Table (one migration step): `users(username TEXT PRIMARY KEY COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','operator')), disabled INTEGER NOT NULL DEFAULT 0, must_change_password INTEGER NOT NULL DEFAULT 0, token_version INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, last_login_at INTEGER)`.

Rules the store enforces: `Create` validates username and role, `ErrExists` on duplicate (any case); `SetRole`, `SetDisabled(true)`, `Delete` return `ErrLastAdmin` when the result would leave zero enabled admins (check + write in one transaction); `SetRole`, `SetDisabled` (either direction), `SetPassword` increment `token_version`; `SetRole`/`SetDisabled` to the current value are no-ops without a bump; `ImportIfEmpty` validates every user first and inserts all-or-nothing in one transaction, returns 0 without writing when the table is non-empty.

- [ ] **Step 1: Write failing tests:**
  - `TestValidateUsername`: ok `admin`, `ivan.petrov`, `a@b.c`, `x_1-2`, 64×`a`; fail `""`, 65×`a`, `ivan petrov`, `ops+ci`, `имя`.
  - `TestValidatePassword` (Review Focus 4): `strings.Repeat("я",12)` ok; `strings.Repeat("я",11)` fail; `strings.Repeat("я",36)` ok; `strings.Repeat("я",37)` fail; `"correcthorse"` (12 ascii) ok; password equal to username `"Administrator"` vs username `"administrator"` fail.
  - `TestStore_CreateGetList`: create two users, `Get` returns fields, `List` ordered, `LastLoginAt` nil.
  - `TestStore_CaseInsensitive` (Review Focus 1): create `anna`; `Create("Anna")` → `ErrExists`; `Get("ANNA").Username == "anna"`.
  - `TestStore_LastAdminGuard`: single admin → `SetRole(op)`, `SetDisabled(true)`, `Delete` each `ErrLastAdmin`; with a second enabled admin all succeed; a disabled second admin does not count.
  - `TestStore_TokenVersionBumps`: `SetPassword`, `SetRole` (real change), `SetDisabled(true)` each +1; `SetRole` to same role no bump.
  - `TestStore_HasEnabledUsers`: empty false; one disabled operator false; enabled true.
  - `TestImportIfEmpty`: empty table → imports 2, returns 2; second call returns 0 and changes nothing.
  - `TestImportIfEmpty_InvalidNameImportsNothing` (Review Focus 3): `[ok, "ops+ci"]` → `*ValidationError` whose message contains `ops+ci`; table still empty.
  - `TestStore_NotFound`: `Get`, `SetRole`, `Delete` on missing → `ErrNotFound`.
- [ ] **Step 2: Run** `go test ./internal/users/` — Expected: FAIL (package missing).
- [ ] **Step 3: Implement** `users.go` and `store.go` per the interfaces and rules above.
- [ ] **Step 4: Run** `go test ./internal/users/` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(users): SQLite user store with roles and last-admin guard`.

### Task 3: Login rate limiter

**Files:**
- Create: `internal/auth/ratelimit.go`, `internal/auth/ratelimit_test.go`

**Interfaces:**
- Produces:
  - `func auth.NewLoginLimiter(now func() time.Time) *auth.LoginLimiter` (nil `now` ⇒ `time.Now`)
  - `func (l *LoginLimiter) Allow(username, ip string) (retryAfter time.Duration, ok bool)`
  - `func (l *LoginLimiter) Failure(username, ip string)`, `func (l *LoginLimiter) Success(username, ip string)`
  - Constants `auth.LoginPairLimit = 5`, `auth.LoginIPLimit = 20`, `auth.LoginWindow = 15 * time.Minute`.

Semantics: fixed window per key starting at that key's first failure; a key is blocked when its count ≥ limit and the window has not elapsed; `retryAfter` = window end − now (the larger of the two keys when both block); username part of the pair key is lowercased; expired entries are dropped lazily (on access) plus a sweep when the map grows past 10 000 keys. Safe for concurrent use.

- [ ] **Step 1: Write failing tests** with a fake clock:
  - `TestLimiter_PairBlocksAfterFive`: 5 `Failure("admin","1.1.1.1")` → `Allow` false, `retryAfter` ≈ 15m; `Allow("admin","2.2.2.2")` true (other IP unaffected); `Allow("ADMIN","1.1.1.1")` false.
  - `TestLimiter_WindowExpires`: after 5 failures advance 15m+1s → `Allow` true.
  - `TestLimiter_IPBlocksAcrossUsernames`: 20 failures over 20 distinct usernames from one IP → `Allow("fresh","1.1.1.1")` false; another IP true.
  - `TestLimiter_SuccessResetsPair`: 4 failures, `Success`, 4 failures → still allowed.
  - `TestLimiter_Concurrent`: 50 goroutines calling `Failure`/`Allow` (meaningful only under `-race`, run in the Docker race pass).
- [ ] **Step 2: Run** `go test ./internal/auth/ -run Limiter` — Expected: FAIL.
- [ ] **Step 3: Implement** with a `sync.Mutex` + `map[string]*window`.
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(auth): login rate limiter`.

### Task 4: DB-backed sessions, identity, revocation, password change

**Files:**
- Modify: `internal/auth/users.go` (credential map removed; keep env/config parsing as bootstrap parser), `internal/auth/session.go`, `internal/auth/handlers.go`, `internal/auth/token.go`, their tests (`session_test.go`, `handlers_test.go`, `users_test.go`, `token_test.go`)

**Interfaces:**
- Consumes: Task 2 `users.User`, `users.Role`, `users.ErrNotFound`, `users.ValidatePassword`, `users.HashPassword`, `users.CheckPassword`; Task 3 `*auth.LoginLimiter`; Task 1 `(*httpx.ClientIPResolver).ClientIP` (as a plain `func(*http.Request) string`).
- Produces:
  - `type auth.UserStore interface { Get(username string) (users.User, error); HasEnabledUsers() (bool, error); TouchLogin(username string, at time.Time) error; SetPassword(username, hash string, mustChange bool) error }` — `*users.Store` satisfies it.
  - `func auth.NewSessions(store UserStore, signer *Signer, accessTTL, refreshTTL time.Duration, opts ...Option) *Sessions`
  - `type auth.Option func(*Sessions)`; `auth.WithLoginLimiter(*LoginLimiter)`, `auth.WithClientIP(func(*http.Request) string)` (default: host of `RemoteAddr`), `auth.WithLogger(zerolog.Logger)`.
  - `func (s *Sessions) Locked() bool` — true when `HasEnabledUsers` is false or errors (fail closed).
  - `type auth.Identity struct { Username string; Role users.Role; MustChangePassword bool }`; `func auth.IdentityFromContext(ctx context.Context) (Identity, bool)`; `func auth.WithIdentity(ctx context.Context, id Identity) context.Context` (exported for handler tests); `auth.UserFromContext` kept, returns `Identity.Username`.
  - `Claims` gains `Ver int64 \`json:"ver"\``; `func (s *Signer) Issue(username string, ver int64, typ string, ttl time.Duration) (string, error)`.
  - `func auth.ParseBootstrapUsers(fileUsers []User, envValue string) ([]User, error)` — today's `NewUsers` parsing/validation (bcrypt validity, env overrides file), returning the list. `NewUsers`, `Users`, `Verify`, `Known` are deleted.
  - New route `POST /api/auth/password` body `{"current":…, "new":…}`.

Behaviour:
- Middleware and `Authenticate`: verify token, `Get(claims.Sub)`; reject 401 when not found, `Disabled`, or `claims.Ver != user.TokenVersion`. Identity uses the stored username. If `MustChangePassword` → `403 password_change_required` (middleware only; `/api/auth/*` is outside it).
- Login: limiter `Allow` first (blocked → `429 too_many_attempts` with `Retry-After` header in whole seconds, rounded up, and log `login rate limited`); then `Get` + `CheckPassword` (unknown user still burns a bcrypt compare on the existing dummy hash); disabled user → same `401 invalid_credentials`; on failure `Failure` + `login failed`; on success `Success`, `TouchLogin(now)`, issue tokens with the user's `TokenVersion` and stored username, `login succeeded`. Response adds `role` and `must_change_password`.
- Refresh: same user checks as middleware (disabled / version mismatch → 401); a `MustChangePassword` user may refresh.
- `GET /api/auth/me` → `{"username","role","must_change_password"}`; allowed while `MustChangePassword`.
- `POST /api/auth/password`: same-origin rule like other cookie mutations; requires a valid access token (bearer or cookie) — not blocked by `MustChangePassword`; `current` must match (else `401 invalid_credentials`, counts as a limiter failure for (user, ip)); `new` passes `users.ValidatePassword` (else `400 {"error":"invalid_password","message":…}`) and differs from `current` (else 400 `invalid_password`); `SetPassword(name, hash, false)` bumps the version, then re-issue this session with the new version (cookies + `access_token` in body); log `password changed`.

- [ ] **Step 1: Write failing tests** (replace `NewUsers`-based fixtures with a fake `UserStore` in `session_test.go`; keep every existing behaviour test passing against it):
  - `TestMiddleware_PutsIdentity`: operator user → handler sees `Identity{Username:"anna", Role:"operator"}`.
  - `TestMiddleware_DisabledUser401`, `TestMiddleware_DeletedUser401`.
  - `TestMiddleware_VersionBumpRevokes` (Review Focus 5): issue tokens at ver 0, store bumps to 1 → access 401 and `POST /api/auth/refresh` with the old refresh cookie 401.
  - `TestMiddleware_MustChangePassword403`: body `{"error":"password_change_required"}`.
  - `TestLocked_NoEnabledUsers503`: store with only disabled users → `/api/x` 503, login 503.
  - `TestLogin_CaseInsensitiveUsername` (Review Focus 1): fake store resolves `ANNA` → `anna`; token `sub == "anna"`, response `username == "anna"`.
  - `TestLogin_DisabledSameAsWrongPassword`: status and body identical to wrong password.
  - `TestLogin_RateLimited`: 5 bad attempts from `RemoteAddr 1.1.1.1:1` → 6th with **correct** password `429`, `Retry-After` > 0; from `2.2.2.2:1` succeeds.
  - `TestLogin_UsesClientIPResolver`: `WithClientIP` returning header value; limiter keyed on it (5 failures with `X-Test-IP: 9.9.9.9` block only that value).
  - `TestLogin_TouchesLastLogin`.
  - `TestMe_ReturnsRoleAndFlag`.
  - `TestChangePassword_Success`: new cookies set, old access token 401 afterwards, new one 200, store has `MustChangePassword=false`.
  - `TestChangePassword_WrongCurrent401`, `TestChangePassword_TooShort400`, `TestChangePassword_SameAsCurrent400`, `TestChangePassword_AllowedWhileMustChange`.
  - `TestParseBootstrapUsers` (rename of the existing `TestNewUsers*` cases).
- [ ] **Step 2: Run** `go test ./internal/auth/` — Expected: FAIL (compile errors on new API).
- [ ] **Step 3: Implement** per Behaviour. Update the package doc comment (credentials now come from the users store; config/env only bootstrap it).
- [ ] **Step 4: Run** `go test ./internal/auth/` — Expected: PASS. `go build ./...` will fail in `cmd/jo-ei` until Task 8 — to keep the tree buildable at this commit, make the minimal wiring change in `cmd/jo-ei/main.go` now: open `users.New(sdb)`, call `NewSessions(userStore, …)`; bootstrap import itself is Task 8. `go build ./... && go test ./...` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(auth): database-backed sessions with roles and revocation`.

### Task 5: Per-route role enforcement in the console API

**Files:**
- Modify: `internal/console/server.go` (route registration), `internal/console/server_test.go` (test helper injects identity), plus any console test that calls handlers directly.

**Interfaces:**
- Consumes: Task 4 `auth.IdentityFromContext`, `auth.WithIdentity`, `users.RoleAdmin`, `users.RoleOperator`.
- Produces: inside `NewHandler`, two registration helpers — `admin(pattern string, h http.HandlerFunc)` and `operator(pattern string, h http.HandlerFunc)`. `admin` allows only `RoleAdmin`; `operator` allows both. No identity in context → `403 forbidden` (fail closed). There is no third helper, so an undeclared route cannot exist; a comment above the block says new routes use `admin` unless operators need them.

Assignment: `operator` — `GET /api/overview`, `/api/requests`, `/api/events`, `/api/quarantine`, `/api/policy`, `/api/registries`, `/api/metrics/daily`. `admin` — `PUT /api/policy`, `PUT /api/registries`, `POST /api/cache/cleanup`.

- [ ] **Step 1: Write failing tests:**
  - `TestRoles_OperatorReadsEverything`: each operator GET with operator identity → not 403.
  - `TestRoles_OperatorForbiddenOnAdminRoutes`: `PUT /api/policy`, `PUT /api/registries`, `POST /api/cache/cleanup` → `403 {"error":"forbidden"}`.
  - `TestRoles_AdminAllowed`: same three with admin identity → not 403.
  - `TestRoles_NoIdentityForbidden`: GET `/api/overview` without identity → 403.
  - Existing tests: the shared test server helper wraps requests with `auth.WithIdentity(ctx, auth.Identity{Username:"admin", Role: users.RoleAdmin})` so they keep passing.
- [ ] **Step 2: Run** `go test ./internal/console/ -run Roles` — Expected: FAIL.
- [ ] **Step 3: Implement** the helpers and re-register routes.
- [ ] **Step 4: Run** `go test ./internal/console/` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(console): per-route role enforcement`.

### Task 6: Atomic list endpoints and settings-only PUT

**Files:**
- Modify: `internal/policy/runtime.go`, `internal/policy/runtime_test.go`, `internal/console/server.go` (`putPolicy`, new handlers), `internal/console/server_test.go`

**Interfaces:**
- Consumes: Task 5 `operator(...)` / `admin(...)` helpers; `auth.UserFromContext`.
- Produces:
  - `const policy.ListAllowlistSupply = "allowlist_supply"`, `ListAllowlistCVE = "allowlist_cve"`, `ListDenylist = "denylist"`
  - `func (r *Runtime) Update(fn func(cur RuntimeParams) RuntimeParams) error` — under `r.mu` (new `sync.Mutex`): read current, apply `fn`, validate, persist, install. `Apply(p)` becomes `Update(func(RuntimeParams) RuntimeParams { return p })`.
  - `func (r *Runtime) EditList(list, entry string, add bool) (changed bool, err error)` — unknown list → `*ValidationError{Field:"list"}`; entry validated with `validateListEntry` (`Field:"entry"`); trims whitespace; add is idempotent, remove of an absent entry is idempotent (`changed=false`, nothing persisted).
  - Routes (operator): `POST /api/policy/lists/{list}` and `DELETE /api/policy/lists/{list}`, body `{"entry":"…"}` (`DisallowUnknownFields`, 4 KiB cap); 200 with the same body as `GET /api/policy`; validation errors use the existing `invalid_policy` shape; log `policy list updated` only when `changed`.
  - `PUT /api/policy` decodes list fields as `*[]string`; absent (nil pointer) ⇒ keep current list; present ⇒ replace. Uses `Update`.

- [ ] **Step 1: Write failing tests:**
  - `runtime_test.go`: `TestEditList_AddRemoveIdempotent` (add twice → one entry, second `changed=false`; remove absent → `changed=false`); `TestEditList_Validation` (unknown list, `"no-slash"` entry); `TestEditList_Persists` (fake store sees the new list); `TestRuntime_ConcurrentEditsNoLoss` (100 goroutines each adding a distinct entry → all 100 present; race pass).
  - `server_test.go`: `TestListEndpoint_OperatorAdds` (operator identity, POST `allowlist_cve` `{"entry":"npm/x@1.0.0"}` → 200, GET shows it); `TestListEndpoint_Delete`; `TestListEndpoint_UnknownList400`; `TestListEndpoint_LogsUserAndEntry` (log buffer has `policy list updated` with `user`, `list`, `entry`, `action:"add"`).
  - `TestPutPolicy_AbsentListsUnchanged` (Review Focus 2): POST list entry as operator, then admin PUT `{"mode":"enforce","min_age_hours":48,"cve_block_on":"HIGH"}` → entry still present, `min_age_hours` 48.
  - `TestPutPolicy_PresentEmptyListClears`: PUT with `"denylist":[]` clears it.
- [ ] **Step 2: Run** `go test ./internal/policy/ ./internal/console/ -run 'EditList|ListEndpoint|PutPolicy|Concurrent'` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/policy/ ./internal/console/` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(policy): atomic list endpoints; PUT keeps absent lists`.

### Task 7: Users management API

**Files:**
- Create: `internal/console/users.go`, `internal/console/users_test.go`
- Modify: `internal/console/server.go` (`Config.Users`, route registration)

**Interfaces:**
- Consumes: Task 2 store methods and errors; Task 5 `admin(...)`; `auth.IdentityFromContext`.
- Produces:
  - `type console.UserAdmin interface { List() ([]users.User, error); Get(string) (users.User, error); Create(users.User) error; SetRole(string, users.Role) error; SetDisabled(string, bool) error; SetPassword(string, string, bool) error; Delete(string) error }` — `*users.Store` satisfies it; `console.Config.Users UserAdmin` (nil ⇒ routes return `503 {"error":"users_unavailable"}`).
  - Admin routes: `GET /api/users` → `[{"username","role","disabled","must_change_password","created_at","last_login_at"}]` (RFC 3339 timestamps, `last_login_at` null when never); `POST /api/users` `{"username","role","password"}` → 201 + user JSON, `must_change_password:true`; `PATCH /api/users/{name}` `{"role"?, "disabled"?}` → 200 + user JSON; `POST /api/users/{name}/password` `{"password"}` → 204, sets `must_change_password`; `DELETE /api/users/{name}` → 204.
  - Errors map: `users.ValidationError` and `ValidatePassword` failures → `400 invalid_user` (`field` = `username`|`role`|`password`); `ErrExists` → `409 user_exists`; `ErrNotFound` → `404 user_not_found`; `ErrLastAdmin` → `409 last_admin`; actor == target (case-insensitive) on delete, `disabled:true`, or role → operator → `409 self`.
  - Each successful mutation logs `user management` with `user`, `target`, `action` (`create`|`role`|`disable`|`enable`|`reset_password`|`delete`), `role` on create/role. A PATCH carrying both fields logs one line per changed field.

- [ ] **Step 1: Write failing tests** against a real `users.Store` on a temp DB:
  - `TestUsersAPI_CreateListGet` (no `password_hash` key anywhere in responses — assert on raw body).
  - `TestUsersAPI_DuplicateCaseInsensitive409`.
  - `TestUsersAPI_InvalidUsernameAndPassword400` (`field` values).
  - `TestUsersAPI_SelfGuards409` (delete self, disable self, demote self).
  - `TestUsersAPI_LastAdmin409`: store holds one enabled admin `root`; request identity is admin `ghost` (not in the store, so the self rule does not apply); `PATCH /api/users/root {"role":"operator"}` → `409 {"error":"last_admin"}`.
  - `TestUsersAPI_ResetPasswordForcesChange`.
  - `TestUsersAPI_RoleChangeRevokesSessions` (Review Focus 5): token version in store increments after PATCH role.
  - `TestUsersAPI_OperatorForbidden` (operator identity → 403 on all five routes, including GET).
  - `TestUsersAPI_Logs` (create + delete produce `user management` lines; no `password` substring in the log buffer).
- [ ] **Step 2: Run** `go test ./internal/console/ -run UsersAPI` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/console/` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(console): users management API`.

### Task 8: Bootstrap, wiring and auth docs

**Files:**
- Create: `cmd/jo-ei/users_bootstrap.go`, `cmd/jo-ei/users_bootstrap_test.go`
- Modify: `cmd/jo-ei/main.go` (auth wiring block ~L417–470), `config.yaml` (console.auth comments), `docs/configuration.md` (auth section), `CHANGELOG.md` (Unreleased)

**Interfaces:**
- Consumes: Task 2 `users.New`, `ImportIfEmpty`, `HasEnabledUsers`; Task 4 `auth.ParseBootstrapUsers`, `auth.NewSessions` + options, `auth.NewLoginLimiter`; Task 1 `httpx.NewClientIPResolver`; Task 7 `console.Config.Users`.
- Produces: `func bootstrapUsers(store *users.Store, fileUsers []auth.User, envValue string, log zerolog.Logger) error` — parses via `ParseBootstrapUsers`; if the table is empty and there are users, `ImportIfEmpty` them as `RoleAdmin`, `MustChangePassword:false`, logs `imported N console users from config`; if the table is non-empty and config/env define users, logs one warning: `console.auth.users / JOEI_CONSOLE_AUTH_USERS are ignored: users are managed in the database (console Users page or jo-ei user)`; validation errors are returned (startup fails).

Wiring: build the resolver from `cfg.Server.TrustedProxies` / `ClientIPHeader`; `NewSessions(userStore, signer, accessTTL, refreshTTL, auth.WithLoginLimiter(auth.NewLoginLimiter(nil)), auth.WithClientIP(resolver.ClientIP), auth.WithLogger(logger))`; pass `Users: userStore` to `console.Config`. Locked warning text becomes: `console auth not configured — no enabled users; /api/ is disabled (HTTP 503) until one is created with "jo-ei user create <name> --role admin" (or bootstrap via console.auth.users / JOEI_CONSOLE_AUTH_USERS on an empty database); the proxy continues to serve`.

- [ ] **Step 1: Write failing tests:** `TestBootstrapUsers_ImportsOnce` (empty → 1 admin imported, `MustChangePassword` false; second call with a different env user changes nothing); `TestBootstrapUsers_WarnsWhenIgnored` (log buffer contains the warning); `TestBootstrapUsers_InvalidName` (Review Focus 3; env `ops+ci:<hash>` → error mentions `ops+ci`; table empty); `TestBootstrapUsers_NothingToImport` (empty env/config, empty table → nil error, no rows).
- [ ] **Step 2: Run** `go test ./cmd/jo-ei/ -run BootstrapUsers` — Expected: FAIL.
- [ ] **Step 3: Implement** and wire `main.go`.
- [ ] **Step 4: Run** `go build ./... && go test ./...` — Expected: PASS.
- [ ] **Step 5: Docs.** `docs/configuration.md` auth section: users live in the DB; roles table (what operator can/cannot do); bootstrap-once behaviour and the ignored-after-first-boot warning; passwords 12 chars – 72 bytes; login limits and pointer to the reverse-proxy note; multi-replica limits are per process. `config.yaml`: comment says `users` / env var only seed an empty database. `CHANGELOG.md` Unreleased: **Added** console users & roles (Users page, `jo-ei user`, login rate limiting, `server.trusted_proxies` + `server.client_ip_header`, list endpoints); **Changed** config/env users are bootstrap-only — editing them after first boot no longer changes who can log in; `PUT /api/policy` and `POST /api/cache/cleanup` are admin-only and `PUT /api/policy` keeps lists that are absent from the body.
- [ ] **Step 6: Commit** `feat: bootstrap console users from config once; wire users store`.

### Task 9: `jo-ei user` CLI

**Files:**
- Create: `cmd/jo-ei/user.go`, `cmd/jo-ei/user_test.go`
- Modify: `docs/configuration.md` (recovery subsection with the Docker form)

**Interfaces:**
- Consumes: global `cfgFile` / `--config`; `config.Load`; `storage.Open(cfg.Database.Path)`; Task 2 store + `ValidatePassword`, `HashPassword`.
- Produces: `func newUserCmd() *cobra.Command` registered in `init()` (constructor pattern like `newHashpwCmd`), subcommands:
  - `create <name> --role admin|operator [--generate] [--no-force-change]` — password from first stdin line (same reading as `runHashpw`) unless `--generate`, which prints a 20-char random password (`crypto/rand`, alphabet `A–Z a–z 0–9`) on stdout; validates; `MustChangePassword` true unless `--no-force-change`; `ErrExists` → error `user "x" already exists`.
  - `reset-password <name> [--generate] [--no-force-change]` — sets the password (bumps version) and `SetDisabled(false)`.
  - `list` — tab-aligned `USERNAME ROLE STATUS LAST LOGIN` (status `active` | `disabled` | `must change password`).
  - Bypasses the console's self guard; store guards still apply (they cannot trip for these operations).

- [ ] **Step 1: Write failing tests** driving the command with `SetArgs`/`SetIn`/`SetOut` and a temp config file pointing `database.path` into `t.TempDir()`: `TestUserCreate_FromStdin`, `TestUserCreate_Generate` (stdout password is 20 chars and logs in via `users.CheckPassword`), `TestUserCreate_RejectsShortPassword`, `TestUserResetPassword_ReEnablesAndBumpsVersion`, `TestUserList_Output`.
- [ ] **Step 2: Run** `go test ./cmd/jo-ei/ -run User` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./cmd/jo-ei/` — Expected: PASS.
- [ ] **Step 5: Docs.** Recovery subsection: `jo-ei user reset-password admin` and `docker compose exec jo-ei jo-ei user reset-password admin`; note it works while the server runs.
- [ ] **Step 6: Commit** `feat(cli): jo-ei user create/reset-password/list`.

### Task 10: Console — identity, roles, forced password change, list editing

**Files:**
- Modify: `web/console/src/api.js`, `web/console/src/app.jsx`, `web/console/src/policy.jsx`, `web/console/src/registries.jsx`, `web/console/src/drawer.jsx` (only if it calls `savePolicy`), `web/console/app.bundle.js` (generated)

**Interfaces:**
- Consumes: Task 4 `me`/login response fields and `POST /api/auth/password`; Task 6 list endpoints and settings-only PUT; Task 5 403 shape.
- Produces (on `window.JOEI`): `J.role` (`"admin"|"operator"|""`), `J.mustChangePassword` (bool), both set from `me`/login and cleared on logout, `joei:auth` fired on change; `J.isAdmin()`; `J.editList(list, entry, add)` → `POST|DELETE /api/policy/lists/{list}`, updates `J.policy` from the response and fires `joei:policy`; `J.savePolicy(p)` sends only `mode`, `min_age_hours`, `cve_block_on`; `J.changePassword(current, next)`; `authFetch` turns `403 forbidden` into an error with `status 403` and message "You don't have permission for this action".

UI (approved mockup):
- Sidebar footer: avatar, `username · role`, "Change password" (opens a small modal with current/new/confirm; shows server `message` on 400), "Sign out".
- Forced change screen: when `J.mustChangePassword`, render a full-page form (same styling as the login screen) instead of the shell; on success reload data via the existing boot path.
- Quarantine/drawer allowlist & denylist actions call `J.editList` (replace `saveLists`'s whole-policy PUT; keep the serialised chain and toasts).
- Policy page: list add/remove calls `J.editList` immediately (no draft). Settings block (mode, min age, CVE threshold) keeps the draft + "Save & apply" for admin; for operator it renders read-only with a 🔒 note "Only an admin can change these settings" and no save button.
- Registries page: operator sees upstreams read-only, no save, no "Clean up" button.

- [ ] **Step 1: Implement** the changes above.
- [ ] **Step 2: Regenerate** `go generate ./...` — Expected: `web/console/app.bundle.js` updated, no esbuild errors; `go test ./web/` PASS.
- [ ] **Step 3: Manual check** (use the `run` skill or a local `go run ./cmd/jo-ei` with a temp `database.path`): create an operator via `jo-ei user create anna --role operator --generate`; sign in as anna → forced change screen → change → Policy settings locked, list add/remove works, Registries read-only, no Users nav; sign in as admin → settings save works and does not drop anna's entry. Record what was checked in the commit body.
- [ ] **Step 4: Commit** `feat(console): roles in the UI, forced password change, atomic list edits`.

### Task 11: Console — Users page

**Files:**
- Create: `web/console/src/users.jsx`
- Modify: `web/console/src/api.js` (users calls), `web/console/src/app.jsx` (nav item, page switch), `web/console/index.html` or the esbuild entry if new files must be listed (check how `go generate ./web` collects sources), `web/console/app.bundle.js` (generated)

**Interfaces:**
- Consumes: Task 7 routes and error codes; Task 10 `J.isAdmin()`.
- Produces: `J.listUsers()`, `J.createUser({username, role, password})`, `J.updateUser(name, {role?, disabled?})`, `J.resetUserPassword(name, password)`, `J.deleteUser(name)`; NAV entry `{ id: "users", label: "Users", icon: … }` included only when `J.isAdmin()`.

UI (approved mockup): table Login / Role / Status / Last login / ⋯ menu (Change role, Reset password, Disable/Enable, Delete — delete asks for confirmation). Status text: `active`, `disabled`, `must change password`. "Add user" form: login, role radio (default operator), temporary password field + "Generate" (client-side, `crypto.getRandomValues`, 20 chars `A–Z a–z 0–9`), password shown once after create/reset with a copy button and the note "Shown once. The user sets their own at first sign-in." Error codes map to toasts: `user_exists` "A user with this name already exists", `last_admin` "At least one enabled admin must remain", `self` "You can't do this to your own account", `invalid_user` → server `message`.

- [ ] **Step 1: Implement.**
- [ ] **Step 2: Regenerate** `go generate ./...`; `go test ./web/` PASS.
- [ ] **Step 3: Manual check:** as admin create, change role, reset (temporary password shown once; that user is forced to change at sign-in), disable (their open session drops on next request), delete; try demoting yourself → "self" toast; operator never sees the nav item and `GET /api/users` returns 403. Record in the commit body.
- [ ] **Step 4: Commit** `feat(console): users management page`.

### Task 12: Final verification

- [ ] **Step 1:** `gofmt -l .` — Expected: no output. `golangci-lint run ./...` — Expected: `0 issues.`
- [ ] **Step 2:** `go test ./... && go test -tags integration ./integration/...` — Expected: all `ok`.
- [ ] **Step 3:** Race pass in Docker (memory `docker-race-tests`, image tag = go.mod `toolchain`):
  `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/src" -w /src -v joei-gomod:/go/pkg/mod -v joei-gocache:/root/.cache/go-build golang:1.26.10 sh -c 'go test ./... -race && go test -tags integration ./integration/... -race'` — Expected: all `ok`, no `DATA RACE`.
- [ ] **Step 4:** `go generate ./... && git diff --exit-code -- web/console/app.bundle.js` — Expected: exit 0.
- [ ] **Step 5:** Fix anything found, commit, then hand off to the whole-branch review.

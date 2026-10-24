# Console users and roles — design

Date: 2026-10-24
Status: draft, awaiting approval

## Problem

Console users are a static list of bcrypt hashes from `console.auth.users` or
`JOEI_CONSOLE_AUTH_USERS` (`internal/auth/users.go`). Every user can do
everything, and adding, removing or re-keying a person means editing an env var
or config file and restarting the proxy. The owner wants to manage people from
the console itself and give most of them a restricted role, without passing
credentials through environment variables.

## Goals

- Users live in the Jō-ei SQLite database and are managed by an admin in the
  console: create, change role, reset password, disable/enable, delete.
- Two fixed roles:
  - **admin**: everything, including user management.
  - **operator**: read everything; add/remove allowlist and denylist entries.
    Cannot change policy settings (mode, min age, CVE threshold), registries,
    cache cleanup, or users.
- Enforcement is server-side on every API route. The UI hides or locks what a
  role cannot do, but that is convenience, never the control.
- Changes take effect immediately: a deleted, disabled, demoted or re-passworded
  user loses what they lost on their next request, not when a token expires.
- The log records who added or removed each allowlist/denylist entry, and who
  did each user-management action.

## Non-goals

- SSO, OIDC, LDAP/Active Directory.
- Custom roles or a permission editor. Two roles, hard-coded.
- API tokens / service accounts (scripts keep using `POST /api/auth/login` and
  the bearer token it returns, as today).
- MFA, password expiry, e-mail invites or recovery.
- An audit-log page in the console. The structured log is the audit trail.

## Anti-goals

- A "first visitor becomes admin" setup wizard in the browser.
- Any path where losing every admin password means losing the install.
- Role taken from the JWT alone (a demoted user would keep admin rights until
  the token expires).

## Decided with the owner

1. **Roles** as listed above. Approved UI: mockup in the brainstorm session
   (new `Users` nav item visible to admin only; table of login / role / status /
   last login with a per-row menu: change role, reset password,
   disable/enable, delete; "Add user" form with login, role radio, temporary
   password with a "generate" button, shown once; "Change password" and
   "Sign out" at the bottom of the sidebar for everyone; operator sees the
   Policy settings block read-only with a lock and "only admin can change",
   lists editable; Quarantine allow/deny buttons work for operator).
2. **Storage**: users and bcrypt hashes in the database.
3. **Bootstrap** (revised by owner decision, 2026-10-24): on startup, if the
   users table is completely empty, create user `admin` with a generated
   temporary password that is logged once. Config/env users
   (`console.auth.users`, `JOEI_CONSOLE_AUTH_USERS`) are removed. The database
   is the only source of truth. No browser setup wizard.
4. **Recovery** (revised by owner decision, 2026-10-24): a single CLI command,
   `jo-ei reset-admin-password`, that works on the database directly. The
   `jo-ei user …` and `jo-ei hashpw` commands are removed.
5. **Cache cleanup is admin-only.**
6. **Audit**: log lines are enough, no UI.
7. Accepted best-practice set (proposed by Claude, approved by the owner):
   cannot remove/demote the last admin; changes are immediate; temporary
   password + forced change on first login; users change their own password;
   minimum password length 12 with no composition rules (NIST 800-63B); login
   rate limiting.

## Design

### Data

New migration component `users` (via `storage.DB.ApplyMigrations`), table
`users`:

| column | notes |
|---|---|
| `username` | primary key, see naming rule below |
| `password_hash` | bcrypt |
| `role` | `admin` \| `operator` |
| `disabled` | bool |
| `must_change_password` | bool |
| `tokens_valid_after` | Unix seconds; tokens with `iat` before this are rejected |
| `created_at`, `last_login_at` | Unix seconds; `last_login_at` nullable |

Username rule: 1–64 chars of `[A-Za-z0-9._@-]`, uniqueness case-insensitive
(stored as entered, compared lowercased). Imported users that break the rule
fail startup with a message naming the user.

### Roles and the route matrix

Role is read from the database on every request (with the user's
`disabled` and `tokens_valid_after`), never from the token. The existing
per-request `Users.Known(sub)` check already makes this the shape; it becomes a
lookup returning the user record.

| route | operator | admin |
|---|---|---|
| `GET` overview, requests, events, quarantine, policy, registries, metrics/daily | ✓ | ✓ |
| `POST /api/policy/lists/{list}` / `DELETE /api/policy/lists/{list}` (new) | ✓ | ✓ |
| `PUT /api/policy` | — | ✓ |
| `PUT /api/registries`, `POST /api/cache/cleanup` | — | ✓ |
| `/api/users*` (new) | — | ✓ |
| `/api/auth/*` (login, refresh, logout, me, password) | ✓ | ✓ |

Forbidden → `403 {"error":"forbidden"}`. New routes default to admin-only: the
check is a per-route declaration, so a route added without one is denied to
operators, not allowed.

**List endpoints.** Today the console edits lists by `PUT /api/policy` with the
whole policy object. That cannot be split by field safely (an operator PUT
carrying a stale `mode` either overwrites an admin's change or must be
rejected), and two concurrent whole-object PUTs lose entries. So list edits get
their own atomic endpoints:

- `{list}` ∈ `allowlist_supply`, `allowlist_cve`, `denylist`
- body `{"entry":"eco/name[@version]"}`; same validation as `PUT /api/policy`
- `POST` adds (idempotent if present), `DELETE` removes (idempotent if absent)
- applied through `policy.Runtime` under its lock, persisted like a PUT
- response: the full policy, same shape as `GET /api/policy`
- log line: `policy list updated`, fields `user`, `list`, `entry`,
  `action` (`add`|`remove`)

`PUT /api/policy` stays (admin-only) and keeps logging `runtime policy updated`
with `user`. *(Claude's call, from the builder check)* To stop an admin's
settings save from wiping list entries added meanwhile, list fields in the PUT
body become optional: an **absent** list field means "leave unchanged"; a
present one (even `[]`) replaces as today. Scripts sending the full object keep
working; the console stops sending lists in PUT. `policy.Runtime` serialises
`Apply` and list edits under one mutex.

**Policy page save model** *(Claude's call)*: list add/remove applies
immediately through the list endpoints, for admin and operator alike (matches
the mockup's `+ добавить` / `✕`). The "Save & apply" button covers only mode,
min age and CVE threshold, sends PUT without list fields, and is absent for
operator. Quarantine/drawer `saveLists` also switches to the list endpoints.

### Sessions

- `iat` < user's `tokens_valid_after` → 401, same as an invalid token.
- `tokens_valid_after` is bumped to now on: password reset by admin, own
  password change, disable, role change. Own password change re-issues the
  caller's session in the same response, so only *other* sessions die.
- Delete removes the row; existing tokens fail the lookup → 401.
- `must_change_password`: such a user can call `/api/auth/me`,
  `/api/auth/password`, `/api/auth/logout`, `/api/auth/refresh`; everything
  else under `/api/` → `403 {"error":"password_change_required"}`. The console
  shows a change-password screen after login when `me` reports the flag.
- `GET /api/auth/me` returns `{username, role, must_change_password}`.
- Login: a disabled user gets the same `401 invalid_credentials` as a wrong
  password (no enumeration). Successful login sets `last_login_at`.
- Login rate limiting, in memory (not persisted). *(Claude's call, from the
  builder check)*:
  - Keyed on **(username, client IP)**: after 5 failures within 15 minutes,
    attempts for that pair get `429` + `Retry-After` until the window passes —
    **including a correct password** (otherwise the 429 leaks nothing and the
    limit does not slow guessing). Keying on the pair rather than the username
    alone means an attacker cannot lock a real admin out from another address.
  - Keyed on **client IP** alone: 20 failures per 15 minutes → `429`, against
    password spraying across usernames.
  - A successful login resets that pair's counter. No CLI reset is needed:
    windows expire on their own, and a restart clears everything.
  - **Client IP behind a reverse proxy** *(decided with the owner)*. The
    limits must see the original client, so forwarded headers are honoured —
    but only from trusted peers, or any client could spoof its address:
    - `server.trusted_proxies`: list of CIDRs/IPs, **default empty**.
    - `server.client_ip_header`: `X-Forwarded-For` (default) | `X-Real-IP` |
      `Forwarded` (RFC 7239 `for=`).
    - If the TCP peer (`r.RemoteAddr`) is not trusted → client IP is the peer,
      headers ignored. If trusted → walk the header's address chain from the
      right and take the first address not in `trusted_proxies` (for
      `X-Real-IP`, its single value). Malformed or missing header from a
      trusted peer → fall back to the peer address.
    - When a request carries `X-Forwarded-For`, `X-Real-IP` or `Forwarded`
      from an untrusted peer, log one warning per process (not per request):
      Jō-ei looks to be behind a proxy, every client shares the proxy's IP for
      the limits, set `server.trusted_proxies`. Includes the peer address.
    - The resolved client IP is also what the auth log lines report.
    - The compose example with a proxy (or its docs) shows `trusted_proxies`
      set to the proxy's network.
    - Validation: unparsable CIDR/IP or unknown header name fails startup.
  - Counters are per process; multi-replica deployments get per-replica limits
    (acceptable; noted in docs).

### Passwords

- Length 12–72 bytes (72 is bcrypt's input limit; longer is rejected, not
  truncated). No composition rules. Must not equal the username.
- Admin-set passwords (create, reset) mark `must_change_password`. The
  "generate" button works client-side (`crypto.getRandomValues`, 20 chars);
  the server only sees the result.
- `POST /api/auth/password` `{current, new}`: requires the current password
  (also when `must_change_password` is set), new ≠ current.

### Users API (admin-only)

- `GET /api/users` → list of `{username, role, disabled,
  must_change_password, created_at, last_login_at}`. Never hashes.
- `POST /api/users` `{username, role, password}` → 201; 409 if taken.
- `PATCH /api/users/{name}` `{role?, disabled?}`.
- `POST /api/users/{name}/password` `{password}` → reset; sets
  `must_change_password`.
- `DELETE /api/users/{name}`.
- Guard rails → `409 {"error":"last_admin"}` if the change would leave zero
  enabled admins; `409 {"error":"self"}` for an admin deleting, disabling or
  demoting themselves (they use another admin, or the CLI).
- Every mutation logs `user management` with `user` (actor), `target`,
  `action` (`create`|`role`|`disable`|`enable`|`reset_password`|`delete`), and
  `role` where relevant. Never the password or hash.

### Bootstrap: the initial admin

*Owner decision, 2026-10-24.* This replaces the earlier draft, which imported
config/env users into an empty table and kept a `jo-ei user` CLI.

- Startup: open DB, run migrations, call `Store.EnsureInitialAdmin`. If the
  `users` table has no rows at all it creates — with a single
  `INSERT ... WHERE NOT EXISTS (SELECT 1 FROM users)` statement, so two
  processes starting on the same empty database cannot both create it or fail
  with "database is locked" — user `admin` with role `admin`,
  `must_change_password = true` and a random 20-character password
  (`A–Z a–z 0–9`, crypto/rand, unbiased — `users.GeneratePassword`).
- The password is logged exactly once, at creation, as one `warn` line:
  message `created initial admin user`, fields `user=admin`,
  `password=<temp>` and a hint to change it at first sign-in or run
  `jo-ei reset-admin-password`. This is the only place a password ever appears
  in logs; later restarts print nothing.
- If the table has any row (even only disabled users), nothing is created. With
  no enabled users the console is locked (`/api/` → 503) and the startup
  warning points at `jo-ei reset-admin-password`.
- `console.auth.users`, `JOEI_CONSOLE_AUTH_USERS`, `auth.ParseBootstrapUsers`
  and `Store.ImportIfEmpty` are removed outright — no compatibility handling and
  no warning. A database that already holds users keeps them; a fresh or empty
  database no longer reads config/env users. Upgrading from 0.5.x: the users
  table is new, so the accounts defined in `console.auth.users` /
  `JOEI_CONSOLE_AUTH_USERS` are not imported — a fresh `admin` with a generated
  password is created and the other people are re-created on the Users page.
- Security trade-off, documented: the temporary password lands in the logs (and
  any log aggregator) and stays valid until `admin` signs in and changes it.
- `Users` is DB-backed; `Locked()` = no enabled users.

### CLI: `jo-ei reset-admin-password`

*Owner decision, 2026-10-24.* The only user-related CLI command; it reads the
global `--config` to find the DB.

- Fails clearly if the database file does not exist (a wrong `--config` must
  not silently create an empty database).
- Generates a new temporary password with `users.GeneratePassword` and prints
  only that password on stdout (one line); other messages go to stderr.
- `Store.ResetAdmin(hash)`, one transaction: if `admin` exists, set the
  password (token_version bump → all its sessions revoked), set
  `must_change_password`, enable it and restore role `admin` if it was demoted;
  if `admin` was deleted, recreate it as an admin with `must_change_password`.
- Restoring or enabling an admin only adds admins, so the console's last-admin
  and self guards never apply to it.
- Works while the server runs (WAL mode; the server reads users per request).
- Docker form: `docker compose exec -T jo-ei /jo-ei --config
  /etc/jo-ei/config.yaml reset-admin-password` (the distroless image has no
  shell, `/jo-ei` is not on `PATH`, and `--config` defaults to `config.yaml` in
  the working directory).

### Console

- `Users` page and nav item, rendered only for admin (approved mockup).
- Sidebar identity from `me`: `name · role`, plus "Change password", "Sign out".
- Operator: Policy settings block read-only with a lock note; lists editable via
  the new endpoints. Registries page read-only (save controls hidden); cache
  cleanup button hidden.
- Forced change-password screen when `must_change_password`.
- A `403 forbidden` from the API shows a toast; it should not happen in normal
  use.

### Docs and release

- `docs/configuration.md`: auth section rewritten — DB users, roles, the
  initial admin, `reset-admin-password`, rate limits.
- `config.yaml` comments updated.
- CHANGELOG `Added` (users & roles, `server.trusted_proxies` +
  `server.client_ip_header`, list endpoints)
  and `Changed` (initial admin with a logged temporary password replaces
  config/env users, which are removed along with `jo-ei hashpw`;
  `PUT /api/policy` is admin-only and treats absent list fields as unchanged).

### Builder's own calls already noted

`/api/users*` is admin-only even for GET (the users row overrides the
`GET /api/*` row); `tokens_valid_after` comparison must not reject the session
re-issued in the same second (use sub-second precision or compare `iat` with
`>=` against a value truncated down); usernames are normalised (lowercased) in
the token subject.

## Left to the builder

- Whether user records are read straight from SQLite per request or through a
  write-through in-memory cache — as long as CLI writes are seen live (a cache
  must then be invalidated or have a short TTL; plain per-request reads are
  fine at console traffic levels).
- Exact rate-limiter structure and cleanup of stale counters.
- Package layout (e.g. a store in `internal/auth` or a new `internal/users`).
- UI copy and styling within the approved mockup.
- Test split; race-sensitive paths (rate limiter, concurrent list edits) run
  under `-race` (see Docker recipe used for this repo).

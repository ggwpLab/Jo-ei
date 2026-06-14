# Console & API Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add HTTP Basic authentication to `/console/` and `/api/` (per-user accounts, fail-closed when unconfigured), leaving registry traffic and `/health` open.

**Architecture:** A new `internal/auth` package holds the credential set (username → bcrypt hash, loaded from config + the `JOEI_CONSOLE_AUTH_USERS` env var) and an `http.Handler` middleware. `cmd/jo-ei/main.go` wraps only the console and API handlers with it; the proxy mux is untouched. A `jo-ei hashpw` subcommand generates bcrypt hashes. The authenticated username flows into the request context so `PUT /api/policy` can log who made a change.

**Tech Stack:** Go 1.25 stdlib + `golang.org/x/crypto/bcrypt` (new direct dependency; already in the module graph at v0.21.0), `spf13/cobra` (existing), `spf13/viper` (existing), zerolog, testify.

**Spec:** `docs/superpowers/specs/2026-06-13-console-auth-design.md`

---

## File structure

| File | Responsibility |
|---|---|
| `internal/config/config.go` (modify) | add `Console.Auth.Users` config types + field |
| `internal/config/config_test.go` (modify) | test that `console.auth.users` unmarshals |
| `internal/auth/users.go` (new) | `User`, `Users`, `NewUsers` (parse file+env, validate), `Verify`, `Locked` |
| `internal/auth/users_test.go` (new) | construction/merge/validation/verify tests |
| `internal/auth/middleware.go` (new) | `Middleware`, context key, `UserFromContext` |
| `internal/auth/middleware_test.go` (new) | locked/401/200/context tests |
| `cmd/jo-ei/hashpw.go` (new) | `hashpw` cobra subcommand |
| `cmd/jo-ei/hashpw_test.go` (new) | hash round-trips; empty input errors |
| `cmd/jo-ei/main.go` (modify) | build `auth.Users`, wrap `/console/` + `/api/`, fail-closed warn |
| `internal/console/server.go` (modify) | `putPolicy` logs the authenticated `user` |
| `internal/console/server_test.go` (modify) | putPolicy still works with no user in context |
| `integration/console_auth_test.go` (new) | end-to-end: 401/200/503, proxy+health open, policy change attributed |
| `README.md`, `config.yaml`, `docker-compose.yaml` (modify) | document auth, hashpw, fail-closed, TLS-via-proxy |

**Conventions to hold across tasks:**
- Module path: `github.com/ggwpLab/Jo-ei`.
- The `WWW-Authenticate` realm uses **ASCII** `"Joei Console"` (not "Jōei") — HTTP header values must be ASCII; the non-ASCII `ō` from the spec prose is dropped here deliberately.
- Per-task verification uses plain `go test` (this repo's `-race` gate requires cgo, which CI provides on Linux but may be absent locally). The final task notes the full `-race` run for CI.

---

## Task 1: Config types for `console.auth.users`

**Files:**
- Modify: `internal/config/config.go` (add field to `Config`, add three types)
- Modify: `internal/config/config_test.go` (append one test)

- [ ] **Step 1: Write the failing test**

Append to `internal/config/config_test.go`:

```go
func TestLoadConsoleAuthUsers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
console:
  auth:
    users:
      - username: admin
        password_hash: "$2a$10$abcdefghijklmnopqrstuv"
      - username: alice
        password_hash: "$2a$10$zyxwvutsrqponmlkjihgfe"
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	require.NoError(t, err)
	require.Len(t, cfg.Console.Auth.Users, 2)
	assert.Equal(t, "admin", cfg.Console.Auth.Users[0].Username)
	assert.Equal(t, "$2a$10$abcdefghijklmnopqrstuv", cfg.Console.Auth.Users[0].PasswordHash)
	assert.Equal(t, "alice", cfg.Console.Auth.Users[1].Username)
}
```

If `filepath`, `os`, `require`, or `assert` are not already imported in this test file, add them. (The test only depends on `config.Load`, which already tolerates a minimal config: no enabled registries and no scanners pass `Validate`.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/config/ -run TestLoadConsoleAuthUsers -v`
Expected: FAIL — `cfg.Console` undefined.

- [ ] **Step 3: Add the config types**

In `internal/config/config.go`, add `Console` to the `Config` struct (after the `Logging` field):

```go
type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	Registries  RegistriesConfig  `mapstructure:"registries"`
	SupplyChain SupplyChainConfig `mapstructure:"supply_chain"`
	CVE         CVEConfig         `mapstructure:"cve"`
	Malware     MalwareConfig     `mapstructure:"malware"`
	Cache       CacheConfig       `mapstructure:"cache"`
	Policy      PolicyConfig      `mapstructure:"policy"`
	Logging     LoggingConfig     `mapstructure:"logging"`
	Console     ConsoleConfig     `mapstructure:"console"`
}
```

Add these types near `ServerConfig` (anywhere at file scope):

```go
// ConsoleConfig holds admin-console settings.
type ConsoleConfig struct {
	Auth AuthConfig `mapstructure:"auth"`
}

// AuthConfig holds the console/API Basic-auth credential list. An empty Users
// list means authentication is unconfigured; the server then serves the
// console and API as 503 (fail-closed).
type AuthConfig struct {
	Users []AuthUser `mapstructure:"users"`
}

// AuthUser is one console credential: a username and a bcrypt password hash.
type AuthUser struct {
	Username     string `mapstructure:"username"`
	PasswordHash string `mapstructure:"password_hash"`
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/config/ -run TestLoadConsoleAuthUsers -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add console.auth.users credential config"
```

---

## Task 2: `auth.Users` — credential set, merge, validation, verify

**Files:**
- Create: `internal/auth/users.go`
- Test: `internal/auth/users_test.go`

This task introduces the `golang.org/x/crypto/bcrypt` dependency.

- [ ] **Step 1: Write the failing tests**

Create `internal/auth/users_test.go`:

```go
package auth_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/ggwpLab/Jo-ei/internal/auth"
)

// hash returns a low-cost bcrypt hash of pw, for fast tests.
func hash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	require.NoError(t, err)
	return string(h)
}

func TestNewUsersFileOnly(t *testing.T) {
	u, err := auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: hash(t, "secret")}}, "")
	require.NoError(t, err)
	assert.False(t, u.Locked())
	assert.True(t, u.Verify("admin", "secret"))
	assert.False(t, u.Verify("admin", "wrong"))
}

func TestNewUsersEnvOnly(t *testing.T) {
	env := "alice:" + hash(t, "pw1") + " ; bob:" + hash(t, "pw2")
	u, err := auth.NewUsers(nil, env)
	require.NoError(t, err)
	assert.True(t, u.Verify("alice", "pw1"))
	assert.True(t, u.Verify("bob", "pw2"))
	assert.False(t, u.Verify("alice", "pw2"))
}

func TestNewUsersEnvOverridesFile(t *testing.T) {
	file := []auth.User{{Username: "admin", PasswordHash: hash(t, "oldpw")}}
	env := "admin:" + hash(t, "newpw")
	u, err := auth.NewUsers(file, env)
	require.NoError(t, err)
	assert.False(t, u.Verify("admin", "oldpw"), "env entry overrides the file entry")
	assert.True(t, u.Verify("admin", "newpw"))
}

func TestNewUsersEmptyIsLocked(t *testing.T) {
	u, err := auth.NewUsers(nil, "")
	require.NoError(t, err)
	assert.True(t, u.Locked())
	assert.False(t, u.Verify("admin", "secret"))
}

func TestNewUsersValidationErrors(t *testing.T) {
	good := hash(t, "secret")

	_, err := auth.NewUsers([]auth.User{{Username: "  ", PasswordHash: good}}, "")
	require.Error(t, err, "blank username")

	_, err = auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: "not-a-bcrypt-hash"}}, "")
	require.Error(t, err, "non-bcrypt hash")

	_, err = auth.NewUsers(nil, "no-colon-entry")
	require.Error(t, err, "env entry without ':'")
}

func TestVerifyUnknownUser(t *testing.T) {
	u, err := auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: hash(t, "secret")}}, "")
	require.NoError(t, err)
	assert.False(t, u.Verify("nobody", "secret"))
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/auth/ -v`
Expected: FAIL — package does not exist / undefined `auth.NewUsers`.

- [ ] **Step 3: Implement `internal/auth/users.go`**

```go
// Package auth provides HTTP Basic authentication for the admin console and
// API. Credentials are a set of username + bcrypt password-hash pairs loaded
// from config and the JOEI_CONSOLE_AUTH_USERS environment variable. With no
// users configured the set is "locked" (fail-closed): the middleware serves
// 503 and never reaches the wrapped handler.
package auth

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// User is one credential: a username and its bcrypt password hash.
type User struct {
	Username     string
	PasswordHash string
}

// Users is a validated set of credentials. An empty set is the locked state.
type Users struct {
	byName map[string]string // username -> bcrypt hash
}

// dummyHash is compared against when an unknown username is supplied so that
// response timing does not reveal whether a username exists. Generated once at
// package load at the default cost.
var dummyHash []byte

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte("joei-timing-dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		panic("auth: generating dummy hash: " + err.Error())
	}
	dummyHash = h
}

// NewUsers builds the credential set from config-file users and the
// semicolon-separated JOEI_CONSOLE_AUTH_USERS env value
// ("username:hash;username:hash"). Whitespace around entries is trimmed. Env
// entries override file entries with the same username. Every username must be
// non-empty and every hash must be a valid bcrypt hash, else an error is
// returned. An empty result is valid and yields the locked state.
func NewUsers(fileUsers []User, envValue string) (*Users, error) {
	byName := map[string]string{}

	add := func(username, passwordHash, src string) error {
		name := strings.TrimSpace(username)
		if name == "" {
			return fmt.Errorf("auth: %s: empty username", src)
		}
		h := strings.TrimSpace(passwordHash)
		if _, err := bcrypt.Cost([]byte(h)); err != nil {
			return fmt.Errorf("auth: %s: user %q: password_hash is not a valid bcrypt hash: %w", src, name, err)
		}
		byName[name] = h
		return nil
	}

	for _, u := range fileUsers {
		if err := add(u.Username, u.PasswordHash, "config"); err != nil {
			return nil, err
		}
	}
	for _, entry := range strings.Split(envValue, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// bcrypt hashes contain no ':' and usernames may not, so split on the
		// first ':' — everything after it is the hash.
		name, h, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("auth: JOEI_CONSOLE_AUTH_USERS entry %q must be username:hash", entry)
		}
		if err := add(name, h, "JOEI_CONSOLE_AUTH_USERS"); err != nil {
			return nil, err
		}
	}

	return &Users{byName: byName}, nil
}

// Locked reports whether no users are configured (fail-closed state).
func (u *Users) Locked() bool { return len(u.byName) == 0 }

// Verify reports whether username/password match a configured user. For an
// unknown username it still performs a bcrypt comparison against a dummy hash
// so timing does not reveal which usernames exist.
func (u *Users) Verify(username, password string) bool {
	h, ok := u.byName[username]
	if !ok {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) == nil
}
```

- [ ] **Step 4: Add the dependency and run the tests**

Run: `go mod tidy && go test ./internal/auth/ -v`
Expected: `go mod tidy` promotes `golang.org/x/crypto` to a direct require; all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/users.go internal/auth/users_test.go go.mod go.sum
git commit -m "feat(auth): credential set with bcrypt verify and config+env merge"
```

---

## Task 3: `auth.Middleware` + request-context username

**Files:**
- Create: `internal/auth/middleware.go`
- Test: `internal/auth/middleware_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/auth/middleware_test.go`:

```go
package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestMiddlewareLockedReturns503(t *testing.T) {
	u, err := auth.NewUsers(nil, "") // no users -> locked
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	u.Middleware(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.False(t, called, "locked middleware must not reach the handler")
	assert.Contains(t, rec.Body.String(), "auth_not_configured")
}

func TestMiddlewareNoCredentialsChallenges(t *testing.T) {
	u, err := auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: hash(t, "secret")}}, "")
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	u.Middleware(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Basic realm=")
}

func TestMiddlewareBadCredentials(t *testing.T) {
	u, err := auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: hash(t, "secret")}}, "")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.SetBasicAuth("admin", "wrong")
	rec := httptest.NewRecorder()
	u.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareGoodCredentialsPassesAndSetsContext(t *testing.T) {
	u, err := auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: hash(t, "secret")}}, "")
	require.NoError(t, err)

	var seenUser string
	var seenOK bool
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUser, seenOK = auth.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.SetBasicAuth("admin", "secret")
	rec := httptest.NewRecorder()
	u.Middleware(probe).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, seenOK)
	assert.Equal(t, "admin", seenUser)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/auth/ -run TestMiddleware -v`
Expected: FAIL — undefined `Middleware` / `UserFromContext`.

- [ ] **Step 3: Implement `internal/auth/middleware.go`**

```go
package auth

import (
	"context"
	"net/http"
)

type ctxKey struct{}

// Middleware wraps h with HTTP Basic authentication.
//
//   - Locked (no users configured): serves 503 and never calls h.
//   - Missing or invalid credentials: serves 401 with a Basic challenge.
//   - Valid credentials: stores the username in the request context (see
//     UserFromContext) and calls h.
func (u *Users) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u.Locked() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"auth_not_configured"}` + "\n"))
			return
		}
		username, password, ok := r.BasicAuth()
		if !ok || !u.Verify(username, password) {
			// Realm is ASCII on purpose: HTTP header values must be ASCII.
			w.Header().Set("WWW-Authenticate", `Basic realm="Joei Console", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, username)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserFromContext returns the authenticated username stored by Middleware, and
// false when the request did not pass through the authenticating middleware.
func UserFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(ctxKey{}).(string)
	return name, ok
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/auth/ -v`
Expected: PASS (all Task 2 and Task 3 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/auth/middleware.go internal/auth/middleware_test.go
git commit -m "feat(auth): Basic-auth middleware with fail-closed lock and context username"
```

---

## Task 4: `jo-ei hashpw` subcommand

**Files:**
- Create: `cmd/jo-ei/hashpw.go`
- Test: `cmd/jo-ei/hashpw_test.go`

- [ ] **Step 1: Write the failing tests**

Create `cmd/jo-ei/hashpw_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHashpwProducesVerifiableHash(t *testing.T) {
	cmd := newHashpwCmd()
	cmd.SetIn(strings.NewReader("mypassword\n"))
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())

	got := strings.TrimSpace(out.String())
	require.NotEmpty(t, got)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(got), []byte("mypassword")),
		"printed hash must verify against the original password")
}

func TestHashpwEmptyPasswordErrors(t *testing.T) {
	cmd := newHashpwCmd()
	cmd.SetIn(strings.NewReader("\n"))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	assert.Error(t, cmd.Execute())
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/jo-ei/ -run TestHashpw -v`
Expected: FAIL — undefined `newHashpwCmd`.

- [ ] **Step 3: Implement `cmd/jo-ei/hashpw.go`**

```go
package main

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

// newHashpwCmd builds the `jo-ei hashpw` subcommand. It is a constructor (not a
// package var) so tests can wire in their own stdin/stdout.
func newHashpwCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hashpw",
		Short: "Read a password from stdin and print its bcrypt hash",
		Long: "Reads a single line from stdin and prints its bcrypt hash on stdout, " +
			"for use in console.auth.users[].password_hash or the " +
			"JOEI_CONSOLE_AUTH_USERS environment variable.\n\n" +
			"Example: printf '%s' \"$PASSWORD\" | jo-ei hashpw",
		Args: cobra.NoArgs,
		RunE: runHashpw,
	}
}

func init() {
	rootCmd.AddCommand(newHashpwCmd())
}

func runHashpw(cmd *cobra.Command, _ []string) error {
	reader := bufio.NewReader(cmd.InOrStdin())
	line, err := reader.ReadString('\n')
	// A final line with no trailing newline returns io.EOF together with the
	// data, so only treat EOF as fatal when nothing was read.
	if err != nil && line == "" {
		return fmt.Errorf("reading password from stdin: %w", err)
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return fmt.Errorf("empty password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// bcrypt rejects passwords longer than 72 bytes.
		return fmt.Errorf("hashing password: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(hash))
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./cmd/jo-ei/ -run TestHashpw -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/jo-ei/hashpw.go cmd/jo-ei/hashpw_test.go
git commit -m "feat(cmd): add jo-ei hashpw subcommand for bcrypt hashes"
```

---

## Task 5: Wire auth into the server

**Files:**
- Modify: `cmd/jo-ei/main.go` (imports; build `auth.Users`; wrap handlers; warn when locked; add `toAuthUsers` helper)

There is no unit test for `main.go` wiring; build verification here, behavior verified end-to-end in Task 7.

- [ ] **Step 1: Add the auth import**

In `internal/auth`'s consumer `cmd/jo-ei/main.go`, add to the import block (keep imports grouped/sorted as the file already is):

```go
	"github.com/ggwpLab/Jo-ei/internal/auth"
```

- [ ] **Step 2: Build the credential set before the root mux**

In `runProxy`, immediately **before** the `root := http.NewServeMux()` line (currently `cmd/jo-ei/main.go:189`), insert:

```go
	authUsers, err := auth.NewUsers(toAuthUsers(cfg.Console.Auth.Users), os.Getenv("JOEI_CONSOLE_AUTH_USERS"))
	if err != nil {
		return err
	}
	if authUsers.Locked() {
		logger.Warn().Msg("console auth not configured — /console/ and /api/ are disabled (HTTP 503) until users are added (set console.auth.users or JOEI_CONSOLE_AUTH_USERS); the proxy continues to serve")
	}
```

(`os` is already imported.)

- [ ] **Step 3: Wrap the console and API handlers**

Replace the three `root.Handle(...)` lines (currently `cmd/jo-ei/main.go:190-201`) so the console and API are wrapped while the proxy mux is not:

```go
	root := http.NewServeMux()
	root.Handle("/console/", authUsers.Middleware(web.ConsoleHandler()))
	root.Handle("/api/", authUsers.Middleware(console.NewHandler(console.Config{
		Store:         store,
		Broadcaster:   broadcaster,
		Policy:        policyRuntime,
		Cache:         artifactCache,
		CacheMaxBytes: int64(cfg.Cache.Local.MaxSizeGB) << 30,
		Registries:    registryInfo(cfg),
		Scanners:      scannerInfo(cfg, profile),
		Logger:        logger,
	})))
	root.Handle("/", mux)
```

- [ ] **Step 4: Add the `toAuthUsers` helper**

Add at file scope in `cmd/jo-ei/main.go` (e.g. near `registryInfo`):

```go
// toAuthUsers converts the config credential list into auth.User values.
func toAuthUsers(in []config.AuthUser) []auth.User {
	out := make([]auth.User, len(in))
	for i, u := range in {
		out[i] = auth.User{Username: u.Username, PasswordHash: u.PasswordHash}
	}
	return out
}
```

- [ ] **Step 5: Build and run the existing suite**

Run: `go build ./... && go test ./cmd/jo-ei/ ./internal/auth/ ./internal/config/`
Expected: clean build; all PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/jo-ei/main.go
git commit -m "feat(cmd): require Basic auth on /console/ and /api/, fail-closed when unset"
```

---

## Task 6: Attribute policy changes to the authenticated user

**Files:**
- Modify: `internal/console/server.go` (`putPolicy` success log; new import)
- Modify: `internal/console/server_test.go` (append one test)

- [ ] **Step 1: Write the failing test**

Append to `internal/console/server_test.go` (it is package `console_test`; if it is internal `package console`, drop the package-qualified `console.` prefixes and adjust imports to match the file):

```go
func TestPutPolicyLogsWithoutUserWhenContextEmpty(t *testing.T) {
	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)

	rt := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{}, config.PolicyProfile{}, nil,
	)
	h := console.NewHandler(console.Config{
		Store: telemetry.NewStore(8), Broadcaster: telemetry.NewBroadcaster(),
		Policy: rt, Logger: logger,
	})

	body := `{"mode":"enforce","min_age_hours":24,"cve_block_on":"HIGH","allowlist":[],"denylist":[]}`
	req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	// No authenticating middleware in front, so the log line must not carry a
	// "user" field (and must not panic building it).
	assert.NotContains(t, logBuf.String(), `"user"`)
}
```

Ensure the test file imports `bytes`, `strings`, `net/http`, `net/http/httptest`, `github.com/rs/zerolog`, the testify packages, and the `config`/`policy`/`telemetry`/`console` packages. Most are already present in `server_test.go`; add only what is missing.

- [ ] **Step 2: Run the test to verify it passes against current code, then make it meaningful**

Run: `go test ./internal/console/ -run TestPutPolicyLogsWithoutUserWhenContextEmpty -v`
Expected: PASS already (current code logs no user field). This test locks in the "no user → no field, no panic" behavior so the Step 3 change cannot regress it. Proceed to Step 3.

- [ ] **Step 3: Read the user from context in `putPolicy`**

In `internal/console/server.go`, add the auth import:

```go
	"github.com/ggwpLab/Jo-ei/internal/auth"
```

Replace the success log line in `putPolicy` (currently `internal/console/server.go:240`):

```go
	s.cfg.Logger.Info().Interface("policy", s.cfg.Policy.Current()).Msg("runtime policy updated via console")
```

with:

```go
	logEvent := s.cfg.Logger.Info().Interface("policy", s.cfg.Policy.Current())
	if user, ok := auth.UserFromContext(r.Context()); ok && user != "" {
		logEvent = logEvent.Str("user", user)
	}
	logEvent.Msg("runtime policy updated via console")
```

(`r` is already the `*http.Request` parameter of `putPolicy`.)

- [ ] **Step 4: Run the console suite**

Run: `go test ./internal/console/ -v`
Expected: PASS (the new test and all existing ones).

- [ ] **Step 5: Commit**

```bash
git add internal/console/server.go internal/console/server_test.go
git commit -m "feat(console): attribute runtime policy edits to the authenticated user"
```

---

## Task 7: End-to-end integration tests

**Files:**
- Create: `integration/console_auth_test.go`

- [ ] **Step 1: Write the tests**

Create `integration/console_auth_test.go`:

```go
//go:build integration

package integration_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

// authConsoleStack mirrors cmd/jo-ei wiring with auth.Middleware in front of
// /console/ and /api/. users==nil yields the locked (fail-closed) state. The
// console handler logs into logBuf so attribution can be asserted.
func authConsoleStack(t *testing.T, upstream *httptest.Server, users *auth.Users, logBuf *bytes.Buffer) *httptest.Server {
	t.Helper()

	dir := t.TempDir()
	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, TTL: 24 * time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = localCache.Close() })

	runtime := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{}, config.PolicyProfile{}, nil,
	)
	store := telemetry.NewStore(100)
	bcast := telemetry.NewBroadcaster()
	hub := &telemetry.Hub{Store: store, Broadcaster: bcast}

	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:  adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:   runtime,
		Cache:    &localCacheAdapter{lc: localCache},
		Logger:   zerolog.Nop(),
		Recorder: hub,
	})
	mux := proxy.NewMux(map[string]*proxy.Handler{"pypi": handler}, zerolog.Nop())

	consoleLogger := zerolog.New(logBuf)
	root := http.NewServeMux()
	root.Handle("/api/", users.Middleware(console.NewHandler(console.Config{
		Store: store, Broadcaster: bcast, Policy: runtime, Logger: consoleLogger,
	})))
	root.Handle("/", mux)

	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)
	return srv
}

func testUsers(t *testing.T) *auth.Users {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	require.NoError(t, err)
	u, err := auth.NewUsers([]auth.User{{Username: "admin", PasswordHash: string(h)}}, "")
	require.NoError(t, err)
	return u
}

func TestConsoleAuth_RequiresCredentials(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	srv := authConsoleStack(t, upstream, testUsers(t), &bytes.Buffer{})

	// No credentials -> 401.
	resp, err := http.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Basic realm=")

	// Wrong password -> 401.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/overview", nil)
	req.SetBasicAuth("admin", "wrong")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Correct credentials -> 200.
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/overview", nil)
	req.SetBasicAuth("admin", "s3cret")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// /health is open without credentials.
	resp, err = http.Get(srv.URL + "/health")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestConsoleAuth_LockedReturns503(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()

	locked, err := auth.NewUsers(nil, "") // no users
	require.NoError(t, err)
	srv := authConsoleStack(t, upstream, locked, &bytes.Buffer{})

	resp, err := http.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	// Proxy/health still serve while the console is locked.
	resp, err = http.Get(srv.URL + "/health")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestConsoleAuth_PolicyChangeAttributed(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	var logBuf bytes.Buffer
	srv := authConsoleStack(t, upstream, testUsers(t), &logBuf)

	body := `{"mode":"enforce","min_age_hours":24,"cve_block_on":"HIGH","allowlist":[],"denylist":[]}`
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/policy", strings.NewReader(body))
	req.SetBasicAuth("admin", "s3cret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Contains(t, logBuf.String(), `"user":"admin"`,
		"policy edit must be attributed to the authenticated user")
}
```

This file relies on helpers already defined in the `integration` package: `newTestRegistry` and `localCacheAdapter` (used by `console_test.go`), and the `httptest` import is provided transitively — add an explicit `"net/http/httptest"` import to this file since it references `*httptest.Server`.

- [ ] **Step 2: Run the integration tests**

Run: `go test -tags integration ./integration/ -run TestConsoleAuth -v`
Expected: PASS (3 tests).

- [ ] **Step 3: Run the whole integration suite to confirm no regressions**

Run: `go test -tags integration ./integration/`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add integration/console_auth_test.go
git commit -m "test(integration): console auth — 401/200/503, open proxy, attributed edits"
```

---

## Task 8: Documentation & deployment examples

**Files:**
- Modify: `README.md`
- Modify: `config.yaml`
- Modify: `docker-compose.yaml`

- [ ] **Step 1: Update the README "Admin Console" section**

In `README.md`, replace the "Known risk — no authentication" blockquote (the `> ⚠️ **Known risk — no authentication.** ...` paragraph) with a documented auth section:

```markdown
### Console authentication

The console and `/api/` require HTTP Basic authentication. Configure one or more
operator accounts; the proxy data path (`/pypi/`, `/npm/`, …) and `/health`
stay open.

**Fail-closed:** with no users configured, `/console/` and `/api/` return
**HTTP 503** until you add at least one user. The proxy keeps serving.

Generate a bcrypt hash:

```bash
printf '%s' 'choose-a-strong-password' | jo-ei hashpw
# -> $2a$10$... (copy this)
```

Configure users in `config.yaml`:

```yaml
console:
  auth:
    users:
      - username: admin
        password_hash: "$2a$10$...."
```

Or inject them via the environment (preferred for secrets — keeps hashes out of
committed config). Entries are `username:hash`, separated by `;`:

```bash
export JOEI_CONSOLE_AUTH_USERS='admin:$2a$10$...;alice:$2a$10$...'
```

Env entries override file entries with the same username.

> **TLS:** Jōei serves plain HTTP. Basic credentials are only as private as the
> transport — for any non-loopback or public deployment, terminate TLS at a
> reverse proxy (nginx, Traefik, Caddy) in front of Jōei. In-binary TLS is not
> provided.
```

- [ ] **Step 2: Update the Quick Start to create a user**

In `README.md`, in the Quick Start, after "**1. Start the proxy**" (before opening the console), add a step:

```markdown
**Create a console user** (the console is fail-closed until you do):

```bash
# bcrypt-hash a password, then start the proxy with the credential in the env
export JOEI_CONSOLE_AUTH_USERS="admin:$(printf '%s' 'change-me' | jo-ei hashpw)"
docker-compose up -d
```

Then open the console and log in as `admin`.
```

(Place this so it reads coherently with the existing `docker-compose up -d` instruction; if that command already appears above, fold the `export` line in just before it rather than duplicating `docker-compose up -d`.)

- [ ] **Step 3: Add a commented example to `config.yaml`**

In `config.yaml`, add a top-level block (commented, so the default remains fail-closed and operators opt in explicitly):

```yaml
# Admin console / API authentication (HTTP Basic).
# Without at least one user, /console/ and /api/ return HTTP 503 (fail-closed).
# Generate a hash with:  printf '%s' 'your-password' | jo-ei hashpw
# Prefer the JOEI_CONSOLE_AUTH_USERS env var so hashes stay out of this file.
# console:
#   auth:
#     users:
#       - username: admin
#         password_hash: "$2a$10$REPLACE_WITH_A_REAL_BCRYPT_HASH"
```

- [ ] **Step 4: Add an example credential to `docker-compose.yaml`**

In `docker-compose.yaml`, under the Jōei service's `environment:` (add an `environment:` key if none exists), add:

```yaml
      # CHANGE THIS — example only. Generate your own with `jo-ei hashpw`.
      # Without it the console is fail-closed (HTTP 503). Format: user:bcrypt-hash[;user:hash]
      - "JOEI_CONSOLE_AUTH_USERS=admin:$2a$10$REPLACE_WITH_A_REAL_BCRYPT_HASH"
```

Note: in docker-compose YAML a literal `$` must be written `$$` to avoid
variable interpolation, so when you paste a real hash, double every `$`
(`$2a$10$...` → `$$2a$$10$$...`). Add a comment to that effect next to the line.

- [ ] **Step 5: Verify the build and the docs reference real commands**

Run: `go build ./... && go vet ./...`
Expected: clean. Manually confirm the README `jo-ei hashpw` and `JOEI_CONSOLE_AUTH_USERS` references match the implemented names.

- [ ] **Step 6: Commit**

```bash
git add README.md config.yaml docker-compose.yaml
git commit -m "docs: document console auth, hashpw, fail-closed and TLS-via-proxy"
```

---

## Task 9: Final verification

- [ ] **Step 1: Full build, format, vet**

Run: `go build ./... && gofmt -l . && go vet ./...`
Expected: build clean; `gofmt -l` lists no Go files (CRLF-only diffs on Windows are not real — confirm `git status` shows no modified `.go` files); vet clean.

- [ ] **Step 2: Full test suite (matches CI)**

Run: `go test ./... && go test -tags integration ./integration/...`
Expected: all PASS. (CI additionally runs these with `-race` on Linux; the race detector needs cgo, which may be unavailable locally.)

- [ ] **Step 3: Manual smoke (optional but recommended)**

```bash
# locked: no users -> 503 on the API, proxy/health still up
go run ./cmd/jo-ei --config config.yaml &
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/api/overview   # 503
curl -s http://localhost:8080/health                                          # {"status":"ok"}
kill %1

# with a user -> 401 without creds, 200 with creds
export JOEI_CONSOLE_AUTH_USERS="admin:$(printf '%s' 'demo' | go run ./cmd/jo-ei hashpw)"
go run ./cmd/jo-ei --config config.yaml &
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/api/overview              # 401
curl -s -o /dev/null -w '%{http_code}\n' -u admin:demo http://localhost:8080/api/overview # 200
kill %1
```

---

## Self-review notes

- **Spec coverage:** new `internal/auth` package (Tasks 2-3) ✓; Basic Auth scheme + per-user accounts ✓; `EventSource`/fetch unaffected — no frontend changes, browser-cached creds reused (no JS task, by design) ✓; config list + `JOEI_CONSOLE_AUTH_USERS` merge with env override (Tasks 1-2) ✓; fail-closed 503 + startup warning (Tasks 3, 5) ✓; 401 + `WWW-Authenticate` challenge (Task 3) ✓; unknown-user timing defense (Task 2) ✓; bcrypt via `golang.org/x/crypto` + `jo-ei hashpw` (Tasks 2, 4) ✓; wrap only `/console/`+`/api/`, leave proxy+`/health` open (Tasks 5, 7) ✓; username in context + `PUT /api/policy` attribution (Tasks 3, 6) ✓; README/config/docker-compose docs incl. TLS-via-proxy (Task 8) ✓.
- **Realm encoding:** the spec prose says realm `"Jōei Console"`; the plan uses ASCII `"Joei Console"` because HTTP header values must be ASCII. Noted in Conventions and Task 3.
- **Type consistency:** `auth.User{Username, PasswordHash}`, `auth.NewUsers([]User, string) (*Users, error)`, `(*Users).Locked()`, `(*Users).Verify(string,string) bool`, `(*Users).Middleware(http.Handler) http.Handler`, `auth.UserFromContext(context.Context) (string, bool)`, `config.AuthUser{Username, PasswordHash}`, `toAuthUsers([]config.AuthUser) []auth.User`, `newHashpwCmd() *cobra.Command` — names used identically across Tasks 1-7.
- **Env via os.Getenv, not viper:** viper is not configured with an env-key replacer for nested keys and cannot unmarshal a `;`-list into `[]AuthUser`, so `JOEI_CONSOLE_AUTH_USERS` is read directly in `main.go` (Task 5) and parsed in `auth.NewUsers` (Task 2). Consistent across both.
- **Out of scope (per spec):** cookie sessions, login form, logout, lockout/rate-limit, persistent audit log + view, in-binary TLS, per-user roles — none implemented here.
```

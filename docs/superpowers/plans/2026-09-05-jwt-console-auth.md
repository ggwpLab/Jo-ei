# JWT Console Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace HTTP Basic on the console and API with HS256 JWT sessions — HttpOnly access/refresh cookies for the browser, a bearer token from the same login endpoint for curl and CI — and give the console a real login screen, identity, and logout.

**Architecture:** `internal/auth` keeps its bcrypt `Users` set and gains three files: a stdlib HS256 signer (`token.go`), a session type owning cookies and the middleware (`session.go`), and the four `/api/auth/*` handlers (`handlers.go`). `cmd/jo-ei` resolves the signing secret (env → config → settings store → generate-and-persist), serves `/console/` publicly so the login screen can load, mounts `/api/auth/` outside the middleware and keeps `/api/` behind it. The console SPA routes every call through an `authFetch` wrapper that retries once through `/api/auth/refresh`.

**Tech Stack:** Go 1.25 (toolchain 1.26.6), stdlib `crypto/hmac`+`crypto/sha256` for JWT, `golang.org/x/crypto/bcrypt` (already present), testify, React 18 vendored + esbuild via `go generate ./web`.

**Spec:** `docs/superpowers/specs/2026-09-05-jwt-console-auth-design.md` — read it before Task 1. It records what was deliberately excluded (revocation, API tokens, roles, SSO, login rate limiting) and why.

## Global Constraints

- **No new Go module dependency.** JWT is implemented on the standard library. Do not add `golang-jwt` or any other library — this was decided explicitly in the spec, in a tool whose purpose is limiting dependency intake.
- **HS256 only.** The verifier accepts exactly `alg: HS256` and rejects everything else, including `none`. Never dispatch on the header's algorithm.
- **Fail closed.** Zero configured users keeps today's behaviour: 503 `{"error":"auth_not_configured"}` from `/api/`, and the proxy data path plus `/health` stay open.
- **Cookie names and attributes** are fixed: `joei_at` (`Path=/`) and `joei_rt` (`Path=/api/auth`), both `HttpOnly`, `SameSite=Strict`, `Secure` only when the request arrived over TLS.
- **Default TTLs:** access 15 minutes (`console.auth.access_ttl_minutes`), refresh 168 hours (`console.auth.refresh_ttl_hours`). Minimum signing secret length is 32 bytes.
- **`auth.UserFromContext` keeps its exact signature** — console logging and attribution depend on it.
- **No `WWW-Authenticate` header on 401.** It is what makes browsers pop the native Basic dialog over the SPA's own login screen.
- **Console sources are not ES modules.** `web/console/src/*.jsx` share one global scope, concatenated in the order in `internal/uibuild/main.go`. No `import`/`export`; publish globals via `Object.assign(window, {...})`. Run `go generate ./web` after every source edit and commit the regenerated `web/console/app.bundle.js`.
- **There is no JavaScript test runner in this repository, by design.** The Go side is fully tested; the SPA is verified by build plus the documented manual passes. Do not claim JS test coverage, and do not introduce npm.
- **Lint gate is golangci-lint**, not just `go vet`. Run `golangci-lint run` before pushing.
- **Branch:** `feat/jwt-auth` (already cut; it holds the spec commit). One PR into `main`. Never commit to `main` directly.

---

### Task 1: HS256 token signer

**Files:**
- Create: `internal/auth/token.go`
- Test: `internal/auth/token_test.go`

**Interfaces:**
- Produces, used by every later Go task:
  - `const TypeAccess = "access"`, `const TypeRefresh = "refresh"`, `const MinSecretLen = 32`
  - `type Claims struct { Sub, Typ, JTI string; IAT, Exp int64 }`
  - `func NewSigner(secret []byte) (*Signer, error)`
  - `func (s *Signer) Issue(username, typ string, ttl time.Duration) (string, error)`
  - `func (s *Signer) Verify(token, wantType string) (Claims, error)`
  - Sentinel errors `ErrMalformedToken`, `ErrBadSignature`, `ErrExpiredToken`, `ErrWrongTokenType`
  - Test seam: the unexported field `Signer.now func() time.Time`, defaulted to `time.Now`; the package-internal test file sets it to travel through time.

- [ ] **Step 1: Write the failing test**

Create `internal/auth/token_test.go`. Note the package: this is an **internal** test (`package auth`, not `auth_test`) because it manipulates the `now` seam. The existing `middleware_test.go` and `users_test.go` are external — that mix is already the pattern in this repo (see `internal/cache/local_internal_test.go`).

```go
package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	return s
}

func TestNewSignerRejectsShortSecret(t *testing.T) {
	_, err := NewSigner([]byte("too-short"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 32 bytes")
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	s := testSigner(t)

	tok, err := s.Issue("ops", TypeAccess, 15*time.Minute)
	require.NoError(t, err)

	claims, err := s.Verify(tok, TypeAccess)
	require.NoError(t, err)
	assert.Equal(t, "ops", claims.Sub)
	assert.Equal(t, TypeAccess, claims.Typ)
	assert.NotEmpty(t, claims.JTI)
	assert.Equal(t, claims.IAT+int64((15*time.Minute).Seconds()), claims.Exp)
}

func TestIssueGivesEachTokenItsOwnID(t *testing.T) {
	s := testSigner(t)
	a, err := s.Issue("ops", TypeAccess, time.Minute)
	require.NoError(t, err)
	b, err := s.Issue("ops", TypeAccess, time.Minute)
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "two tokens issued in the same second must still differ")
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Issue("ops", TypeAccess, time.Minute)
	require.NoError(t, err)

	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	_, err = s.Verify(tok, TypeAccess)
	assert.ErrorIs(t, err, ErrExpiredToken)
}

func TestVerifyRejectsWrongType(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Issue("ops", TypeRefresh, time.Hour)
	require.NoError(t, err)

	_, err = s.Verify(tok, TypeAccess)
	assert.ErrorIs(t, err, ErrWrongTokenType)
}

func TestVerifyRejectsAnotherSecret(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Issue("ops", TypeAccess, time.Minute)
	require.NoError(t, err)

	other, err := NewSigner([]byte("ffffffffffffffffffffffffffffffff"))
	require.NoError(t, err)
	_, err = other.Verify(tok, TypeAccess)
	assert.ErrorIs(t, err, ErrBadSignature)
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Issue("ops", TypeAccess, time.Minute)
	require.NoError(t, err)

	parts := strings.Split(tok, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var c Claims
	require.NoError(t, json.Unmarshal(payload, &c))
	c.Sub = "root" // privilege escalation attempt
	forged, err := json.Marshal(c)
	require.NoError(t, err)
	parts[1] = base64.RawURLEncoding.EncodeToString(forged)

	_, err = s.Verify(strings.Join(parts, "."), TypeAccess)
	assert.ErrorIs(t, err, ErrBadSignature)
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	s := testSigner(t)
	// A token whose header says the signature is unnecessary. Signed with the
	// real secret so only the alg check can reject it.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"sub":"root","typ":"access","iat":1,"exp":9999999999,"jti":"x"}`))
	signing := header + "." + payload
	tok := signing + "." + base64.RawURLEncoding.EncodeToString(s.sign(signing))

	_, err := s.Verify(tok, TypeAccess)
	require.Error(t, err)
	assert.NotErrorIs(t, err, nil)
}

func TestVerifyRejectsMalformedTokens(t *testing.T) {
	s := testSigner(t)
	for name, tok := range map[string]string{
		"empty":          "",
		"one segment":    "abc",
		"two segments":   "abc.def",
		"four segments":  "a.b.c.d",
		"not base64":     "!!!.???.###",
		"not json":       base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".x.y",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.Verify(tok, TypeAccess)
			require.Error(t, err)
		})
	}
}

func TestVerifyRejectsEmptySubject(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Issue("", TypeAccess, time.Minute)
	require.NoError(t, err)
	_, err = s.Verify(tok, TypeAccess)
	assert.ErrorIs(t, err, ErrMalformedToken)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/auth/ -run 'Token|Signer|Verify|Issue' -v`
Expected: compile failure — `undefined: NewSigner`, `undefined: Claims`, `undefined: TypeAccess`.

- [ ] **Step 3: Write the implementation**

Create `internal/auth/token.go`:

```go
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Token types. A refresh token is never accepted where an access token is
// expected, and vice versa: the type is part of what Verify checks.
const (
	TypeAccess  = "access"
	TypeRefresh = "refresh"
)

// MinSecretLen is the shortest signing secret accepted. HMAC-SHA256 keys
// shorter than the hash output add no security and a short secret is almost
// always a placeholder someone forgot to replace.
const MinSecretLen = 32

// Token verification failures. Callers map all of them to the same 401 — the
// distinction exists for logs and tests, never for the response body.
var (
	ErrMalformedToken = errors.New("auth: malformed token")
	ErrBadSignature   = errors.New("auth: bad token signature")
	ErrExpiredToken   = errors.New("auth: token expired")
	ErrWrongTokenType = errors.New("auth: wrong token type")
)

// Claims is the JWT payload. Issuer and audience are omitted: single issuer,
// single audience, and every claim we do not need is one more thing to check.
type Claims struct {
	Sub string `json:"sub"` // username
	Typ string `json:"typ"` // TypeAccess or TypeRefresh
	IAT int64  `json:"iat"` // issued at, Unix seconds
	Exp int64  `json:"exp"` // expires at, Unix seconds
	JTI string `json:"jti"` // random id, so two tokens issued in the same second differ
}

// jwtHeader is the only header this package emits, and the only one it accepts.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

const algHS256 = "HS256"

// Signer issues and verifies HS256 tokens against one secret.
type Signer struct {
	secret []byte
	now    func() time.Time // seam for tests
}

// NewSigner returns a Signer over secret, which must be at least MinSecretLen
// bytes. The secret is copied, so the caller may reuse its buffer.
func NewSigner(secret []byte) (*Signer, error) {
	if len(secret) < MinSecretLen {
		return nil, fmt.Errorf("auth: signing secret must be at least %d bytes, got %d", MinSecretLen, len(secret))
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return &Signer{secret: cp, now: time.Now}, nil
}

// Issue returns a signed token for username with the given type and lifetime.
func (s *Signer) Issue(username, typ string, ttl time.Duration) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: generating token id: %w", err)
	}
	now := s.now()
	header, err := json.Marshal(jwtHeader{Alg: algHS256, Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("auth: encoding token header: %w", err)
	}
	payload, err := json.Marshal(Claims{
		Sub: username,
		Typ: typ,
		IAT: now.Unix(),
		Exp: now.Add(ttl).Unix(),
		JTI: hex.EncodeToString(raw),
	})
	if err != nil {
		return "", fmt.Errorf("auth: encoding token claims: %w", err)
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signing + "." + base64.RawURLEncoding.EncodeToString(s.sign(signing)), nil
}

// Verify checks a token's signature, algorithm, type and expiry, and returns
// its claims. wantType is TypeAccess or TypeRefresh.
func (s *Signer) Verify(token, wantType string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformedToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrMalformedToken
	}
	// Signature first: nothing else in the token is trustworthy until it holds.
	if !hmac.Equal(sig, s.sign(parts[0]+"."+parts[1])) {
		return Claims{}, ErrBadSignature
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrMalformedToken
	}
	var h jwtHeader
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return Claims{}, ErrMalformedToken
	}
	// HS256 is the only algorithm issued and the only one accepted. Dispatching
	// on the header's choice is where "alg: none" and algorithm-confusion bugs
	// come from, so this compares rather than switches.
	if h.Alg != algHS256 {
		return Claims{}, ErrBadSignature
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrMalformedToken
	}
	var c Claims
	if err := json.Unmarshal(rawPayload, &c); err != nil {
		return Claims{}, ErrMalformedToken
	}
	if c.Sub == "" {
		return Claims{}, ErrMalformedToken
	}
	if c.Typ != wantType {
		return Claims{}, ErrWrongTokenType
	}
	if s.now().Unix() >= c.Exp {
		return Claims{}, ErrExpiredToken
	}
	return c, nil
}

func (s *Signer) sign(signingInput string) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(signingInput))
	return m.Sum(nil)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/auth/ -v`
Expected: PASS, including the pre-existing `users_test.go` and `middleware_test.go` (still Basic at this point — Task 2 replaces them).

- [ ] **Step 5: Commit**

```bash
git add internal/auth/token.go internal/auth/token_test.go
git commit -m "feat(auth): HS256 token signer on the standard library

Issue and verify access/refresh JWTs without a third-party dependency:
signature first, then a strict HS256 comparison (never a dispatch on the
header's alg), then type and expiry. A signing secret shorter than 32
bytes is refused at construction."
```

---

### Task 2: Session middleware over cookies and bearer tokens

**Files:**
- Create: `internal/auth/session.go`
- Delete: `internal/auth/middleware.go` (its `ctxKey`/`UserFromContext` move into `session.go`)
- Modify: `internal/auth/users.go` (add `Known`)
- Test: `internal/auth/session_test.go` (new), `internal/auth/middleware_test.go` (delete — replaced)

**Interfaces:**
- Consumes: `Signer`, `Claims`, `TypeAccess`, `TypeRefresh` from Task 1; `*Users`, `Users.Locked`, `Users.Verify` from `users.go`.
- Produces, used by Tasks 3, 5 and 6:
  - `const AccessCookie = "joei_at"`, `const RefreshCookie = "joei_rt"`, `const RefreshCookiePath = "/api/auth"`
  - `func NewSessions(users *Users, signer *Signer, accessTTL, refreshTTL time.Duration) *Sessions`
  - `func (s *Sessions) Middleware(h http.Handler) http.Handler`
  - `func (s *Sessions) Authenticate(r *http.Request) (string, bool)` — token-only check, no origin rule; used by `GET /api/auth/me`
  - `func (s *Sessions) Locked() bool`
  - `func (s *Sessions) issueSession(w http.ResponseWriter, r *http.Request, username string) (string, error)` (unexported, used by Task 3)
  - `func (s *Sessions) clearSession(w http.ResponseWriter, r *http.Request)` (unexported, used by Task 3)
  - `func writeJSONError(w http.ResponseWriter, status int, code string)` (unexported, used by Task 3)
  - `func UserFromContext(ctx context.Context) (string, bool)` — unchanged signature
  - `func (u *Users) Known(username string) bool`

- [ ] **Step 1: Write the failing test**

Delete the old Basic-auth test file and create the new one:

```bash
git rm internal/auth/middleware_test.go
```

Create `internal/auth/session_test.go`:

```go
package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// sessions builds a Sessions with one user "admin"/"secret". Pass no users to
// get the locked (fail-closed) state.
func sessions(t *testing.T, users ...auth.User) *auth.Sessions {
	t.Helper()
	u, err := auth.NewUsers(users, "")
	require.NoError(t, err)
	signer, err := auth.NewSigner([]byte(testSecret))
	require.NoError(t, err)
	return auth.NewSessions(u, signer, 15*time.Minute, 168*time.Hour)
}

func adminUser(t *testing.T) auth.User {
	t.Helper()
	return auth.User{Username: "admin", PasswordHash: hash(t, "secret")}
}

// accessToken logs in through the handler and returns the bearer token.
func accessToken(t *testing.T, s *auth.Sessions) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"secret"}`))
	s.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.AccessToken)
	return body.AccessToken
}

func TestMiddlewareLockedReturns503(t *testing.T) {
	s := sessions(t) // no users
	rec := httptest.NewRecorder()
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	s.Middleware(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.False(t, called, "locked middleware must not reach the handler")
	assert.Contains(t, rec.Body.String(), "auth_not_configured")
}

func TestMiddlewareWithoutCredentials401sWithoutBasicChallenge(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := httptest.NewRecorder()

	s.Middleware(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "unauthorized")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
		"a Basic challenge would make the browser cover the console's own login screen")
}

func TestMiddlewareRejectsBasicAuth(t *testing.T) {
	s := sessions(t, adminUser(t))
	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.SetBasicAuth("admin", "secret") // the credentials are right; the scheme is gone
	rec := httptest.NewRecorder()

	s.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareAcceptsBearerToken(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddlewareAcceptsAccessCookie(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: tok})
	rec := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddlewarePutsUsernameInContext(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	var got string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		name, ok := auth.UserFromContext(r.Context())
		require.True(t, ok)
		got = name
	})
	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.Middleware(next).ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, "admin", got)
}

func TestMiddlewareRejectsRefreshTokenAsAccess(t *testing.T) {
	s := sessions(t, adminUser(t))
	// Log in, then present the refresh cookie where the access cookie belongs.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"secret"}`)))
	var refresh string
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.RefreshCookie {
			refresh = c.Value
		}
	}
	require.NotEmpty(t, refresh)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: refresh})
	out := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(out, req)

	assert.Equal(t, http.StatusUnauthorized, out.Code)
}

func TestMiddlewareRejectsExpiredToken(t *testing.T) {
	u, err := auth.NewUsers([]auth.User{adminUser(t)}, "")
	require.NoError(t, err)
	signer, err := auth.NewSigner([]byte(testSecret))
	require.NoError(t, err)
	// A one-nanosecond access lifetime: the token is expired before it is read.
	s := auth.NewSessions(u, signer, time.Nanosecond, time.Hour)
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareRejectsTokenForRemovedUser(t *testing.T) {
	issuer := sessions(t, adminUser(t))
	tok := accessToken(t, issuer)
	// Same secret, but the user is no longer configured — as after an operator
	// removes a credential and restarts.
	other := sessions(t, auth.User{Username: "someone-else", PasswordHash: hash(t, "x")})

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	other.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareCookieMutationRequiresSameOrigin(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	cases := map[string]struct {
		origin   string
		fetchSit string
		want     int
	}{
		"same-origin header":     {origin: "http://example.test", want: http.StatusOK},
		"no origin at all":       {want: http.StatusOK},
		"sec-fetch-site same":    {fetchSit: "same-origin", want: http.StatusOK},
		"cross-site origin":      {origin: "http://evil.test", want: http.StatusForbidden},
		"sec-fetch-site cross":   {fetchSit: "cross-site", want: http.StatusForbidden},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader(`{}`))
			req.Host = "example.test"
			req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: tok})
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.fetchSit != "" {
				req.Header.Set("Sec-Fetch-Site", tc.fetchSit)
			}
			rec := httptest.NewRecorder()
			s.Middleware(okHandler()).ServeHTTP(rec, req)
			assert.Equal(t, tc.want, rec.Code)
		})
	}
}

func TestMiddlewareBearerMutationSkipsOriginCheck(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader(`{}`))
	req.Host = "example.test"
	req.Header.Set("Origin", "http://evil.test") // cannot be forged onto a bearer call
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddlewareGETSkipsOriginCheck(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Host = "example.test"
	req.Header.Set("Origin", "http://evil.test")
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: tok})
	rec := httptest.NewRecorder()
	s.Middleware(okHandler()).ServeHTTP(rec, req)

	// SameSite=Strict keeps the cookie off a cross-site GET anyway, and a read
	// is not a state change: the origin rule guards mutations only.
	assert.Equal(t, http.StatusOK, rec.Code)
}
```

Note: `hash(t, …)` is the existing helper in `internal/auth/users_test.go` — same package (`auth_test`), so it is already in scope. Do not redefine it.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/auth/ -run Middleware -v`
Expected: compile failure — `undefined: auth.NewSessions`, `undefined: auth.AccessCookie`.

- [ ] **Step 3: Add `Known` to the user set**

In `internal/auth/users.go`, after the `Locked` method:

```go
// Known reports whether username is configured. A token stays cryptographically
// valid after its user is removed from the config, so every request re-checks
// the subject against the current set.
func (u *Users) Known(username string) bool {
	_, ok := u.byName[username]
	return ok
}
```

- [ ] **Step 4: Write the session implementation**

```bash
git rm internal/auth/middleware.go
```

Create `internal/auth/session.go`:

```go
package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Session cookie names and the refresh cookie's path. The refresh cookie is
// scoped to /api/auth so it never rides along on ordinary API calls: only the
// endpoints that can spend it ever see it.
const (
	AccessCookie      = "joei_at"
	RefreshCookie     = "joei_rt"
	RefreshCookiePath = "/api/auth"
)

type ctxKey struct{}

// Sessions authenticates console and API requests from JWT sessions. It owns
// the cookies, the middleware, and the /api/auth handlers (see handlers.go).
// The credential set it verifies against is the same bcrypt Users as before.
type Sessions struct {
	users      *Users
	signer     *Signer
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewSessions wires a credential set to a signer and the two token lifetimes.
func NewSessions(users *Users, signer *Signer, accessTTL, refreshTTL time.Duration) *Sessions {
	return &Sessions{users: users, signer: signer, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

// Locked reports the fail-closed state: no users configured.
func (s *Sessions) Locked() bool { return s.users.Locked() }

// Middleware gates a handler on a valid access token.
//
//   - Locked (no users configured): 503, handler never runs.
//   - Missing/invalid/expired token, or a token for a user who no longer
//     exists: 401. No WWW-Authenticate header — a Basic challenge would make
//     the browser cover the console's own login screen.
//   - Cookie-authenticated state change from another origin: 403.
//   - Valid: username into the request context (see UserFromContext).
func (s *Sessions) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.users.Locked() {
			writeJSONError(w, http.StatusServiceUnavailable, "auth_not_configured")
			return
		}
		token, bearer, ok := accessCredential(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		claims, err := s.signer.Verify(token, TypeAccess)
		if err != nil || !s.users.Known(claims.Sub) {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		// A cross-site page cannot set an Authorization header, so only cookie
		// authentication needs the origin rule. SameSite=Strict is the first
		// line; this is the second, for anything that drops the attribute.
		if !bearer && isMutating(r.Method) && !sameOrigin(r) {
			writeJSONError(w, http.StatusForbidden, "cross_origin")
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, claims.Sub)))
	})
}

// Authenticate validates the request's access credential and returns the
// username. It applies no origin rule, so it suits read-only endpoints that
// resolve their own caller (GET /api/auth/me).
func (s *Sessions) Authenticate(r *http.Request) (string, bool) {
	token, _, ok := accessCredential(r)
	if !ok {
		return "", false
	}
	claims, err := s.signer.Verify(token, TypeAccess)
	if err != nil || !s.users.Known(claims.Sub) {
		return "", false
	}
	return claims.Sub, true
}

// UserFromContext returns the authenticated username stored by Middleware, and
// false when the request did not pass through the authenticating middleware.
func UserFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(ctxKey{}).(string)
	return name, ok
}

// accessCredential returns the presented access token, whether it came from an
// Authorization header, and whether one was found at all. A malformed
// Authorization header is not retried as a cookie: a client that meant to send
// a bearer token gets a clean 401 rather than a confusing fallback.
func accessCredential(r *http.Request) (token string, bearer bool, found bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		v, ok := strings.CutPrefix(h, "Bearer ")
		v = strings.TrimSpace(v)
		return v, true, ok && v != ""
	}
	if c, err := r.Cookie(AccessCookie); err == nil && c.Value != "" {
		return c.Value, false, true
	}
	return "", false, false
}

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// sameOrigin reports whether a browser request originated from this same site.
// Sec-Fetch-Site is authoritative where the browser sends it; otherwise the
// Origin header is compared to the request's own host. A request with neither
// header is not a cross-site browser request (browsers always send Origin on
// cross-origin requests), so it passes — that is the curl-with-a-cookie case.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "cross-site", "same-site":
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

// issueSession signs a fresh token pair and sets both cookies. It returns the
// access token so the login response can hand it to non-browser clients.
func (s *Sessions) issueSession(w http.ResponseWriter, r *http.Request, username string) (string, error) {
	access, err := s.signer.Issue(username, TypeAccess, s.accessTTL)
	if err != nil {
		return "", err
	}
	refresh, err := s.signer.Issue(username, TypeRefresh, s.refreshTTL)
	if err != nil {
		return "", err
	}
	secure := isTLS(r)
	http.SetCookie(w, &http.Cookie{
		Name: AccessCookie, Value: access, Path: "/",
		MaxAge: int(s.accessTTL.Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: RefreshCookie, Value: refresh, Path: RefreshCookiePath,
		MaxAge: int(s.refreshTTL.Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
	})
	return access, nil
}

// clearSession expires both cookies. The attributes must match those they were
// set with, or the browser keeps the originals alongside the expiring ones.
func (s *Sessions) clearSession(w http.ResponseWriter, r *http.Request) {
	secure := isTLS(r)
	for _, c := range []struct{ name, path string }{
		{AccessCookie, "/"},
		{RefreshCookie, RefreshCookiePath},
	} {
		http.SetCookie(w, &http.Cookie{
			Name: c.name, Value: "", Path: c.path,
			MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
		})
	}
}

// isTLS reports whether the request reached us over TLS, directly or through a
// terminating proxy. Setting Secure unconditionally would break plain-HTTP
// deployments, where the browser would refuse to store the cookie at all.
func isTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func writeJSONError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/auth/ -v`
Expected: the session tests that do not need the login endpoint pass; the ones calling `s.Handler()` still fail to compile (`Handler` arrives in Task 3). That is expected mid-stream — Task 3 is what makes this file green, and the two tasks land in the same PR.

If you prefer a green tree at every commit, do Task 3 before running the suite and commit them together. Either is acceptable; do not "fix" it by stubbing `Handler`.

- [ ] **Step 6: Commit**

```bash
git add internal/auth/session.go internal/auth/users.go internal/auth/session_test.go
git add -u internal/auth/
git commit -m "feat(auth): session middleware over JWT cookies and bearer tokens

Replaces the Basic middleware. Accepts an Authorization bearer or the
joei_at cookie, re-checks the subject against the configured users on
every request, and answers 401 without WWW-Authenticate so the browser
stops covering the console's own login screen. Cookie-authenticated
mutations additionally require a same-origin request."
```

---

### Task 3: The `/api/auth` endpoints

**Files:**
- Create: `internal/auth/handlers.go`
- Test: `internal/auth/handlers_test.go`

**Interfaces:**
- Consumes: everything from Task 2, plus `Users.Verify`.
- Produces, used by Tasks 5 and 6: `func (s *Sessions) Handler() http.Handler` serving `POST /api/auth/login`, `POST /api/auth/refresh`, `POST /api/auth/logout`, `GET /api/auth/me`.

- [ ] **Step 1: Write the failing test**

Create `internal/auth/handlers_test.go`:

```go
package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/auth"
)

func postJSON(t *testing.T, h http.Handler, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(http.MethodPost, path, nil)
	} else {
		r = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func cookieByName(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q cookie in the response", name)
	return nil
}

func TestLoginSetsBothCookiesAndReturnsToken(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := postJSON(t, s.Handler(), "/api/auth/login", `{"username":"admin","password":"secret"}`)

	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Username    string `json:"username"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "admin", body.Username)
	assert.NotEmpty(t, body.AccessToken)
	assert.Equal(t, 900, body.ExpiresIn) // 15 minutes

	at := cookieByName(t, rec, auth.AccessCookie)
	assert.True(t, at.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, at.SameSite)
	assert.Equal(t, "/", at.Path)
	assert.Equal(t, 900, at.MaxAge)
	assert.False(t, at.Secure, "plain HTTP must not set Secure, or the browser drops the cookie")

	rt := cookieByName(t, rec, auth.RefreshCookie)
	assert.True(t, rt.HttpOnly)
	assert.Equal(t, auth.RefreshCookiePath, rt.Path)
	assert.Equal(t, 168*3600, rt.MaxAge)
}

func TestLoginOverTLSSetsSecureCookies(t *testing.T) {
	s := sessions(t, adminUser(t))
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"secret"}`))
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, cookieByName(t, rec, auth.AccessCookie).Secure)
	assert.True(t, cookieByName(t, rec, auth.RefreshCookie).Secure)
}

func TestLoginRejectsWrongPasswordAndUnknownUserIdentically(t *testing.T) {
	s := sessions(t, adminUser(t))

	wrong := postJSON(t, s.Handler(), "/api/auth/login", `{"username":"admin","password":"nope"}`)
	unknown := postJSON(t, s.Handler(), "/api/auth/login", `{"username":"ghost","password":"nope"}`)

	assert.Equal(t, http.StatusUnauthorized, wrong.Code)
	assert.Equal(t, http.StatusUnauthorized, unknown.Code)
	assert.JSONEq(t, `{"error":"invalid_credentials"}`, wrong.Body.String())
	assert.JSONEq(t, wrong.Body.String(), unknown.Body.String(),
		"the response must not reveal whether the username exists")
	assert.Empty(t, wrong.Result().Cookies())
}

func TestLoginRejectsMalformedBody(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := postJSON(t, s.Handler(), "/api/auth/login", `not json`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestLoginLockedReturns503(t *testing.T) {
	s := sessions(t) // no users
	rec := postJSON(t, s.Handler(), "/api/auth/login", `{"username":"admin","password":"secret"}`)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "auth_not_configured")
}

func TestRefreshRotatesBothCookies(t *testing.T) {
	s := sessions(t, adminUser(t))
	login := postJSON(t, s.Handler(), "/api/auth/login", `{"username":"admin","password":"secret"}`)
	oldRefresh := cookieByName(t, login, auth.RefreshCookie)

	rec := postJSON(t, s.Handler(), "/api/auth/refresh", "",
		&http.Cookie{Name: auth.RefreshCookie, Value: oldRefresh.Value})

	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, cookieByName(t, rec, auth.AccessCookie).Value)
	newRefresh := cookieByName(t, rec, auth.RefreshCookie)
	assert.NotEqual(t, oldRefresh.Value, newRefresh.Value, "the refresh cookie must rotate")

	var body struct {
		Username  string `json:"username"`
		ExpiresIn int    `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "admin", body.Username)
	assert.Equal(t, 900, body.ExpiresIn)
}

func TestRefreshWithoutCookieIs401(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := postJSON(t, s.Handler(), "/api/auth/refresh", "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRefreshRejectsAnAccessToken(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)
	rec := postJSON(t, s.Handler(), "/api/auth/refresh", "",
		&http.Cookie{Name: auth.RefreshCookie, Value: tok})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestLogoutClearsBothCookies(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := postJSON(t, s.Handler(), "/api/auth/logout", "")

	assert.Equal(t, http.StatusNoContent, rec.Code)
	for _, name := range []string{auth.AccessCookie, auth.RefreshCookie} {
		c := cookieByName(t, rec, name)
		assert.Empty(t, c.Value)
		assert.Equal(t, -1, c.MaxAge, "MaxAge=-1 is what expires the cookie now")
	}
}

func TestMeReturnsTheUsername(t *testing.T) {
	s := sessions(t, adminUser(t))
	tok := accessToken(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: tok})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"username":"admin"}`, rec.Body.String())
}

func TestMeWithoutSessionIs401(t *testing.T) {
	s := sessions(t, adminUser(t))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/me", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMeLockedReturns503(t *testing.T) {
	s := sessions(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/me", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/auth/ -v`
Expected: compile failure — `s.Handler undefined`.

- [ ] **Step 3: Write the handlers**

Create `internal/auth/handlers.go`:

```go
package auth

import (
	"encoding/json"
	"net/http"
)

// maxLoginBody caps the credential payload. Credentials are two short strings;
// anything larger is a mistake or an attempt to make the server allocate.
const maxLoginBody = 4 << 10

// Handler serves the session endpoints. Mount it at "/api/auth/", outside the
// authenticating middleware — a client with no session must be able to reach
// login, and Go's ServeMux prefers the longer pattern, so "/api/auth/login"
// lands here while "/api/overview" stays gated.
func (s *Sessions) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login", s.login)
	mux.HandleFunc("POST /api/auth/refresh", s.refresh)
	mux.HandleFunc("POST /api/auth/logout", s.logout)
	mux.HandleFunc("GET /api/auth/me", s.me)
	return mux
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Sessions) login(w http.ResponseWriter, r *http.Request) {
	if s.users.Locked() {
		writeJSONError(w, http.StatusServiceUnavailable, "auth_not_configured")
		return
	}
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	// Users.Verify burns a bcrypt comparison against a dummy hash for unknown
	// usernames, so timing does not separate "no such user" from "wrong
	// password" — and neither does this response.
	if !s.users.Verify(req.Username, req.Password) {
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	access, err := s.issueSession(w, r, req.Username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "token_issue_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":     req.Username,
		"access_token": access,
		"expires_in":   int(s.accessTTL.Seconds()),
	})
}

func (s *Sessions) refresh(w http.ResponseWriter, r *http.Request) {
	if s.users.Locked() {
		writeJSONError(w, http.StatusServiceUnavailable, "auth_not_configured")
		return
	}
	// Refresh is a browser-session concern: it reads the cookie only. Machine
	// clients log in again instead of holding a long-lived credential.
	c, err := r.Cookie(RefreshCookie)
	if err != nil || c.Value == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	claims, err := s.signer.Verify(c.Value, TypeRefresh)
	if err != nil || !s.users.Known(claims.Sub) {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// Rotate both tokens, so a browser in continuous use never hits the refresh
	// lifetime wall.
	if _, err := s.issueSession(w, r, claims.Sub); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "token_issue_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":   claims.Sub,
		"expires_in": int(s.accessTTL.Seconds()),
	})
}

// logout always succeeds: clearing cookies that are not there is not an error,
// and a failed logout is a worse outcome than a redundant one.
func (s *Sessions) logout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Sessions) me(w http.ResponseWriter, r *http.Request) {
	if s.users.Locked() {
		writeJSONError(w, http.StatusServiceUnavailable, "auth_not_configured")
		return
	}
	username, ok := s.Authenticate(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": username})
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/auth/ -v`
Expected: PASS — every test from Tasks 1, 2 and 3, plus the untouched `users_test.go`.

Also run the linter now that the package is complete: `golangci-lint run ./internal/auth/...`

- [ ] **Step 5: Commit**

```bash
git add internal/auth/handlers.go internal/auth/handlers_test.go
git commit -m "feat(auth): login, refresh, logout and me endpoints

One login endpoint serves both clients: browsers ride the HttpOnly
cookies it sets, curl and CI read access_token from the body. Refresh is
cookie-only and rotates both tokens; logout always succeeds; me is the
console's session probe."
```

---

### Task 4: Configuration keys

**Files:**
- Modify: `internal/config/config.go:131-141` (`AuthConfig`), `Validate` (around `:82-90`)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces, used by Task 5:
  - `config.AuthConfig{Users []AuthUser; JWTSecret string; AccessTTLMinutes int; RefreshTTLHours int}`
  - `const config.DefaultAccessTTLMinutes = 15`, `const config.DefaultRefreshTTLHours = 168`

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go` (match the file's existing style for building a config — if it writes YAML to a temp file and calls `Load`, do that; if it constructs a `Config` literal and calls `Validate`, do that):

```go
func TestValidateRejectsShortJWTSecret(t *testing.T) {
	c := validConfig(t) // the file's existing helper for a minimal valid config
	c.Console.Auth.JWTSecret = "short"

	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "console.auth.jwt_secret")
}

func TestValidateAcceptsA32ByteJWTSecret(t *testing.T) {
	c := validConfig(t)
	c.Console.Auth.JWTSecret = "0123456789abcdef0123456789abcdef"
	require.NoError(t, c.Validate())
}

func TestValidateRejectsNegativeTTLs(t *testing.T) {
	c := validConfig(t)
	c.Console.Auth.AccessTTLMinutes = -1
	assert.Error(t, c.Validate())

	c = validConfig(t)
	c.Console.Auth.RefreshTTLHours = -1
	assert.Error(t, c.Validate())
}

func TestAuthTTLsParseFromYAML(t *testing.T) {
	// Extend the file's existing full-config YAML fixture with:
	//   console:
	//     auth:
	//       access_ttl_minutes: 5
	//       refresh_ttl_hours: 24
	// and assert they land on the struct.
	cfg := loadTestConfig(t, `
server:
  listen: ":8080"
console:
  auth:
    access_ttl_minutes: 5
    refresh_ttl_hours: 24
`)
	assert.Equal(t, 5, cfg.Console.Auth.AccessTTLMinutes)
	assert.Equal(t, 24, cfg.Console.Auth.RefreshTTLHours)
}
```

If `validConfig`/`loadTestConfig` do not exist under those names, use whatever the file already uses; do not add a second way of building a test config.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/config/ -run 'JWT|TTL' -v`
Expected: compile failure — `c.Console.Auth.JWTSecret undefined`.

- [ ] **Step 3: Extend the config types**

In `internal/config/config.go`, replace the `AuthConfig` block:

```go
// AuthConfig holds the console/API credentials and JWT session parameters. An
// empty Users list means authentication is unconfigured; the API then serves
// 503 (fail-closed) while the console shell still loads its login screen.
type AuthConfig struct {
	Users []AuthUser `mapstructure:"users"`
	// JWTSecret signs console session tokens (HS256). Empty means "resolve it
	// elsewhere": JOEI_CONSOLE_JWT_SECRET, then the settings store, then a
	// generated-and-persisted key. See cmd/jo-ei.
	JWTSecret string `mapstructure:"jwt_secret"`
	// AccessTTLMinutes is the access-token lifetime; zero selects the default
	// (DefaultAccessTTLMinutes).
	AccessTTLMinutes int `mapstructure:"access_ttl_minutes"`
	// RefreshTTLHours is the refresh-token lifetime; zero selects the default
	// (DefaultRefreshTTLHours).
	RefreshTTLHours int `mapstructure:"refresh_ttl_hours"`
}

// Default console session lifetimes, applied when the keys are unset. Fifteen
// minutes keeps a leaked access token short-lived; a week of refresh keeps an
// operator signed in across a working week.
const (
	DefaultAccessTTLMinutes = 15
	DefaultRefreshTTLHours  = 168
)

// MinJWTSecretLen mirrors auth.MinSecretLen. It is duplicated rather than
// imported because config imports nothing from internal/.
const MinJWTSecretLen = 32
```

In `Validate`, next to the other console/cache checks:

```go
	if s := c.Console.Auth.JWTSecret; s != "" && len(s) < MinJWTSecretLen {
		return fmt.Errorf("console.auth.jwt_secret must be at least %d bytes when set, got %d", MinJWTSecretLen, len(s))
	}
	if c.Console.Auth.AccessTTLMinutes < 0 {
		return fmt.Errorf("console.auth.access_ttl_minutes must not be negative")
	}
	if c.Console.Auth.RefreshTTLHours < 0 {
		return fmt.Errorf("console.auth.refresh_ttl_hours must not be negative")
	}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): console.auth jwt_secret and session TTLs

Integer minutes/hours, matching the cache.revalidation keys. A secret is
optional in the file (env and the settings store can supply it) but must
be at least 32 bytes when it is set."
```

---

### Task 5: Wire it in `cmd/jo-ei`

**Files:**
- Modify: `cmd/jo-ei/main.go:375-412` (auth wiring and mounts)
- Create: `cmd/jo-ei/authsecret.go`
- Test: `cmd/jo-ei/authsecret_test.go`

**Interfaces:**
- Consumes: `auth.NewUsers`, `auth.NewSigner`, `auth.NewSessions`, `auth.MinSecretLen`; `config.AuthConfig`, `config.DefaultAccessTTLMinutes`, `config.DefaultRefreshTTLHours`; `settings.Store.Get/Put`.
- Produces:
  - `func resolveJWTSecret(fileValue string, st *settings.Store, logger zerolog.Logger) ([]byte, error)`
  - `const jwtSecretSettingKey = "auth.jwt_secret"`
  - `func authTTLs(c config.AuthConfig) (access, refresh time.Duration)`

- [ ] **Step 1: Write the failing test**

Create `cmd/jo-ei/authsecret_test.go`:

```go
package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

func testSettings(t *testing.T) *settings.Store {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	st, err := settings.New(db)
	require.NoError(t, err)
	return st
}

func TestResolveJWTSecretPrefersTheEnvironment(t *testing.T) {
	t.Setenv("JOEI_CONSOLE_JWT_SECRET", "env-secret-that-is-long-enough-32")
	st := testSettings(t)

	got, err := resolveJWTSecret("file-secret-that-is-long-enough-3", st, zerolog.New(io.Discard))

	require.NoError(t, err)
	assert.Equal(t, "env-secret-that-is-long-enough-32", string(got))
}

func TestResolveJWTSecretFallsBackToTheFile(t *testing.T) {
	t.Setenv("JOEI_CONSOLE_JWT_SECRET", "")
	st := testSettings(t)

	got, err := resolveJWTSecret("file-secret-that-is-long-enough-3", st, zerolog.New(io.Discard))

	require.NoError(t, err)
	assert.Equal(t, "file-secret-that-is-long-enough-3", string(got))
}

func TestResolveJWTSecretGeneratesAndPersists(t *testing.T) {
	t.Setenv("JOEI_CONSOLE_JWT_SECRET", "")
	st := testSettings(t)

	first, err := resolveJWTSecret("", st, zerolog.New(io.Discard))
	require.NoError(t, err)
	assert.Len(t, first, 32)

	// It must be stored, so a restart against the same database keeps sessions
	// alive rather than logging everyone out.
	raw, ok, err := st.Get(jwtSecretSettingKey)
	require.NoError(t, err)
	require.True(t, ok)
	var encoded string
	require.NoError(t, json.Unmarshal(raw, &encoded))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, first, decoded)

	second, err := resolveJWTSecret("", st, zerolog.New(io.Discard))
	require.NoError(t, err)
	assert.Equal(t, first, second, "a second boot must reuse the stored secret")
}

func TestAuthTTLDefaults(t *testing.T) {
	access, refresh := authTTLs(config.AuthConfig{})
	assert.Equal(t, 15*time.Minute, access)
	assert.Equal(t, 168*time.Hour, refresh)

	access, refresh = authTTLs(config.AuthConfig{AccessTTLMinutes: 5, RefreshTTLHours: 24})
	assert.Equal(t, 5*time.Minute, access)
	assert.Equal(t, 24*time.Hour, refresh)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/jo-ei/ -run 'JWTSecret|authTTL' -v`
Expected: compile failure — `undefined: resolveJWTSecret`.

- [ ] **Step 3: Write the secret resolution**

Create `cmd/jo-ei/authsecret.go`:

```go
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/settings"
)

// jwtSecretSettingKey stores the generated signing key in the settings table,
// so a restart does not log every operator out.
const jwtSecretSettingKey = "auth.jwt_secret"

// resolveJWTSecret returns the console's token-signing key, in order of
// precedence: JOEI_CONSOLE_JWT_SECRET, the config file, the settings store, or
// a freshly generated key which is then persisted.
//
// The environment is read directly rather than through viper, exactly as
// JOEI_CONSOLE_AUTH_USERS is: viper's AutomaticEnv only overrides keys that are
// present in the config file, so an env-only secret would silently not apply.
func resolveJWTSecret(fileValue string, st *settings.Store, logger zerolog.Logger) ([]byte, error) {
	if v := strings.TrimSpace(os.Getenv("JOEI_CONSOLE_JWT_SECRET")); v != "" {
		return []byte(v), nil
	}
	if v := strings.TrimSpace(fileValue); v != "" {
		return []byte(v), nil
	}
	raw, ok, err := st.Get(jwtSecretSettingKey)
	if err != nil {
		return nil, fmt.Errorf("reading the stored console signing key: %w", err)
	}
	if ok {
		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return nil, fmt.Errorf("decoding the stored console signing key: %w", err)
		}
		secret, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decoding the stored console signing key: %w", err)
		}
		if len(secret) >= auth.MinSecretLen {
			return secret, nil
		}
		logger.Warn().Msg("console auth: the stored signing key is too short; generating a new one (existing sessions end)")
	}
	secret := make([]byte, auth.MinSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generating a console signing key: %w", err)
	}
	value, err := json.Marshal(base64.StdEncoding.EncodeToString(secret))
	if err != nil {
		return nil, fmt.Errorf("encoding the console signing key: %w", err)
	}
	if err := st.Put(jwtSecretSettingKey, value); err != nil {
		return nil, fmt.Errorf("storing the console signing key: %w", err)
	}
	logger.Info().Msg("console auth: generated a session signing key and stored it in the database (set console.auth.jwt_secret or JOEI_CONSOLE_JWT_SECRET to share one across replicas)")
	return secret, nil
}

// authTTLs resolves the configured session lifetimes, applying the defaults for
// unset keys.
func authTTLs(c config.AuthConfig) (access, refresh time.Duration) {
	minutes := c.AccessTTLMinutes
	if minutes <= 0 {
		minutes = config.DefaultAccessTTLMinutes
	}
	hours := c.RefreshTTLHours
	if hours <= 0 {
		hours = config.DefaultRefreshTTLHours
	}
	return time.Duration(minutes) * time.Minute, time.Duration(hours) * time.Hour
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./cmd/jo-ei/ -run 'JWTSecret|authTTL' -v`
Expected: PASS.

- [ ] **Step 5: Rewire the mounts**

In `cmd/jo-ei/main.go`, replace the block from `authUsers, err := auth.NewUsers(...)` through `root.Handle("/api/", authUsers.Middleware(console.NewHandler(console.Config{`:

```go
	authUsers, err := auth.NewUsers(toAuthUsers(cfg.Console.Auth.Users), os.Getenv("JOEI_CONSOLE_AUTH_USERS"))
	if err != nil {
		return err
	}
	if authUsers.Locked() {
		logger.Warn().Msg("console auth not configured — /api/ is disabled (HTTP 503) and the console cannot sign in until users are added (set console.auth.users or JOEI_CONSOLE_AUTH_USERS); the proxy continues to serve")
	}
	jwtSecret, err := resolveJWTSecret(cfg.Console.Auth.JWTSecret, settingsStore, logger)
	if err != nil {
		return err
	}
	signer, err := auth.NewSigner(jwtSecret)
	if err != nil {
		return fmt.Errorf("console auth: %w", err)
	}
	accessTTL, refreshTTL := authTTLs(cfg.Console.Auth)
	sessions := auth.NewSessions(authUsers, signer, accessTTL, refreshTTL)

	root := http.NewServeMux()
	// Public site icon: browsers auto-probe /favicon.ico on every page load, so
	// serve it before the auth-gated routes and outside the proxy mux.
	root.Handle("/favicon.ico", web.FaviconHandler())
	// The console shell is public: the login screen has to render before a
	// session exists, and the bundle is UI code with no secrets in it. Every
	// byte of data still comes from /api/, which stays gated.
	root.Handle("/console/", web.ConsoleHandler())
	// Session endpoints sit outside the middleware — a client with no session
	// must be able to reach login. ServeMux prefers the longer pattern, so
	// /api/auth/* lands here and everything else under /api/ stays gated.
	root.Handle("/api/auth/", sessions.Handler())
```

…leaving the `staleDays`/`cachePurger` lines that follow where they are, and changing the API mount itself to:

```go
	root.Handle("/api/", sessions.Middleware(console.NewHandler(console.Config{
```

Everything inside `console.Config{…}` is unchanged.

- [ ] **Step 6: Build, test and lint the whole tree**

Run:

```bash
go build ./...
go test ./...
golangci-lint run
```

Expected: all green. If `cmd/jo-ei/main_test.go` asserted on the old warning text or the Basic mount, update it to the new wording — that is a test of a message this task deliberately changed.

- [ ] **Step 7: Commit**

```bash
git add cmd/jo-ei/authsecret.go cmd/jo-ei/authsecret_test.go cmd/jo-ei/main.go
git commit -m "feat(cmd): wire JWT sessions and serve the console shell publicly

Signing key comes from JOEI_CONSOLE_JWT_SECRET, then the config file,
then the settings store, then a generated key which is persisted so a
restart does not end every session. /api/auth/ mounts outside the
middleware and /console/ is no longer gated: the login screen has to
render before a session exists."
```

---

### Task 6: Integration test for the whole flow

**Files:**
- Modify: `integration/console_auth_test.go` (rewrite for sessions)

**Interfaces:**
- Consumes: `auth.NewUsers`, `auth.NewSigner`, `auth.NewSessions`, `auth.AccessCookie`, `auth.RefreshCookie`, and the existing `authConsoleStack` helper in that file.

- [ ] **Step 1: Rewrite the stack helper and the tests**

In `integration/console_auth_test.go`, change `authConsoleStack` to mount sessions the way `cmd/jo-ei` now does. Replace its final mount lines (the ones wrapping the console handler with `users.Middleware`) with:

```go
	signer, err := auth.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	sessions := auth.NewSessions(users, signer, 15*time.Minute, 168*time.Hour)

	root := http.NewServeMux()
	root.Handle("/console/", web.ConsoleHandler())
	root.Handle("/api/auth/", sessions.Handler())
	root.Handle("/api/", sessions.Middleware(console.NewHandler(console.Config{
		// …the existing console.Config literal, unchanged…
	})))
	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)
	return srv
```

Add `"github.com/ggwpLab/Jo-ei/web"` to the imports for the console-shell assertion, and drop any now-unused ones.

Then replace the Basic-auth test bodies with:

```go
func TestConsoleAuth_ShellIsPublicButAPIIsNot(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	srv := authConsoleStack(t, upstream, testUsers(t), &bytes.Buffer{})

	shell, err := http.Get(srv.URL + "/console/")
	require.NoError(t, err)
	defer shell.Body.Close()
	assert.Equal(t, http.StatusOK, shell.StatusCode, "the login screen must load without a session")

	api, err := http.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	defer api.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, api.StatusCode)
	assert.Empty(t, api.Header.Get("WWW-Authenticate"))
}

func TestConsoleAuth_LoginThenCookieAccess(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	srv := authConsoleStack(t, upstream, testUsers(t), &bytes.Buffer{})

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	login, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	require.NoError(t, err)
	defer login.Body.Close()
	require.Equal(t, http.StatusOK, login.StatusCode)

	// The jar now carries joei_at; the console makes exactly this call.
	res, err := client.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)

	me, err := client.Get(srv.URL + "/api/auth/me")
	require.NoError(t, err)
	defer me.Body.Close()
	body, err := io.ReadAll(me.Body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"username":"admin"}`, string(body))
}

func TestConsoleAuth_LoginThenBearerAccess(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	srv := authConsoleStack(t, upstream, testUsers(t), &bytes.Buffer{})

	login, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	require.NoError(t, err)
	defer login.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(login.Body).Decode(&out))
	require.NotEmpty(t, out.AccessToken)

	// The curl/CI path: no cookie jar, one header.
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/overview", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+out.AccessToken)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestConsoleAuth_RefreshKeepsSessionAliveAndLogoutEndsIt(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	srv := authConsoleStack(t, upstream, testUsers(t), &bytes.Buffer{})

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	login, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	require.NoError(t, err)
	defer login.Body.Close()
	require.Equal(t, http.StatusOK, login.StatusCode)

	refresh, err := client.Post(srv.URL+"/api/auth/refresh", "", nil)
	require.NoError(t, err)
	defer refresh.Body.Close()
	assert.Equal(t, http.StatusOK, refresh.StatusCode)

	after, err := client.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	defer after.Body.Close()
	assert.Equal(t, http.StatusOK, after.StatusCode)

	logout, err := client.Post(srv.URL+"/api/auth/logout", "", nil)
	require.NoError(t, err)
	defer logout.Body.Close()
	require.Equal(t, http.StatusNoContent, logout.StatusCode)

	gone, err := client.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	defer gone.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, gone.StatusCode)
}

func TestConsoleAuth_LockedReturns503(t *testing.T) {
	upstream := newTestRegistry(t, "fresh-pkg", "1.0.0", 1)
	defer upstream.Close()
	locked, err := auth.NewUsers(nil, "") // no users configured
	require.NoError(t, err)
	srv := authConsoleStack(t, upstream, locked, &bytes.Buffer{})

	res, err := http.Get(srv.URL + "/api/overview")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)

	login, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	require.NoError(t, err)
	defer login.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, login.StatusCode)
}
```

The file's existing helpers stay exactly as they are: `newTestRegistry(t, "fresh-pkg", "1.0.0", 1)` builds the upstream, `testUsers(t)` builds the `admin`/`s3cret` credential set (bcrypt at `MinCost`), and the locked set is built inline with `auth.NewUsers(nil, "")`. Replace the three existing `TestConsoleAuth_*` bodies rather than adding a parallel set. New imports: `encoding/json`, `io`, `net/http/cookiejar`, `strings`, `time`, and `github.com/ggwpLab/Jo-ei/web`.

If the file asserts on log attribution (the `logBuf` parameter), keep that test and drive it through a logged-in client instead of `SetBasicAuth`.

- [ ] **Step 2: Run the integration suite**

Run: `go test -tags integration ./integration/ -run ConsoleAuth -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add integration/console_auth_test.go
git commit -m "test(integration): cover the JWT session flow end to end

Public console shell with a gated API, cookie and bearer access from one
login, refresh, logout, and the locked fail-closed stack."
```

---

### Task 7: Console API client — sessions in `api.js`

**Files:**
- Modify: `web/console/src/api.js`
- Regenerate: `web/console/app.bundle.js`

**Interfaces:**
- Produces, used by Task 8: `JOEI.authenticated` (bool), `JOEI.username` (string), `JOEI.login(username, password)`, `JOEI.logout()`, and the `joei:auth` window event.

- [ ] **Step 1: Add the auth state to the JOEI object**

In `web/console/src/api.js`, inside the `const J = (window.JOEI = {…})` literal, after the `connected: false,` line, add:

```js
    authenticated: false, // set by the boot probe, login, and any 401
    username: "",
```

- [ ] **Step 2: Add the auth event and the fetch wrapper**

Replace the existing `getJSON` helper:

```js
  async function getJSON(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(path + " -> HTTP " + res.status);
    return res.json();
  }
```

with:

```js
  function setAuthenticated(v, username) {
    const changed = J.authenticated !== v;
    J.authenticated = v;
    J.username = v ? (username || J.username) : "";
    if (changed) fire("joei:auth");
  }

  // Raised when a call fails because the session is gone. The app shell shows
  // the login screen for it, rather than the "no connection" banner: an
  // expired session is not a dead proxy.
  class AuthError extends Error {}

  // One refresh at a time: a page load fires several requests at once and they
  // would otherwise race to rotate the refresh cookie, each invalidating the
  // others' new token.
  let refreshing = null;
  function refreshSession() {
    if (!refreshing) {
      refreshing = fetch("/api/auth/refresh", { method: "POST" })
        .then((res) => res.ok)
        .catch(() => false)
        .finally(() => { refreshing = null; });
    }
    return refreshing;
  }

  // Every API call goes through here: on 401 it refreshes once and replays the
  // request, and gives up to the login screen if that fails.
  async function authFetch(path, opts) {
    let res = await fetch(path, opts);
    if (res.status === 401 && await refreshSession()) {
      res = await fetch(path, opts);
    }
    if (res.status === 401 || res.status === 503) {
      setAuthenticated(false);
      throw new AuthError(res.status === 503 ? "auth_not_configured" : "unauthorized");
    }
    return res;
  }

  async function getJSON(path) {
    const res = await authFetch(path);
    if (!res.ok) throw new Error(path + " -> HTTP " + res.status);
    return res.json();
  }
```

- [ ] **Step 3: Route the mutating calls through the wrapper**

In `savePolicy`, `saveRegistries` and `cleanupCache`, replace each bare `fetch(` with `authFetch(`, keeping every argument as it is. Three call sites:

- `const res = await fetch("/api/policy", {` → `const res = await authFetch("/api/policy", {`
- `const res = await fetch("/api/registries", {` → `const res = await authFetch("/api/registries", {`
- `const res = await fetch("/api/cache/cleanup", { method: "POST" });` → `const res = await authFetch("/api/cache/cleanup", { method: "POST" });`

- [ ] **Step 4: Add login, logout, and the session-aware boot**

Make the EventSource handle module-scoped so logout can close it. Replace:

```js
  function connectEvents() {
    const es = new EventSource("/api/events");
```

with:

```js
  let es = null;
  function connectEvents() {
    if (es) return; // already streaming
    es = new EventSource("/api/events");
```

and, inside that function, replace the error handler:

```js
    es.onerror = () => probeConnection(); // EventSource reconnects on its own
```

with:

```js
    es.onerror = () => probeConnection(); // EventSource reconnects on its own
  }

  function disconnectEvents() {
    if (es) { es.close(); es = null; }
```

(The closing brace of `connectEvents` now belongs to `disconnectEvents`; keep the file balanced — `connectEvents` ends after `es.onerror`, and `disconnectEvents` is a new sibling function.)

Then add the session functions before `J.load = load;`:

```js
  // Sign in, then start the session: load the panels and open the stream. The
  // server sets HttpOnly cookies; the access_token in the body is for curl and
  // CI, and the console deliberately never touches it.
  async function login(username, password) {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON error body */ }
    if (!res.ok) {
      const err = new Error((data && data.error) || "login_failed");
      err.status = res.status;
      throw err;
    }
    setAuthenticated(true, data.username);
    await load().catch(() => setConnected(false));
    connectEvents();
    return J.username;
  }

  async function logout() {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } finally {
      disconnectEvents();
      setAuthenticated(false);
      fire("joei:data"); // let the shell re-render against the signed-out state
    }
  }

  // Boot: ask who we are before loading anything. A 401 here is a normal cold
  // start, not an error — it renders the login screen.
  async function boot() {
    try {
      const res = await fetch("/api/auth/me");
      if (!res.ok) {
        setAuthenticated(false);
        return;
      }
      const me = await res.json();
      setAuthenticated(true, me.username);
      await load();
      connectEvents();
    } catch (_) {
      if (J.authenticated) setConnected(false);
    } finally {
      J.ready = true;
      fire("joei:data");
    }
  }
```

- [ ] **Step 5: Publish the new API and replace the boot call**

Add next to the other `J.` assignments:

```js
  J.login = login;
  J.logout = logout;
```

Replace the initial load line:

```js
  load().catch(() => { J.ready = true; setConnected(false); fire("joei:data"); }).finally(connectEvents);
```

with:

```js
  boot();
```

and guard the two background refreshes so a signed-out tab stops polling:

```js
  setInterval(() => {
    if (!document.hidden && J.authenticated) load().catch(() => { if (J.authenticated) setConnected(false); });
  }, 15000);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && J.authenticated) load().catch(() => { if (J.authenticated) setConnected(false); });
  });
```

Also guard `probeConnection` the same way, so an SSE error after logout does not reopen the banner:

```js
  function probeConnection() {
    if (probing || !J.authenticated) return;
```

- [ ] **Step 6: Rebuild**

Run:

```bash
go generate ./web
go build ./...
```

Expected: both silent. (Behaviour is verified in Task 8, once there is a login screen to drive it from.)

- [ ] **Step 7: Commit**

```bash
git add web/console/src/api.js web/console/app.bundle.js
git commit -m "feat(console): session-aware API client

Every call goes through authFetch, which refreshes once on a 401 and
replays the request; a failed refresh raises the login screen instead of
the no-connection banner. Boot probes /api/auth/me first, and the poll,
the visibility refresh and the SSE probe all stand down when signed out."
```

---

### Task 8: Console login screen, identity and logout

**Files:**
- Modify: `web/console/src/app.jsx`
- Modify: `web/console/screens.css` (login screen styles)
- Regenerate: `web/console/app.bundle.js`

**Interfaces:**
- Consumes: `JOEI.authenticated`, `JOEI.username`, `JOEI.login`, `JOEI.logout`, the `joei:auth` event (Task 7).

- [ ] **Step 1: Add the login screen component**

In `web/console/src/app.jsx`, after the `PurifyLoader` component, add:

```jsx
/* ---------- login ---------- */
function LoginScreen() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = (e) => {
    e.preventDefault();
    if (busy || !username || !password) return;
    setBusy(true);
    setErr("");
    JOEI.login(username, password)
      .catch((ex) => {
        setErr(ex.status === 503
          ? "Authentication is not configured on this server. Add console.auth.users or JOEI_CONSOLE_AUTH_USERS and restart."
          : "Incorrect username or password.");
        setPassword("");
      })
      .finally(() => setBusy(false));
  };

  return (
    <div className="login-wrap">
      <form className="card login-card" onSubmit={submit}>
        <div className="login-mark"><ToriiMark size={44} /></div>
        <div className="login-title kanji">浄衛 <small>Jōei</small></div>
        <div className="login-sub">The Purification Gate · console</div>

        <label className="login-field">
          <span>Username</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)}
            autoFocus autoComplete="username" disabled={busy} />
        </label>
        <label className="login-field">
          <span>Password</span>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password" disabled={busy} />
        </label>

        {err && <div className="login-err">{err}</div>}

        <button className="btn primary login-submit" type="submit" disabled={busy || !username || !password}>
          {busy ? "Opening the gate…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
```

If `btn primary` is not an existing class pair in `styles.css`, use the classes the Policy screen's save button uses — check `web/console/src/policy.jsx` and match it rather than inventing a variant.

- [ ] **Step 2: Track the session in `App`**

After `const [connected, setConnected] = useState(JOEI.connected);` add:

```jsx
  const [authed, setAuthed] = useState(JOEI.authenticated);
  const [username, setUsername] = useState(JOEI.username);
```

and in the subscription effect, extend the handlers:

```jsx
    const onAuth = () => { setAuthed(JOEI.authenticated); setUsername(JOEI.username); };
    window.addEventListener("joei:auth", onAuth);
```

adding the matching `window.removeEventListener("joei:auth", onAuth);` to the effect's cleanup, and calling `onAuth()` next to the existing `onConn()` line so state syncs when the probe settled before React subscribed.

- [ ] **Step 3: Render the login screen when signed out**

Immediately before the existing `return (` of `App`, add:

```jsx
  // The purify overlay covers the /api/auth/me probe, so an operator with a
  // live session never sees a flash of the login screen.
  if (!authed) {
    return (
      <>
        {showLoader && <PurifyLoader hide={!loading} />}
        {!loading && <LoginScreen />}
      </>
    );
  }
```

- [ ] **Step 4: Replace the fake identity with the real one**

In the sidebar footer, replace the hardcoded identity block:

```jsx
          <div className="row" style={{ gap: 10, padding: "0 8px" }}>
            <div style={{ width: 30, height: 30, borderRadius: 8, background: "var(--ink-700)", display: "grid", placeItems: "center", fontSize: 12, fontWeight: 700, color: "var(--washi-soft)" }}>SK</div>
            <div className="col" style={{ lineHeight: 1.25 }}>
              <span style={{ fontSize: 12.5, fontWeight: 600 }}>S. Kurosawa</span>
              <span className="faint" style={{ fontSize: 11 }}>DevSecOps · admin</span>
            </div>
          </div>
```

with:

```jsx
          <div className="row" style={{ gap: 10, padding: "0 8px" }}>
            <div style={{ width: 30, height: 30, borderRadius: 8, background: "var(--ink-700)", display: "grid", placeItems: "center", fontSize: 12, fontWeight: 700, color: "var(--washi-soft)" }}>
              {username.slice(0, 2).toUpperCase()}
            </div>
            <div className="col" style={{ lineHeight: 1.25, minWidth: 0 }}>
              <span style={{ fontSize: 12.5, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis" }}>{username}</span>
              <span className="faint" style={{ fontSize: 11 }}>signed in</span>
            </div>
            <button className="btn sm ghost" style={{ marginLeft: "auto" }} onClick={() => JOEI.logout()}>Sign out</button>
          </div>
```

- [ ] **Step 5: Style the login screen**

Append to `web/console/screens.css`:

```css
/* ===================================================================
   LOGIN
   =================================================================== */
.login-wrap { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
.login-card { width: 100%; max-width: 360px; padding: 28px 26px; display: flex; flex-direction: column; gap: 14px; }
.login-mark { display: grid; place-items: center; }
.login-title { text-align: center; font-size: 22px; letter-spacing: 2px; }
.login-title small { letter-spacing: 0; font-size: 13px; color: var(--washi-mut); }
.login-sub { text-align: center; font-size: 11.5px; color: var(--washi-mut); margin-bottom: 6px; }
.login-field { display: flex; flex-direction: column; gap: 5px; font-size: 11.5px; color: var(--washi-mut); }
.login-field input {
  background: var(--ink-700); border: 1px solid var(--line); border-radius: 8px;
  padding: 9px 11px; color: var(--washi); font-family: inherit; font-size: 13px;
}
.login-field input:focus { outline: none; border-color: var(--jade); }
.login-err { font-size: 11.5px; color: var(--vermilion-l); line-height: 1.45; }
.login-submit { margin-top: 4px; width: 100%; justify-content: center; }
```

Check the variable names against the top of `styles.css` before committing — use the ones that exist there (`--ink-700`, `--line`, `--washi`, `--washi-mut`, `--jade`, `--vermilion-l` are all in use elsewhere in `screens.css`; if one is not, substitute the nearest that is).

- [ ] **Step 6: Rebuild and verify in a browser**

Run:

```bash
go generate ./web
go build ./...
go test ./...
```

Then start the binary with at least one user configured and walk the flow — this manual pass is the verification for the whole SPA half of the feature:

1. Open `/console/` signed out: the torii loader shows briefly, then the login screen. No browser credential dialog appears at any point.
2. Wrong password: inline "Incorrect username or password", the password field clears, the username survives, and no console screen leaks behind the form.
3. Correct password: the console loads, the sidebar shows your username and its initials, and the live feed streams (SSE authenticated by cookie).
4. In devtools, confirm `joei_at` and `joei_rt` are `HttpOnly` and that `document.cookie` shows neither.
5. Wait out the access TTL (set `console.auth.access_ttl_minutes: 1` for the test) with the tab open: the next 15-second poll refreshes silently and nothing flickers.
6. Delete the `joei_rt` cookie in devtools, then wait for the access token to expire: the console falls back to the login screen, not the "no connection" banner.
7. **Sign out**: the login screen returns, the SSE connection closes (network tab), and reloading does not restore the session.
8. Stop the proxy while signed in: the "no connection" banner appears — *not* the login screen. The two states must stay distinguishable.
9. With zero users configured: the login screen loads and submitting shows the "authentication is not configured" copy.
10. `curl -sX POST $J/api/auth/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"…"}'` returns a token, and `curl -H "Authorization: Bearer $TOKEN" $J/api/overview` returns JSON.

- [ ] **Step 7: Commit**

```bash
git add web/console/src/app.jsx web/console/screens.css web/console/app.bundle.js
git commit -m "feat(console): login screen, real identity and sign-out

The shell renders the login form when signed out and the console when
signed in; the sidebar's hardcoded 'S. Kurosawa' placeholder is replaced
by the authenticated username with a sign-out button next to it."
```

---

### Task 9: Documentation, changelog and the PR

**Files:**
- Modify: `README.md`, `docs/configuration.md`, `docs/architecture.md`, `docker-compose.yaml`, `CHANGELOG.md`

- [ ] **Step 1: Update `docs/configuration.md`**

Replace the `console` section (currently around `:263-272`) with:

```markdown
## `console`

| Key | Default | Description |
|---|---|---|
| `auth.users` | — | List of `{username, password_hash}` (bcrypt). Prefer `JOEI_CONSOLE_AUTH_USERS`. |
| `auth.jwt_secret` | generated | HS256 key signing console sessions, at least 32 bytes. Prefer `JOEI_CONSOLE_JWT_SECRET`. Unset, Jōei generates one on first boot and stores it in the database, so sessions survive a restart; set it explicitly to share sessions across replicas. |
| `auth.access_ttl_minutes` | `15` | Access-token lifetime. |
| `auth.refresh_ttl_hours` | `168` | Refresh-token lifetime (7 days). |

Generate a password hash: `printf '%s' 'your-password' | jo-ei hashpw`

**Sessions.** The console signs in at `POST /api/auth/login` and rides two
HttpOnly, `SameSite=Strict` cookies (`joei_at`, `joei_rt`); the browser never
sees the token in JavaScript. `Secure` is set when the request arrives over TLS
— terminate TLS in front of Jōei in any deployment that leaves a trusted
network.

**Scripts and CI** use the same endpoint and read the token from the response
body:

```bash
TOKEN=$(curl -sX POST "$JOEI/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"ops","password":"…"}' | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" "$JOEI/api/overview"
```

HTTP Basic is no longer accepted.

**Fail-closed:** with zero users configured, `/api/` returns HTTP 503 and no
one can sign in; the console shell still loads (it is static UI), and the proxy
data path and `/health` stay open.

**Signing out** clears the cookies. Tokens are stateless, so a bearer token
already issued stays valid until it expires (15 minutes by default); to end
every session at once, change `auth.jwt_secret` and restart.
```

Also update the env-var list near the top of that file (`:24-27`) to mention `JOEI_CONSOLE_JWT_SECRET` alongside `JOEI_CONSOLE_AUTH_USERS`.

- [ ] **Step 2: Update `docs/architecture.md`**

Replace the `internal/auth` row of the package table:

```markdown
| `internal/auth` | Console/API authentication: bcrypt user list from YAML and `JOEI_CONSOLE_AUTH_USERS`, HS256 JWT sessions (HttpOnly access/refresh cookies for the browser, bearer tokens for scripts), the `/api/auth/*` endpoints and the gating middleware. |
```

- [ ] **Step 3: Update `README.md`**

Find every mention of Basic auth and every `curl -u` example in the console/API section and replace them with the login + bearer flow from Step 1. Add one sentence where the console is introduced: the console signs in with the same credentials at `/console/`, and sessions last 15 minutes with a 7-day silent refresh.

- [ ] **Step 4: Update `docker-compose.yaml`**

In the `jo-ei` service's `environment` block, next to `JOEI_CONSOLE_AUTH_USERS`, add:

```yaml
      # Signs console sessions. Unset, Jōei generates one and stores it in the
      # database; set it explicitly to keep sessions across a database reset or
      # to share them between replicas. At least 32 bytes.
      - JOEI_CONSOLE_JWT_SECRET=${JOEI_CONSOLE_JWT_SECRET:-}
```

Leave the rest of the file — including the uncommitted local edits already in the working tree, if any — alone; commit only this hunk.

- [ ] **Step 5: Update `CHANGELOG.md`**

Under `## [Unreleased]`:

```markdown
### Changed

- **BREAKING — console and API authentication is now JWT, not HTTP Basic.**
  The console has a real login screen, identity and sign-out. Scripts obtain a
  token from `POST /api/auth/login` and send `Authorization: Bearer <token>`;
  `curl -u` no longer works. Credentials themselves are unchanged — the same
  `console.auth.users` / `JOEI_CONSOLE_AUTH_USERS` bcrypt hashes keep working.
- `/console/` (the static UI bundle) is now served without authentication so
  the login screen can load; all data remains behind the gated `/api/`.

### Added

- `console.auth.jwt_secret` (`JOEI_CONSOLE_JWT_SECRET`),
  `console.auth.access_ttl_minutes` (default 15) and
  `console.auth.refresh_ttl_hours` (default 168). With no secret configured,
  one is generated on first boot and stored in the database.
```

- [ ] **Step 6: Full verification before pushing**

Run:

```bash
go generate ./web
go build ./...
go test ./...
go test -tags integration ./integration/
golangci-lint run
git status --short
```

Expected: everything green, and `git status` clean apart from the doc files you are about to commit. Report the actual output — if a check fails, fix it before the PR rather than noting it as known.

- [ ] **Step 7: Commit and push**

```bash
git add README.md docs/configuration.md docs/architecture.md docker-compose.yaml CHANGELOG.md
git commit -m "docs: JWT console authentication"
git push -u origin feat/jwt-auth
```

- [ ] **Step 8: Open the PR into main**

```bash
gh pr create --base main --title "feat(auth): JWT console sessions, replacing HTTP Basic" --body "$(cat <<'EOF'
Implements `docs/superpowers/specs/2026-09-05-jwt-console-auth-design.md`.

**Breaking:** HTTP Basic is no longer accepted on `/api/`. Scripts log in and
send a bearer token:

```bash
TOKEN=$(curl -sX POST "$JOEI/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"ops","password":"…"}' | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" "$JOEI/api/overview"
```

Existing credentials are untouched: the same bcrypt hashes in
`console.auth.users` / `JOEI_CONSOLE_AUTH_USERS` keep working.

**What changed**

- `internal/auth` gains an HS256 signer written on the standard library (no new
  dependency; `alg` is compared, never dispatched on), a session middleware
  accepting the `joei_at` cookie or an `Authorization: Bearer` header, and the
  `/api/auth/{login,refresh,logout,me}` endpoints.
- Browser sessions are HttpOnly, `SameSite=Strict` cookies — which is also what
  lets the SSE stream authenticate, since `EventSource` cannot send headers.
  Cookie-authenticated mutations additionally require a same-origin request.
- The signing key comes from `JOEI_CONSOLE_JWT_SECRET`, then the config file,
  then the settings store, then a generated key that is persisted — a restart
  no longer ends every session.
- `/console/` is served publicly (static UI, no secrets) so the login screen can
  render; all data stays behind the gated `/api/`.
- The console gains a login screen, the real signed-in username in the sidebar
  in place of the hardcoded "S. Kurosawa" placeholder, a sign-out button, and a
  fetch wrapper that refreshes once on a 401 before falling back to the login
  screen.

**Known limits, by design** (see the spec's Risks): tokens are stateless, so
sign-out clears cookies but an already-issued bearer token stays valid until it
expires; changing the secret and restarting is the break-glass. No API tokens,
roles, or SSO in this change.

**Verification:** `go test ./...` and `go test -tags integration ./integration/`
green, `golangci-lint run` clean. The Go side covers token forgery (tampered
payload, wrong secret, `alg: none`), expiry, type confusion, the locked state,
cookie attributes, refresh rotation, and the same-origin rule. This repository
has no JavaScript test runner by design, so the SPA was verified by hand across
the flows listed in the plan: cold start, bad password, sign-in, silent refresh,
lost refresh cookie, sign-out, proxy down while signed in, and the zero-users
state.
EOF
)"
```

---

## Self-Review

**Spec coverage.** Token format and claims → Task 1. Middleware, cookies, credential order, same-origin rule, locked state → Task 2. The four endpoints, response shapes, cookie attributes, identical failure responses → Task 3. Config keys, defaults, secret-length validation → Task 4. Secret resolution order with generate-and-persist, public `/console/`, `/api/auth/` mounted outside the middleware, reworded startup warning → Task 5. Integration coverage of the whole flow → Task 6. `authFetch` with single-flight refresh, boot probe, poll/visibility/SSE guards → Task 7. Login screen, real identity, sign-out → Task 8. README, configuration, architecture, compose, changelog → Task 9. The spec's excluded items (revocation, API tokens, roles, SSO, login rate limiting) have no tasks, deliberately, and the PR body says so.

**Placeholders.** None. Every code step gives the code; every verification step gives the command and the expected result. Three steps say "match the file's existing helper" (config test fixtures, the integration file's upstream/user helpers, the button class in `policy.jsx`) — that is deliberate, since inventing a parallel helper next to an existing one is the worse outcome, and each names exactly what to look for.

**Type consistency.** `Signer`, `Claims`, `TypeAccess`/`TypeRefresh`, `MinSecretLen`, and the four sentinel errors are defined in Task 1 and used unchanged in Tasks 2, 3 and 5. `NewSessions(users, signer, accessTTL, refreshTTL)`, `AccessCookie`, `RefreshCookie`, `RefreshCookiePath`, `issueSession`, `clearSession`, `writeJSON`, `writeJSONError`, `Authenticate`, `Known` are defined in Task 2 and used in Tasks 3, 5 and 6. `Handler()` is defined in Task 3 and used by Task 2's tests (noted there as a deliberate mid-stream dependency), Task 5 and Task 6. `resolveJWTSecret`/`authTTLs`/`jwtSecretSettingKey` are defined in Task 5 and used in its own step 5 and its tests. On the JS side `authenticated`, `username`, `login`, `logout`, `joei:auth`, `authFetch`, `refreshSession`, `disconnectEvents` are defined in Task 7 and consumed in Task 8 under those exact names.

**One known ordering wrinkle**, called out where it bites: Task 2's tests use `Sessions.Handler()`, which Task 3 introduces, so `internal/auth` does not compile green between those two commits. Both land in the same PR. The alternative — hand-rolling tokens in Task 2's tests instead of logging in — would test a path no caller uses.

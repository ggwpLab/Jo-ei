package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/logx"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

// Session cookie names and the refresh cookie's path. The refresh cookie is
// scoped to /api/auth so it never rides along on ordinary API calls: only the
// endpoints that can spend it ever see it.
const (
	AccessCookie      = "joei_at"
	RefreshCookie     = "joei_rt"
	RefreshCookiePath = "/api/auth"
)

// UserStore is the slice of the users store that sessions need. *users.Store
// satisfies it. Get is case-insensitive and returns the stored username.
type UserStore interface {
	Get(username string) (users.User, error)
	HasEnabledUsers() (bool, error)
	TouchLogin(username string, at time.Time) error
	SetPassword(username, hash string, mustChange bool) error
}

// Identity is the authenticated caller, as Middleware puts it in the request
// context. Username is the stored spelling, whatever case the client used.
type Identity struct {
	Username           string
	Role               users.Role
	MustChangePassword bool
}

type ctxKey struct{}

// WithIdentity returns ctx carrying id. Middleware uses it; it is exported so
// handler tests can fake an authenticated request.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// IdentityFromContext returns the identity stored by Middleware, and false
// when the request did not pass through the authenticating middleware.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// UserFromContext returns the authenticated username stored by Middleware, and
// false when the request did not pass through the authenticating middleware.
func UserFromContext(ctx context.Context) (string, bool) {
	id, ok := IdentityFromContext(ctx)
	return id.Username, ok
}

// Sessions authenticates console and API requests from JWT sessions. It owns
// the cookies, the middleware, and the /api/auth handlers (see handlers.go).
// Every request re-reads its user from the store, so a disabled or deleted
// user, or a bumped token version, takes effect immediately.
type Sessions struct {
	store      UserStore
	signer     *Signer
	accessTTL  time.Duration
	refreshTTL time.Duration
	limiter    *LoginLimiter
	clientIP   func(*http.Request) string
	logger     zerolog.Logger
	now        func() time.Time
}

// Option configures a Sessions.
type Option func(*Sessions)

// WithLoginLimiter sets the limiter that throttles failed logins and failed
// current-password checks. Without it, Sessions uses its own limiter.
func WithLoginLimiter(l *LoginLimiter) Option {
	return func(s *Sessions) { s.limiter = l }
}

// WithClientIP sets how the client IP is derived from a request, for the
// login limiter and logs. The default is the host part of RemoteAddr, which
// is right only when no reverse proxy sits in front.
func WithClientIP(fn func(*http.Request) string) Option {
	return func(s *Sessions) { s.clientIP = fn }
}

// WithLogger sets the logger for login, rate-limit and password-change lines.
// It is tagged component=auth. The default discards everything.
func WithLogger(l zerolog.Logger) Option {
	return func(s *Sessions) { s.logger = l.With().Str("component", "auth").Logger() }
}

// NewSessions wires a user store to a signer and the two token lifetimes.
func NewSessions(store UserStore, signer *Signer, accessTTL, refreshTTL time.Duration, opts ...Option) *Sessions {
	s := &Sessions{
		store:      store,
		signer:     signer,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		clientIP:   remoteHost,
		logger:     zerolog.Nop(),
		now:        time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	if s.limiter == nil {
		s.limiter = NewLoginLimiter(nil)
	}
	return s
}

// remoteHost is the default client IP: RemoteAddr without its port.
func remoteHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// Locked reports the fail-closed state: no enabled users, or the store could
// not say (an error never opens the console).
func (s *Sessions) Locked() bool {
	ok, err := s.store.HasEnabledUsers()
	if err != nil {
		s.logger.Error().Err(err).Msg("checking for console users failed")
		return true
	}
	return !ok
}

// log returns the auth logger carrying r's request ID.
func (s *Sessions) log(r *http.Request) zerolog.Logger {
	return logx.Logger(r.Context(), s.logger)
}

// userForToken verifies token as wantType and returns its current user. It
// fails when the user is gone or disabled, or when the token was issued at an
// older token version (revoked by a password, role or status change).
func (s *Sessions) userForToken(r *http.Request, token, wantType string) (users.User, bool) {
	claims, err := s.signer.Verify(token, wantType)
	if err != nil {
		return users.User{}, false
	}
	u, err := s.store.Get(claims.Sub)
	if err != nil {
		if !errors.Is(err, users.ErrNotFound) {
			l := s.log(r)
			l.Error().Err(err).Str("user", claims.Sub).Msg("reading console user failed")
		}
		return users.User{}, false
	}
	if u.Disabled || claims.Ver != u.TokenVersion {
		return users.User{}, false
	}
	return u, true
}

// authenticate resolves the request's access credential to its user, and
// reports whether it came from an Authorization header.
func (s *Sessions) authenticate(r *http.Request) (u users.User, bearer bool, ok bool) {
	token, bearer, found := accessCredential(r)
	if !found {
		return users.User{}, bearer, false
	}
	u, ok = s.userForToken(r, token, TypeAccess)
	return u, bearer, ok
}

func identityOf(u users.User) Identity {
	return Identity{Username: u.Username, Role: u.Role, MustChangePassword: u.MustChangePassword}
}

// Middleware gates a handler on a valid access token.
//
//   - Locked (no enabled users): 503, handler never runs.
//   - Missing/invalid/expired token, or a token whose user is gone, disabled
//     or at a newer token version: 401. No WWW-Authenticate header — a Basic
//     challenge would make the browser cover the console's own login screen.
//   - Cookie-authenticated state change from another origin: 403.
//   - User must change their password first: 403 password_change_required.
//   - Valid: Identity into the request context (see IdentityFromContext).
func (s *Sessions) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Locked() {
			writeJSONError(w, http.StatusServiceUnavailable, "auth_not_configured")
			return
		}
		u, bearer, ok := s.authenticate(r)
		if !ok {
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
		// /api/auth/* (me, password) sits outside this middleware, so a user
		// with a pending password change can still see who they are and
		// change it.
		if u.MustChangePassword {
			writeJSONError(w, http.StatusForbidden, "password_change_required")
			return
		}
		h.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), identityOf(u))))
	})
}

// Authenticate validates the request's access credential and returns the
// caller's identity. It applies neither the origin rule nor the
// password-change gate, so it suits read-only endpoints that resolve their
// own caller (GET /api/auth/me).
func (s *Sessions) Authenticate(r *http.Request) (Identity, bool) {
	u, _, ok := s.authenticate(r)
	if !ok {
		return Identity{}, false
	}
	return identityOf(u), true
}

// accessCredential returns the presented access token, whether it came from an
// Authorization header, and whether one was found at all. A malformed
// Authorization header is not retried as a cookie: a client that meant to send
// a bearer token gets a clean 401 rather than a confusing fallback.
func accessCredential(r *http.Request) (token string, bearer bool, found bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		// RFC 7235: the auth scheme name is case-insensitive ("Bearer", "bearer",
		// "BEARER" are the same scheme), so match it that way.
		scheme, rest, hasSpace := strings.Cut(h, " ")
		if !strings.EqualFold(scheme, "Bearer") || !hasSpace {
			return "", true, false
		}
		v := strings.TrimSpace(rest)
		return v, true, v != ""
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
//
// "same-site" (as opposed to "same-origin") is deliberately treated as
// cross-site here: it covers sibling subdomains (e.g. a console at
// console.example.com calling an API at api.example.com), and this project's
// threat model wants those to authenticate as separate origins rather than be
// trusted by virtue of sharing a registrable domain. Do not loosen this to
// accept "same-site" without revisiting that decision.
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
	wantScheme := "http"
	if isTLS(r) {
		wantScheme = "https"
	}
	return u.Host == r.Host && u.Scheme == wantScheme
}

// sessionCookie builds one session cookie with the policy both session cookies
// share: HttpOnly, SameSite=Strict, and Secure only over TLS. Secure must
// track isTLS(r) rather than a literal true, or browsers drop the cookie on
// plain-HTTP deployments; HttpOnly and SameSite=Strict are set unconditionally
// below.
//
//nolint:gosec // G124 only recognises a literal Secure:true, not this reasoning.
func sessionCookie(name, path, value string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: value, Path: path,
		MaxAge: maxAge, HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
	}
}

// issueSession signs a fresh token pair for username at token version ver and
// sets both cookies. It returns the access token so the login response can
// hand it to non-browser clients.
func (s *Sessions) issueSession(w http.ResponseWriter, r *http.Request, username string, ver int64) (string, error) {
	access, err := s.signer.Issue(username, ver, TypeAccess, s.accessTTL)
	if err != nil {
		return "", err
	}
	refresh, err := s.signer.Issue(username, ver, TypeRefresh, s.refreshTTL)
	if err != nil {
		return "", err
	}
	secure := isTLS(r)
	http.SetCookie(w, sessionCookie(AccessCookie, "/", access, int(s.accessTTL.Seconds()), secure))
	http.SetCookie(w, sessionCookie(RefreshCookie, RefreshCookiePath, refresh, int(s.refreshTTL.Seconds()), secure))
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
		http.SetCookie(w, sessionCookie(c.name, c.path, "", -1, secure))
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

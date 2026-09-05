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

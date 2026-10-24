package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ggwpLab/Jo-ei/internal/users"
)

// maxLoginBody caps the credential payload. Credentials are two short strings;
// anything larger is a mistake or an attempt to make the server allocate.
const maxLoginBody = 4 << 10

// dummyHash is compared against when an unknown username is supplied so that
// response timing does not reveal whether a username exists. Generated once at
// package load at the default cost, like real hashes.
var dummyHash string

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte("joei-timing-dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		panic("auth: generating dummy hash: " + err.Error())
	}
	dummyHash = string(h)
}

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
	mux.HandleFunc("POST /api/auth/password", s.changePassword)
	return mux
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// rateLimited answers 429 with Retry-After in whole seconds, rounded up so a
// client that waits exactly that long is no longer blocked.
func rateLimited(w http.ResponseWriter, retry time.Duration) {
	secs := int64((retry + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	writeJSONError(w, http.StatusTooManyRequests, "too_many_attempts")
}

func (s *Sessions) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Locked() {
		writeJSONError(w, http.StatusServiceUnavailable, "auth_not_configured")
		return
	}
	// login sets cookies from a request body a cross-site page can forge (a
	// <form enctype="text/plain"> whose body happens to parse as our JSON), so
	// it gets the same origin check every other cookie-setting mutation gets.
	if !sameOrigin(r) {
		writeJSONError(w, http.StatusForbidden, "cross_origin")
		return
	}
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	ip := s.clientIP(r)
	log := s.log(r)

	// A blocked attempt is refused before the password is looked at — even a
	// correct one — and is not itself counted, so waiting out Retry-After is
	// always enough.
	if retry, ok := s.limiter.Allow(req.Username, ip); !ok {
		log.Warn().Str("user", req.Username).Str("client_ip", ip).Msg("login rate limited")
		rateLimited(w, retry)
		return
	}

	// Unknown and disabled users cost the same bcrypt comparison as a wrong
	// password and get the same response, so neither timing nor body tells
	// them apart.
	u, err := s.store.Get(req.Username)
	valid := false
	if err == nil {
		valid = users.CheckPassword(u.PasswordHash, req.Password) && !u.Disabled
	} else {
		if !errors.Is(err, users.ErrNotFound) {
			log.Error().Err(err).Str("user", req.Username).Msg("reading console user failed")
		}
		_ = users.CheckPassword(dummyHash, req.Password)
	}
	if !valid {
		s.limiter.Failure(req.Username, ip)
		log.Warn().Str("user", req.Username).Str("client_ip", ip).Msg("login failed")
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}

	s.limiter.Success(req.Username, ip)
	if err := s.store.TouchLogin(u.Username, s.now()); err != nil {
		// Bookkeeping only: a failed timestamp write must not fail the login.
		log.Error().Err(err).Str("user", u.Username).Msg("recording login time failed")
	}
	access, err := s.issueSession(w, r, u.Username, u.TokenVersion)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "token_issue_failed")
		return
	}
	log.Info().Str("user", u.Username).Str("client_ip", ip).Msg("login succeeded")
	writeJSON(w, http.StatusOK, map[string]any{
		"username":             u.Username,
		"role":                 u.Role,
		"must_change_password": u.MustChangePassword,
		"access_token":         access,
		"expires_in":           int(s.accessTTL.Seconds()),
	})
}

func (s *Sessions) refresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Locked() {
		writeJSONError(w, http.StatusServiceUnavailable, "auth_not_configured")
		return
	}
	// refresh is cookie-authenticated like every other mutation, so it gets the
	// same origin check the Middleware applies to cookie-authenticated POSTs.
	if !sameOrigin(r) {
		writeJSONError(w, http.StatusForbidden, "cross_origin")
		return
	}
	// Refresh is a browser-session concern: it reads the cookie only. Machine
	// clients log in again instead of holding a long-lived credential.
	c, err := r.Cookie(RefreshCookie)
	if err != nil || c.Value == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// The same user checks as the middleware, minus the password-change gate:
	// a user who must change their password keeps a session to do it with.
	u, ok := s.userForToken(r, c.Value, TypeRefresh)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// Rotate both tokens, so a browser in continuous use never hits the refresh
	// lifetime wall.
	if _, err := s.issueSession(w, r, u.Username, u.TokenVersion); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "token_issue_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":   u.Username,
		"expires_in": int(s.accessTTL.Seconds()),
	})
}

// logout always succeeds: clearing cookies that are not there is not an error,
// and a failed logout is a worse outcome than a redundant one. "Always
// succeeds" means regardless of whether a session existed, not regardless of
// origin — a cross-site logout is still rejected like any other mutation.
func (s *Sessions) logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !sameOrigin(r) {
		writeJSONError(w, http.StatusForbidden, "cross_origin")
		return
	}
	s.clearSession(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// me is allowed while a password change is pending: the console needs it to
// know it must show the change-password screen.
func (s *Sessions) me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Locked() {
		writeJSONError(w, http.StatusServiceUnavailable, "auth_not_configured")
		return
	}
	id, ok := s.Authenticate(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":             id.Username,
		"role":                 id.Role,
		"must_change_password": id.MustChangePassword,
	})
}

type passwordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// changePassword replaces the caller's own password. It is the way out of
// must_change_password, so it is not gated on it. The change bumps the user's
// token version — revoking every other session — and this session is
// re-issued at the new version.
func (s *Sessions) changePassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Locked() {
		writeJSONError(w, http.StatusServiceUnavailable, "auth_not_configured")
		return
	}
	// It sets cookies, so it gets the origin check every other /api/auth
	// mutation gets.
	if !sameOrigin(r) {
		writeJSONError(w, http.StatusForbidden, "cross_origin")
		return
	}
	u, _, ok := s.authenticate(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req passwordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	ip := s.clientIP(r)
	log := s.log(r)

	// A stolen session must not become an unthrottled password oracle: wrong
	// current passwords count against the same limiter as failed logins.
	if retry, ok := s.limiter.Allow(u.Username, ip); !ok {
		log.Warn().Str("user", u.Username).Str("client_ip", ip).Msg("login rate limited")
		rateLimited(w, retry)
		return
	}
	if !users.CheckPassword(u.PasswordHash, req.Current) {
		s.limiter.Failure(u.Username, ip)
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	s.limiter.Success(u.Username, ip)

	if err := users.ValidatePassword(u.Username, req.New); err != nil {
		msg := err.Error()
		var ve *users.ValidationError
		if errors.As(err, &ve) {
			msg = "password " + ve.Message
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_password", "message": msg})
		return
	}
	if req.New == req.Current {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_password", "message": "new password must differ from the current one",
		})
		return
	}

	h, err := users.HashPassword(req.New)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if err := s.store.SetPassword(u.Username, h, false); err != nil {
		if errors.Is(err, users.ErrNotFound) {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		log.Error().Err(err).Str("user", u.Username).Msg("changing password failed")
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	// Re-read rather than assume version+1, so the new session matches
	// whatever the store recorded.
	fresh, err := s.store.Get(u.Username)
	if err != nil {
		log.Error().Err(err).Str("user", u.Username).Msg("reading console user failed")
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	log.Info().Str("user", fresh.Username).Msg("password changed")
	access, err := s.issueSession(w, r, fresh.Username, fresh.TokenVersion)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "token_issue_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":             fresh.Username,
		"role":                 fresh.Role,
		"must_change_password": fresh.MustChangePassword,
		"access_token":         access,
		"expires_in":           int(s.accessTTL.Seconds()),
	})
}

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
// and a failed logout is a worse outcome than a redundant one. "Always
// succeeds" means regardless of whether a session existed, not regardless of
// origin — a cross-site logout is still rejected like any other mutation.
func (s *Sessions) logout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeJSONError(w, http.StatusForbidden, "cross_origin")
		return
	}
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

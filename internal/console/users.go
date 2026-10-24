package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

// UserAdmin is the user store surface the management API needs.
// *users.Store satisfies it.
type UserAdmin interface {
	List() ([]users.User, error)
	Get(username string) (users.User, error)
	Create(u users.User) error
	SetRole(username string, r users.Role) error
	SetDisabled(username string, disabled bool) error
	SetPassword(username, hash string, mustChange bool) error
	Delete(username string) error
}

type userJSON struct {
	Username           string  `json:"username"`
	Role               string  `json:"role"`
	Disabled           bool    `json:"disabled"`
	MustChangePassword bool    `json:"must_change_password"`
	CreatedAt          string  `json:"created_at"`
	LastLoginAt        *string `json:"last_login_at"`
}

// toUserJSON deliberately omits the password hash and token version.
func toUserJSON(u users.User) userJSON {
	out := userJSON{
		Username:           u.Username,
		Role:               string(u.Role),
		Disabled:           u.Disabled,
		MustChangePassword: u.MustChangePassword,
		CreatedAt:          u.CreatedAt.UTC().Format(time.RFC3339),
	}
	if u.LastLoginAt != nil {
		t := u.LastLoginAt.UTC().Format(time.RFC3339)
		out.LastLoginAt = &t
	}
	return out
}

func (s *server) invalidUser(w http.ResponseWriter, r *http.Request, field, msg string) {
	s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": "invalid_user", "field": field, "message": msg})
}

// decodeUserBody reads a small strict JSON body into v, writing the error
// response itself and returning false on failure.
func (s *server) decodeUserBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeJSON(w, r, http.StatusRequestEntityTooLarge, map[string]any{
				"error": "invalid_user", "field": "body", "message": "request body too large",
			})
			return false
		}
		s.invalidUser(w, r, "body", err.Error())
		return false
	}
	return true
}

// userStore returns the configured store or answers 503.
func (s *server) userStore(w http.ResponseWriter, r *http.Request) (UserAdmin, bool) {
	if s.cfg.Users == nil {
		s.writeJSON(w, r, http.StatusServiceUnavailable, map[string]any{"error": "users_unavailable"})
		return nil, false
	}
	return s.cfg.Users, true
}

// writeUserError maps a store error to a response and reports whether err
// was non-nil.
func (s *server) writeUserError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	var verr *users.ValidationError
	switch {
	case errors.As(err, &verr):
		s.invalidUser(w, r, verr.Field, verr.Message)
	case errors.Is(err, users.ErrExists):
		s.writeJSON(w, r, http.StatusConflict, map[string]any{"error": "user_exists"})
	case errors.Is(err, users.ErrNotFound):
		s.writeJSON(w, r, http.StatusNotFound, map[string]any{"error": "user_not_found"})
	case errors.Is(err, users.ErrLastAdmin):
		s.writeJSON(w, r, http.StatusConflict, map[string]any{"error": "last_admin"})
	default:
		s.log(r).Error().Err(err).Msg("user management failed")
		s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "users_failed"})
	}
	return true
}

func (s *server) isSelf(r *http.Request, target string) bool {
	actor, _ := auth.UserFromContext(r.Context())
	return actor != "" && strings.EqualFold(actor, target)
}

func (s *server) logUserAction(r *http.Request, target, action string, role users.Role) {
	actor, _ := auth.UserFromContext(r.Context())
	e := s.log(r).Info().Str("user", actor).Str("target", target).Str("action", action)
	if role != "" {
		e = e.Str("role", string(role))
	}
	e.Msg("user management")
}

func (s *server) listUsers(w http.ResponseWriter, r *http.Request) {
	st, ok := s.userStore(w, r)
	if !ok {
		return
	}
	list, err := st.List()
	if s.writeUserError(w, r, err) {
		return
	}
	out := make([]userJSON, 0, len(list))
	for _, u := range list {
		out = append(out, toUserJSON(u))
	}
	s.writeJSON(w, r, http.StatusOK, out)
}

func (s *server) createUser(w http.ResponseWriter, r *http.Request) {
	st, ok := s.userStore(w, r)
	if !ok {
		return
	}
	var in struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if !s.decodeUserBody(w, r, &in) {
		return
	}
	// Validate everything before the (slow) bcrypt hash.
	if s.writeUserError(w, r, users.ValidateUsername(in.Username)) {
		return
	}
	role := users.Role(in.Role)
	if !role.Valid() {
		s.invalidUser(w, r, "role", "must be admin or operator")
		return
	}
	if s.writeUserError(w, r, users.ValidatePassword(in.Username, in.Password)) {
		return
	}
	hash, err := users.HashPassword(in.Password)
	if s.writeUserError(w, r, err) {
		return
	}
	err = st.Create(users.User{Username: in.Username, PasswordHash: hash, Role: role, MustChangePassword: true})
	if s.writeUserError(w, r, err) {
		return
	}
	s.logUserAction(r, in.Username, "create", role)
	u, err := st.Get(in.Username)
	if s.writeUserError(w, r, err) {
		return
	}
	s.writeJSON(w, r, http.StatusCreated, toUserJSON(u))
}

func (s *server) patchUser(w http.ResponseWriter, r *http.Request) {
	st, ok := s.userStore(w, r)
	if !ok {
		return
	}
	var in struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
	}
	if !s.decodeUserBody(w, r, &in) {
		return
	}
	if in.Role == nil && in.Disabled == nil {
		s.invalidUser(w, r, "body", "role or disabled is required")
		return
	}
	var newRole users.Role
	if in.Role != nil {
		newRole = users.Role(*in.Role)
		if !newRole.Valid() {
			s.invalidUser(w, r, "role", "must be admin or operator")
			return
		}
	}
	cur, err := st.Get(r.PathValue("name"))
	if s.writeUserError(w, r, err) {
		return
	}
	roleChange := in.Role != nil && cur.Role != newRole
	disableChange := in.Disabled != nil && cur.Disabled != *in.Disabled
	demote := roleChange && newRole == users.RoleOperator
	disable := in.Disabled != nil && *in.Disabled
	if s.isSelf(r, cur.Username) && (demote || disable) {
		s.writeJSON(w, r, http.StatusConflict, map[string]any{"error": "self"})
		return
	}
	if roleChange {
		if s.writeUserError(w, r, st.SetRole(cur.Username, newRole)) {
			return
		}
		s.logUserAction(r, cur.Username, "role", newRole)
	}
	if disableChange {
		if s.writeUserError(w, r, st.SetDisabled(cur.Username, *in.Disabled)) {
			return
		}
		action := "enable"
		if disable {
			action = "disable"
		}
		s.logUserAction(r, cur.Username, action, "")
	}
	u, err := st.Get(cur.Username)
	if s.writeUserError(w, r, err) {
		return
	}
	s.writeJSON(w, r, http.StatusOK, toUserJSON(u))
}

func (s *server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	st, ok := s.userStore(w, r)
	if !ok {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !s.decodeUserBody(w, r, &in) {
		return
	}
	cur, err := st.Get(r.PathValue("name"))
	if s.writeUserError(w, r, err) {
		return
	}
	if s.writeUserError(w, r, users.ValidatePassword(cur.Username, in.Password)) {
		return
	}
	hash, err := users.HashPassword(in.Password)
	if s.writeUserError(w, r, err) {
		return
	}
	if s.writeUserError(w, r, st.SetPassword(cur.Username, hash, true)) {
		return
	}
	s.logUserAction(r, cur.Username, "reset_password", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) deleteUser(w http.ResponseWriter, r *http.Request) {
	st, ok := s.userStore(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if s.isSelf(r, name) {
		s.writeJSON(w, r, http.StatusConflict, map[string]any{"error": "self"})
		return
	}
	cur, err := st.Get(name)
	if s.writeUserError(w, r, err) {
		return
	}
	if s.writeUserError(w, r, st.Delete(cur.Username)) {
		return
	}
	s.logUserAction(r, cur.Username, "delete", "")
	w.WriteHeader(http.StatusNoContent)
}

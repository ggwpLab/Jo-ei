package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/policy"
)

// writePolicy renders the current runtime policy. "persistence" tells the UI
// whether edits survive a restart: "database" when the runtime is backed by a
// settings store, "runtime" when edits reset to the YAML config on restart.
func (s *server) writePolicy(w http.ResponseWriter, r *http.Request, status int) {
	p := s.cfg.Policy.Current()
	persistence := "runtime"
	if s.cfg.Policy.Persistent() {
		persistence = "database"
	}
	s.writeJSON(w, r, status, map[string]any{
		"mode":             p.Mode,
		"min_age_hours":    p.MinAgeHours,
		"cve_block_on":     p.CVEBlockOn,
		"allowlist_supply": p.AllowlistSupply,
		"allowlist_cve":    p.AllowlistCVE,
		"denylist":         p.Denylist,
		"persistence":      persistence,
	})
}

func (s *server) getPolicy(w http.ResponseWriter, r *http.Request) {
	s.writePolicy(w, r, http.StatusOK)
}

func (s *server) putPolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // policy JSON is tiny; reject abuse
	// Every field is a pointer: absent keeps the current value (so a
	// settings-only save cannot clobber concurrent list edits, and an omitted
	// min_age_hours cannot turn into 0), present replaces it.
	var in struct {
		Mode            *string   `json:"mode"`
		MinAgeHours     *int      `json:"min_age_hours"`
		CVEBlockOn      *string   `json:"cve_block_on"`
		AllowlistSupply *[]string `json:"allowlist_supply"`
		AllowlistCVE    *[]string `json:"allowlist_cve"`
		Denylist        *[]string `json:"denylist"`
		Persistence     string    `json:"persistence"` // read-only field from GET; accepted and ignored so GET→PUT round-trips
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeJSON(w, r, http.StatusRequestEntityTooLarge, map[string]any{
				"error": "invalid_policy", "field": "body", "message": "request body too large",
			})
			return
		}
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{
			"error": "invalid_policy", "field": "body", "message": err.Error(),
		})
		return
	}
	err := s.cfg.Policy.Update(func(cur policy.RuntimeParams) policy.RuntimeParams {
		if in.Mode != nil {
			cur.Mode = *in.Mode
		}
		if in.MinAgeHours != nil {
			cur.MinAgeHours = *in.MinAgeHours
		}
		if in.CVEBlockOn != nil {
			cur.CVEBlockOn = *in.CVEBlockOn
		}
		if in.AllowlistSupply != nil {
			cur.AllowlistSupply = *in.AllowlistSupply
		}
		if in.AllowlistCVE != nil {
			cur.AllowlistCVE = *in.AllowlistCVE
		}
		if in.Denylist != nil {
			cur.Denylist = *in.Denylist
		}
		return cur
	})
	if s.writePolicyError(w, r, err) {
		return
	}
	logEvent := s.log(r).Info().Interface("policy", s.cfg.Policy.Current())
	if user, ok := auth.UserFromContext(r.Context()); ok && user != "" {
		logEvent = logEvent.Str("user", user)
	}
	logEvent.Msg("runtime policy updated")
	s.writePolicy(w, r, http.StatusOK)
}

// writePolicyError maps a policy update error onto the HTTP response and
// reports whether it wrote one (err != nil).
func (s *server) writePolicyError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	var verr *policy.ValidationError
	if errors.As(err, &verr) {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{
			"error": "invalid_policy", "field": verr.Field, "message": verr.Message,
		})
		return true
	}
	var perr *policy.PersistError
	if errors.As(err, &perr) {
		s.log(r).Error().Err(err).Msg("persisting policy")
		s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "persist_failed"})
		return true
	}
	s.log(r).Error().Err(err).Msg("applying policy")
	s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "apply_failed"})
	return true
}

// editList handles POST (add) and DELETE (remove) of a single list entry.
func (s *server) editList(add bool) http.HandlerFunc {
	action := "remove"
	if add {
		action = "add"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		var in struct {
			Entry string `json:"entry"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				s.writeJSON(w, r, http.StatusRequestEntityTooLarge, map[string]any{
					"error": "invalid_policy", "field": "body", "message": "request body too large",
				})
				return
			}
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{
				"error": "invalid_policy", "field": "body", "message": err.Error(),
			})
			return
		}
		list := r.PathValue("list")
		changed, err := s.cfg.Policy.EditList(list, in.Entry, add)
		if s.writePolicyError(w, r, err) {
			return
		}
		if changed {
			user, _ := auth.UserFromContext(r.Context())
			s.log(r).Info().Str("user", user).Str("list", list).
				Str("entry", strings.TrimSpace(in.Entry)).Str("action", action).
				Msg("policy list updated")
		}
		s.writePolicy(w, r, http.StatusOK)
	}
}

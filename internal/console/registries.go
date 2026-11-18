package console

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/ggwpLab/Jo-ei/internal/auth"
)

// RegistryInfo describes one configured registry for GET /api/registries.
type RegistryInfo struct {
	Ecosystem string   `json:"eco"`
	Enabled   bool     `json:"enabled"`
	Upstreams []string `json:"upstreams"`
}

// RegistryStore persists the editable registry set. Implemented in cmd/jo-ei by
// an adapter over *settings.Store. When nil, registries are read-only.
type RegistryStore interface {
	LoadRegistries() ([]RegistryInfo, bool, error)
	SaveRegistries([]RegistryInfo) error
}

var knownEcos = []string{"pypi", "npm", "maven", "rubygems", "go", "docker"}

func (s *server) registries(w http.ResponseWriter, r *http.Request) {
	regs, err := s.storedRegistries()
	if err != nil {
		s.log(r).Error().Err(err).Msg("loading registries")
		s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "registries_unavailable"})
		return
	}
	s.writeRegistries(w, r, http.StatusOK, regs)
}

func (s *server) putRegistries(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RegistryStore == nil {
		s.writeJSON(w, r, http.StatusServiceUnavailable, map[string]any{"error": "registries_read_only"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var in struct {
		Registries []RegistryInfo `json:"registries"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeJSON(w, r, http.StatusRequestEntityTooLarge, map[string]any{
				"error": "invalid_registries", "field": "body", "message": "request body too large",
			})
			return
		}
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{
			"error": "invalid_registries", "field": "body", "message": err.Error(),
		})
		return
	}
	stored, err := s.storedRegistries()
	if err != nil {
		s.log(r).Error().Err(err).Msg("loading registries")
		s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "registries_unavailable"})
		return
	}
	if field, msg := unmaskRegistries(in.Registries, stored); field != "" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{
			"error": "invalid_registries", "field": field, "message": msg,
		})
		return
	}
	if field, msg := validateRegistries(in.Registries); field != "" {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{
			"error": "invalid_registries", "field": field, "message": msg,
		})
		return
	}
	for i := range in.Registries {
		if in.Registries[i].Upstreams == nil {
			in.Registries[i].Upstreams = []string{}
		}
	}
	if err := s.cfg.RegistryStore.SaveRegistries(in.Registries); err != nil {
		s.log(r).Error().Err(err).Msg("saving registries")
		s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "persist_failed"})
		return
	}
	logged := make([]RegistryInfo, len(in.Registries))
	for i, reg := range in.Registries {
		logged[i] = RegistryInfo{Ecosystem: reg.Ecosystem, Enabled: reg.Enabled, Upstreams: maskUpstreams(reg.Upstreams)}
	}
	user, _ := auth.UserFromContext(r.Context())
	s.log(r).Info().Str("user", user).Interface("registries", logged).Msg("registries updated")
	s.writeRegistries(w, r, http.StatusOK, in.Registries)
}

// storedRegistries returns the persisted set when a store is configured,
// otherwise the static Registries (read-only mode).
func (s *server) storedRegistries() ([]RegistryInfo, error) {
	if s.cfg.RegistryStore != nil {
		regs, ok, err := s.cfg.RegistryStore.LoadRegistries()
		if err != nil {
			return nil, err
		}
		if ok {
			return regs, nil
		}
	}
	return s.cfg.Registries, nil
}

func (s *server) writeRegistries(w http.ResponseWriter, r *http.Request, status int, regs []RegistryInfo) {
	// Defensive copy: normalising nil Upstreams must not mutate the caller's
	// backing array (e.g. a store's internal slice or s.cfg.Registries).
	out := make([]RegistryInfo, len(regs))
	copy(out, regs)
	for i := range out {
		if out[i].Upstreams == nil {
			out[i].Upstreams = []string{}
		}
	}
	warnings := registryWarnings(out, s.cfg.ImageScanEnabled)
	pending := s.cfg.RegistryStore != nil && s.cfg.RunningRegistries != nil && !registriesEqual(out, s.cfg.RunningRegistries)
	// Upstream URLs may embed credentials and this screen is open to
	// operators: they leave the server masked, and PUT maps a masked URL back
	// to the stored one (unmaskRegistries).
	for i := range out {
		out[i].Upstreams = maskUpstreams(out[i].Upstreams)
	}
	s.writeJSON(w, r, status, map[string]any{
		"registries":      out,
		"pending_restart": pending,
		"warnings":        warnings,
	})
}

// credentialMask stands in for upstream credentials in API responses.
const credentialMask = "***"

// maskUpstream hides the credentials in an upstream URL: the password of
// "user:pass@", or the whole userinfo when it is a bare token ("token@"),
// since a token is a secret even in the user position. A URL without
// userinfo is returned unchanged.
func maskUpstream(raw string) string {
	start := strings.Index(raw, "://")
	if start < 0 {
		return raw
	}
	start += len("://")
	end := len(raw)
	if i := strings.IndexAny(raw[start:], "/?#"); i >= 0 {
		end = start + i
	}
	at := strings.LastIndex(raw[start:end], "@")
	if at < 0 {
		return raw
	}
	masked := credentialMask
	if name, _, hasPassword := strings.Cut(raw[start:start+at], ":"); hasPassword {
		masked = name + ":" + credentialMask
	}
	return raw[:start] + masked + raw[start+at:]
}

// maskUpstreams returns a masked copy of upstreams.
func maskUpstreams(upstreams []string) []string {
	out := make([]string, len(upstreams))
	for i, u := range upstreams {
		out[i] = maskUpstream(u)
	}
	return out
}

// unmaskRegistries replaces, in place, each masked upstream a client sent back
// with the stored URL it was masked from, matched within the same ecosystem.
// A masked URL that matches none — edited, or never stored — cannot be
// restored and is rejected rather than saved with "***" as its credentials.
// It returns ("","") on success, otherwise the offending field and a message.
func unmaskRegistries(in, stored []RegistryInfo) (field, msg string) {
	originals := map[string]map[string]string{} // ecosystem → masked → stored
	for _, reg := range stored {
		m := map[string]string{}
		for _, u := range reg.Upstreams {
			m[maskUpstream(u)] = u
		}
		originals[reg.Ecosystem] = m
	}
	for i := range in {
		for j, u := range in[i].Upstreams {
			if orig, ok := originals[in[i].Ecosystem][u]; ok {
				in[i].Upstreams[j] = orig
				continue
			}
			if strings.Contains(u, credentialMask+"@") {
				return in[i].Ecosystem, fmt.Sprintf("upstream %q has masked credentials that match no stored upstream; enter the full URL", u)
			}
		}
	}
	return "", ""
}

// validateRegistries checks the PUT payload. It returns ("","") when valid,
// otherwise the offending field and a message.
func validateRegistries(in []RegistryInfo) (field, msg string) {
	seen := map[string]bool{}
	for _, r := range in {
		if !slices.Contains(knownEcos, r.Ecosystem) {
			return "registries", fmt.Sprintf("unknown ecosystem %q", r.Ecosystem)
		}
		if seen[r.Ecosystem] {
			return "registries", fmt.Sprintf("duplicate ecosystem %q", r.Ecosystem)
		}
		seen[r.Ecosystem] = true
	}
	if len(seen) != len(knownEcos) {
		return "registries", fmt.Sprintf("must list all %d ecosystems", len(knownEcos))
	}
	for _, r := range in {
		if !r.Enabled {
			continue
		}
		if len(r.Upstreams) == 0 {
			return r.Ecosystem, "an enabled registry needs at least one upstream"
		}
		for _, u := range r.Upstreams {
			parsed, err := url.Parse(u)
			if u == "" || err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
				return r.Ecosystem, fmt.Sprintf("upstream %q must be an http(s) URL", u)
			}
		}
	}
	return "", ""
}

// registryWarnings flags non-fatal configuration problems (currently: docker
// enabled without image-scan, which won't serve /v2/ after restart).
func registryWarnings(regs []RegistryInfo, imageScan bool) []string {
	warnings := []string{}
	for _, r := range regs {
		if r.Ecosystem == "docker" && r.Enabled && !imageScan {
			warnings = append(warnings,
				"docker is enabled but image_scan is not configured in config.yaml; /v2/ will not serve after restart")
		}
	}
	return warnings
}

// registriesEqual reports whether two registry sets are identical. Ecosystems
// are matched order-independently (by name); upstreams within each ecosystem
// are compared positionally — index 0 is the primary URL.
func registriesEqual(a, b []RegistryInfo) bool {
	if len(a) != len(b) {
		return false
	}
	idx := func(list []RegistryInfo) map[string]RegistryInfo {
		m := make(map[string]RegistryInfo, len(list))
		for _, r := range list {
			m[r.Ecosystem] = r
		}
		return m
	}
	ma, mb := idx(a), idx(b)
	for eco, ra := range ma {
		rb, ok := mb[eco]
		if !ok || ra.Enabled != rb.Enabled {
			return false
		}
		if len(ra.Upstreams) != len(rb.Upstreams) {
			return false
		}
		for i := range ra.Upstreams {
			if ra.Upstreams[i] != rb.Upstreams[i] {
				return false
			}
		}
	}
	return true
}

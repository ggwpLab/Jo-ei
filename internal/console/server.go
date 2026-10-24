// Package console serves the admin console HTTP API over live proxy state:
// telemetry from internal/telemetry, the runtime policy, registry config and
// cache stats. Authentication is enforced by auth.Middleware in cmd/jo-ei,
// which mounts this handler behind HTTP Basic auth at /api/.
package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/logx"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
	"github.com/ggwpLab/Jo-ei/internal/users"
)

// CacheStatsProvider exposes cache statistics; cache.Cache satisfies it.
type CacheStatsProvider interface {
	Stats() (cache.CacheStats, error)
}

// CachePurger deletes stale cache entries on demand; *cache.LocalCache
// satisfies it.
type CachePurger interface {
	PurgeStale() (removed int64, freedBytes int64, err error)
}

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

// ScannerHealthProvider supplies live scan-engine health for the overview.
// *health.Monitor satisfies it.
type ScannerHealthProvider interface {
	Snapshot() []health.ScannerHealth
}

// Config wires the API to runtime state.
type Config struct {
	Store         *telemetry.Store
	Broadcaster   *telemetry.Broadcaster
	Policy        *policy.Runtime
	Cache         CacheStatsProvider // optional; nil reports zero stats
	CacheMaxBytes int64
	// Purger enables POST /api/cache/cleanup; nil returns 404 there.
	Purger CachePurger
	// CacheStaleAfterDays is the effective idle threshold, echoed to the UI
	// for the "unused Nd+" legend.
	CacheStaleAfterDays int
	Registries          []RegistryInfo
	// RegistryStore persists registry edits (PUT /api/registries). Nil keeps the
	// screen read-only using the static Registries field.
	RegistryStore RegistryStore
	// RunningRegistries is the registry set the live proxy mux actually serves
	// (captured at boot). GET/PUT report pending_restart when the stored set
	// differs from this.
	RunningRegistries []RegistryInfo
	// ImageScanEnabled reports whether Trivy image-scanning is configured; when
	// false, enabling the docker registry produces a warning (the docker handler
	// is gated on image-scan at boot).
	ImageScanEnabled bool
	Health           ScannerHealthProvider // optional; nil reports no scanners
	// Users backs the /api/users routes; nil answers 503 users_unavailable.
	Users  UserAdmin
	Logger zerolog.Logger
	// SSEHeartbeat is the idle keep-alive interval for /api/events. With no
	// traffic the stream is otherwise silent for hours and intermediaries
	// (Docker port-forwards, AV web filters) drop the idle connection.
	// Zero means the 25s default.
	SSEHeartbeat time.Duration
}

type server struct {
	cfg    Config
	logger zerolog.Logger // cfg.Logger tagged component=console
}

// log returns the console logger carrying r's request ID.
func (s *server) log(r *http.Request) *zerolog.Logger {
	l := logx.Logger(r.Context(), s.logger)
	return &l
}

// NewHandler returns the console API handler; mount it at "/api/".
func NewHandler(cfg Config) http.Handler {
	if cfg.Registries == nil {
		cfg.Registries = []RegistryInfo{}
	}
	for i := range cfg.Registries {
		// Disabled registries carry no upstreams; keep the wire shape an
		// array — null crashes the SPA's Registries screen.
		if cfg.Registries[i].Upstreams == nil {
			cfg.Registries[i].Upstreams = []string{}
		}
	}
	s := &server{cfg: cfg, logger: cfg.Logger.With().Str("component", "console").Logger()}
	mux := http.NewServeMux()
	// Every route is registered through admin or operator; there is no
	// unguarded helper, so an undeclared route cannot exist. New routes use
	// admin unless operators need them.
	admin := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, s.requireRole(h, users.RoleAdmin))
	}
	operator := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, s.requireRole(h, users.RoleAdmin, users.RoleOperator))
	}
	operator("GET /api/overview", s.overview)
	operator("GET /api/requests", s.requests)
	operator("GET /api/events", s.events)
	operator("GET /api/quarantine", s.quarantine)
	operator("GET /api/policy", s.getPolicy)
	admin("PUT /api/policy", s.putPolicy)
	operator("POST /api/policy/lists/{list}", s.editList(true))
	operator("DELETE /api/policy/lists/{list}", s.editList(false))
	operator("GET /api/registries", s.registries)
	admin("PUT /api/registries", s.putRegistries)
	admin("POST /api/cache/cleanup", s.cacheCleanup)
	operator("GET /api/metrics/daily", s.dailyMetrics)
	admin("GET /api/users", s.listUsers)
	admin("POST /api/users", s.createUser)
	admin("PATCH /api/users/{name}", s.patchUser)
	admin("POST /api/users/{name}/password", s.resetUserPassword)
	admin("DELETE /api/users/{name}", s.deleteUser)
	return mux
}

// requireRole runs h only when the request carries an identity whose role is
// one of allowed; otherwise (including no identity) it answers 403.
func (s *server) requireRole(h http.HandlerFunc, allowed ...users.Role) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.IdentityFromContext(r.Context())
		if !ok || !slices.Contains(allowed, id.Role) {
			s.writeJSON(w, r, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		h(w, r)
	}
}

func (s *server) writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		s.log(r).Error().Err(err).Msg("encoding JSON response")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := buf.WriteTo(w); err != nil {
		s.log(r).Error().Err(err).Msg("writing JSON response")
	}
}

func (s *server) overview(w http.ResponseWriter, r *http.Request) {
	snap := s.cfg.Store.Snapshot()

	var cs cache.CacheStats
	if s.cfg.Cache != nil {
		got, err := s.cfg.Cache.Stats()
		if err != nil {
			s.log(r).Error().Err(err).Msg("reading cache stats")
		} else {
			cs = got
		}
	}

	hitRate := 0.0
	if snap.Requests > 0 {
		hitRate = float64(snap.CacheHits) / float64(snap.Requests)
	}

	scanners := []health.ScannerHealth{}
	if s.cfg.Health != nil {
		scanners = s.cfg.Health.Snapshot()
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"started_at":     snap.StartedAt,
		"uptime_seconds": int64(time.Since(snap.StartedAt).Seconds()),
		"kpis": map[string]any{
			"requests_total":  snap.Requests,
			"cache_hits":      snap.CacheHits,
			"hit_rate":        hitRate,
			"blocked_total":   snap.Blocked,
			"errors":          snap.Errors,
			"supply_blocked":  snap.SupplyBlocked,
			"cve_blocked":     snap.CVEBlocked,
			"malware_blocked": snap.MalwareBlocked,
			"denylisted":      snap.Denylisted,
		},
		"gates": snap.Gates,
		// LocalCache.Stats does not track per-object hits; the request-level
		// rate (cache_hits/requests) is the meaningful cache hit rate here.
		"cache": map[string]any{
			"objects":          cs.Entries,
			"size_bytes":       cs.SizeBytes,
			"max_bytes":        s.cfg.CacheMaxBytes,
			"hit_rate":         hitRate,
			"evictions":        cs.Evictions,
			"stale_bytes":      cs.StaleBytes,
			"stale_after_days": s.cfg.CacheStaleAfterDays,
		},
		"scanners": scanners,
	})
}

// cacheCleanup deletes stale cache entries (idle longer than the configured
// threshold) and reports what was freed.
func (s *server) cacheCleanup(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Purger == nil {
		s.writeJSON(w, r, http.StatusNotFound, map[string]any{"error": "no_cache"})
		return
	}
	removed, freed, err := s.cfg.Purger.PurgeStale()
	if err != nil {
		s.log(r).Error().Err(err).Msg("cache cleanup failed")
		s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "purge_failed"})
		return
	}
	s.log(r).Info().Int64("removed", removed).Int64("freed_bytes", freed).Msg("cache cleanup")
	s.writeJSON(w, r, http.StatusOK, map[string]any{"removed": removed, "freed_bytes": freed})
}

// dailyMetrics serves per-UTC-day telemetry tallies. ?days=N (default 30) limits
// the window; the store reads from persistent storage when configured.
func (s *server) dailyMetrics(w http.ResponseWriter, r *http.Request) {
	days := 30
	if q := r.URL.Query().Get("days"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": "invalid_days"})
			return
		}
		if n > 365 {
			n = 365
		}
		days = n
	}
	daily, err := s.cfg.Store.DailyMetrics(days)
	if err != nil {
		s.log(r).Error().Err(err).Msg("reading daily metrics")
		s.writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "metrics_unavailable"})
		return
	}
	if daily == nil {
		daily = []telemetry.DailyMetric{}
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"daily": daily})
}

func (s *server) requests(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": "invalid_limit"})
			return
		}
		limit = min(n, maxRequestsLimit)
	}

	verdict := r.URL.Query().Get("verdict")
	if verdict != "" && !validVerdict(verdict) {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": "invalid_verdict"})
		return
	}

	text := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(text) > maxRequestQuery {
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": "invalid_query"})
		return
	}

	var cursor telemetry.Cursor
	if q := r.URL.Query().Get("cursor"); q != "" {
		c, ok := parseCursor(q)
		if !ok {
			s.writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": "invalid_cursor"})
			return
		}
		cursor = c
	}

	events, next := s.cfg.Store.Page(verdict, text, cursor, limit)
	out := make([]eventJSON, 0, len(events))
	for _, ev := range events {
		out = append(out, toEventJSON(ev))
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"requests":    out,
		"next_cursor": encodeCursor(next),
	})
}

func (s *server) quarantine(w http.ResponseWriter, r *http.Request) {
	type qJSON struct {
		Eco         string    `json:"eco"`
		Pkg         string    `json:"pkg"`
		Ver         string    `json:"ver"`
		PublishedAt time.Time `json:"published_at"`
		BlockUntil  time.Time `json:"block_until"`
		RequestID   string    `json:"request_id"`
	}
	events := s.cfg.Store.Quarantine(time.Now())
	out := make([]qJSON, 0, len(events))
	for _, ev := range events {
		out = append(out, qJSON{
			Eco: ev.Ecosystem, Pkg: ev.Package, Ver: ev.Version,
			PublishedAt: ev.PublishedAt, BlockUntil: ev.BlockUntil, RequestID: ev.RequestID,
		})
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"quarantine": out})
}

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
	// List fields are pointers: absent keeps the current list (so settings-only
	// saves cannot clobber concurrent list edits), present replaces it.
	var in struct {
		Mode            string    `json:"mode"`
		MinAgeHours     int       `json:"min_age_hours"`
		CVEBlockOn      string    `json:"cve_block_on"`
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
		cur.Mode, cur.MinAgeHours, cur.CVEBlockOn = in.Mode, in.MinAgeHours, in.CVEBlockOn
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
		s.writeJSON(w, r, http.StatusBadRequest, map[string]any{
			"error": "invalid_registries", "field": "body", "message": err.Error(),
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
	s.writeJSON(w, r, status, map[string]any{
		"registries":      out,
		"pending_restart": s.cfg.RegistryStore != nil && s.cfg.RunningRegistries != nil && !registriesEqual(out, s.cfg.RunningRegistries),
		"warnings":        warnings,
	})
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

// events streams new telemetry over SSE. The browser EventSource reconnects
// automatically if the connection drops.
func (s *server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch, cancel := s.cfg.Broadcaster.Subscribe()
	defer cancel()

	// The server-wide Read/WriteTimeouts (cmd/jo-ei sets 120s) are armed once
	// at request start, which poisons a long-lived stream: the first event
	// written after the deadline kills the connection and is silently lost.
	// Drop the read deadline and bound each write individually instead, so a
	// stalled client still cannot pin this goroutine forever.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	armWrite := func() { _ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second)) }
	armWrite()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// Initial comment line: tells clients (and tests) the subscription is
	// live, and defeats reverse-proxy response buffering.
	if _, err := fmt.Fprint(w, ": connected\n\n"); err != nil {
		return
	}
	fl.Flush()

	heartbeat := s.cfg.SSEHeartbeat
	if heartbeat <= 0 {
		heartbeat = 25 * time.Second
	}
	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			// A deleted, disabled or demoted user (any change that revokes
			// sessions) must not keep receiving the feed: end the stream;
			// the browser's reconnect then meets the auth middleware.
			if !auth.Recheck(r.Context()) {
				return
			}
			armWrite()
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		case ev, open := <-ch:
			if !open {
				return
			}
			data, err := json.Marshal(toEventJSON(ev))
			if err != nil {
				continue
			}
			armWrite()
			if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

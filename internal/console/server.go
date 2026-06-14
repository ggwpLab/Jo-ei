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
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

// CacheStatsProvider exposes cache statistics; cache.Cache satisfies it.
type CacheStatsProvider interface {
	Stats() (cache.CacheStats, error)
}

// RegistryInfo describes one configured registry for GET /api/registries.
type RegistryInfo struct {
	Ecosystem string   `json:"eco"`
	Enabled   bool     `json:"enabled"`
	Upstreams []string `json:"upstreams"`
}

// ScannerInfo describes one configured scan engine. Static configuration
// only — no live health probes this phase.
type ScannerInfo struct {
	Name    string `json:"name"`
	Detail  string `json:"detail"`
	Enabled bool   `json:"enabled"`
}

// Config wires the API to runtime state.
type Config struct {
	Store         *telemetry.Store
	Broadcaster   *telemetry.Broadcaster
	Policy        *policy.Runtime
	Cache         CacheStatsProvider // optional; nil reports zero stats
	CacheMaxBytes int64
	Registries    []RegistryInfo
	Scanners      []ScannerInfo
	Logger        zerolog.Logger
	// SSEHeartbeat is the idle keep-alive interval for /api/events. With no
	// traffic the stream is otherwise silent for hours and intermediaries
	// (Docker port-forwards, AV web filters) drop the idle connection.
	// Zero means the 25s default.
	SSEHeartbeat time.Duration
}

type server struct {
	cfg Config
}

// NewHandler returns the console API handler; mount it at "/api/".
func NewHandler(cfg Config) http.Handler {
	if cfg.Scanners == nil {
		cfg.Scanners = []ScannerInfo{}
	}
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
	s := &server{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/overview", s.overview)
	mux.HandleFunc("GET /api/requests", s.requests)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/quarantine", s.quarantine)
	mux.HandleFunc("GET /api/policy", s.getPolicy)
	mux.HandleFunc("PUT /api/policy", s.putPolicy)
	mux.HandleFunc("GET /api/registries", s.registries)
	return mux
}

func (s *server) writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		s.cfg.Logger.Error().Err(err).Msg("console: encoding JSON response")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := buf.WriteTo(w); err != nil {
		s.cfg.Logger.Error().Err(err).Msg("console: writing JSON response")
	}
}

func (s *server) overview(w http.ResponseWriter, _ *http.Request) {
	snap := s.cfg.Store.Snapshot()

	var cs cache.CacheStats
	if s.cfg.Cache != nil {
		got, err := s.cfg.Cache.Stats()
		if err != nil {
			s.cfg.Logger.Error().Err(err).Msg("console: cache stats")
		} else {
			cs = got
		}
	}

	hitRate := 0.0
	if snap.Requests > 0 {
		hitRate = float64(snap.CacheHits) / float64(snap.Requests)
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
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
			"objects":    cs.Entries,
			"size_bytes": cs.SizeBytes,
			"max_bytes":  s.cfg.CacheMaxBytes,
			"hit_rate":   hitRate,
			"evictions":  cs.Evictions,
		},
		"scanners": s.cfg.Scanners,
	})
}

func (s *server) requests(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 {
			s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_limit"})
			return
		}
		limit = n
	}
	events := s.cfg.Store.Recent(limit)
	out := make([]eventJSON, 0, len(events))
	for _, ev := range events {
		out = append(out, toEventJSON(ev))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

func (s *server) quarantine(w http.ResponseWriter, _ *http.Request) {
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
	s.writeJSON(w, http.StatusOK, map[string]any{"quarantine": out})
}

// writePolicy renders the current runtime policy. "persistence":"runtime"
// tells the UI that edits reset to the YAML config on restart.
func (s *server) writePolicy(w http.ResponseWriter, status int) {
	p := s.cfg.Policy.Current()
	s.writeJSON(w, status, map[string]any{
		"mode":          p.Mode,
		"min_age_hours": p.MinAgeHours,
		"cve_block_on":  p.CVEBlockOn,
		"allowlist":     p.Allowlist,
		"denylist":      p.Denylist,
		"persistence":   "runtime",
	})
}

func (s *server) getPolicy(w http.ResponseWriter, _ *http.Request) {
	s.writePolicy(w, http.StatusOK)
}

func (s *server) putPolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // policy JSON is tiny; reject abuse
	var in struct {
		policy.RuntimeParams
		Persistence string `json:"persistence"` // read-only field from GET; accepted and ignored so GET→PUT round-trips
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
				"error": "invalid_policy", "field": "body", "message": "request body too large",
			})
			return
		}
		s.writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_policy", "field": "body", "message": err.Error(),
		})
		return
	}
	p := in.RuntimeParams
	if err := s.cfg.Policy.Apply(p); err != nil {
		var verr *policy.ValidationError
		if errors.As(err, &verr) {
			s.writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "invalid_policy", "field": verr.Field, "message": verr.Message,
			})
			return
		}
		s.cfg.Logger.Error().Err(err).Msg("console: policy apply")
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "apply_failed"})
		return
	}
	logEvent := s.cfg.Logger.Info().Interface("policy", s.cfg.Policy.Current())
	if user, ok := auth.UserFromContext(r.Context()); ok && user != "" {
		logEvent = logEvent.Str("user", user)
	}
	logEvent.Msg("runtime policy updated via console")
	s.writePolicy(w, http.StatusOK)
}

func (s *server) registries(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{"registries": s.cfg.Registries})
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

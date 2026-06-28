package dockerproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// Config groups the Docker proxy handler dependencies.
type Config struct {
	Adapter  *Adapter
	Gate     *manifestGate
	Store    *verdictStore
	Tags     *tagIndex
	Recorder proxy.Recorder
	Logger   zerolog.Logger
}

// Handler implements the Docker Registry V2 pull-through flow.
type Handler struct {
	cfg Config
}

// NewHandler creates a Docker proxy handler.
func NewHandler(cfg Config) *Handler { return &Handler{cfg: cfg} }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pp := ParsePath(r.URL.Path)
	switch pp.Kind {
	case KindPing:
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
	case KindManifest:
		h.serveManifest(w, r, pp)
	case KindBlob:
		h.serveBlob(w, r, pp)
	default:
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "unsupported registry path")
	}
}

func (h *Handler) serveManifest(w http.ResponseWriter, r *http.Request, pp ParsedPath) {
	requestID := uuid.New().String()
	start := time.Now()
	log := h.cfg.Logger.With().Str("request_id", requestID).Str("repo", pp.Repo).Str("ref", pp.Reference).Logger()

	digest, v, err := h.cfg.Gate.Evaluate(r.Context(), pp.Repo, pp.Reference)
	if err != nil {
		log.Error().Err(err).Msg("docker gate error")
		h.record(requestID, pp, proxy.VerdictError, proxy.GateImageScan, "gate_error", http.StatusBadGateway, start, nil)
		h.writeError(w, http.StatusBadGateway, "UNAVAILABLE", "upstream or scan failure")
		return
	}
	// Feed label: prefer the human tag over the resolved digest. A by-tag pull
	// already carries the tag in pp.Reference; a multi-arch platform child is
	// requested by digest, so recover its tag from the index seen earlier.
	displayVer := h.displayVersion(pp, digest)

	if !v.Allowed {
		log.Warn().Str("reason", v.Reason).Str("blocked_by", v.BlockedBy).Msg("docker image blocked")
		h.record(requestID, pp, proxy.VerdictBlock, gateForBlockedBy(v.BlockedBy), v.Reason, http.StatusForbidden, start, func(ev *proxy.Event) {
			ev.BlockedBy = []string{v.BlockedBy}
			ev.CVEs = v.Findings
			ev.Version = displayVer
			// Supply-chain holds carry these; other block reasons leave them zero
			// (correct — only supply-chain blocks are quarantined).
			ev.PublishedAt = v.PublishedAt
			ev.BlockUntil = v.BlockUntil
		})
		h.writeError(w, http.StatusForbidden, "DENIED", "image blocked by policy: "+v.Reason)
		return
	}

	w.Header().Set("Docker-Content-Digest", digest)
	if v.ContentType != "" {
		w.Header().Set("Content-Type", v.ContentType)
	}
	// An index or attestation manifest is a transit response, not a gate
	// decision: the real PASS/BLOCK event comes from the concrete platform image
	// manifest the client requests by digest. Serve it but keep it out of the
	// request feed so a pull shows a single, meaningful entry.
	recordPass := !v.Passthrough
	if v.Passthrough {
		log.Debug().Str("digest", digest).Str("reason", v.Reason).Msg("serving manifest passthrough (not gated)")
	}
	// A repeat pull served from the cached gate decision is a CACHE event, not a
	// fresh PASS, so the feed distinguishes re-pulls from first-time evaluations.
	passVerdict, passGate, passReason := proxy.VerdictPass, proxy.GateImageScan, v.Reason
	if v.FromCache {
		passVerdict, passGate, passReason = proxy.VerdictCache, proxy.GateCache, "cache_hit"
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		if recordPass {
			h.record(requestID, pp, passVerdict, passGate, passReason, http.StatusOK, start, func(ev *proxy.Event) { ev.Version = displayVer })
		}
		return
	}
	// Open the cached manifest before writing any header so a cache-read
	// failure can still emit the Docker error envelope (and a telemetry event).
	f, err := os.Open(v.ManifestPath)
	if err != nil {
		log.Error().Err(err).Msg("opening cached manifest")
		h.record(requestID, pp, proxy.VerdictError, proxy.GateImageScan, "cache_read_error", http.StatusInternalServerError, start, func(ev *proxy.Event) { ev.Version = displayVer })
		h.writeError(w, http.StatusInternalServerError, "UNAVAILABLE", "cache read error")
		return
	}
	defer f.Close()
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		// Headers are already sent; can only log.
		log.Error().Err(err).Msg("serving cached manifest")
		return
	}
	if recordPass {
		h.record(requestID, pp, passVerdict, passGate, passReason, http.StatusOK, start, func(ev *proxy.Event) { ev.Version = displayVer })
	}
}

// displayVersion picks the feed label for a gated manifest: the human tag when
// known (a by-tag pull, or a multi-arch platform child whose tag was recorded
// from the index), otherwise the resolved digest.
func (h *Handler) displayVersion(pp ParsedPath, digest string) string {
	if !isDigestRef(pp.Reference) {
		return pp.Reference
	}
	if h.cfg.Tags != nil {
		if tag, ok := h.cfg.Tags.tag(pp.Repo, digest); ok {
			return tag
		}
	}
	return digest
}

func (h *Handler) serveBlob(w http.ResponseWriter, _ *http.Request, pp ParsedPath) {
	path, clean, found := h.cfg.Store.GetBlob(pp.Reference)
	if !found || !clean {
		h.writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not available")
		return
	}
	// Open before writing any header so a cache-read failure yields the Docker
	// error envelope rather than a half-written 200.
	f, err := os.Open(path)
	if err != nil {
		h.cfg.Logger.Error().Err(err).Str("digest", pp.Reference).Msg("opening cached blob")
		h.writeError(w, http.StatusInternalServerError, "UNAVAILABLE", "cache read error")
		return
	}
	defer f.Close()
	w.Header().Set("Docker-Content-Digest", pp.Reference)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	// Blob serves are deliberately not recorded as telemetry events: a single
	// pull fetches many blobs, and one event per blob would inflate the console
	// request metrics. The manifest gate already records the per-image outcome.
	if _, err := io.Copy(w, f); err != nil {
		h.cfg.Logger.Error().Err(err).Str("digest", pp.Reference).Msg("serving cached blob")
	}
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{{"code": code, "message": msg}},
	})
}

func (h *Handler) record(requestID string, pp ParsedPath, verdict, gate, reason string, status int, start time.Time, mod func(*proxy.Event)) {
	if h.cfg.Recorder == nil {
		return
	}
	ev := proxy.Event{
		RequestID: requestID, Time: time.Now(),
		Ecosystem: "docker", Package: pp.Repo, Version: pp.Reference,
		Verdict: verdict, Gate: gate, Reason: reason,
		HTTPStatus: status, LatencyMS: time.Since(start).Milliseconds(),
	}
	if mod != nil {
		mod(&ev)
	}
	h.cfg.Recorder.Record(ev)
}

func gateForBlockedBy(by string) string {
	switch by {
	case "malware":
		return proxy.GateMalware
	case "supply_chain":
		return proxy.GateSupply
	default:
		return proxy.GateImageScan
	}
}

// HandlerDeps is the public assembly input for the Docker proxy handler.
type HandlerDeps struct {
	Upstreams     []string
	Scanner       ImageScanner
	AV            proxy.AVScanner
	Filter        proxy.SCFilter
	Policy        proxy.PolicyDecider
	Cache         cache.Cache
	MaxLayerBytes int64
	Recorder      proxy.Recorder
	Logger        zerolog.Logger
	// HTTPClient talks to the upstream registry. Optional; nil uses a private
	// client with a 120s timeout. Pass a client whose transport caps per-host
	// concurrency (shared with the other registries) to avoid 429 throttling.
	HTTPClient *http.Client
}

// New assembles a ready-to-serve Docker Registry V2 proxy handler.
func New(d HandlerDeps) http.Handler {
	adapter := NewAdapter(d.Upstreams, d.HTTPClient)
	store := newVerdictStore(d.Cache)
	tags := newTagIndex(0)
	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: d.Scanner, av: d.AV,
		filter: d.Filter, policy: d.Policy, store: store, tags: tags,
		maxLayerBytes: d.MaxLayerBytes, logger: d.Logger,
	})
	return NewHandler(Config{Adapter: adapter, Gate: gate, Store: store, Tags: tags, Recorder: d.Recorder, Logger: d.Logger})
}

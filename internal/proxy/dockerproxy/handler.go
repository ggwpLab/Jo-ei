package dockerproxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/logx"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
)

// Config groups the Docker proxy handler dependencies.
type Config struct {
	Adapter  *Adapter
	Gate     *manifestGate
	Store    *verdictStore
	Tags     *tagIndex
	Recorder gate.Recorder
	Logger   zerolog.Logger
	// Throttles reports upstream hosts in a post-throttle cooldown; optional
	// (see proxy.HandlerConfig.Throttles).
	Throttles upstream.ThrottleLookup
}

// Handler implements the Docker Registry V2 pull-through flow.
type Handler struct {
	cfg Config
	log zerolog.Logger // cfg.Logger tagged component=docker, ecosystem=docker
}

// NewHandler creates a Docker proxy handler.
func NewHandler(cfg Config) *Handler {
	return &Handler{
		cfg: cfg,
		log: cfg.Logger.With().Str("component", "docker").Str("ecosystem", "docker").Logger(),
	}
}

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
	r, requestID := logx.Ensure(r)
	start := time.Now()
	log := logx.Logger(r.Context(), h.log).With().Str("package", pp.Repo).Str("version", pp.Reference).Logger()

	digest, v, err := h.cfg.Gate.Evaluate(r.Context(), pp.Repo, pp.Reference)
	if err != nil {
		atts, hasAtts := upstream.AttemptsFrom(err)
		// Every mirror answered 404/410 for the manifest: it does not exist (a
		// typo'd tag, or a client's OCI referrers tag-schema fallback probe).
		// Answer with the registry's own MANIFEST_UNKNOWN, not a 502 gate failure.
		if errors.Is(err, errManifestNotFound) {
			log.Warn().Array("upstream_attempts", atts).Msg("manifest not found on any upstream")
			h.record(log, requestID, pp, gate.VerdictError, gate.GateImageScan, "manifest_not_found", http.StatusNotFound, start, nil)
			h.writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown")
			return
		}
		// The rest were throttled: neither proof of absence nor an outage.
		if status, retry, ok := atts.Throttled(h.cfg.Throttles); hasAtts && ok {
			log.Warn().Err(err).Array("upstream_attempts", atts).Msg("upstream throttled")
			h.record(log, requestID, pp, gate.VerdictError, gate.GateImageScan, "upstream_throttled", status, start, nil)
			httpx.SetRetryAfter(w.Header(), retry)
			code := "UNAVAILABLE"
			if status == http.StatusTooManyRequests {
				code = "TOOMANYREQUESTS"
			}
			h.writeError(w, status, code, "upstream registry throttled")
			return
		}
		ev := log.Error().Err(err)
		if hasAtts {
			ev = ev.Array("upstream_attempts", atts)
		}
		ev.Msg("gate error")
		h.record(log, requestID, pp, gate.VerdictError, gate.GateImageScan, "gate_error", http.StatusBadGateway, start, nil)
		h.writeError(w, http.StatusBadGateway, "UNAVAILABLE", "upstream or scan failure")
		return
	}
	// Feed label: prefer the human tag over the resolved digest. A by-tag pull
	// already carries the tag in pp.Reference; a multi-arch platform child is
	// requested by digest, so recover its tag from the index seen earlier.
	displayVer := h.displayVersion(pp, digest)
	log = log.With().Str("digest", digest).Logger()

	if !v.Allowed {
		h.record(log, requestID, pp, gate.VerdictBlock, gateForBlockedBy(v.BlockedBy), v.Reason, http.StatusForbidden, start, func(ev *gate.Event) {
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
		log.Debug().Str("reason", v.Reason).Msg("serving manifest passthrough (not gated)")
	}
	// A repeat pull served from the cached gate decision is a CACHE event, not a
	// fresh PASS, so the feed distinguishes re-pulls from first-time evaluations.
	passVerdict, passGate, passReason := gate.VerdictPass, gate.GateImageScan, v.Reason
	if v.FromCache {
		passVerdict, passGate, passReason = gate.VerdictCache, gate.GateCache, "cache_hit"
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		if recordPass {
			h.record(log, requestID, pp, passVerdict, passGate, passReason, http.StatusOK, start, func(ev *gate.Event) { ev.Version = displayVer })
		}
		return
	}
	// Open the cached manifest before writing any header so a cache-read
	// failure can still emit the Docker error envelope (and a telemetry event).
	f, err := os.Open(v.ManifestPath)
	if err != nil {
		log.Error().Err(err).Msg("opening cached manifest")
		h.record(log, requestID, pp, gate.VerdictError, gate.GateImageScan, "cache_read_error", http.StatusInternalServerError, start, func(ev *gate.Event) { ev.Version = displayVer })
		h.writeError(w, http.StatusInternalServerError, "UNAVAILABLE", "cache read error")
		return
	}
	defer f.Close()
	w.WriteHeader(http.StatusOK)
	if _, err := httpx.CopyWithWriteDeadline(w, f, httpx.DefaultWriteIdleTimeout); err != nil {
		// Headers are already sent; can only log.
		log.Error().Err(err).Msg("serving cached manifest")
		return
	}
	if recordPass {
		h.record(log, requestID, pp, passVerdict, passGate, passReason, http.StatusOK, start, func(ev *gate.Event) { ev.Version = displayVer })
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

func (h *Handler) serveBlob(w http.ResponseWriter, r *http.Request, pp ParsedPath) {
	log := logx.Logger(r.Context(), h.log).With().Str("package", pp.Repo).Str("digest", pp.Reference).Logger()
	path, clean, found := h.cfg.Store.GetBlob(pp.Reference)
	if !found || !clean {
		h.writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not available")
		return
	}
	// Open before writing any header so a cache-read failure yields the Docker
	// error envelope rather than a half-written 200.
	f, err := os.Open(path) // #nosec G304 -- path comes from the verdict store, always inside the cache root
	if err != nil {
		log.Error().Err(err).Msg("opening cached blob")
		h.writeError(w, http.StatusInternalServerError, "UNAVAILABLE", "cache read error")
		return
	}
	defer f.Close()
	w.Header().Set("Docker-Content-Digest", pp.Reference)
	w.Header().Set("Content-Type", "application/octet-stream")
	// An explicit length lets the client detect a truncated transfer.
	if fi, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}
	w.WriteHeader(http.StatusOK)
	// Blob serves are deliberately not recorded as telemetry events: a single
	// pull fetches many blobs, and one event per blob would inflate the console
	// request metrics. The manifest gate already records the per-image outcome.
	if _, err := httpx.CopyWithWriteDeadline(w, f, httpx.DefaultWriteIdleTimeout); err != nil {
		log.Error().Err(err).Msg("serving cached blob")
	}
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{{"code": code, "message": msg}},
	})
}

// record ends a manifest request: one telemetry event and the matching
// outcome log line. A nil Recorder disables only the event.
func (h *Handler) record(log zerolog.Logger, requestID string, pp ParsedPath, verdict, gateName, reason string, status int, start time.Time, mod func(*gate.Event)) {
	ev := gate.Event{
		RequestID: requestID, Time: time.Now(),
		Ecosystem: "docker", Package: pp.Repo, Version: pp.Reference,
		Verdict: verdict, Gate: gateName, Reason: reason,
		HTTPStatus: status, LatencyMS: time.Since(start).Milliseconds(),
	}
	if mod != nil {
		mod(&ev)
	}
	logx.Outcome(log, ev)
	if h.cfg.Recorder != nil {
		h.cfg.Recorder.Record(ev)
	}
}

func gateForBlockedBy(by string) string {
	switch by {
	case "malware":
		return gate.GateMalware
	case "supply_chain":
		return gate.GateSupply
	default:
		return gate.GateImageScan
	}
}

// HandlerDeps is the public assembly input for the Docker proxy handler.
type HandlerDeps struct {
	Upstreams     []string
	Scanner       ImageScanner
	AV            gate.AVScanner
	Filter        gate.SCFilter
	Policy        gate.PolicyDecider
	Cache         cache.Cache
	MaxLayerBytes int64
	Recorder      gate.Recorder
	Logger        zerolog.Logger
	// RecheckTTL: cached image verdicts older than this are re-evaluated by the
	// full gate on the next pull (0 = never expire). Wire min of the enabled
	// per-gate TTLs.
	RecheckTTL time.Duration
	// HTTPClient talks to the upstream registry. Optional; nil uses a private
	// client with a 120s timeout. Pass a client whose transport caps per-host
	// concurrency (shared with the other registries) to avoid 429 throttling.
	HTTPClient *http.Client
	// Throttles reports upstream hosts in a post-throttle cooldown; optional.
	Throttles upstream.ThrottleLookup
}

// New assembles a ready-to-serve Docker Registry V2 proxy handler.
func New(d HandlerDeps) http.Handler {
	adapter := NewAdapter(d.Upstreams, d.HTTPClient)
	store := newVerdictStore(d.Cache)
	tags := newTagIndex(0)
	mgate := newManifestGate(gateDeps{
		adapter: adapter, scanner: d.Scanner, av: d.AV,
		filter: d.Filter, policy: d.Policy, store: store, tags: tags,
		maxLayerBytes: d.MaxLayerBytes, recheckTTL: d.RecheckTTL, logger: d.Logger,
	})
	return NewHandler(Config{Adapter: adapter, Gate: mgate, Store: store, Tags: tags, Recorder: d.Recorder, Logger: d.Logger, Throttles: d.Throttles})
}

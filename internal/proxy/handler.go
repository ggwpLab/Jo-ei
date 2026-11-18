package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/singleflight"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/logx"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
)

// HandlerConfig groups dependencies for the ProxyHandler.
type HandlerConfig struct {
	Adapter    gate.RegistryAdapter
	Filter     gate.SCFilter
	Cache      gate.ArtifactCache
	Logger     zerolog.Logger
	CVEScanner gate.CVEScanner    // optional; nil disables CVE scanning
	Policy     gate.PolicyDecider // optional; nil allows all when CVEScanner is set
	AVScanner  gate.AVScanner     // optional; nil disables malware scanning
	Recorder   gate.Recorder      // optional; nil disables telemetry
	// CVERecheckTTL / MalwareRecheckTTL: a cache hit whose respective check is
	// older than this re-runs that gate before serving (0 disables). A scanner
	// failure serves the stale entry and leaves the timestamp untouched.
	CVERecheckTTL     time.Duration
	MalwareRecheckTTL time.Duration
	// MetadataFilterMaxMB caps the decompressed size of a metadata document the
	// handler buffers to hide versions policy would block at download time and
	// to point its download links at the proxy. A larger document fails the
	// request. Zero means no cap.
	MetadataFilterMaxMB int
	// PublicBase derives the client-facing base URL written into rewritten
	// metadata links. Optional: nil uses the request's own Host and TLS state
	// and trusts no forwarding header.
	PublicBase *httpx.PublicBaseResolver
	// HTTPClient downloads artifacts and serves transparent proxy requests.
	// Optional; nil uses a private client with a 60s timeout. Pass a client whose
	// transport caps per-host concurrency (shared with the adapters) so artifact
	// downloads count against the same upstream rate limit as metadata fetches.
	HTTPClient *http.Client
	// IndexMaxMB caps a decoded index document an IndexRewriter adapter's
	// requests may return (0 = 64). An index over the cap fails the request:
	// it cannot be served unrewritten.
	IndexMaxMB int
	// MaxArtifactBytes caps a downloaded artifact (0 = unlimited). A larger
	// one is refused before it can fill the cache volume.
	MaxArtifactBytes int64
	// TempDir holds artifact downloads while they are checked. Empty uses
	// os.TempDir(); point it at the cache volume so multi-GB downloads do not
	// land on the container's root filesystem.
	TempDir string
	// Throttles reports upstream hosts in a post-throttle cooldown (the shared
	// transport's circuit breaker). Optional: it only supplies Retry-After and
	// the 429-versus-503 choice for circuit-open mirrors on a throttled answer.
	Throttles upstream.ThrottleLookup
}

// hopByHopHeaders are connection-specific headers that must not be forwarded
// by a proxy per RFC 7230 §6.1.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

// Handler is the main HTTP handler: intercepts downloads, applies SC filter, caches, proxies.
type Handler struct {
	cfg        HandlerConfig
	httpClient *http.Client
	// log and metaLog are cfg.Logger tagged with this handler's components:
	// artifact and transparent traffic, and metadata filtering respectively.
	log     zerolog.Logger
	metaLog zerolog.Logger
	// recheckGroup coalesces concurrent lazy re-checks of the same cache
	// entry: one flight scans, every waiter shares the outcome.
	recheckGroup singleflight.Group
	// metadataGroup coalesces concurrent fetches of one metadata document, so a
	// CI fleet resolving the same dependency tree costs one upstream request
	// rather than one per worker.
	metadataGroup singleflight.Group
}

// NewHandler creates a new ProxyHandler.
func NewHandler(cfg HandlerConfig) *Handler {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	return &Handler{
		cfg:        cfg,
		httpClient: client,
		log:        cfg.Logger.With().Str("component", "proxy").Logger(),
		metaLog:    cfg.Logger.With().Str("component", "metadata_filter").Logger(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r, requestID := logx.Ensure(r)

	ref, isDownload := h.cfg.Adapter.NormalizeRequest(r)
	if !isDownload {
		if m, ok := h.cfg.Adapter.(gate.ArtifactPathMatcher); ok && m.IsArtifactPath(r) {
			// An artifact path NormalizeRequest could not name: no gate can
			// check it, so it must not be streamed through untouched.
			log := logx.Logger(r.Context(), h.log)
			log.Warn().Str("path", r.URL.Path).Msg("refusing unrecognized artifact path")
			h.writeJSON(w, requestID, http.StatusForbidden, map[string]any{"error": "unrecognized_artifact"})
			return
		}
		if rw, ok := h.cfg.Adapter.(gate.IndexRewriter); ok && rw.IsIndexRequest(r) {
			h.proxyIndex(w, r, rw)
			return
		}
		if mref, ok := h.metadataFilterRef(r); ok {
			h.proxyMetadata(w, r, mref)
			return
		}
		// Metadata / simple API — proxy transparently, no interception
		h.proxyTransparent(w, r)
		return
	}

	logCtx := logx.Logger(r.Context(), h.log).With().
		Str("ecosystem", ref.Ecosystem).
		Str("package", ref.Name).
		Str("version", ref.Version)
	if ref.Classifier != "" {
		logCtx = logCtx.Str("classifier", ref.Classifier)
	}
	log := logCtx.Logger()

	// Exactly one outcome per intercepted request: a telemetry event and the
	// matching log line. A nil Recorder disables only the event; telemetry can
	// never fail a request.
	start := time.Now()
	record := func(verdict, gateName, reason string, status int, mod func(*gate.Event)) {
		ev := gate.Event{
			RequestID: requestID, Time: time.Now(),
			Ecosystem: ref.Ecosystem, Package: ref.Name, Version: ref.Version,
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

	if entry, found := h.cfg.Cache.Get(ref); found {
		h.serveCached(r.Context(), w, requestID, ref, entry, record, log)
		return
	}
	h.serveDownload(w, r, requestID, ref, record, log)
}

type recordOutcome func(verdict, gateName, reason string, status int, modify func(*gate.Event))

// errNoUpstreams and errUnreadableRequestBody are local failures — nothing was
// attempted upstream — so callers answer them directly instead of reporting an
// upstream outage.
var (
	errNoUpstreams           = errors.New("no upstream configured")
	errUnreadableRequestBody = errors.New("unreadable request body")
)

// forwardUpstream replays r against each configured upstream in priority order
// and returns the first response with status < 400; the caller closes its body.
// A nil response with a nil error means every upstream failed and atts carries
// each mirror's own outcome.
func (h *Handler) forwardUpstream(r *http.Request) (*http.Response, upstream.Attempts, error) {
	urls := h.cfg.Adapter.UpstreamURLs(r)
	if len(urls) == 0 {
		return nil, nil, errNoUpstreams
	}

	// Buffer the request body once so it can be replayed across attempts.
	var body []byte
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, nil, errUnreadableRequestBody
		}
		body = b
	}

	var atts upstream.Attempts
	for _, url := range urls {
		start := time.Now()
		req, err := http.NewRequestWithContext(r.Context(), r.Method, url, bytes.NewReader(body))
		if err != nil {
			atts.Add(url, 0, fmt.Errorf("building request: %w", err), time.Since(start))
			continue
		}
		for key, vals := range r.Header {
			for _, v := range vals {
				req.Header.Add(key, v)
			}
		}
		for _, hop := range hopByHopHeaders {
			req.Header.Del(hop)
		}

		resp, err := h.httpClient.Do(req) // #nosec G704 -- fetching configured upstream registries is the proxy's purpose
		if err != nil {
			atts.Add(url, 0, err, time.Since(start))
			continue
		}
		if resp.StatusCode < 400 {
			return resp, atts, nil
		}
		atts.Add(url, resp.StatusCode, fmt.Errorf("upstream returned HTTP %d", resp.StatusCode), time.Since(start))
		resp.Body.Close()
	}
	return nil, atts, nil
}

// writeForwardError answers a request that never got a usable upstream
// response: 500 when no upstream is configured, 400 when the client's own
// request body could not be read, 404 when every mirror said not-found, 429 or
// 503 when the rest were throttled (see upstream.Attempts.Throttled), and 502
// for every other upstream failure.
func (h *Handler) writeForwardError(w http.ResponseWriter, atts upstream.Attempts, err error, log zerolog.Logger) {
	throttleStatus, retry, throttled := atts.Throttled(h.cfg.Throttles)
	switch {
	case errors.Is(err, errNoUpstreams):
		log.Error().Msg("adapter returned no upstream URLs")
		http.Error(w, "no upstream configured", http.StatusInternalServerError)
	case errors.Is(err, errUnreadableRequestBody):
		http.Error(w, "bad request", http.StatusBadRequest)
	case atts.AllNotFound():
		log.Warn().Array("upstream_attempts", atts).Msg("not found on any upstream")
		http.Error(w, "not found", http.StatusNotFound)
	case throttled:
		log.Warn().Array("upstream_attempts", atts).Msg("not found on reachable upstreams; others throttled")
		httpx.SetRetryAfter(w.Header(), retry)
		http.Error(w, "upstream throttled", throttleStatus)
	default:
		log.Error().Array("upstream_attempts", atts).Msg("no upstream available")
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
}

// copyProxyHeaders copies src onto dst minus the hop-by-hop headers, which are
// connection-specific and must not cross a proxy.
func copyProxyHeaders(dst http.Header, src http.Header) {
	for key, vals := range src {
		for _, v := range vals {
			dst.Add(key, v)
		}
	}
	for _, hop := range hopByHopHeaders {
		dst.Del(hop)
	}
}

// proxyTransparent forwards a non-intercepted request to each configured
// upstream in order, streaming back the first response with status < 400.
// If all fail, returns 404 (all were 404/410) or 502.
func (h *Handler) proxyTransparent(w http.ResponseWriter, r *http.Request) {
	log := logx.Logger(r.Context(), h.log).With().Str("path", r.URL.Path).Logger()
	resp, atts, err := h.forwardUpstream(r)
	if resp == nil {
		h.writeForwardError(w, atts, err, log)
		return
	}
	defer resp.Body.Close()

	copyProxyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := httpx.CopyWithWriteDeadline(w, resp.Body, httpx.DefaultWriteIdleTimeout); err != nil {
		log.Error().Err(err).Msg("streaming proxy response")
	}
}

// serveFromCache streams the cached artifact to the response writer. It
// returns an error only when the artifact cannot be opened (a 500 is written
// in that case); streaming errors after headers are sent are logged only.
func (h *Handler) serveFromCache(w http.ResponseWriter, entry *gate.ArtifactEntry, log zerolog.Logger) error {
	f, err := os.Open(entry.ArtifactPath)
	if err != nil {
		http.Error(w, "cache read error", http.StatusInternalServerError)
		return err
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Joei-Cache", "HIT")
	// An explicit length lets the client detect a truncated transfer.
	if fi, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}
	w.WriteHeader(http.StatusOK)
	if _, err := httpx.CopyWithWriteDeadline(w, f, httpx.DefaultWriteIdleTimeout); err != nil {
		log.Error().Err(err).Str("artifact_path", entry.ArtifactPath).Msg("streaming cached artifact")
	}
	return nil
}

// writeBlockedResponse sends a 423 Locked response with structured JSON.
func (h *Handler) writeBlockedResponse(w http.ResponseWriter, requestID string, ref *gate.PackageRef, scResult gate.FilterResult) {
	body := map[string]any{
		"error":      "package_blocked",
		"package":    ref.Name,
		"version":    ref.Version,
		"reason":     scResult.Reason,
		"blocked_by": []string{"supply_chain_filter"},
		"request_id": requestID,
	}
	if !scResult.PublishedAt.IsZero() {
		body["published_at"] = scResult.PublishedAt.Format(time.RFC3339)
	}
	if !scResult.BlockUntil.IsZero() {
		body["block_until"] = scResult.BlockUntil.Format(time.RFC3339)
	}
	h.writeJSON(w, requestID, http.StatusLocked, body)
}

// writeError sends a structured JSON error response.
func (h *Handler) writeError(w http.ResponseWriter, requestID string, ref *gate.PackageRef, status int, reason string) {
	body := map[string]any{
		"error":      "proxy_error",
		"reason":     reason,
		"request_id": requestID,
	}
	if ref != nil {
		body["package"] = ref.Name
		body["version"] = ref.Version
	}
	h.writeJSON(w, requestID, status, body)
}

// blockMalware records the finding and sends a 403 Forbidden response.
func (h *Handler) blockMalware(w http.ResponseWriter, requestID string, ref *gate.PackageRef, result *gate.AVResult, record recordOutcome) {
	record(gate.VerdictBlock, gate.GateMalware, "malware_found", http.StatusForbidden, func(ev *gate.Event) {
		ev.BlockedBy = []string{"malware"}
		ev.MalwareEngine = result.Engine
		ev.MalwareSignature = result.Signature
	})
	body := map[string]any{
		"error":      "package_blocked",
		"package":    ref.Name,
		"version":    ref.Version,
		"reason":     "malware_found",
		"engine":     result.Engine,
		"signature":  result.Signature,
		"blocked_by": []string{"malware_scanner"},
		"request_id": requestID,
	}
	h.writeJSON(w, requestID, http.StatusForbidden, body)
}

// blockCVE records the policy decision and sends a 403 Forbidden response.
func (h *Handler) blockCVE(w http.ResponseWriter, requestID string, ref *gate.PackageRef, d gate.PolicyDecision, record recordOutcome) {
	blockedBy := "cve"
	if d.Reason == gate.ReasonDenylisted {
		blockedBy = "denylist"
	}
	record(gate.VerdictBlock, gate.GateCVE, d.Reason, http.StatusForbidden, func(ev *gate.Event) {
		ev.BlockedBy = []string{blockedBy}
		ev.CVEs = d.Findings
	})
	type findingJSON struct {
		ID       string  `json:"id"`
		Severity string  `json:"severity"`
		Summary  string  `json:"summary"`
		Score    float64 `json:"cvss_score,omitempty"`
	}
	var cves []findingJSON
	for _, f := range d.Findings {
		cves = append(cves, findingJSON{
			ID:       f.ID,
			Severity: f.Severity.String(),
			Summary:  f.Summary,
			Score:    f.Score,
		})
	}
	body := map[string]any{
		"error":      "package_blocked",
		"package":    ref.Name,
		"version":    ref.Version,
		"reason":     d.Reason,
		"cves":       cves,
		"blocked_by": []string{"cve_scanner"},
		"request_id": requestID,
	}
	h.writeJSON(w, requestID, http.StatusForbidden, body)
}

// writeJSON sends body as a JSON response with the given status.
func (h *Handler) writeJSON(w http.ResponseWriter, requestID string, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.log.Error().Err(err).Str("request_id", requestID).Msg("writing JSON response")
	}
}

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/gate"
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
	// HTTPClient downloads artifacts and serves transparent proxy requests.
	// Optional; nil uses a private client with a 60s timeout. Pass a client whose
	// transport caps per-host concurrency (shared with the adapters) so artifact
	// downloads count against the same upstream rate limit as metadata fetches.
	HTTPClient *http.Client
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
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()

	ref, isDownload := h.cfg.Adapter.NormalizeRequest(r)
	if !isDownload {
		// Metadata / simple API — proxy transparently, no interception
		h.proxyTransparent(w, r)
		return
	}

	// Telemetry: exactly one event per intercepted request at its outcome.
	// A nil Recorder makes record a no-op; telemetry can never fail a request.
	start := time.Now()
	record := func(verdict, gateName, reason string, status int, mod func(*gate.Event)) {
		if h.cfg.Recorder == nil {
			return
		}
		ev := gate.Event{
			RequestID: requestID, Time: time.Now(),
			Ecosystem: ref.Ecosystem, Package: ref.Name, Version: ref.Version,
			Verdict: verdict, Gate: gateName, Reason: reason,
			HTTPStatus: status, LatencyMS: time.Since(start).Milliseconds(),
		}
		if mod != nil {
			mod(&ev)
		}
		h.cfg.Recorder.Record(ev)
	}

	log := h.cfg.Logger.With().
		Str("request_id", requestID).
		Str("package", ref.Key()).
		Logger()

	// Check cache first
	if entry, found := h.cfg.Cache.Get(ref); found {
		if !entry.ScanClean {
			// Fail-closed: cached entry has failed scan result
			record(gate.VerdictBlock, gate.GateCache, "scan_failed", http.StatusForbidden, nil)
			h.writeError(w, requestID, ref, http.StatusForbidden, "scan_failed")
			return
		}
		log.Debug().Msg("cache hit")
		if err := h.serveFromCache(w, entry); err != nil {
			record(gate.VerdictError, gate.GateCache, "cache_read_error", http.StatusInternalServerError, nil)
			return
		}
		record(gate.VerdictCache, gate.GateCache, "cache_hit", http.StatusOK, nil)
		return
	}

	ctx := r.Context()

	// Supply-chain check. Adapters that carry the publish date on the artifact
	// download itself (Maven, via Last-Modified) defer the check until after the
	// download, which avoids a separate metadata request; other adapters fetch
	// metadata up front and check now.
	extractor, deferSC := h.cfg.Adapter.(gate.DownloadMetadataExtractor)

	var scResult gate.FilterResult
	// checkSupplyChain runs the filter and, on a block, writes the response and
	// records telemetry; it also emits the dry_run warning. It returns false when
	// the request is finished (blocked) and the caller must return.
	checkSupplyChain := func(meta *gate.PackageMetadata) bool {
		scResult = h.cfg.Filter.Check(ctx, ref, meta)
		if !scResult.Allowed {
			log.Warn().
				Str("reason", scResult.Reason).
				Time("published_at", scResult.PublishedAt).
				Time("block_until", scResult.BlockUntil).
				Msg("supply chain filter blocked package")
			record(gate.VerdictBlock, gate.GateSupply, scResult.Reason, http.StatusLocked, func(ev *gate.Event) {
				ev.BlockedBy = []string{"supply_chain"}
				ev.PublishedAt = scResult.PublishedAt
				ev.BlockUntil = scResult.BlockUntil
			})
			h.writeBlockedResponse(w, requestID, ref, scResult)
			return false
		}
		if scResult.Reason == "dry_run" {
			log.Warn().
				Time("published_at", scResult.PublishedAt).
				Time("block_until", scResult.BlockUntil).
				Msg("dry_run: package would be blocked by supply chain filter")
		}
		return true
	}

	if !deferSC {
		meta, err := h.cfg.Adapter.FetchMetadata(ctx, ref)
		if err != nil {
			log.Error().Err(err).Msg("failed to fetch upstream metadata")
			record(gate.VerdictError, gate.GateSupply, "upstream_metadata_unavailable", http.StatusBadGateway, nil)
			h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_metadata_unavailable")
			return
		}
		if !checkSupplyChain(meta) {
			return
		}
	}

	// CVE scan — before downloading the artifact (fail-closed if scanner errors).
	if h.cfg.CVEScanner != nil {
		scanResult, err := h.cfg.CVEScanner.Scan(ctx, ref)
		if err != nil {
			log.Error().Err(err).Msg("CVE scan failed")
			record(gate.VerdictError, gate.GateCVE, "cve_scan_error", http.StatusServiceUnavailable, nil)
			h.writeError(w, requestID, ref, http.StatusServiceUnavailable, "cve_scan_error")
			return
		}
		if h.cfg.Policy != nil {
			decision := h.cfg.Policy.Evaluate(ref, scanResult)
			if !decision.Allowed {
				log.Warn().
					Str("reason", decision.Reason).
					Int("findings", len(decision.Findings)).
					Msg("CVE policy blocked package")
				blockedBy := "cve"
				if decision.Reason == gate.ReasonDenylisted {
					blockedBy = "denylist"
				}
				record(gate.VerdictBlock, gate.GateCVE, decision.Reason, http.StatusForbidden, func(ev *gate.Event) {
					ev.BlockedBy = []string{blockedBy}
					ev.CVEs = decision.Findings
				})
				h.writeCVEBlockedResponse(w, requestID, ref, decision)
				return
			}
		}
	}

	// Download artifact, trying each configured upstream in order.
	upstreamURLs := h.cfg.Adapter.UpstreamURLs(r)
	if len(upstreamURLs) == 0 {
		log.Error().Msg("adapter returned no upstream URLs")
		record(gate.VerdictError, gate.GateSupply, "no_upstream_configured", http.StatusInternalServerError, nil)
		h.writeError(w, requestID, ref, http.StatusInternalServerError, "no_upstream_configured")
		return
	}
	tmpPath, header, allNotFound, err := h.downloadFromUpstreams(ctx, upstreamURLs)
	if err != nil {
		if allNotFound {
			log.Warn().Strs("upstream_urls", upstreamURLs).Msg("artifact not found on any upstream")
			record(gate.VerdictError, gate.GateSupply, "artifact_not_found", http.StatusNotFound, nil)
			h.writeError(w, requestID, ref, http.StatusNotFound, "artifact_not_found")
			return
		}
		log.Error().Err(err).Strs("upstream_urls", upstreamURLs).Msg("failed to download artifact")
		record(gate.VerdictError, gate.GateSupply, "upstream_unavailable", http.StatusBadGateway, nil)
		h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer os.Remove(tmpPath)

	// Deferred supply-chain: the artifact download carried the publish date
	// (e.g. Maven's Last-Modified), so run the check now, before serving.
	if deferSC {
		if !checkSupplyChain(extractor.MetadataFromHeader(header)) {
			return
		}
	}

	// Antivirus scan — after download, before caching (fail-closed on error).
	if h.cfg.AVScanner != nil {
		avResult, err := h.cfg.AVScanner.Scan(ctx, tmpPath)
		if err != nil {
			log.Error().Err(err).Msg("AV scan failed")
			record(gate.VerdictError, gate.GateMalware, "av_scan_error", http.StatusServiceUnavailable, nil)
			h.writeError(w, requestID, ref, http.StatusServiceUnavailable, "av_scan_error")
			return
		}
		if !avResult.Clean {
			log.Warn().Str("engine", avResult.Engine).Str("signature", avResult.Signature).Msg("malware detected")
			record(gate.VerdictBlock, gate.GateMalware, "malware_found", http.StatusForbidden, func(ev *gate.Event) {
				ev.BlockedBy = []string{"malware"}
				ev.MalwareEngine = avResult.Engine
				ev.MalwareSignature = avResult.Signature
			})
			h.writeMalwareBlockedResponse(w, requestID, ref, avResult.Engine, avResult.Signature)
			return
		}
	}

	// Cache the artifact (scan passed).
	if err := h.cfg.Cache.Put(ref, tmpPath, true, ""); err != nil {
		log.Error().Err(err).Msg("failed to cache artifact")
		// Fail-closed: don't serve if we cannot cache
		record(gate.VerdictError, gate.GateCache, "cache_error", http.StatusInternalServerError, nil)
		h.writeError(w, requestID, ref, http.StatusInternalServerError, "cache_error")
		return
	}

	log.Info().Str("sc_reason", scResult.Reason).Msg("serving artifact")
	entry, found := h.cfg.Cache.Get(ref)
	if !found {
		// Should not happen — we just Put it
		record(gate.VerdictError, gate.GateCache, "cache_error", http.StatusInternalServerError, nil)
		h.writeError(w, requestID, ref, http.StatusInternalServerError, "cache_error")
		return
	}
	// PASS gate = the deepest gate this artifact actually cleared.
	lastGate := gate.GateSupply
	if h.cfg.CVEScanner != nil && h.cfg.Policy != nil {
		lastGate = gate.GateCVE
	}
	if h.cfg.AVScanner != nil {
		lastGate = gate.GateMalware
	}
	if err := h.serveFromCache(w, entry); err != nil {
		record(gate.VerdictError, gate.GateCache, "cache_read_error", http.StatusInternalServerError, nil)
		return
	}
	record(gate.VerdictPass, lastGate, scResult.Reason, http.StatusOK, func(ev *gate.Event) {
		ev.PublishedAt = scResult.PublishedAt
	})
}

// proxyTransparent forwards a non-intercepted request to each configured
// upstream in order, streaming back the first response with status < 400.
// If all fail, returns 404 (all were 404/410) or 502.
func (h *Handler) proxyTransparent(w http.ResponseWriter, r *http.Request) {
	urls := h.cfg.Adapter.UpstreamURLs(r)
	if len(urls) == 0 {
		h.cfg.Logger.Error().Msg("adapter returned no upstream URLs for transparent request")
		http.Error(w, "no upstream configured", http.StatusInternalServerError)
		return
	}

	// Buffer the request body once so it can be replayed across attempts.
	var body []byte
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body = b
	}

	allNotFound := true
	for _, url := range urls {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, url, bytes.NewReader(body))
		if err != nil {
			allNotFound = false
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
			allNotFound = false
			continue
		}
		if resp.StatusCode < 400 {
			for _, hop := range hopByHopHeaders {
				resp.Header.Del(hop)
			}
			for key, vals := range resp.Header {
				for _, v := range vals {
					w.Header().Add(key, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			if _, err := io.Copy(w, resp.Body); err != nil {
				h.cfg.Logger.Error().Err(err).Msg("error streaming proxy response")
			}
			resp.Body.Close()
			return
		}
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusGone {
			allNotFound = false
		}
		resp.Body.Close()
	}

	if allNotFound {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	http.Error(w, "upstream unavailable", http.StatusBadGateway)
}

// tryDownload downloads url to a temp file. Returns the temp path and the
// response header on HTTP 200. statusCode is the upstream HTTP status (0 on
// transport error). The caller removes the file.
func (h *Handler) tryDownload(ctx context.Context, url string) (tmpPath string, header http.Header, statusCode int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, 0, err
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", nil, 0, fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.Header, resp.StatusCode, fmt.Errorf("upstream returned HTTP %d for %s", resp.StatusCode, url)
	}

	tmp, err := os.CreateTemp("", "jo-ei-artifact-*")
	if err != nil {
		return "", resp.Header, resp.StatusCode, fmt.Errorf("creating temp file: %w", err)
	}
	defer tmp.Close()
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		os.Remove(tmp.Name())
		return "", resp.Header, resp.StatusCode, fmt.Errorf("writing temp file: %w", err)
	}
	return tmp.Name(), resp.Header, resp.StatusCode, nil
}

// downloadFromUpstreams tries each candidate URL in order, returning the first
// HTTP 200 with its response header. allNotFound is true iff every attempt
// returned 404/410 (no other failure occurred), which the caller maps to a 404
// instead of 502.
func (h *Handler) downloadFromUpstreams(ctx context.Context, urls []string) (tmpPath string, header http.Header, allNotFound bool, err error) {
	if len(urls) == 0 {
		return "", nil, false, fmt.Errorf("downloadFromUpstreams: no upstream URLs provided")
	}
	allNotFound = true
	for _, u := range urls {
		path, hdr, status, derr := h.tryDownload(ctx, u)
		if derr == nil {
			return path, hdr, false, nil
		}
		if status != http.StatusNotFound && status != http.StatusGone {
			allNotFound = false
		}
		err = derr
	}
	return "", nil, allNotFound, err
}

// serveFromCache streams the cached artifact to the response writer. It
// returns an error only when the artifact cannot be opened (a 500 is written
// in that case); streaming errors after headers are sent are logged only.
func (h *Handler) serveFromCache(w http.ResponseWriter, entry *gate.ArtifactEntry) error {
	f, err := os.Open(entry.ArtifactPath)
	if err != nil {
		http.Error(w, "cache read error", http.StatusInternalServerError)
		return err
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Joei-Cache", "HIT")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		h.cfg.Logger.Error().Err(err).Str("artifact_path", entry.ArtifactPath).Msg("error streaming cached artifact")
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusLocked)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.cfg.Logger.Error().Err(err).Msg("writing JSON response")
	}
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.cfg.Logger.Error().Err(err).Msg("writing JSON response")
	}
}

// writeMalwareBlockedResponse sends a 403 Forbidden response for a malware hit.
func (h *Handler) writeMalwareBlockedResponse(w http.ResponseWriter, requestID string, ref *gate.PackageRef, engine, signature string) {
	body := map[string]any{
		"error":      "package_blocked",
		"package":    ref.Name,
		"version":    ref.Version,
		"reason":     "malware_found",
		"engine":     engine,
		"signature":  signature,
		"blocked_by": []string{"malware_scanner"},
		"request_id": requestID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.cfg.Logger.Error().Err(err).Msg("writing JSON response")
	}
}

// writeCVEBlockedResponse sends a 403 Forbidden response with CVE details.
func (h *Handler) writeCVEBlockedResponse(w http.ResponseWriter, requestID string, ref *gate.PackageRef, d gate.PolicyDecision) {
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.cfg.Logger.Error().Err(err).Msg("writing JSON response")
	}
}

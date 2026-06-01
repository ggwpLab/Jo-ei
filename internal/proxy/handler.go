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
)

// ArtifactEntry is a minimal view of a cached artifact, avoiding an import cycle
// with the cache package (which itself imports proxy for PackageRef).
type ArtifactEntry struct {
	// ArtifactPath is the absolute path to the cached file on disk.
	ArtifactPath string
	// ScanClean is true if all scanners passed.
	ScanClean bool
}

// ArtifactCache is the storage interface used by the handler.
// It is intentionally defined here (not in the cache package) to avoid the
// import cycle: proxy → cache → proxy.
// The real cache.LocalCache satisfies this interface via structural typing.
type ArtifactCache interface {
	Get(ref *PackageRef) (*ArtifactEntry, bool)
	Put(ref *PackageRef, tmpPath string, scanClean bool, scanJSON string) error
	Invalidate(ref *PackageRef) error
}

// HandlerConfig groups dependencies for the ProxyHandler.
type HandlerConfig struct {
	Adapter    RegistryAdapter
	Filter     SCFilter
	Cache      ArtifactCache
	Logger     zerolog.Logger
	CVEScanner CVEScanner    // optional; nil disables CVE scanning
	Policy     PolicyDecider // optional; nil allows all when CVEScanner is set
	AVScanner  AVScanner     // optional; nil disables malware scanning
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
	return &Handler{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()

	// Built-in endpoints
	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok"}`)
		return
	}

	ref, isDownload := h.cfg.Adapter.NormalizeRequest(r)
	if !isDownload {
		// Metadata / simple API — proxy transparently, no interception
		h.proxyTransparent(w, r)
		return
	}

	log := h.cfg.Logger.With().
		Str("request_id", requestID).
		Str("package", ref.Key()).
		Logger()

	// Check cache first
	if entry, found := h.cfg.Cache.Get(ref); found {
		if !entry.ScanClean {
			// Fail-closed: cached entry has failed scan result
			h.writeError(w, requestID, ref, http.StatusForbidden, "scan_failed")
			return
		}
		log.Debug().Msg("cache hit")
		h.serveFromCache(w, entry)
		return
	}

	// Fetch upstream metadata for supply chain check
	ctx := r.Context()
	meta, err := h.cfg.Adapter.FetchMetadata(ctx, ref)
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch upstream metadata")
		h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_metadata_unavailable")
		return
	}

	// Supply chain filter
	scResult := h.cfg.Filter.Check(ctx, ref, meta)
	if !scResult.Allowed {
		log.Warn().
			Str("reason", scResult.Reason).
			Time("published_at", scResult.PublishedAt).
			Time("block_until", scResult.BlockUntil).
			Msg("supply chain filter blocked package")
		h.writeBlockedResponse(w, requestID, ref, scResult)
		return
	}
	if scResult.Reason == "dry_run" {
		log.Warn().
			Time("published_at", scResult.PublishedAt).
			Time("block_until", scResult.BlockUntil).
			Msg("dry_run: package would be blocked by supply chain filter")
	}

	// CVE scan — before downloading the artifact (fail-closed if scanner errors).
	if h.cfg.CVEScanner != nil {
		scanResult, err := h.cfg.CVEScanner.Scan(ctx, ref)
		if err != nil {
			log.Error().Err(err).Msg("CVE scan failed")
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
				h.writeCVEBlockedResponse(w, requestID, ref, decision)
				return
			}
		}
	}

	// Download artifact, trying each configured upstream in order.
	upstreamURLs := h.cfg.Adapter.UpstreamURLs(r)
	if len(upstreamURLs) == 0 {
		log.Error().Msg("adapter returned no upstream URLs")
		h.writeError(w, requestID, ref, http.StatusInternalServerError, "no_upstream_configured")
		return
	}
	tmpPath, allNotFound, err := h.downloadFromUpstreams(ctx, upstreamURLs)
	if err != nil {
		if allNotFound {
			log.Warn().Strs("upstream_urls", upstreamURLs).Msg("artifact not found on any upstream")
			h.writeError(w, requestID, ref, http.StatusNotFound, "artifact_not_found")
			return
		}
		log.Error().Err(err).Strs("upstream_urls", upstreamURLs).Msg("failed to download artifact")
		h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer os.Remove(tmpPath)

	// Antivirus scan — after download, before caching (fail-closed on error).
	if h.cfg.AVScanner != nil {
		avResult, err := h.cfg.AVScanner.Scan(ctx, tmpPath)
		if err != nil {
			log.Error().Err(err).Msg("AV scan failed")
			h.writeError(w, requestID, ref, http.StatusServiceUnavailable, "av_scan_error")
			return
		}
		if !avResult.Clean {
			log.Warn().Str("signature", avResult.Signature).Msg("malware detected")
			h.writeMalwareBlockedResponse(w, requestID, ref, avResult.Signature)
			return
		}
	}

	// Cache the artifact (scan passed).
	if err := h.cfg.Cache.Put(ref, tmpPath, true, ""); err != nil {
		log.Error().Err(err).Msg("failed to cache artifact")
		// Fail-closed: don't serve if we cannot cache
		h.writeError(w, requestID, ref, http.StatusInternalServerError, "cache_error")
		return
	}

	log.Info().Str("sc_reason", scResult.Reason).Msg("serving artifact")
	entry, found := h.cfg.Cache.Get(ref)
	if !found {
		// Should not happen — we just Put it
		h.writeError(w, requestID, ref, http.StatusInternalServerError, "cache_error")
		return
	}
	h.serveFromCache(w, entry)
}

// proxyTransparent forwards a non-intercepted request to each configured
// upstream in order, streaming back the first response with status < 400.
// If all fail, returns 404 (all were 404/410) or 502.
func (h *Handler) proxyTransparent(w http.ResponseWriter, r *http.Request) {
	urls := h.cfg.Adapter.UpstreamURLs(r)

	// Buffer the request body once so it can be replayed across attempts.
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		r.Body.Close()
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

		resp, err := h.httpClient.Do(req)
		if err != nil {
			allNotFound = false
			continue
		}
		if resp.StatusCode < 400 {
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

// tryDownload downloads url to a temp file. Returns the temp path on HTTP 200.
// statusCode is the upstream HTTP status (0 on transport error). The caller
// removes the file.
func (h *Handler) tryDownload(ctx context.Context, url string) (tmpPath string, statusCode int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, fmt.Errorf("upstream returned HTTP %d for %s", resp.StatusCode, url)
	}

	tmp, err := os.CreateTemp("", "sca-proxy-artifact-*")
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("creating temp file: %w", err)
	}
	defer tmp.Close()
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		os.Remove(tmp.Name())
		return "", resp.StatusCode, fmt.Errorf("writing temp file: %w", err)
	}
	return tmp.Name(), resp.StatusCode, nil
}

// downloadFromUpstreams tries each candidate URL in order, returning the first
// HTTP 200. allNotFound is true iff every attempt returned 404/410 (no other
// failure occurred), which the caller maps to a 404 instead of 502.
func (h *Handler) downloadFromUpstreams(ctx context.Context, urls []string) (tmpPath string, allNotFound bool, err error) {
	if len(urls) == 0 {
		return "", false, fmt.Errorf("downloadFromUpstreams: no upstream URLs provided")
	}
	allNotFound = true
	for _, u := range urls {
		path, status, derr := h.tryDownload(ctx, u)
		if derr == nil {
			return path, false, nil
		}
		if status != http.StatusNotFound && status != http.StatusGone {
			allNotFound = false
		}
		err = derr
	}
	return "", allNotFound, err
}

// serveFromCache streams the cached artifact to the response writer.
func (h *Handler) serveFromCache(w http.ResponseWriter, entry *ArtifactEntry) {
	f, err := os.Open(entry.ArtifactPath)
	if err != nil {
		http.Error(w, "cache read error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-SCA-Proxy-Cache", "HIT")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		h.cfg.Logger.Error().Err(err).Str("artifact_path", entry.ArtifactPath).Msg("error streaming cached artifact")
	}
}

// writeBlockedResponse sends a 423 Locked response with structured JSON.
func (h *Handler) writeBlockedResponse(w http.ResponseWriter, requestID string, ref *PackageRef, scResult FilterResult) {
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
	json.NewEncoder(w).Encode(body)
}

// writeError sends a structured JSON error response.
func (h *Handler) writeError(w http.ResponseWriter, requestID string, ref *PackageRef, status int, reason string) {
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
	json.NewEncoder(w).Encode(body)
}

// writeMalwareBlockedResponse sends a 403 Forbidden response for a malware hit.
func (h *Handler) writeMalwareBlockedResponse(w http.ResponseWriter, requestID string, ref *PackageRef, signature string) {
	body := map[string]any{
		"error":      "package_blocked",
		"package":    ref.Name,
		"version":    ref.Version,
		"reason":     "malware_found",
		"signature":  signature,
		"blocked_by": []string{"malware_scanner"},
		"request_id": requestID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(body)
}

// writeCVEBlockedResponse sends a 403 Forbidden response with CVE details.
func (h *Handler) writeCVEBlockedResponse(w http.ResponseWriter, requestID string, ref *PackageRef, d PolicyDecision) {
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
	json.NewEncoder(w).Encode(body)
}

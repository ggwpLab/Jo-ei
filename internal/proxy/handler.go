package proxy

import (
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
	Adapter  RegistryAdapter
	Filter   SCFilter
	Cache    ArtifactCache
	Logger   zerolog.Logger
	Upstream string
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

	// Download artifact from upstream to a temp file
	upstreamURL := h.cfg.Adapter.UpstreamURL(r)
	tmpPath, err := h.downloadToTemp(ctx, upstreamURL)
	if err != nil {
		log.Error().Err(err).Str("upstream_url", upstreamURL).Msg("failed to download artifact")
		h.writeError(w, requestID, ref, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer os.Remove(tmpPath)

	// Cache the artifact.
	// Phase 1: scanClean=true (no CVE/AV scanner yet).
	// Phase 2 will run CVEScanner + AVScanner here before caching.
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

// proxyTransparent forwards a request to upstream and streams the response back.
func (h *Handler) proxyTransparent(w http.ResponseWriter, r *http.Request) {
	upstreamURL := h.cfg.Upstream + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	for key, vals := range r.Header {
		for _, v := range vals {
			req.Header.Add(key, v)
		}
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// downloadToTemp downloads url to a temporary file and returns its path.
// The caller is responsible for removing the file.
func (h *Handler) downloadToTemp(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upstream returned HTTP %d for %s", resp.StatusCode, url)
	}

	tmp, err := os.CreateTemp("", "sca-proxy-artifact-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	defer tmp.Close()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("writing temp file: %w", err)
	}

	return tmp.Name(), nil
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
	io.Copy(w, f)
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

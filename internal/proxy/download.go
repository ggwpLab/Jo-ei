package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
)

func (h *Handler) serveDownload(w http.ResponseWriter, r *http.Request, requestID string, ref *gate.PackageRef, record recordOutcome, log zerolog.Logger) {
	ctx := r.Context()
	fail := func(gateName, reason string, status int) {
		record(gate.VerdictError, gateName, reason, status, nil)
		h.writeError(w, requestID, ref, status, reason)
	}

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
				Msg("dry run: supply chain filter would block package")
		}
		return true
	}

	if !deferSC {
		meta, err := h.cfg.Adapter.FetchMetadata(ctx, ref)
		if err != nil {
			atts, hasAtts := upstream.AttemptsFrom(err)
			if status, retry, ok := atts.Throttled(h.cfg.Throttles); hasAtts && ok {
				log.Warn().Array("upstream_attempts", atts).Msg("upstream metadata unavailable: mirrors throttled")
				httpx.SetRetryAfter(w.Header(), retry)
				fail(gate.GateSupply, "upstream_throttled", status)
				return
			}
			ev := log.Error().Err(err)
			if hasAtts {
				ev = ev.Array("upstream_attempts", atts)
			}
			ev.Msg("failed to fetch upstream metadata")
			fail(gate.GateSupply, "upstream_metadata_unavailable", http.StatusBadGateway)
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
			log.Error().Err(err).Msg("cve scan failed")
			fail(gate.GateCVE, "cve_scan_error", http.StatusServiceUnavailable)
			return
		}
		if h.cfg.Policy != nil {
			decision := h.cfg.Policy.Evaluate(ref, scanResult)
			if !decision.Allowed {
				h.blockCVE(w, requestID, ref, decision, record)
				return
			}
		}
	}

	// Download artifact, trying each configured upstream in order.
	upstreamURLs := h.cfg.Adapter.UpstreamURLs(r)
	if len(upstreamURLs) == 0 {
		log.Error().Msg("adapter returned no upstream URLs")
		fail(gate.GateSupply, "no_upstream_configured", http.StatusInternalServerError)
		return
	}
	tmpPath, header, atts, err := h.downloadFromUpstreams(ctx, upstreamURLs)
	if err != nil {
		if errors.Is(err, errArtifactTooLarge) {
			log.Warn().Err(err).Int64("max_bytes", h.cfg.MaxArtifactBytes).Msg("artifact over the size cap")
			fail(gate.GateCache, "artifact_too_large", http.StatusForbidden)
			return
		}
		if atts.AllNotFound() {
			log.Warn().Array("upstream_attempts", atts).Msg("artifact not found on any upstream")
			fail(gate.GateSupply, "artifact_not_found", http.StatusNotFound)
			return
		}
		if status, retry, ok := atts.Throttled(h.cfg.Throttles); ok {
			log.Warn().Array("upstream_attempts", atts).Msg("artifact not found on reachable upstreams; others throttled")
			httpx.SetRetryAfter(w.Header(), retry)
			fail(gate.GateSupply, "upstream_throttled", status)
			return
		}
		log.Error().Err(err).Array("upstream_attempts", atts).Msg("failed to download artifact")
		fail(gate.GateSupply, "upstream_unavailable", http.StatusBadGateway)
		return
	}
	defer os.Remove(tmpPath)

	// Deferred supply-chain: the artifact download carried the publish date
	// (e.g. Maven's Last-Modified), so run the check now, before serving.
	if deferSC && !checkSupplyChain(extractor.MetadataFromHeader(header)) {
		return
	}

	// Antivirus scan — after download, before caching (fail-closed on error).
	if h.cfg.AVScanner != nil {
		avResult, err := h.cfg.AVScanner.Scan(ctx, tmpPath)
		if err != nil {
			log.Error().Err(err).Msg("malware scan failed")
			fail(gate.GateMalware, "av_scan_error", http.StatusServiceUnavailable)
			return
		}
		if avResult.Incomplete {
			// Not fully checked, so not served — but not malware either.
			log.Warn().Str("engine", avResult.Engine).Str("signature", avResult.Signature).
				Msg("malware scan incomplete; blocking")
			record(gate.VerdictBlock, gate.GateMalware, gate.ReasonScanIncomplete, http.StatusForbidden, func(ev *gate.Event) {
				ev.BlockedBy = []string{gate.ReasonScanIncomplete}
				ev.MalwareEngine = avResult.Engine
				ev.MalwareSignature = avResult.Signature
			})
			h.writeError(w, requestID, ref, http.StatusForbidden, gate.ReasonScanIncomplete)
			return
		}
		if !avResult.Clean {
			h.blockMalware(w, requestID, ref, avResult, record)
			return
		}
	}

	// Cache the artifact (scan passed).
	if err := h.cfg.Cache.Put(ref, tmpPath, true, ""); err != nil {
		log.Error().Err(err).Msg("failed to cache artifact")
		// Fail-closed: don't serve if we cannot cache
		fail(gate.GateCache, "cache_error", http.StatusInternalServerError)
		return
	}

	entry, found := h.cfg.Cache.Get(ref)
	if !found {
		// Should not happen — we just Put it
		fail(gate.GateCache, "cache_error", http.StatusInternalServerError)
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
	if err := h.serveFromCache(w, entry, log); err != nil {
		record(gate.VerdictError, gate.GateCache, "cache_read_error", http.StatusInternalServerError, nil)
		return
	}
	record(gate.VerdictPass, lastGate, scResult.Reason, http.StatusOK, func(ev *gate.Event) {
		ev.PublishedAt = scResult.PublishedAt
	})
}

// errArtifactTooLarge marks a download refused for exceeding
// HandlerConfig.MaxArtifactBytes.
var errArtifactTooLarge = errors.New("artifact exceeds the size cap")

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
		return "", nil, 0, fmt.Errorf("downloading %s: %w", upstream.SanitizeURL(url), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.Header, resp.StatusCode, fmt.Errorf("upstream returned HTTP %d for %s", resp.StatusCode, upstream.SanitizeURL(url))
	}

	max := h.cfg.MaxArtifactBytes
	if max > 0 && resp.ContentLength > max {
		return "", resp.Header, resp.StatusCode, fmt.Errorf("%w: %d bytes", errArtifactTooLarge, resp.ContentLength)
	}

	tmp, err := os.CreateTemp(h.cfg.TempDir, "jo-ei-artifact-*")
	if err != nil {
		return "", resp.Header, resp.StatusCode, fmt.Errorf("creating temp file: %w", err)
	}
	defer tmp.Close()
	src := io.Reader(resp.Body)
	if max > 0 {
		src = io.LimitReader(resp.Body, max+1) // one byte over reveals an oversized body
	}
	written, err := io.Copy(tmp, src)
	if err != nil {
		os.Remove(tmp.Name())
		return "", resp.Header, resp.StatusCode, fmt.Errorf("writing temp file: %w", err)
	}
	if max > 0 && written > max {
		os.Remove(tmp.Name())
		return "", resp.Header, resp.StatusCode, fmt.Errorf("%w: over %d bytes", errArtifactTooLarge, max)
	}
	return tmp.Name(), resp.Header, resp.StatusCode, nil
}

// downloadFromUpstreams tries each candidate URL in order, returning the first
// HTTP 200 with its response header. Every failed mirror is recorded in atts,
// which is also returned as the error when no mirror succeeded — so the caller
// can both log each attempt and ask atts.AllNotFound() whether the artifact was
// merely absent (404) rather than unreachable (502). It does not itself guard
// against an empty urls list — the caller owns that check — and an empty list
// here simply returns a zero-length, non-nil atts as the error.
func (h *Handler) downloadFromUpstreams(ctx context.Context, urls []string) (tmpPath string, header http.Header, atts upstream.Attempts, err error) {
	for _, u := range urls {
		start := time.Now()
		path, hdr, status, derr := h.tryDownload(ctx, u)
		if derr == nil {
			return path, hdr, atts, nil
		}
		if errors.Is(derr, errArtifactTooLarge) {
			// The same artifact is no smaller on another mirror.
			return "", nil, atts, derr
		}
		atts.Add(u, status, derr, time.Since(start))
	}
	return "", nil, atts, atts
}

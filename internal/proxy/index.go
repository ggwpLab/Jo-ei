package proxy

import (
	"net/http"
	"strings"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/logx"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
)

// defaultIndexMaxMB caps a decoded index document when HandlerConfig.IndexMaxMB
// is unset. The largest PyPI project pages are well under 10 MB.
const defaultIndexMaxMB = 64

// maxLoggedDrops bounds how many dropped links one warning lists.
const maxLoggedDrops = 5

// proxyIndex serves an index document only with its download links pointed at
// the proxy. Unlike metadata filtering, which may fall back to the untouched
// document because the artifact gate still guards the download, an untouched
// index sends the client around the proxy entirely — so every path that
// cannot rewrite fails the request instead.
func (h *Handler) proxyIndex(w http.ResponseWriter, r *http.Request, rw gate.IndexRewriter) {
	log := logx.Logger(r.Context(), h.metaLog).With().Str("path", r.URL.Path).Logger()

	// The client's validators belong to whatever copy it cached — possibly an
	// unrewritten one from before this proxy rewrote indexes. Upstream must
	// never answer 304 for that copy, so the fetch is always unconditional.
	// gzip is the only coding readMetadataDocument decodes, so ask for exactly
	// that rather than relaying the client's own Accept-Encoding.
	outbound := r.Clone(r.Context())
	outbound.Header.Del("If-None-Match")
	outbound.Header.Del("If-Modified-Since")
	outbound.Header.Set("Accept-Encoding", "gzip")

	resp, atts, err := h.forwardUpstream(outbound)
	if resp == nil {
		h.writeForwardError(w, atts, err, log)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// No document to rewrite (a redirect, 204, ...): relay as-is.
		copyProxyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if _, err := httpx.CopyWithWriteDeadline(w, resp.Body, httpx.DefaultWriteIdleTimeout); err != nil {
			log.Debug().Err(err).Msg("relaying index response")
		}
		return
	}

	maxMB := h.cfg.IndexMaxMB
	if maxMB <= 0 {
		maxMB = defaultIndexMaxMB
	}
	doc, rest, unsupported, err := readMetadataDocument(resp, int64(maxMB)<<20)
	switch {
	case err != nil:
		h.failIndex(w, log.Error().Err(err), "reading upstream index")
		return
	case unsupported:
		h.failIndex(w, log.Error().Str("content_encoding", resp.Header.Get("Content-Encoding")),
			"upstream index in an encoding the proxy cannot decode")
		return
	case rest != nil:
		h.failIndex(w, log.Error().Int("max_mb", maxMB), "upstream index exceeds the size cap")
		return
	}

	out, err := rw.RewriteIndex(doc, resp.Header.Get("Content-Type"), r.URL.Path)
	if err != nil {
		h.failIndex(w, log.Error().Err(err), "unparseable upstream index")
		return
	}
	if len(out.Dropped) > 0 {
		examples := out.Dropped
		if len(examples) > maxLoggedDrops {
			examples = examples[:maxLoggedDrops]
		}
		sanitized := make([]string, len(examples))
		for i, u := range examples {
			sanitized[i] = upstream.SanitizeURL(u)
		}
		log.Warn().Int("count", len(out.Dropped)).Strs("examples", sanitized).
			Msg("dropped index links that cannot route through the proxy")
	}
	log.Debug().Int("rewritten", out.Rewritten).Msg("index rewritten")

	tag := syntheticETag(out.Body)
	if etagMatches(strings.Join(r.Header.Values("If-None-Match"), ", "), tag) {
		w.Header().Set("ETag", tag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeMetadataDocument(w, r, resp.Header, resp.StatusCode, out.Body, true, log)
}

// failIndex logs why an index could not be rewritten and answers 502: serving
// it untouched would hand the client links around the proxy.
func (h *Handler) failIndex(w http.ResponseWriter, event *zerolog.Event, msg string) {
	event.Msg(msg)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write([]byte(`{"error":"index_rewrite_failed"}`))
}

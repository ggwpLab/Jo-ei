package proxy

import (
	"net/http"
	"strings"

	"github.com/rs/zerolog"
)

// Mux routes requests to per-registry handlers by URL path prefix.
// A request to /<prefix>/... is dispatched to the handler registered for
// <prefix> with the prefix stripped, so each registry adapter sees the same
// paths it would without the proxy wrapper.
type Mux struct {
	handlers map[string]*Handler
	raw      map[string]http.Handler // prefix → handler for non-package registries (docker)
	logger   zerolog.Logger
}

// NewMux creates a Mux. raw may be nil; it holds prefixes served by a plain
// http.Handler (e.g. the Docker V2 proxy).
func NewMux(handlers map[string]*Handler, raw map[string]http.Handler, logger zerolog.Logger) *Mux {
	return &Mux{handlers: handlers, raw: raw, logger: logger}
}

func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
			m.logger.Error().Err(err).Msg("writing health response")
		}
		return
	}

	// Browsers auto-probe paths like the Chrome DevTools /.well-known descriptor
	// on every page load. They are not registry requests, so answer them quietly
	// instead of logging an "unknown registry prefix" warning each time.
	// (/favicon.ico is intercepted earlier by the root mux, which serves a real
	// icon, so it never reaches here.)
	if isBrowserNoise(r.URL.Path) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	prefix, rest := splitPrefix(r.URL.Path)

	if rh, ok := m.raw[prefix]; ok {
		r.URL.Path = rest
		r.URL.RawPath = ""
		rh.ServeHTTP(w, r)
		return
	}

	h, ok := m.handlers[prefix]
	if !ok {
		m.logger.Warn().Str("prefix", prefix).Str("path", r.URL.Path).Msg("request to unknown registry prefix")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write([]byte(`{"error":"unknown_registry"}`)); err != nil {
			m.logger.Error().Err(err).Msg("writing not-found response")
		}
		return
	}

	// Strip the prefix so the downstream handler/adapter sees native paths.
	// RawPath is cleared so RequestURI() re-encodes from Path; safe for the
	// pypi/npm/maven path shapes (no encoded slashes in REST segments).
	r.URL.Path = rest
	r.URL.RawPath = ""
	h.ServeHTTP(w, r)
}

// isBrowserNoise reports whether path is an automatic browser request
// (/.well-known/ probes such as the Chrome DevTools descriptor) rather than a
// registry request, so the mux can answer it without logging an
// unknown-registry warning.
func isBrowserNoise(path string) bool {
	return strings.HasPrefix(path, "/.well-known/")
}

// splitPrefix splits "/npm/foo/bar" into ("npm", "/foo/bar").
// "/npm" alone → ("npm", "/").
func splitPrefix(path string) (prefix, rest string) {
	trimmed := strings.TrimPrefix(path, "/")
	idx := strings.IndexByte(trimmed, '/')
	if idx == -1 {
		return trimmed, "/"
	}
	return trimmed[:idx], trimmed[idx:]
}

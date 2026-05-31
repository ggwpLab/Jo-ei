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
	logger   zerolog.Logger
}

// NewMux creates a Mux from a prefix→handler map, e.g. {"pypi": h1, "npm": h2}.
func NewMux(handlers map[string]*Handler, logger zerolog.Logger) *Mux {
	return &Mux{handlers: handlers, logger: logger}
}

func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	prefix, rest := splitPrefix(r.URL.Path)
	h, ok := m.handlers[prefix]
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"unknown_registry"}`))
		return
	}

	// Strip the prefix so the downstream handler/adapter sees native paths.
	r.URL.Path = rest
	r.URL.RawPath = ""
	h.ServeHTTP(w, r)
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

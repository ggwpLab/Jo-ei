package adapters

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
)

func trimUpstreams(upstreams []string) []string {
	trimmed := make([]string, len(upstreams))
	for i, u := range upstreams {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	return trimmed
}

func upstreamURLs(upstreams []string, r *http.Request) []string {
	urls := make([]string, len(upstreams))
	for i, base := range upstreams {
		urls[i] = base + r.URL.RequestURI()
	}
	return urls
}

func firstMetadata(upstreams []string, ecosystem string, fetch func(string) (*gate.PackageMetadata, string, int, error)) (*gate.PackageMetadata, error) {
	if len(upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured for %s", ecosystem)
	}
	var atts upstream.Attempts
	for _, base := range upstreams {
		start := time.Now()
		meta, url, status, err := fetch(base)
		if err == nil {
			return meta, nil
		}
		atts.Add(url, status, err, time.Since(start))
	}
	return nil, atts
}

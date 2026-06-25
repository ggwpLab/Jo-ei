package adapters

import (
	"net/http"
	"time"
)

// defaultAdapterTimeout is the per-request timeout for a registry adapter's HTTP
// client when the caller does not supply its own.
const defaultAdapterTimeout = 30 * time.Second

// Option customizes an adapter at construction. With no options an adapter uses a
// private http.Client with defaultAdapterTimeout.
type Option func(*adapterConfig)

type adapterConfig struct {
	client *http.Client
}

// WithHTTPClient makes the adapter use client for all upstream requests. Sharing
// one client whose transport caps per-host concurrency (see internal/httpx)
// across every adapter and the proxy handler keeps total outbound concurrency to
// a single registry bounded, which is what prevents HTTP 429 throttling.
func WithHTTPClient(client *http.Client) Option {
	return func(c *adapterConfig) {
		if client != nil {
			c.client = client
		}
	}
}

// resolveClient applies opts over the default per-adapter client.
func resolveClient(opts []Option) *http.Client {
	cfg := adapterConfig{client: &http.Client{Timeout: defaultAdapterTimeout}}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg.client
}

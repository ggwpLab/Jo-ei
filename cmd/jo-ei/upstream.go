package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/metrics"
)

// Upstream 429/503 circuit-breaker cooldown bounds (see httpx.CircuitBreaker).
// The cooldown honors Retry-After when sent; these bound the fallback
// exponential cooldown when it is absent.
const (
	upstreamRetryBaseDelay = 1 * time.Second
	upstreamRetryMaxDelay  = 20 * time.Second
)

// upstreamClients are the HTTP clients for every upstream call, all sharing
// one instrumented transport chain.
type upstreamClients struct {
	// breaker is the chain's circuit breaker; handlers read it as an
	// upstream.ThrottleLookup to answer 429/503 with Retry-After.
	breaker  *httpx.CircuitBreaker
	adapter  *http.Client // upstream metadata
	download *http.Client // artifact downloads and transparent proxying
	docker   *http.Client // Docker registry API and blobs
}

// buildUpstream wires the shared upstream transport and the clients over it.
// cfg.Registries must already carry the stored overlay, so the metrics see the
// effective upstream hosts.
func buildUpstream(cfg *config.Config, mx *metrics.Metrics, serverLog zerolog.Logger) (upstreamClients, error) {
	// One shared upstream transport for every client (metadata, download,
	// transparent proxy, Docker): a per-host request-rate cap (the primary 429
	// defense — registries throttle by rate) over a per-host concurrency cap
	// (complementary, bounds parallelism). Shared so all traffic to a host counts
	// against the same caps.
	maxConc := cfg.Server.UpstreamMaxConcurrent
	if maxConc <= 0 {
		maxConc = config.DefaultUpstreamMaxConcurrent
	}
	rate := cfg.Server.UpstreamRatePerSecond
	if rate <= 0 {
		rate = config.DefaultUpstreamRatePerSecond
	}

	// Upstream TLS trust: the system roots plus any operator-supplied CA files,
	// so mirrors with a corporate or self-signed certificate can be fetched. A
	// bad CA file stops startup here rather than becoming an x509 error on the
	// first pull.
	rootPool, addedCAs, err := httpx.RootPool(cfg.TLS.CAFiles)
	if err != nil {
		return upstreamClients{}, fmt.Errorf("upstream TLS trust: %w", err)
	}
	if addedCAs > 0 {
		serverLog.Info().
			Int("certificates", addedCAs).
			Int("sources", len(cfg.TLS.CAFiles)).
			Msg("added CA certificates to the upstream trust pool")
	}

	// Outermost: a per-host circuit breaker that fast-fails a host for a cooldown
	// after it returns 429/503 (honoring Retry-After), so a throttled primary is
	// skipped immediately in favor of a mirror instead of being retried/hammered.
	// Inner: a coarse rate cap, then a concurrency cap, then an idle timeout,
	// over a transport carrying the configured CA trust pool. The idle timeout
	// sits inside the limiters so waiting for a slot is not upstream silence.
	// Metrics instrument the whole chain from the outside, so rate-limit waits
	// and circuit-open fast-fails are visible.
	cb := httpx.NewCircuitBreaker(
		httpx.NewRateLimiter(
			httpx.NewConcurrencyLimiter(httpx.NewIdleTimeout(httpx.NewTransport(rootPool), httpx.DefaultUpstreamIdleTimeout), maxConc),
			float64(rate), 2*rate,
		),
		upstreamRetryBaseDelay, upstreamRetryMaxDelay,
	)
	// cfg.Registries already carries the stored overlay, so these are the
	// effective upstream hosts.
	hosts := metrics.UpstreamHosts(
		cfg.Registries.PyPI.Upstreams, cfg.Registries.NPM.Upstreams, cfg.Registries.Maven.Upstreams,
		cfg.Registries.RubyGems.Upstreams, cfg.Registries.Go.Upstreams, cfg.Registries.Docker.Upstreams,
	)
	upstreamLimiter := mx.WrapTransport(cb, hosts)
	mx.RegisterCircuitBreaker(cb, hosts)
	// Metadata documents are bounded, so the adapter client keeps a total cap.
	// Downloads and Docker blobs can be many GB: only the idle timeout bounds
	// them, so a slow but steady transfer is never cut off.
	adapterClient := &http.Client{Timeout: 30 * time.Second, Transport: upstreamLimiter}
	downloadClient := &http.Client{Transport: upstreamLimiter}
	dockerClient := &http.Client{Transport: upstreamLimiter}
	return upstreamClients{breaker: cb, adapter: adapterClient, download: downloadClient, docker: dockerClient}, nil
}

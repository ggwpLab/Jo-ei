package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/metrics"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/proxy/dockerproxy"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
)

// sharedDeps groups dependencies shared across every per-registry handler.
type sharedDeps struct {
	filter     gate.SCFilter
	cache      gate.ArtifactCache
	logger     zerolog.Logger
	cveScanner gate.CVEScanner
	policy     gate.PolicyDecider
	avScanner  gate.AVScanner
	recorder   gate.Recorder
	// adapterClient fetches upstream metadata; downloadClient downloads artifacts
	// and serves transparent proxy requests. Both share one per-host
	// concurrency-limiting transport so all traffic to a registry counts against
	// the same cap.
	adapterClient  *http.Client
	downloadClient *http.Client
	// throttles is the shared transport's circuit breaker, read by handlers
	// to answer 429/503 with Retry-After when the other mirrors returned 404.
	throttles upstream.ThrottleLookup

	cveRecheckTTL       time.Duration
	malwareRecheckTTL   time.Duration
	metadataFilterMaxMB int
	// tempDir holds downloads while they are checked (on the cache volume).
	tempDir string
	// maxArtifactBytes caps a package artifact download (0 = unlimited).
	maxArtifactBytes int64
}

// proxyRoutes are the registry handlers keyed by URL prefix: package
// registries in handlers, plain http.Handlers (Docker's /v2/) in raw.
type proxyRoutes struct {
	handlers map[string]*proxy.Handler
	raw      map[string]http.Handler
}

// buildProxyRoutes builds every enabled registry handler. It fails when no
// registry ends up enabled. Docker is served only when an image scanner is
// configured.
func buildProxyRoutes(cfg *config.Config, shared sharedDeps, sc scanners, up upstreamClients, policyRuntime *policy.Runtime, artifactCache cache.Cache, mx *metrics.Metrics) (proxyRoutes, error) {
	r := proxyRoutes{handlers: buildHandlers(cfg, shared), raw: map[string]http.Handler{}}
	if cfg.Registries.Docker.Enabled && sc.trivy == nil {
		shared.logger.Warn().Str("component", "server").
			Msg("docker registry enabled but image_scan is disabled; /v2/ is not served")
	}
	if cfg.Registries.Docker.Enabled && sc.trivy != nil {
		r.raw["v2"] = dockerproxy.New(dockerproxy.HandlerDeps{
			Upstreams:     cfg.Registries.Docker.Upstreams,
			Scanner:       mx.WrapImageScanner("trivy", sc.trivy),
			AV:            shared.avScanner,
			Filter:        policyRuntime,
			Policy:        policyRuntime,
			Cache:         artifactCache,
			MaxLayerBytes: cfg.ImageScan.MaxLayerBytes,
			Recorder:      shared.recorder,
			Logger:        shared.logger,
			HTTPClient:    up.docker,
			Throttles:     up.breaker,
			RecheckTTL:    minEnabledTTL(shared.cveRecheckTTL, shared.malwareRecheckTTL),
			TempDir:       shared.tempDir,
			ClientWait:    time.Duration(cfg.ImageScan.ClientWaitSeconds) * time.Second,
		})
	}
	if len(r.handlers) == 0 && len(r.raw) == 0 {
		return proxyRoutes{}, fmt.Errorf("no registries enabled; set at least one of registries.{pypi,npm,maven,rubygems,go,docker}.enabled: true")
	}
	return r, nil
}

// registryCount is the number of registries served, for the startup log. The
// yarn prefix is an alias of the npm handler, not a separate registry; Docker
// lives in raw, so it is counted separately — without that a docker-only
// deployment would report "registries: 0".
func (r proxyRoutes) registryCount() int {
	n := len(r.handlers)
	if _, ok := r.handlers["yarn"]; ok {
		n--
	}
	if _, ok := r.raw["v2"]; ok {
		n++
	}
	return n
}

// prefixes lists every routed prefix, the closed set that keeps the metrics
// route label bounded.
func (r proxyRoutes) prefixes() []string {
	out := make([]string, 0, len(r.handlers)+len(r.raw))
	for p := range r.handlers {
		out = append(out, p)
	}
	for p := range r.raw {
		out = append(out, p)
	}
	return out
}

// buildHandlers constructs the routing map of prefix→handler from config.
// The "yarn" prefix is an alias for the npm handler, since yarn speaks the npm
// registry protocol.
func buildHandlers(cfg *config.Config, shared sharedDeps) map[string]*proxy.Handler {
	handlers := map[string]*proxy.Handler{}
	client := adapters.WithHTTPClient(shared.adapterClient)
	if cfg.Registries.PyPI.Enabled {
		handlers["pypi"] = buildHandler(adapters.NewPyPIAdapter(cfg.Registries.PyPI.Upstreams, client), shared)
	}
	if cfg.Registries.NPM.Enabled {
		npmHandler := buildHandler(adapters.NewNPMAdapter(cfg.Registries.NPM.Upstreams, client), shared)
		handlers["npm"] = npmHandler
		handlers["yarn"] = npmHandler
	}
	if cfg.Registries.Maven.Enabled {
		handlers["maven"] = buildHandler(adapters.NewMavenAdapter(cfg.Registries.Maven.Upstreams, client), shared)
	}
	if cfg.Registries.RubyGems.Enabled {
		handlers["rubygems"] = buildHandler(adapters.NewRubyGemsAdapter(cfg.Registries.RubyGems.Upstreams, client), shared)
	}
	if cfg.Registries.Go.Enabled {
		handlers["go"] = buildHandler(adapters.NewGoAdapter(cfg.Registries.Go.Upstreams, client), shared)
	}
	return handlers
}

// minEnabledTTL returns the smaller of the enabled (positive) TTLs; 0 when
// both are disabled. Docker's single verdict covers both gates, so it expires
// by the stricter one.
func minEnabledTTL(a, b time.Duration) time.Duration {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}

// buildHandler constructs a proxy.Handler for one registry adapter with the
// shared dependency set.
func buildHandler(adapter gate.RegistryAdapter, shared sharedDeps) *proxy.Handler {
	return proxy.NewHandler(proxy.HandlerConfig{
		Adapter:             adapter,
		Filter:              shared.filter,
		Cache:               shared.cache,
		Logger:              shared.logger,
		CVEScanner:          shared.cveScanner,
		Policy:              shared.policy,
		AVScanner:           shared.avScanner,
		Recorder:            shared.recorder,
		CVERecheckTTL:       shared.cveRecheckTTL,
		MalwareRecheckTTL:   shared.malwareRecheckTTL,
		HTTPClient:          shared.downloadClient,
		Throttles:           shared.throttles,
		MetadataFilterMaxMB: shared.metadataFilterMaxMB,
		TempDir:             shared.tempDir,
		MaxArtifactBytes:    shared.maxArtifactBytes,
	})
}

// Command jo-ei is the Jōei supply-chain security proxy for package registries.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/logx"
	"github.com/ggwpLab/Jo-ei/internal/metrics"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/proxy/dockerproxy"
	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
	"github.com/ggwpLab/Jo-ei/internal/users"
	"github.com/ggwpLab/Jo-ei/web"
)

var cfgFile string

// Build metadata, overridden at release time via
// -ldflags "-X main.version=… -X main.commit=… -X main.date=…" (see
// .goreleaser.yaml). Defaults identify a from-source build.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:     "jo-ei",
	Short:   "Jōei — transparent supply chain security proxy for package registries",
	Version: version,
	RunE:    runProxy,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "config.yaml", "path to config file")
	rootCmd.SetVersionTemplate(fmt.Sprintf(
		"jo-ei {{.Version}} (commit %s, built %s)\n", commit, date))
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

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
}

func runProxy(_ *cobra.Command, _ []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, cfgFile)
}

// run loads the config at cfgPath, wires the proxy and serves it (plus the
// metrics listener when enabled) until ctx is cancelled or a server fails.
func run(ctx context.Context, cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	a := &app{}
	defer a.close()

	logger, serverLog, err := setupLogging(a, cfg.Logging)
	if err != nil {
		return err
	}

	// mx stays nil when metrics are disabled; every Wrap*/Register* method on
	// it is then a pass-through or no-op.
	var mx *metrics.Metrics
	if cfg.Metrics.Enabled {
		mx = metrics.New(metrics.BuildInfo{Version: version, Commit: commit}, logger)
	}

	sdb, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("opening database at %q: %w", cfg.Database.Path, err)
	}
	a.onClose(sdb.Close)

	settingsStore, err := settings.New(sdb)
	if err != nil {
		return err
	}

	if err := applyStoredRegistries(cfg, settingsStore); err != nil {
		return err
	}

	artifactCache, err := cache.New(cfg.Cache)
	if err != nil {
		return err
	}
	a.onClose(artifactCache.Close)
	mx.RegisterCache(artifactCache, int64(cfg.Cache.Local.MaxSizeGB)<<30)

	profile, ok := cfg.Policy.Profiles[cfg.Policy.ActiveProfile]
	if !ok {
		return fmt.Errorf("active_profile %q not found in policy.profiles", cfg.Policy.ActiveProfile)
	}

	var fileAllow []string
	if cfg.SupplyChain.AllowlistPath != "" {
		allowlist, err := supplychain.LoadAllowlist(cfg.SupplyChain.AllowlistPath)
		if err != nil {
			return err
		}
		fileAllow = allowlist.Entries()
	}

	// Runtime policy: engine + supply-chain filter behind an atomic swap so
	// the console can apply edits without restart. Edits now persist to the
	// shared SQLite database so they survive a restart.
	policyRuntime, err := policy.NewRuntimeWithStore(cfg.SupplyChain, cfg.CVE, profile, fileAllow, policySettingsStore{s: settingsStore})
	if err != nil {
		return err
	}

	store, err := buildTelemetryStore(sdb, cfg, logger)
	if err != nil {
		return err
	}
	serverLog.Info().Str("path", cfg.Database.Path).Msg("telemetry persistence enabled")
	a.onClose(store.Close)
	broadcaster := telemetry.NewBroadcaster()

	up, err := buildUpstream(cfg, mx, serverLog)
	if err != nil {
		return err
	}

	shared := sharedDeps{
		filter:         policyRuntime,
		cache:          cache.AsArtifactCache(artifactCache),
		logger:         logger,
		recorder:       mx.WrapRecorder(&telemetry.Hub{Store: store, Broadcaster: broadcaster}),
		adapterClient:  up.adapter,
		downloadClient: up.download,
		throttles:      up.breaker,

		cveRecheckTTL:       time.Duration(cfg.Cache.Revalidation.CVETTLMinutes) * time.Minute,
		malwareRecheckTTL:   time.Duration(cfg.Cache.Revalidation.MalwareTTLMinutes) * time.Minute,
		metadataFilterMaxMB: cfg.Server.MetadataFilterMaxMB,
	}

	if shared.cveRecheckTTL <= 0 && shared.malwareRecheckTTL <= 0 {
		serverLog.Warn().Msg("cache re-validation disabled: cached artifacts are never re-checked")
	} else {
		serverLog.Info().Dur("cve_ttl", shared.cveRecheckTTL).Dur("malware_ttl", shared.malwareRecheckTTL).
			Msg("lazy cache re-validation configured")
	}

	sc, err := buildScanners(a, cfg, profile, mx, serverLog)
	if err != nil {
		return err
	}
	shared.cveScanner = sc.cve
	shared.avScanner = sc.av
	if cfg.CVE.Enabled {
		shared.policy = policyRuntime
	}

	// Build the prefix→handler routing map from config.
	handlers := buildHandlers(cfg, shared)

	rawHandlers := map[string]http.Handler{}
	if cfg.Registries.Docker.Enabled && sc.trivy != nil {
		rawHandlers["v2"] = dockerproxy.New(dockerproxy.HandlerDeps{
			Upstreams:     cfg.Registries.Docker.Upstreams,
			Scanner:       mx.WrapImageScanner("trivy", sc.trivy),
			AV:            shared.avScanner,
			Filter:        policyRuntime,
			Policy:        policyRuntime,
			Cache:         artifactCache,
			MaxLayerBytes: cfg.ImageScan.MaxLayerBytes,
			Recorder:      shared.recorder,
			Logger:        logger,
			HTTPClient:    up.docker,
			Throttles:     up.breaker,
			RecheckTTL:    minEnabledTTL(shared.cveRecheckTTL, shared.malwareRecheckTTL),
		})
	}

	if len(handlers) == 0 && len(rawHandlers) == 0 {
		return fmt.Errorf("no registries enabled; set at least one of registries.{pypi,npm,maven,rubygems,go,docker}.enabled: true")
	}

	// The yarn prefix is an alias of the npm handler, not a separate registry.
	registryCount := len(handlers)
	if _, ok := handlers["yarn"]; ok {
		registryCount--
	}
	// Docker is served via the raw-handler map (not *proxy.Handler), so count it
	// separately for the startup log; without this a docker-only deployment
	// would report "registries: 0".
	if _, ok := rawHandlers["v2"]; ok {
		registryCount++
	}

	mux := proxy.NewMux(handlers, rawHandlers, logger)
	runningRegistries := registryInfo(cfg)

	// Wrap the proxy mux so the admin console is served at /console/ while every
	// other path (registry prefixes, /health) falls through to the proxy mux
	// untouched. Keeping the console in a parent mux leaves the proxy package
	// and its routing free of UI concerns.
	// Console users live in the database. On an empty table the initial
	// admin is created and its temporary password logged once.
	userStore, err := users.New(sdb)
	if err != nil {
		return fmt.Errorf("console users: %w", err)
	}
	if err := ensureInitialAdmin(userStore, serverLog); err != nil {
		return err
	}
	jwtSecret, err := resolveJWTSecret(cfg.Console.Auth.JWTSecret, settingsStore, logger)
	if err != nil {
		return err
	}
	signer, err := auth.NewSigner(jwtSecret)
	if err != nil {
		return fmt.Errorf("console auth: %w", err)
	}
	accessTTL, refreshTTL := authTTLs(cfg.Console.Auth)
	clientIP, err := httpx.NewClientIPResolver(cfg.Server.TrustedProxies, cfg.Server.ClientIPHeader, serverLog)
	if err != nil {
		return fmt.Errorf("server.trusted_proxies: %w", err)
	}
	sessions := auth.NewSessions(userStore, signer, accessTTL, refreshTTL,
		auth.WithLoginLimiter(auth.NewLoginLimiter(nil)),
		auth.WithClientIP(clientIP.ClientIP),
		auth.WithLogger(logger))
	if sessions.Locked() {
		serverLog.Warn().Msg(`console locked — no enabled users; /api/ is disabled (HTTP 503) until an admin is restored with "jo-ei reset-admin-password"; the proxy continues to serve`)
	}

	root := http.NewServeMux()
	// Public site icon: browsers auto-probe /favicon.ico on every page load, so
	// serve it before the auth-gated routes and outside the proxy mux.
	root.Handle("/favicon.ico", web.FaviconHandler())
	// The console shell is public: the login screen has to render before a
	// session exists, and the bundle is UI code with no secrets in it. Every
	// byte of data still comes from /api/, which stays gated.
	root.Handle("/console/", web.ConsoleHandler())
	// Session endpoints sit outside the middleware — a client with no session
	// must be able to reach login. ServeMux prefers the longer pattern, so
	// /api/auth/* lands here and everything else under /api/ stays gated.
	root.Handle("/api/auth/", sessions.Handler())
	// The console needs the effective staleness threshold (mirrors the default
	// cache.New applies) and, when the backend supports it, on-demand purge.
	staleDays := cfg.Cache.Local.StaleAfterDays
	if staleDays <= 0 {
		staleDays = cache.DefaultStaleAfterDays
	}
	var cachePurger console.CachePurger
	if p, ok := artifactCache.(console.CachePurger); ok {
		cachePurger = p
	}
	root.Handle("/api/", sessions.Middleware(console.NewHandler(console.Config{
		Store:               store,
		Broadcaster:         broadcaster,
		Policy:              policyRuntime,
		Cache:               artifactCache,
		CacheMaxBytes:       int64(cfg.Cache.Local.MaxSizeGB) << 30,
		Purger:              cachePurger,
		CacheStaleAfterDays: staleDays,
		Registries:          runningRegistries,
		RegistryStore:       registrySettingsStore{s: settingsStore},
		RunningRegistries:   runningRegistries,
		ImageScanEnabled:    cfg.ImageScan.Enabled,
		Health:              sc.health,
		Users:               userStore,
		Logger:              logger,
	})))
	root.Handle("/", mux)

	metricsAddr := "disabled"
	if mx != nil {
		metricsAddr = cfg.Metrics.Listen + cfg.Metrics.Path
	}

	// Label proxy traffic by registry prefix; the closed set keeps the route
	// label bounded.
	prefixes := make([]string, 0, len(handlers)+len(rawHandlers))
	for p := range handlers {
		prefixes = append(prefixes, p)
	}
	for p := range rawHandlers {
		prefixes = append(prefixes, p)
	}

	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      logx.Middleware(mx.WrapHandler(root, metrics.NewRouteFunc(prefixes))),
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	// Bind every listener before serving any of them, so a port clash (notably
	// on metrics.listen) stops startup before the proxy accepts traffic.
	var servers []boundServer
	defer func() {
		for _, s := range servers {
			_ = s.ln.Close() // no-op once the server has shut down
		}
	}()
	if mx != nil {
		mmux := http.NewServeMux()
		mmux.Handle(cfg.Metrics.Path, mx.Handler())
		metricsSrv := &http.Server{
			Handler:           mmux,
			ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout:      30 * time.Second,
		}
		ln, err := net.Listen("tcp", cfg.Metrics.Listen)
		if err != nil {
			return fmt.Errorf("metrics.listen %s: %w", cfg.Metrics.Listen, err)
		}
		servers = append(servers, boundServer{metricsSrv, ln})
	}
	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("server.listen %s: %w", cfg.Server.Listen, err)
	}
	servers = append(servers, boundServer{srv, ln})

	serverLog.Info().
		Str("listen", cfg.Server.Listen).
		Str("metrics", metricsAddr).
		Int("registries", registryCount).
		Int("malware_engines", sc.engineCount).
		Bool("cve", shared.cveScanner != nil).
		Str("mode", cfg.SupplyChain.Mode).
		Str("console", "/console/").
		Str("api", "/api/").
		Msg("Jōei starting")

	return serveAll(ctx, servers...)
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
	})
}

// buildTelemetryStore initialises the SQLite-backed telemetry store on the
// shared database. Telemetry is SQLite-only: any schema error aborts startup.
func buildTelemetryStore(sdb *storage.DB, cfg *config.Config, logger zerolog.Logger) (*telemetry.Store, error) {
	store, err := telemetry.Open(sdb, cfg.Database.EventRetentionDays, cfg.Database.DailyRetentionDays, logger)
	if err != nil {
		return nil, fmt.Errorf("initialising telemetry store: %w", err)
	}
	return store, nil
}

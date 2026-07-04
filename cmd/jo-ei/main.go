// Command jo-ei is the Jōei supply-chain security proxy for package registries.
package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/proxy/dockerproxy"
	"github.com/ggwpLab/Jo-ei/internal/revalidate"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
	"github.com/ggwpLab/Jo-ei/web"
)

var cfgFile string

// defaultOSVBaseURL is used for both the live scanner and the console's
// scanner listing when cve.base_url is unset.
const defaultOSVBaseURL = "https://api.osv.dev"

// defaultMaxConcurrentScans bounds simultaneous malware scans when
// malware.max_concurrent_scans is unset. It roughly matches clamd's default
// worker pool so bursts don't queue past the per-scan deadline.
const defaultMaxConcurrentScans = 8

// Upstream 429/503 circuit-breaker cooldown bounds (see httpx.CircuitBreaker).
// The cooldown honors Retry-After when sent; these bound the fallback
// exponential cooldown when it is absent.
const (
	upstreamRetryBaseDelay = 1 * time.Second
	upstreamRetryMaxDelay  = 20 * time.Second
)

var rootCmd = &cobra.Command{
	Use:   "jo-ei",
	Short: "Jōei — transparent supply chain security proxy for package registries",
	RunE:  runProxy,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "config.yaml", "path to config file")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// sharedDeps groups dependencies shared across every per-registry handler.
type sharedDeps struct {
	filter     proxy.SCFilter
	cache      proxy.ArtifactCache
	logger     zerolog.Logger
	cveScanner proxy.CVEScanner
	policy     proxy.PolicyDecider
	avScanner  proxy.AVScanner
	recorder   proxy.Recorder
	// adapterClient fetches upstream metadata; downloadClient downloads artifacts
	// and serves transparent proxy requests. Both share one per-host
	// concurrency-limiting transport so all traffic to a registry counts against
	// the same cap.
	adapterClient  *http.Client
	downloadClient *http.Client
}

func runProxy(_ *cobra.Command, _ []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	level, levelErr := zerolog.ParseLevel(cfg.Logging.Level)
	if levelErr != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	logOut, closeLog, err := logWriter(cfg.Logging.Output)
	if err != nil {
		return err
	}
	defer func() { _ = closeLog() }()

	var logger zerolog.Logger
	if cfg.Logging.Format == "text" {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: logOut, TimeFormat: time.RFC3339}).
			With().Timestamp().Logger()
	} else {
		logger = zerolog.New(logOut).With().Timestamp().Logger()
	}
	if levelErr != nil {
		logger.Warn().Str("value", cfg.Logging.Level).Msg("unknown log level; defaulting to info")
	}

	sdb, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("opening database at %q: %w", cfg.Database.Path, err)
	}
	defer func() { _ = sdb.Close() }()

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
	defer func() { _ = artifactCache.Close() }()

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
	defer func() { _ = store.Close() }()
	broadcaster := telemetry.NewBroadcaster()

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
	// Outermost: a per-host circuit breaker that fast-fails a host for a cooldown
	// after it returns 429/503 (honoring Retry-After), so a throttled primary is
	// skipped immediately in favor of a mirror instead of being retried/hammered.
	// Inner: a coarse rate cap, then a concurrency cap, over the default transport.
	upstreamLimiter := httpx.NewCircuitBreaker(
		httpx.NewRateLimiter(
			httpx.NewConcurrencyLimiter(http.DefaultTransport, maxConc),
			float64(rate), 2*rate,
		),
		upstreamRetryBaseDelay, upstreamRetryMaxDelay,
	)
	adapterClient := &http.Client{Timeout: 30 * time.Second, Transport: upstreamLimiter}
	downloadClient := &http.Client{Timeout: 60 * time.Second, Transport: upstreamLimiter}
	dockerClient := &http.Client{Timeout: 120 * time.Second, Transport: upstreamLimiter}

	shared := sharedDeps{
		filter:         policyRuntime,
		cache:          &cacheAdapter{c: artifactCache},
		logger:         logger,
		recorder:       &telemetry.Hub{Store: store, Broadcaster: broadcaster},
		adapterClient:  adapterClient,
		downloadClient: downloadClient,
	}

	// CVE scanner + policy (optional).
	var osvScanner *scanner.OSVScanner
	if cfg.CVE.Enabled {
		baseURL := cfg.CVE.BaseURL
		if baseURL == "" {
			baseURL = defaultOSVBaseURL
		}
		ttl := time.Duration(cfg.CVE.CacheTTLMinutes) * time.Minute
		if ttl == 0 {
			ttl = 24 * time.Hour
		}
		osvScanner = scanner.NewOSVScanner(baseURL, ttl)
		defer func() { _ = osvScanner.Close() }()
		shared.cveScanner = osvScanner
		shared.policy = policyRuntime
	}

	if !cfg.CVE.Enabled {
		logger.Warn().Msg("cve.enabled is false — console policy edits to cve_block_on, allowlist_cve and denylist have no effect (supply-chain mode/min-age/allowlist_supply still apply)")
	}

	// Malware scanners (optional; attached only when the profile blocks malware).
	var avScanners []proxy.AVScanner
	engineCount := 0
	if profile.MalwareBlock && len(cfg.Malware.Scanners) > 0 {
		avScanners = make([]proxy.AVScanner, 0, len(cfg.Malware.Scanners))
		for _, sc := range cfg.Malware.Scanners {
			av, err := scanner.New(sc)
			if err != nil {
				return err
			}
			avScanners = append(avScanners, av)
		}
		limit := cfg.Malware.MaxConcurrentScans
		if limit == 0 {
			limit = defaultMaxConcurrentScans
		}
		// Cap concurrent scans so download bursts don't overwhelm the engines'
		// worker pools and make clamd/ICAP responses time out.
		shared.avScanner = scanner.NewLimitedScanner(scanner.NewMultiScanner(avScanners...), limit)
		engineCount = len(avScanners)
	} else if len(cfg.Malware.Scanners) > 0 {
		logger.Warn().Str("active_profile", cfg.Policy.ActiveProfile).
			Msg("malware.scanners configured but active profile has malware_block:false — scanners not attached")
	}

	// Image scanner (Trivy) for the Docker registry (optional).
	var trivyScanner *dockerproxy.TrivyScanner
	if cfg.ImageScan.Enabled {
		timeout := time.Duration(cfg.ImageScan.TimeoutSeconds) * time.Second
		trivyScanner = dockerproxy.NewTrivyScanner(cfg.ImageScan.TrivyServer, cfg.ImageScan.Scanners, timeout)
	}

	// Scanner health monitor: active probes for socket engines, passive
	// tracking for the remote osv.dev API.
	interval := time.Duration(cfg.Health.ProbeIntervalSeconds) * time.Second
	slow := time.Duration(cfg.Health.SlowThresholdMS) * time.Millisecond
	if slow <= 0 {
		slow = 2000 * time.Millisecond
	}
	healthMon := health.NewMonitor(interval, slow) // interval<=0 → 30s default
	if cfg.CVE.Enabled && osvScanner != nil {
		base := cfg.CVE.BaseURL
		if base == "" {
			base = defaultOSVBaseURL
		}
		healthMon.AddPassive("osv.dev", base, true, osvScanner.Health)
	}
	for i, sc := range cfg.Malware.Scanners {
		if profile.MalwareBlock && i < len(avScanners) {
			if pr, ok := avScanners[i].(scanner.Prober); ok {
				healthMon.AddActive(sc.Type, sc.Address, true, pr.Probe)
				continue
			}
		}
		healthMon.AddDisabled(sc.Type, sc.Address)
	}
	if cfg.ImageScan.Enabled && trivyScanner != nil {
		healthMon.AddActive("trivy", cfg.ImageScan.TrivyServer, true, trivyScanner.Probe)
	}
	healthMon.Start()
	defer healthMon.Close() //nolint:errcheck

	// Cache re-validation sweep (optional): periodically re-run the gates over
	// cached artifacts and evict any that now fail.
	if cfg.Cache.Revalidation.Enabled {
		if rstore, ok := artifactCache.(revalidate.RevalidationStore); ok {
			revalidators := map[string]revalidate.Revalidator{}
			pr := revalidate.NewPackageRevalidator(shared.cveScanner, shared.policy, shared.avScanner)
			for _, eco := range []string{"pypi", "npm", "maven", "rubygems"} {
				revalidators[eco] = pr
			}
			if cfg.Registries.Docker.Enabled && trivyScanner != nil {
				revalidators["docker"] = dockerproxy.NewRevalidator(dockerproxy.HandlerDeps{
					Upstreams:     cfg.Registries.Docker.Upstreams,
					Scanner:       trivyScanner,
					AV:            shared.avScanner,
					Filter:        policyRuntime,
					Policy:        policyRuntime,
					Cache:         artifactCache,
					MaxLayerBytes: cfg.ImageScan.MaxLayerBytes,
					Logger:        logger,
					HTTPClient:    dockerClient,
				})
			}
			interval := time.Duration(cfg.Cache.Revalidation.IntervalMinutes) * time.Minute
			if interval <= 0 {
				interval = 60 * time.Minute
			}
			revalAfter := time.Duration(cfg.Cache.Revalidation.RevalidateAfterHours) * time.Hour
			if revalAfter <= 0 {
				revalAfter = 24 * time.Hour
			}
			batch := cfg.Cache.Revalidation.BatchSize
			if batch <= 0 {
				batch = 50
			}
			sweeper := revalidate.NewSweeper(rstore, revalidators, shared.recorder, revalidate.Config{
				Interval: interval, RevalidateAfter: revalAfter, BatchSize: batch,
			}, logger)
			sweeper.Start()
			defer sweeper.Close()
			logger.Info().Dur("interval", interval).Dur("revalidate_after", revalAfter).Int("batch", batch).
				Msg("cache re-validation sweep enabled")
		} else {
			logger.Warn().Msg("cache.revalidation.enabled but cache backend does not support re-validation; skipping")
		}
	}

	// Build the prefix→handler routing map from config.
	handlers := buildHandlers(cfg, shared)

	rawHandlers := map[string]http.Handler{}
	if cfg.Registries.Docker.Enabled && trivyScanner != nil {
		rawHandlers["v2"] = dockerproxy.New(dockerproxy.HandlerDeps{
			Upstreams:     cfg.Registries.Docker.Upstreams,
			Scanner:       trivyScanner,
			AV:            shared.avScanner,
			Filter:        policyRuntime,
			Policy:        policyRuntime,
			Cache:         artifactCache,
			MaxLayerBytes: cfg.ImageScan.MaxLayerBytes,
			Recorder:      shared.recorder,
			Logger:        logger,
			HTTPClient:    dockerClient,
		})
	}

	if len(handlers) == 0 && len(rawHandlers) == 0 {
		return fmt.Errorf("no registries enabled; set at least one of registries.{pypi,npm,maven,rubygems,docker}.enabled: true")
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
	authUsers, err := auth.NewUsers(toAuthUsers(cfg.Console.Auth.Users), os.Getenv("JOEI_CONSOLE_AUTH_USERS"))
	if err != nil {
		return err
	}
	if authUsers.Locked() {
		logger.Warn().Msg("console auth not configured — /console/ and /api/ are disabled (HTTP 503) until users are added (set console.auth.users or JOEI_CONSOLE_AUTH_USERS); the proxy continues to serve")
	}
	root := http.NewServeMux()
	// Public site icon: browsers auto-probe /favicon.ico on every page load, so
	// serve it before the auth-gated routes and outside the proxy mux.
	root.Handle("/favicon.ico", web.FaviconHandler())
	root.Handle("/console/", authUsers.Middleware(web.ConsoleHandler()))
	root.Handle("/api/", authUsers.Middleware(console.NewHandler(console.Config{
		Store:             store,
		Broadcaster:       broadcaster,
		Policy:            policyRuntime,
		Cache:             artifactCache,
		CacheMaxBytes:     int64(cfg.Cache.Local.MaxSizeGB) << 30,
		Registries:        runningRegistries,
		RegistryStore:     registrySettingsStore{s: settingsStore},
		RunningRegistries: runningRegistries,
		ImageScanEnabled:  cfg.ImageScan.Enabled,
		Health:            healthMon,
		Logger:            logger,
	})))
	root.Handle("/", mux)

	logger.Info().
		Str("listen", cfg.Server.Listen).
		Int("registries", registryCount).
		Int("malware_engines", engineCount).
		Bool("cve", shared.cveScanner != nil).
		Str("mode", cfg.SupplyChain.Mode).
		Str("console", "/console/").
		Str("api", "/api/").
		Msg("Jōei starting")

	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      root,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}
	return serve(ctx, srv)
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
	return handlers
}

// buildHandler constructs a proxy.Handler for one registry adapter with the
// shared dependency set.
func buildHandler(adapter proxy.RegistryAdapter, shared sharedDeps) *proxy.Handler {
	return proxy.NewHandler(proxy.HandlerConfig{
		Adapter:    adapter,
		Filter:     shared.filter,
		Cache:      shared.cache,
		Logger:     shared.logger,
		CVEScanner: shared.cveScanner,
		Policy:     shared.policy,
		AVScanner:  shared.avScanner,
		Recorder:   shared.recorder,
		HTTPClient: shared.downloadClient,
	})
}

// cacheAdapter bridges cache.Cache to the proxy.ArtifactCache interface.
type cacheAdapter struct {
	c cache.Cache
}

func (a *cacheAdapter) Get(ref *proxy.PackageRef) (*proxy.ArtifactEntry, bool) {
	entry, found := a.c.Get(ref)
	if !found {
		return nil, false
	}
	return &proxy.ArtifactEntry{
		ArtifactPath: entry.ArtifactPath,
		ScanClean:    entry.ScanClean,
	}, true
}

func (a *cacheAdapter) Put(ref *proxy.PackageRef, tmpPath string, scanClean bool, scanJSON string) error {
	return a.c.Put(ref, tmpPath, scanClean, scanJSON)
}

func (a *cacheAdapter) Invalidate(ref *proxy.PackageRef) error {
	return a.c.Invalidate(ref)
}

// policySettingsStore adapts *settings.Store to policy.SettingsStore, storing
// the runtime policy params as JSON under the "policy" key.
type policySettingsStore struct{ s *settings.Store }

func (p policySettingsStore) LoadPolicy() (policy.RuntimeParams, bool, error) {
	b, ok, err := p.s.Get("policy")
	if err != nil || !ok {
		return policy.RuntimeParams{}, ok, err
	}
	rp, err := policy.DecodeStored(b)
	if err != nil {
		return policy.RuntimeParams{}, false, fmt.Errorf("decoding stored policy: %w", err)
	}
	return rp, true, nil
}

func (p policySettingsStore) SavePolicy(rp policy.RuntimeParams) error {
	b, err := policy.EncodeStored(rp)
	if err != nil {
		return err
	}
	return p.s.Put("policy", b)
}

// registrySettingsStore adapts *settings.Store to console.RegistryStore, storing
// the registry set as JSON under the "registries" key.
type registrySettingsStore struct{ s *settings.Store }

func (r registrySettingsStore) LoadRegistries() ([]console.RegistryInfo, bool, error) {
	b, ok, err := r.s.Get("registries")
	if err != nil || !ok {
		return nil, ok, err
	}
	var regs []console.RegistryInfo
	if err := json.Unmarshal(b, &regs); err != nil {
		return nil, false, fmt.Errorf("decoding stored registries: %w", err)
	}
	return regs, true, nil
}

func (r registrySettingsStore) SaveRegistries(in []console.RegistryInfo) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return r.s.Put("registries", b)
}

// applyStoredRegistries overlays persisted registry settings onto cfg before the
// proxy mux is built (DB wins), or seeds the store from the YAML config on first
// boot. A corrupt stored value fails fast rather than silently using YAML.
func applyStoredRegistries(cfg *config.Config, st *settings.Store) error {
	stored, ok, err := registrySettingsStore{s: st}.LoadRegistries()
	if err != nil {
		return err
	}
	if !ok {
		seed, err := json.Marshal(registryInfo(cfg))
		if err != nil {
			return err
		}
		return st.Put("registries", seed)
	}
	for _, ri := range stored {
		rc := config.RegistryConfig{Enabled: ri.Enabled, Upstreams: ri.Upstreams}
		switch ri.Ecosystem {
		case "pypi":
			cfg.Registries.PyPI = rc
		case "npm":
			cfg.Registries.NPM = rc
		case "maven":
			cfg.Registries.Maven = rc
		case "rubygems":
			cfg.Registries.RubyGems = rc
		case "docker":
			cfg.Registries.Docker = rc
		default:
			return fmt.Errorf("unknown ecosystem %q in stored registries", ri.Ecosystem)
		}
	}
	return nil
}

// toAuthUsers converts the config credential list into auth.User values.
func toAuthUsers(in []config.AuthUser) []auth.User {
	out := make([]auth.User, len(in))
	for i, u := range in {
		out[i] = auth.User{Username: u.Username, PasswordHash: u.PasswordHash}
	}
	return out
}

// registryInfo flattens the registry config for GET /api/registries.
func registryInfo(cfg *config.Config) []console.RegistryInfo {
	return []console.RegistryInfo{
		{Ecosystem: "pypi", Enabled: cfg.Registries.PyPI.Enabled, Upstreams: cfg.Registries.PyPI.Upstreams},
		{Ecosystem: "npm", Enabled: cfg.Registries.NPM.Enabled, Upstreams: cfg.Registries.NPM.Upstreams},
		{Ecosystem: "maven", Enabled: cfg.Registries.Maven.Enabled, Upstreams: cfg.Registries.Maven.Upstreams},
		{Ecosystem: "rubygems", Enabled: cfg.Registries.RubyGems.Enabled, Upstreams: cfg.Registries.RubyGems.Upstreams},
		{Ecosystem: "docker", Enabled: cfg.Registries.Docker.Enabled, Upstreams: cfg.Registries.Docker.Upstreams},
	}
}

// buildTelemetryStore initialises the SQLite-backed telemetry store on the
// shared database. Telemetry is SQLite-only: any schema error aborts startup.
func buildTelemetryStore(sdb *storage.DB, cfg *config.Config, logger zerolog.Logger) (*telemetry.Store, error) {
	store, err := telemetry.Open(sdb, cfg.Database.EventRetentionDays, cfg.Database.DailyRetentionDays, logger)
	if err != nil {
		return nil, fmt.Errorf("initialising telemetry store: %w", err)
	}
	logger.Info().Str("path", cfg.Database.Path).Msg("telemetry persistence enabled")
	return store, nil
}

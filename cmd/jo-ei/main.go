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

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/logx"
	"github.com/ggwpLab/Jo-ei/internal/metrics"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
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

	routes, err := buildProxyRoutes(cfg, shared, sc, up, policyRuntime, artifactCache, mx)
	if err != nil {
		return err
	}
	root, err := buildRootHandler(consoleDeps{
		cfg:         cfg,
		db:          sdb,
		settings:    settingsStore,
		store:       store,
		broadcaster: broadcaster,
		policy:      policyRuntime,
		cache:       artifactCache,
		health:      sc.health,
		logger:      logger,
		serverLog:   serverLog,
	}, proxy.NewMux(routes.handlers, routes.raw, logger))
	if err != nil {
		return err
	}

	metricsAddr := "disabled"
	if mx != nil {
		metricsAddr = cfg.Metrics.Listen + cfg.Metrics.Path
	}

	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      logx.Middleware(mx.WrapHandler(root, metrics.NewRouteFunc(routes.prefixes()))),
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
		Int("registries", routes.registryCount()).
		Int("malware_engines", sc.engineCount).
		Bool("cve", shared.cveScanner != nil).
		Str("mode", cfg.SupplyChain.Mode).
		Str("console", "/console/").
		Str("api", "/api/").
		Msg("Jōei starting")

	return serveAll(ctx, servers...)
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

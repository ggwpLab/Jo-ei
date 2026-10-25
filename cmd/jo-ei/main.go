// Command jo-ei is the Jōei supply-chain security proxy for package registries.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/logx"
	"github.com/ggwpLab/Jo-ei/internal/metrics"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
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

	st, err := openState(a, cfg, mx, logger, serverLog)
	if err != nil {
		return err
	}

	up, err := buildUpstream(cfg, mx, serverLog)
	if err != nil {
		return err
	}

	shared := sharedDeps{
		filter:         st.policy,
		cache:          cache.AsArtifactCache(st.cache),
		logger:         logger,
		recorder:       mx.WrapRecorder(&telemetry.Hub{Store: st.store, Broadcaster: st.broadcaster}),
		adapterClient:  up.adapter,
		downloadClient: up.download,
		throttles:      up.breaker,

		cveRecheckTTL:       time.Duration(cfg.Cache.Revalidation.CVETTLMinutes) * time.Minute,
		malwareRecheckTTL:   time.Duration(cfg.Cache.Revalidation.MalwareTTLMinutes) * time.Minute,
		metadataFilterMaxMB: cfg.Server.MetadataFilterMaxMB,
		tempDir:             st.tempDir,
	}

	if shared.cveRecheckTTL <= 0 && shared.malwareRecheckTTL <= 0 {
		serverLog.Warn().Msg("cache re-validation disabled: cached artifacts are never re-checked")
	} else {
		serverLog.Info().Dur("cve_ttl", shared.cveRecheckTTL).Dur("malware_ttl", shared.malwareRecheckTTL).
			Msg("lazy cache re-validation configured")
	}

	sc, err := buildScanners(a, cfg, st.profile, mx, serverLog)
	if err != nil {
		return err
	}
	shared.cveScanner = sc.cve
	shared.avScanner = sc.av
	if cfg.CVE.Enabled {
		shared.policy = st.policy
	}

	routes, err := buildProxyRoutes(cfg, shared, sc, up, st.policy, st.cache, mx)
	if err != nil {
		return err
	}
	root, err := buildRootHandler(consoleDeps{
		cfg:         cfg,
		db:          st.db,
		settings:    st.settings,
		store:       st.store,
		broadcaster: st.broadcaster,
		policy:      st.policy,
		cache:       st.cache,
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

	handler := httpx.BodyReadDeadline(root, httpx.DefaultBodyReadIdleTimeout)
	servers, err := bindServers(a, cfg, logx.Middleware(mx.WrapHandler(handler, metrics.NewRouteFunc(routes.prefixes()))), mx, serverLog)
	if err != nil {
		return err
	}
	// The main server is bound last. Ending the SSE streams at shutdown keeps
	// an open console tab from holding the drain until its deadline.
	servers[len(servers)-1].srv.RegisterOnShutdown(st.broadcaster.Close)

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

package main

import (
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/sca-proxy/sca-proxy/internal/cache"
	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "sca-proxy",
	Short: "SCA Proxy — transparent supply chain security proxy for package registries",
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

func runProxy(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	// Configure logger
	level, _ := zerolog.ParseLevel(cfg.Logging.Level)
	zerolog.SetGlobalLevel(level)
	logger := log.Logger

	if cfg.Logging.Format == "text" {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).
			With().Timestamp().Logger()
	}

	// Build local cache
	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:  cfg.Cache.Local.Path,
		MaxSizeGB: cfg.Cache.Local.MaxSizeGB,
		TTL:       24 * time.Hour,
	})
	if err != nil {
		return err
	}

	// Build SC filter. Allowlist file loading is added in Phase 2.
	scFilter := supplychain.NewFilter(cfg.SupplyChain, nil)

	// Build PyPI adapter (Phase 1 only; Phase 3 adds npm/Maven/Go)
	pypiAdapter := adapters.NewPyPIAdapter(cfg.Registries.PyPI.Upstream)

	// cacheAdapter bridges cache.LocalCache (returns *cache.CacheEntry) to
	// proxy.ArtifactCache (returns *proxy.ArtifactEntry), avoiding import cycle.
	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:  pypiAdapter,
		Filter:   scFilter,
		Cache:    &cacheAdapter{lc: localCache},
		Logger:   logger,
		Upstream: cfg.Registries.PyPI.Upstream,
	})

	logger.Info().
		Str("listen", cfg.Server.Listen).
		Str("upstream", cfg.Registries.PyPI.Upstream).
		Str("mode", cfg.SupplyChain.Mode).
		Msg("SCA Proxy starting")

	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      handler,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	return srv.ListenAndServe()
}

// cacheAdapter bridges cache.LocalCache to the proxy.ArtifactCache interface.
// cache.LocalCache.Get returns *cache.CacheEntry; proxy.ArtifactCache.Get must
// return *proxy.ArtifactEntry. Structural typing doesn't apply here.
type cacheAdapter struct {
	lc *cache.LocalCache
}

func (a *cacheAdapter) Get(ref *proxy.PackageRef) (*proxy.ArtifactEntry, bool) {
	entry, found := a.lc.Get(ref)
	if !found {
		return nil, false
	}
	return &proxy.ArtifactEntry{
		ArtifactPath: entry.ArtifactPath,
		ScanClean:    entry.ScanClean,
	}, true
}

func (a *cacheAdapter) Put(ref *proxy.PackageRef, tmpPath string, scanClean bool, scanJSON string) error {
	return a.lc.Put(ref, tmpPath, scanClean, scanJSON)
}

func (a *cacheAdapter) Invalidate(ref *proxy.PackageRef) error {
	return a.lc.Invalidate(ref)
}

package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sca-proxy/sca-proxy/internal/cache"
	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/policy"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/sca-proxy/sca-proxy/internal/scanner"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
	"github.com/spf13/cobra"
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

// sharedDeps groups dependencies shared across every per-registry handler.
type sharedDeps struct {
	filter     proxy.SCFilter
	cache      proxy.ArtifactCache
	logger     zerolog.Logger
	cveScanner proxy.CVEScanner
	policy     proxy.PolicyDecider
	avScanner  proxy.AVScanner
}

func runProxy(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	level, levelErr := zerolog.ParseLevel(cfg.Logging.Level)
	if levelErr != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	logger := log.Logger
	if cfg.Logging.Format == "text" {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).
			With().Timestamp().Logger()
	}
	if levelErr != nil {
		logger.Warn().Str("value", cfg.Logging.Level).Msg("unknown log level; defaulting to info")
	}

	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:  cfg.Cache.Local.Path,
		MaxSizeGB: cfg.Cache.Local.MaxSizeGB,
		TTL:       24 * time.Hour,
	})
	if err != nil {
		return err
	}

	profile, ok := cfg.Policy.Profiles[cfg.Policy.ActiveProfile]
	if !ok {
		return fmt.Errorf("active_profile %q not found in policy.profiles", cfg.Policy.ActiveProfile)
	}

	shared := sharedDeps{
		filter: supplychain.NewFilter(cfg.SupplyChain, nil),
		cache:  &cacheAdapter{lc: localCache},
		logger: logger,
	}

	// CVE scanner + policy (optional).
	if cfg.CVE.Enabled {
		baseURL := cfg.CVE.BaseURL
		if baseURL == "" {
			baseURL = "https://api.osv.dev"
		}
		ttl := time.Duration(cfg.CVE.CacheTTLMinutes) * time.Minute
		if ttl == 0 {
			ttl = 24 * time.Hour
		}
		shared.cveScanner = scanner.NewOSVScanner(baseURL, ttl)
		shared.policy = policy.NewEngine(cfg.CVE, profile)
	}

	// ClamAV scanner (optional; attached only when the profile blocks malware).
	if cfg.ClamAV.Enabled && profile.MalwareBlock {
		av, err := scanner.NewClamAVScanner(cfg.ClamAV.Address,
			time.Duration(cfg.ClamAV.TimeoutSeconds)*time.Second)
		if err != nil {
			return err
		}
		shared.avScanner = av
	} else if cfg.ClamAV.Enabled {
		logger.Warn().Str("active_profile", cfg.Policy.ActiveProfile).
			Msg("clamav.enabled is true but active profile has malware_block:false — AV scanner not attached")
	}

	// Build one handler per enabled registry, keyed by routing prefix.
	handlers := map[string]*proxy.Handler{}
	if cfg.Registries.PyPI.Enabled {
		handlers["pypi"] = buildHandler(adapters.NewPyPIAdapter(cfg.Registries.PyPI.Upstreams), shared)
	}
	if cfg.Registries.NPM.Enabled {
		handlers["npm"] = buildHandler(adapters.NewNPMAdapter(cfg.Registries.NPM.Upstreams), shared)
	}
	if cfg.Registries.Maven.Enabled {
		handlers["maven"] = buildHandler(adapters.NewMavenAdapter(cfg.Registries.Maven.Upstreams), shared)
	}

	if len(handlers) == 0 {
		return fmt.Errorf("no registries enabled; set at least one of registries.{pypi,npm,maven}.enabled: true")
	}

	mux := proxy.NewMux(handlers, logger)

	logger.Info().
		Str("listen", cfg.Server.Listen).
		Int("registries", len(handlers)).
		Bool("clamav", shared.avScanner != nil).
		Bool("cve", shared.cveScanner != nil).
		Str("mode", cfg.SupplyChain.Mode).
		Msg("SCA Proxy starting")

	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      mux,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}
	return srv.ListenAndServe()
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
	})
}

// cacheAdapter bridges cache.LocalCache to the proxy.ArtifactCache interface.
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

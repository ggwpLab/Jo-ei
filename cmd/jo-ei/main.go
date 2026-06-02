// Command jo-ei is the Jōei supply-chain security proxy for package registries.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var cfgFile string

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

	// Malware scanners (optional; attached only when the profile blocks malware).
	engineCount := 0
	if profile.MalwareBlock && len(cfg.Malware.Scanners) > 0 {
		scanners := make([]proxy.AVScanner, 0, len(cfg.Malware.Scanners))
		for _, sc := range cfg.Malware.Scanners {
			av, err := scanner.New(sc)
			if err != nil {
				return err
			}
			scanners = append(scanners, av)
		}
		shared.avScanner = scanner.NewMultiScanner(scanners...)
		engineCount = len(scanners)
	} else if len(cfg.Malware.Scanners) > 0 {
		logger.Warn().Str("active_profile", cfg.Policy.ActiveProfile).
			Msg("malware.scanners configured but active profile has malware_block:false — scanners not attached")
	}

	// Build the prefix→handler routing map from config.
	handlers := buildHandlers(cfg, shared)

	if len(handlers) == 0 {
		return fmt.Errorf("no registries enabled; set at least one of registries.{pypi,npm,maven,rubygems}.enabled: true")
	}

	// The yarn prefix is an alias of the npm handler, not a separate registry.
	registryCount := len(handlers)
	if _, ok := handlers["yarn"]; ok {
		registryCount--
	}

	mux := proxy.NewMux(handlers, logger)

	logger.Info().
		Str("listen", cfg.Server.Listen).
		Int("registries", registryCount).
		Int("malware_engines", engineCount).
		Bool("cve", shared.cveScanner != nil).
		Str("mode", cfg.SupplyChain.Mode).
		Msg("Jōei starting")

	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      mux,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}
	return srv.ListenAndServe()
}

// buildHandlers constructs the routing map of prefix→handler from config.
// The "yarn" prefix is an alias for the npm handler, since yarn speaks the npm
// registry protocol.
func buildHandlers(cfg *config.Config, shared sharedDeps) map[string]*proxy.Handler {
	handlers := map[string]*proxy.Handler{}
	if cfg.Registries.PyPI.Enabled {
		handlers["pypi"] = buildHandler(adapters.NewPyPIAdapter(cfg.Registries.PyPI.Upstreams), shared)
	}
	if cfg.Registries.NPM.Enabled {
		npmHandler := buildHandler(adapters.NewNPMAdapter(cfg.Registries.NPM.Upstreams), shared)
		handlers["npm"] = npmHandler
		handlers["yarn"] = npmHandler
	}
	if cfg.Registries.Maven.Enabled {
		handlers["maven"] = buildHandler(adapters.NewMavenAdapter(cfg.Registries.Maven.Upstreams), shared)
	}
	if cfg.Registries.RubyGems.Enabled {
		handlers["rubygems"] = buildHandler(adapters.NewRubyGemsAdapter(cfg.Registries.RubyGems.Upstreams), shared)
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

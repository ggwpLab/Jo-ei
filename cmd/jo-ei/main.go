// Command jo-ei is the Jōei supply-chain security proxy for package registries.
package main

import (
	"context"
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
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
	"github.com/ggwpLab/Jo-ei/web"
)

var cfgFile string

// eventHistorySize is the telemetry ring-buffer capacity backing the console
// request feed (process-lifetime, in-memory).
const eventHistorySize = 500

// defaultOSVBaseURL is used for both the live scanner and the console's
// scanner listing when cve.base_url is unset.
const defaultOSVBaseURL = "https://api.osv.dev"

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
	// the console can apply edits without restart (runtime-only; the YAML
	// config wins again after restart).
	policyRuntime := policy.NewRuntime(cfg.SupplyChain, cfg.CVE, profile, fileAllow)

	store := telemetry.NewStore(eventHistorySize)
	broadcaster := telemetry.NewBroadcaster()

	shared := sharedDeps{
		filter:   policyRuntime,
		cache:    &cacheAdapter{c: artifactCache},
		logger:   logger,
		recorder: &telemetry.Hub{Store: store, Broadcaster: broadcaster},
	}

	// CVE scanner + policy (optional).
	if cfg.CVE.Enabled {
		baseURL := cfg.CVE.BaseURL
		if baseURL == "" {
			baseURL = defaultOSVBaseURL
		}
		ttl := time.Duration(cfg.CVE.CacheTTLMinutes) * time.Minute
		if ttl == 0 {
			ttl = 24 * time.Hour
		}
		osvScanner := scanner.NewOSVScanner(baseURL, ttl)
		defer func() { _ = osvScanner.Close() }()
		shared.cveScanner = osvScanner
		shared.policy = policyRuntime
	}

	if !cfg.CVE.Enabled {
		logger.Warn().Msg("cve.enabled is false — console policy edits to cve_block_on and denylist have no effect (supply-chain mode/min-age/allowlist still apply)")
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
	root.Handle("/console/", authUsers.Middleware(web.ConsoleHandler()))
	root.Handle("/api/", authUsers.Middleware(console.NewHandler(console.Config{
		Store:         store,
		Broadcaster:   broadcaster,
		Policy:        policyRuntime,
		Cache:         artifactCache,
		CacheMaxBytes: int64(cfg.Cache.Local.MaxSizeGB) << 30,
		Registries:    registryInfo(cfg),
		Scanners:      scannerInfo(cfg, profile),
		Logger:        logger,
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
		Recorder:   shared.recorder,
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
	}
}

// scannerInfo lists configured scan engines for the overview (static config,
// no health probes this phase).
func scannerInfo(cfg *config.Config, profile config.PolicyProfile) []console.ScannerInfo {
	var out []console.ScannerInfo
	if cfg.CVE.Enabled {
		base := cfg.CVE.BaseURL
		if base == "" {
			base = defaultOSVBaseURL
		}
		out = append(out, console.ScannerInfo{Name: "osv.dev", Detail: base, Enabled: true})
	}
	for _, sc := range cfg.Malware.Scanners {
		out = append(out, console.ScannerInfo{Name: sc.Type, Detail: sc.Address, Enabled: profile.MalwareBlock})
	}
	return out
}

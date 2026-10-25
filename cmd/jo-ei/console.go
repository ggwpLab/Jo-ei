package main

import (
	"fmt"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/console"
	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
	"github.com/ggwpLab/Jo-ei/internal/users"
	"github.com/ggwpLab/Jo-ei/web"
)

// consoleDeps is what the admin console and its auth need from run.
type consoleDeps struct {
	cfg         *config.Config
	db          *storage.DB
	settings    *settings.Store
	store       *telemetry.Store
	broadcaster *telemetry.Broadcaster
	policy      *policy.Runtime
	cache       cache.Cache
	health      *health.Monitor
	logger      zerolog.Logger
	serverLog   zerolog.Logger
}

// buildRootHandler wraps proxyMux so the admin console is served at /console/
// while every other path (registry prefixes, /health) falls through to the
// proxy mux untouched. Keeping the console in a parent mux leaves the proxy
// package and its routing free of UI concerns.
func buildRootHandler(d consoleDeps, proxyMux http.Handler) (http.Handler, error) {
	cfg := d.cfg
	// Console users live in the database. On an empty table the initial
	// admin is created and its temporary password logged once.
	userStore, err := users.New(d.db)
	if err != nil {
		return nil, fmt.Errorf("console users: %w", err)
	}
	if err := ensureInitialAdmin(userStore, d.serverLog); err != nil {
		return nil, err
	}
	jwtSecret, err := resolveJWTSecret(cfg.Console.Auth.JWTSecret, d.settings, d.logger)
	if err != nil {
		return nil, err
	}
	signer, err := auth.NewSigner(jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("console auth: %w", err)
	}
	accessTTL, refreshTTL := authTTLs(cfg.Console.Auth)
	clientIP, err := httpx.NewClientIPResolver(cfg.Server.TrustedProxies, cfg.Server.ClientIPHeader, d.serverLog)
	if err != nil {
		return nil, fmt.Errorf("server.trusted_proxies: %w", err)
	}
	sessions := auth.NewSessions(userStore, signer, accessTTL, refreshTTL,
		auth.WithLoginLimiter(auth.NewLoginLimiter(nil)),
		auth.WithClientIP(clientIP.ClientIP),
		auth.WithLogger(d.logger))
	if sessions.Locked() {
		d.serverLog.Warn().Msg(`console locked — no enabled users; /api/ is disabled (HTTP 503) until an admin is restored with "jo-ei reset-admin-password"; the proxy continues to serve`)
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
	if p, ok := d.cache.(console.CachePurger); ok {
		cachePurger = p
	}
	runningRegistries := registryInfo(cfg)
	root.Handle("/api/", sessions.Middleware(console.NewHandler(console.Config{
		Store:               d.store,
		Broadcaster:         d.broadcaster,
		Policy:              d.policy,
		Cache:               d.cache,
		CacheMaxBytes:       int64(cfg.Cache.Local.MaxSizeGB) << 30,
		Purger:              cachePurger,
		CacheStaleAfterDays: staleDays,
		Registries:          runningRegistries,
		RegistryStore:       registrySettingsStore{s: d.settings},
		RunningRegistries:   runningRegistries,
		ImageScanEnabled:    cfg.ImageScan.Enabled,
		Health:              d.health,
		Users:               userStore,
		Logger:              d.logger,
	})))
	root.Handle("/", proxyMux)
	return root, nil
}

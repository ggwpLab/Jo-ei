package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/metrics"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

// state is the persistent and runtime state the proxy and console share.
type state struct {
	db          *storage.DB
	settings    *settings.Store
	cache       cache.Cache
	tempDir     string // download/layer temp files, on the cache volume
	profile     config.PolicyProfile
	policy      *policy.Runtime
	store       *telemetry.Store
	broadcaster *telemetry.Broadcaster
}

// openState opens the database, applies the stored registry overlay to cfg,
// opens the artifact cache, builds the runtime policy for the active profile
// and the telemetry store. Closers are registered on a.
func openState(a *app, cfg *config.Config, mx *metrics.Metrics, logger, serverLog zerolog.Logger) (state, error) {
	sdb, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return state{}, fmt.Errorf("opening database at %q: %w", cfg.Database.Path, err)
	}
	a.onClose(sdb.Close)

	settingsStore, err := settings.New(sdb)
	if err != nil {
		return state{}, err
	}

	if err := applyStoredRegistries(cfg, settingsStore); err != nil {
		return state{}, err
	}

	artifactCache, err := cache.New(cfg.Cache)
	if err != nil {
		return state{}, err
	}
	a.onClose(artifactCache.Close)
	mx.RegisterCache(artifactCache, int64(cfg.Cache.Local.MaxSizeGB)<<30)

	tempDir := filepath.Join(cfg.Cache.Local.Path, "tmp")
	if err := prepareTempDir(tempDir); err != nil {
		return state{}, fmt.Errorf("cache temp dir %q: %w", tempDir, err)
	}

	profile, ok := cfg.Policy.Profiles[cfg.Policy.ActiveProfile]
	if !ok {
		return state{}, fmt.Errorf("active_profile %q not found in policy.profiles", cfg.Policy.ActiveProfile)
	}

	var fileAllow []string
	if cfg.SupplyChain.AllowlistPath != "" {
		allowlist, err := supplychain.LoadAllowlist(cfg.SupplyChain.AllowlistPath)
		if err != nil {
			return state{}, err
		}
		fileAllow = allowlist.Entries()
	}

	// Runtime policy: engine + supply-chain filter behind an atomic swap so
	// the console can apply edits without restart. Edits now persist to the
	// shared SQLite database so they survive a restart.
	policyRuntime, err := policy.NewRuntimeWithStore(cfg.SupplyChain, cfg.CVE, profile, fileAllow, policySettingsStore{s: settingsStore})
	if err != nil {
		return state{}, err
	}

	store, err := buildTelemetryStore(sdb, cfg, logger)
	if err != nil {
		return state{}, err
	}
	serverLog.Info().Str("path", cfg.Database.Path).Msg("telemetry persistence enabled")
	a.onClose(store.Close)
	broadcaster := telemetry.NewBroadcaster()

	return state{
		db: sdb, settings: settingsStore, cache: artifactCache, tempDir: tempDir, profile: profile,
		policy: policyRuntime, store: store, broadcaster: broadcaster,
	}, nil
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

// prepareTempDir creates dir and removes the "jo-ei-*" temp files a previous
// run left behind when it stopped mid-download. Other files are left alone.
func prepareTempDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- holds public package artifacts under check
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "jo-ei-") {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

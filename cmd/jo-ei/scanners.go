package main

import (
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/metrics"
	"github.com/ggwpLab/Jo-ei/internal/proxy/dockerproxy"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
)

// defaultOSVBaseURL is used for both the live scanner and the console's
// scanner listing when cve.base_url is unset.
const defaultOSVBaseURL = "https://api.osv.dev"

// defaultMaxConcurrentScans bounds simultaneous malware scans when
// malware.max_concurrent_scans is unset. It roughly matches clamd's default
// worker pool so bursts don't queue past the per-scan deadline.
const defaultMaxConcurrentScans = 8

// scanners are the gate engines built from config, plus the health monitor
// that watches them.
type scanners struct {
	cve         gate.CVEScanner           // nil when cve.enabled is false
	av          gate.AVScanner            // concurrency-limited multi-engine; nil when not attached
	trivy       *dockerproxy.TrivyScanner // nil when image_scan is disabled
	health      *health.Monitor           // started
	engineCount int
}

// buildScanners builds the CVE, malware and image scanners and starts the
// health monitor over them. Closers for the OSV scanner and the monitor are
// registered on a.
func buildScanners(a *app, cfg *config.Config, profile config.PolicyProfile, mx *metrics.Metrics, serverLog zerolog.Logger) (scanners, error) {
	var sc scanners

	// CVE scanner (optional).
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
		a.onClose(osvScanner.Close)
		sc.cve = mx.WrapCVEScanner("osv", osvScanner)
	}

	if !cfg.CVE.Enabled {
		serverLog.Warn().Msg("cve.enabled is false — console policy edits to cve_block_on, allowlist_cve and denylist have no effect (supply-chain mode/min-age/allowlist_supply still apply)")
	}

	// Malware scanners (optional; attached only when the profile blocks malware).
	var avScanners []gate.AVScanner
	if profile.MalwareBlock && len(cfg.Malware.Scanners) > 0 {
		avScanners = make([]gate.AVScanner, 0, len(cfg.Malware.Scanners))
		for _, scfg := range cfg.Malware.Scanners {
			av, err := scanner.New(scfg)
			if err != nil {
				return scanners{}, err
			}
			avScanners = append(avScanners, av)
		}
		limit := cfg.Malware.MaxConcurrentScans
		if limit == 0 {
			limit = defaultMaxConcurrentScans
		}
		// avScanners stays unwrapped: the health monitor below type-asserts
		// scanner.Prober on it, which a metrics wrapper would hide.
		wrapped := make([]gate.AVScanner, len(avScanners))
		for i, av := range avScanners {
			wrapped[i] = mx.WrapAVScanner(cfg.Malware.Scanners[i].DisplayName(), cfg.Malware.Scanners[i].Type, av)
		}
		// Cap concurrent scans so download bursts don't overwhelm the engines'
		// worker pools and make clamd/ICAP responses time out.
		sc.av = scanner.NewLimitedScanner(scanner.NewMultiScanner(wrapped...), limit,
			scanner.WithWaitObserver(mx.ScanWaitObserver()))
		mx.SetScanConcurrencyLimit(limit)
		sc.engineCount = len(avScanners)
	} else if len(cfg.Malware.Scanners) > 0 {
		serverLog.Warn().Str("active_profile", cfg.Policy.ActiveProfile).
			Msg("malware.scanners configured but active profile has malware_block:false — scanners not attached")
	}

	// Image scanner (Trivy) for the Docker registry (optional).
	if cfg.ImageScan.Enabled {
		timeout := time.Duration(cfg.ImageScan.TimeoutSeconds) * time.Second
		sc.trivy = dockerproxy.NewTrivyScanner(cfg.ImageScan.TrivyServer, cfg.ImageScan.Scanners, timeout)
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
	scannerTypes := map[string]string{} // display name → type, for metric labels
	for i, scfg := range cfg.Malware.Scanners {
		scannerTypes[scfg.DisplayName()] = scfg.Type
		if profile.MalwareBlock && i < len(avScanners) {
			if pr, ok := avScanners[i].(scanner.Prober); ok {
				healthMon.AddActive(scfg.DisplayName(), scfg.Address, true, pr.Probe)
				continue
			}
		}
		healthMon.AddDisabled(scfg.DisplayName(), scfg.Address)
	}
	if cfg.ImageScan.Enabled && sc.trivy != nil {
		healthMon.AddActive("trivy", cfg.ImageScan.TrivyServer, true, sc.trivy.Probe)
	}
	healthMon.Start()
	a.onClose(healthMon.Close)
	mx.RegisterScannerHealth(healthMon.Snapshot, scannerTypes)
	sc.health = healthMon

	return sc, nil
}

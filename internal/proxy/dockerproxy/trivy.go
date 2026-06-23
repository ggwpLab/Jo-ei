package dockerproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// commandRunner runs an external command and returns its stdout. Injectable for
// tests; the default wraps exec.CommandContext.
type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// TrivyScanner runs the `trivy` CLI in client/server mode against a sidecar
// `trivy server` that holds the vulnerability DB. It implements ImageScanner.
type TrivyScanner struct {
	serverURL string
	scanners  string
	timeout   time.Duration
	run       commandRunner

	healthMu      sync.Mutex
	healthOK      bool
	healthHasData bool
	healthLatency time.Duration
}

// NewTrivyScanner creates a scanner that shells out to the real trivy binary.
func NewTrivyScanner(serverURL, scanners string, timeout time.Duration) *TrivyScanner {
	return NewTrivyScannerWithRunner(serverURL, scanners, timeout, execRunner)
}

// NewTrivyScannerWithRunner is NewTrivyScanner with an injectable command runner.
func NewTrivyScannerWithRunner(serverURL, scanners string, timeout time.Duration, run commandRunner) *TrivyScanner {
	if scanners == "" {
		scanners = "vuln,secret"
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &TrivyScanner{serverURL: serverURL, scanners: scanners, timeout: timeout, run: run}
}

// trivyReport is the subset of `trivy image --format json` output we consume.
type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			Severity        string `json:"Severity"`
			Title           string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ScanImage runs trivy against imageRef and maps findings to proxy.CVEFinding.
func (s *TrivyScanner) ScanImage(ctx context.Context, imageRef string) (*ImageScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	args := []string{
		"image", "--server", s.serverURL,
		"--format", "json", "--quiet",
		"--scanners", s.scanners,
		imageRef,
	}
	start := time.Now()
	out, err := s.run(ctx, "trivy", args...)
	s.recordHealth(time.Since(start), err)
	if err != nil {
		return nil, fmt.Errorf("running trivy for %s: %w", imageRef, err)
	}

	var report trivyReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("decoding trivy output: %w", err)
	}
	var findings []proxy.CVEFinding
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			findings = append(findings, proxy.CVEFinding{
				ID:       v.VulnerabilityID,
				Severity: proxy.ParseSeverity(v.Severity),
				Summary:  v.Title,
			})
		}
	}
	return &ImageScanResult{Findings: findings}, nil
}

func (s *TrivyScanner) recordHealth(latency time.Duration, err error) {
	s.healthMu.Lock()
	s.healthLatency = latency
	s.healthOK = err == nil
	s.healthHasData = true
	s.healthMu.Unlock()
}

// Health reports the outcome of the last scan as a passive sample.
func (s *TrivyScanner) Health() health.Sample {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	return health.Sample{OK: s.healthOK, Latency: s.healthLatency, HasData: s.healthHasData}
}

// Probe checks Trivy server reachability (trivy version --server <url>).
func (s *TrivyScanner) Probe(ctx context.Context) error {
	_, err := s.run(ctx, "trivy", "version", "--server", s.serverURL, "--format", "json")
	return err
}

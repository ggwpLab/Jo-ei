package dockerproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/health"
)

// commandRunner runs an external command and returns its stdout. Injectable for
// tests; the default wraps exec.CommandContext.
type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// execRunner runs name with args, capturing stdout and stderr separately. On a
// non-zero exit it folds the captured stderr into the returned error so the
// real tool message (e.g. why trivy failed) reaches the logs instead of an
// opaque "exit status 1".
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- binary and args come from wiring/config, never from request input
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%w: %s", err, msg)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

// TrivyScanner runs the `trivy` CLI in client/server mode against a sidecar
// `trivy server` that holds the vulnerability DB. It implements ImageScanner.
type TrivyScanner struct {
	serverURL  string
	scanners   string
	timeout    time.Duration
	run        commandRunner
	httpClient *http.Client

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
	return &TrivyScanner{
		serverURL:  serverURL,
		scanners:   scanners,
		timeout:    timeout,
		run:        run,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
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

// ScanImage runs trivy against imageRef and maps findings to gate.CVEFinding.
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
	var findings []gate.CVEFinding
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			findings = append(findings, gate.CVEFinding{
				ID:       v.VulnerabilityID,
				Severity: gate.ParseSeverity(v.Severity),
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

// Probe checks Trivy server liveness via its /healthz endpoint (returns "ok"
// with HTTP 200). Unlike `trivy version`, this is a real round-trip to the
// server, so the reported status and latency reflect actual reachability.
func (s *TrivyScanner) Probe(ctx context.Context) error {
	url := strings.TrimRight(s.serverURL, "/") + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("building trivy health request: %w", err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("probing trivy server: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("trivy health check returned status %d", resp.StatusCode)
	}
	return nil
}

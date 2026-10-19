package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/storage/storagetest"
)

func TestBuildTelemetryStore_FailsOnUnopenablePath(t *testing.T) {
	// Parent of the db path is a regular file, so MkdirAll fails → fail fast.
	// storage.Open is now the entry point that rejects the bad path.
	f := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o644))
	badPath := filepath.Join(f, "sub", "jo-ei.db")
	_, err := storage.Open(badPath)
	require.Error(t, err)
}

func TestBuildTelemetryStore_SucceedsOnValidPath(t *testing.T) {
	dir := storagetest.TempDir(t)
	cfg := &config.Config{}
	cfg.Database.Path = filepath.Join(dir, "jo-ei.db")
	sdb, err := storage.Open(cfg.Database.Path)
	require.NoError(t, err)
	defer func() { _ = sdb.Close() }()
	store, err := buildTelemetryStore(sdb, cfg, zerolog.Nop())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()
}

func TestBuildHandlers_YarnAliasesNPM(t *testing.T) {
	cfg := &config.Config{}
	cfg.Registries.NPM.Enabled = true
	cfg.Registries.NPM.Upstreams = []string{"https://registry.npmjs.org"}

	h := buildHandlers(cfg, sharedDeps{logger: zerolog.Nop()})

	assert.Contains(t, h, "npm")
	assert.Contains(t, h, "yarn")
	assert.Same(t, h["npm"], h["yarn"]) // same handler object
}

func TestBuildHandlers_RubyGemsRegisteredWhenEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Registries.RubyGems.Enabled = true
	cfg.Registries.RubyGems.Upstreams = []string{"https://rubygems.org"}

	h := buildHandlers(cfg, sharedDeps{logger: zerolog.Nop()})

	assert.Contains(t, h, "rubygems")
	assert.NotContains(t, h, "npm")
	assert.NotContains(t, h, "yarn")
}

// A CA file that cannot be parsed must stop startup with a message naming it,
// not surface later as an opaque x509 failure on the first artifact fetch.
func TestRunProxy_FailsFastOnUnusableCAFile(t *testing.T) {
	dir := t.TempDir()
	badCA := filepath.Join(dir, "not-a-cert.pem")
	if err := os.WriteFile(badCA, []byte("definitely not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}

	slash := filepath.ToSlash
	body := "" +
		"database:\n  path: " + slash(filepath.Join(dir, "jo-ei.db")) + "\n" +
		"cache:\n  backend: local\n  local:\n    path: " + slash(filepath.Join(dir, "cache")) + "\n" +
		"policy:\n  active_profile: default\n  profiles:\n    default:\n      cve_block: false\n" +
		"tls:\n  ca_files:\n    - " + slash(badCA) + "\n"
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	old := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = old })

	err := runProxy(nil, nil)
	if err == nil {
		t.Fatal("startup succeeded with an unusable CA file")
	}
	if !strings.Contains(err.Error(), "not-a-cert.pem") {
		t.Fatalf("err = %v, want it to name the offending CA file", err)
	}
}

// freeAddr returns a loopback address with a port that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// writeTestConfig writes a minimal config (pypi only, no CVE/image scanning)
// with malware_block on, listening on proxyAddr, with extra YAML appended, and returns its path.
func writeTestConfig(t *testing.T, proxyAddr, extra string) string {
	t.Helper()
	dir := t.TempDir()
	slash := filepath.ToSlash
	body := "" +
		"server:\n  listen: \"" + proxyAddr + "\"\n" +
		"database:\n  path: " + slash(filepath.Join(dir, "jo-ei.db")) + "\n" +
		"cache:\n  backend: local\n  local:\n    path: " + slash(filepath.Join(dir, "cache")) + "\n    max_size_gb: 1\n" +
		"registries:\n  pypi:\n    enabled: true\n    upstreams: [\"https://pypi.org/simple\"]\n" +
		"policy:\n  active_profile: default\n  profiles:\n    default:\n      malware_block: true\n" +
		"logging:\n  level: error\n" +
		extra
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))
	return cfgPath
}

// startRun boots run in the background and returns a func that cancels it and
// returns its error.
func startRun(t *testing.T, cfgPath string) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() { ch <- run(ctx, cfgPath) }()
	var once sync.Once
	var runErr error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case runErr = <-ch:
			case <-time.After(10 * time.Second):
				t.Fatal("run did not return after cancel")
			}
		})
		return runErr
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

// get fetches url, retrying until the server answers or the deadline passes.
func get(t *testing.T, url string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := client.Get(url)
		if err == nil {
			b, rerr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, rerr)
			return resp.StatusCode, string(b)
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET %s: %v", url, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func metricsYAML(addr string) string {
	return "metrics:\n  enabled: true\n  listen: \"" + addr + "\"\n  path: /metrics\n"
}

func TestRunProxy_MetricsOnSeparateListener(t *testing.T) {
	proxyAddr, metricsAddr := freeAddr(t), freeAddr(t)
	stop := startRun(t, writeTestConfig(t, proxyAddr, metricsYAML(metricsAddr)))

	code, body := get(t, "http://"+metricsAddr+"/metrics")
	assert.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, "jo_ei_build_info")

	code, body = get(t, "http://"+proxyAddr+"/metrics")
	assert.Equal(t, http.StatusNotFound, code)
	assert.Contains(t, body, "unknown_registry")

	code, _ = get(t, "http://"+proxyAddr+"/health")
	assert.Equal(t, http.StatusOK, code)
	_, body = get(t, "http://"+metricsAddr+"/metrics")
	assert.Contains(t, body, `jo_ei_http_requests_total{code="200",method="GET",route="health"}`)

	require.NoError(t, stop())
}

func TestRunProxy_MetricsPortInUse(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = busy.Close() }()

	proxyAddr := freeAddr(t)
	cfgPath := writeTestConfig(t, proxyAddr, metricsYAML(busy.Addr().String()))
	// The timeout only bounds a regression where startup wrongly succeeds.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = run(ctx, cfgPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metrics.listen")
	// The proxy must not be left accepting traffic.
	_, err = net.DialTimeout("tcp", proxyAddr, time.Second)
	assert.Error(t, err)
}

func TestRunProxy_MetricsDisabled(t *testing.T) {
	proxyAddr, metricsAddr := freeAddr(t), freeAddr(t)
	extra := "metrics:\n  enabled: false\n  listen: \"" + metricsAddr + "\"\n"
	stop := startRun(t, writeTestConfig(t, proxyAddr, extra))

	code, _ := get(t, "http://"+proxyAddr+"/health") // wait for startup
	require.Equal(t, http.StatusOK, code)
	_, err := net.DialTimeout("tcp", metricsAddr, time.Second)
	assert.Error(t, err, "nothing may listen on metrics.listen when disabled")

	require.NoError(t, stop())
}

// fakeClamd answers every connection's PING with PONG, enough for the health
// monitor's active probe.
func fakeClamd(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("PONG\x00"))
			}()
		}
	}()
	return ln.Addr().String()
}

// The AV scanners handed to the health monitor must stay the unwrapped
// concrete ones: wrapping them for metrics would hide scanner.Prober and turn
// the engine "off". jo_ei_scanner_up is only emitted for an enabled, probed
// scanner, so seeing it at 1 proves the probe is still registered.
func TestRunProxy_AVProbeStillRegistered(t *testing.T) {
	proxyAddr, metricsAddr := freeAddr(t), freeAddr(t)
	extra := metricsYAML(metricsAddr) +
		"malware:\n  scanners:\n    - type: clamav\n      address: \"tcp:" + fakeClamd(t) + "\"\n"
	stop := startRun(t, writeTestConfig(t, proxyAddr, extra))

	want := `jo_ei_scanner_up{scanner="clamav"} 1`
	deadline := time.Now().Add(10 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		_, body = get(t, "http://"+metricsAddr+"/metrics")
		if strings.Contains(body, want) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.Contains(t, body, want)

	require.NoError(t, stop())
}

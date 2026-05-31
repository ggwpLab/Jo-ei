# Phase 3 Implementation Plan — ClamAV Scanner + npm/Maven Adapters

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ClamAV malware scanning, npm and Maven registry adapters, and a path-prefix router so one sca-proxy instance serves PyPI, npm, and Maven.

**Architecture:** A new `proxy.AVScanner` interface is implemented by a clamd INSTREAM client; the handler runs it after download, before caching, and fails closed. Two new `RegistryAdapter`s (npm, Maven) follow the existing PyPI adapter pattern. A new `proxy.Mux` dispatches by path prefix (`/pypi`, `/npm`, `/maven`), strips the prefix, and delegates to a per-registry handler that shares one cache/filter/scanner set.

**Tech Stack:** Go 1.25, stdlib `net`/`net/http`/`encoding/binary`, `testify`, a TCP mock for clamd. No new external dependencies. Module path `github.com/sca-proxy/sca-proxy`.

**Design doc:** `docs/superpowers/specs/2026-05-31-phase3-clamav-npm-maven-design.md`

**Environment:** Go 1.25.10 lives at `/home/neody/go-sdk/go/bin` and is NOT on `PATH` by default. Every Go command below is prefixed with the PATH export. Repo root is `/home/neody/Jo-ei`.

---

## File Map

```
internal/
├── proxy/
│   ├── adapter.go          # MODIFY: add AVResult + AVScanner interface
│   ├── handler.go          # MODIFY: add AVScanner field + AV step + malware response
│   ├── handler_test.go     # MODIFY: add mockAVScanner + 3 AV tests
│   ├── mux.go              # CREATE: path-prefix router
│   ├── mux_test.go         # CREATE: router tests
│   └── adapters/
│       ├── npm.go          # CREATE: npm RegistryAdapter
│       ├── npm_test.go     # CREATE
│       ├── maven.go        # CREATE: Maven RegistryAdapter
│       └── maven_test.go   # CREATE
├── scanner/
│   ├── clamav.go               # CREATE: clamd INSTREAM client (proxy.AVScanner)
│   ├── clamav_test.go          # CREATE: black-box, TCP mock clamd
│   └── clamav_internal_test.go # CREATE: white-box, parse helpers
├── config/
│   ├── config.go           # MODIFY: add ClamAVConfig
│   └── config_test.go      # MODIFY: add ClamAV section test
cmd/sca-proxy/main.go        # MODIFY: build adapters + AV scanner + CVE/policy + Mux
config.yaml                  # MODIFY: clamav section, enable npm/maven
integration/phase3_test.go   # CREATE: end-to-end with mock clamd/npm/maven
README.md                    # MODIFY: prefix URLs + malware block response
```

---

## Task 1: AVScanner interface + AVResult type

**Files:**
- Modify: `internal/proxy/adapter.go` (append at end of file)

This is an interface/type-only change. No dedicated test (consumers are tested in Tasks 2 and 4). It must compile.

- [ ] **Step 1: Append the AV types to `internal/proxy/adapter.go`**

Append after the `SCFilter` interface (the last declaration in the file):

```go

// ── Antivirus / malware-scan types ───────────────────────────────────────────

// AVResult records the outcome of an antivirus scan of a single file.
type AVResult struct {
	Clean     bool   // true iff no malware signature matched
	Signature string // signature name when infected, "" otherwise
}

// AVScanner scans a file on disk for malware.
// Implementations must be safe for concurrent use.
type AVScanner interface {
	Scan(ctx context.Context, filePath string) (*AVResult, error)
}
```

- [ ] **Step 2: Verify it compiles**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go build ./internal/proxy/...
```

Expected: no output, no errors.

- [ ] **Step 3: Commit**

```bash
cd /home/neody/Jo-ei
git add internal/proxy/adapter.go
git commit -m "feat: add AVResult and AVScanner interface to proxy"
```

---

## Task 2: ClamAV INSTREAM client

**Files:**
- Create: `internal/scanner/clamav.go`
- Create: `internal/scanner/clamav_test.go` (black-box, `package scanner_test`)
- Create: `internal/scanner/clamav_internal_test.go` (white-box, `package scanner`)

- [ ] **Step 1: Write the white-box failing test for the parse helpers**

Create `internal/scanner/clamav_internal_test.go`:

```go
package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseClamAVAddress(t *testing.T) {
	cases := []struct {
		in          string
		wantNetwork string
		wantAddr    string
		wantErr     bool
	}{
		{"unix:///var/run/clamav/clamd.sock", "unix", "/var/run/clamav/clamd.sock", false},
		{"tcp:127.0.0.1:3310", "tcp", "127.0.0.1:3310", false},
		{"http://nope", "", "", true},
		{"", "", "", true},
	}
	for _, c := range cases {
		network, addr, err := parseClamAVAddress(c.in)
		if c.wantErr {
			assert.Error(t, err, "address %q", c.in)
			continue
		}
		require.NoError(t, err, "address %q", c.in)
		assert.Equal(t, c.wantNetwork, network, "network for %q", c.in)
		assert.Equal(t, c.wantAddr, addr, "addr for %q", c.in)
	}
}

func TestParseClamAVResponse(t *testing.T) {
	clean, err := parseClamAVResponse("stream: OK\x00")
	require.NoError(t, err)
	assert.True(t, clean.Clean)
	assert.Equal(t, "", clean.Signature)

	found, err := parseClamAVResponse("stream: Eicar-Test-Signature FOUND\x00")
	require.NoError(t, err)
	assert.False(t, found.Clean)
	assert.Equal(t, "Eicar-Test-Signature", found.Signature)

	_, err = parseClamAVResponse("INSTREAM size limit exceeded. ERROR\x00")
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/scanner/... -run "TestParseClamAV" -v
```

Expected: FAIL — `parseClamAVAddress`/`parseClamAVResponse` undefined.

- [ ] **Step 3: Implement the clamd client**

Create `internal/scanner/clamav.go`:

```go
package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// clamavChunkSize is the size of each INSTREAM data chunk sent to clamd.
const clamavChunkSize = 8192

// ClamAVScanner is a clamd client that scans files via the INSTREAM command.
// It implements proxy.AVScanner.
type ClamAVScanner struct {
	network string // "unix" or "tcp"
	addr    string
	timeout time.Duration
}

// NewClamAVScanner creates a scanner for the given clamd address.
// address is "unix:///var/run/clamav/clamd.sock" or "tcp:host:3310".
func NewClamAVScanner(address string, timeout time.Duration) (*ClamAVScanner, error) {
	network, addr, err := parseClamAVAddress(address)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &ClamAVScanner{network: network, addr: addr, timeout: timeout}, nil
}

// parseClamAVAddress splits "unix:///path" or "tcp:host:port" into (network, addr).
func parseClamAVAddress(address string) (network, addr string, err error) {
	switch {
	case strings.HasPrefix(address, "unix://"):
		return "unix", strings.TrimPrefix(address, "unix://"), nil
	case strings.HasPrefix(address, "tcp:"):
		return "tcp", strings.TrimPrefix(address, "tcp:"), nil
	default:
		return "", "", fmt.Errorf("unsupported clamav address %q (want unix:// or tcp:)", address)
	}
}

// Scan implements proxy.AVScanner using the clamd INSTREAM protocol.
func (s *ClamAVScanner) Scan(ctx context.Context, filePath string) (*proxy.AVResult, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening artifact for scan: %w", err)
	}
	defer f.Close()

	dialer := net.Dialer{Timeout: s.timeout}
	conn, err := dialer.DialContext(ctx, s.network, s.addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to clamd: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(s.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// "z" prefix = NULL-terminated command.
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return nil, fmt.Errorf("sending INSTREAM command: %w", err)
	}

	// Stream the file as length-prefixed chunks.
	buf := make([]byte, clamavChunkSize)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			var sizeBuf [4]byte
			binary.BigEndian.PutUint32(sizeBuf[:], uint32(n))
			if _, err := conn.Write(sizeBuf[:]); err != nil {
				return nil, fmt.Errorf("sending chunk size: %w", err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return nil, fmt.Errorf("sending chunk data: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("reading artifact: %w", readErr)
		}
	}

	// Zero-length chunk terminates the stream.
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return nil, fmt.Errorf("sending stream terminator: %w", err)
	}

	respBytes, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("reading clamd response: %w", err)
	}
	return parseClamAVResponse(string(respBytes))
}

// parseClamAVResponse interprets a clamd INSTREAM reply.
// "stream: OK" → clean; "stream: <sig> FOUND" → infected; anything else → error.
func parseClamAVResponse(resp string) (*proxy.AVResult, error) {
	trimmed := strings.TrimRight(resp, "\x00\n ")
	switch {
	case strings.HasSuffix(trimmed, "OK"):
		return &proxy.AVResult{Clean: true}, nil
	case strings.HasSuffix(trimmed, "FOUND"):
		sig := strings.TrimSuffix(trimmed, " FOUND")
		if idx := strings.Index(sig, ": "); idx != -1 {
			sig = sig[idx+2:]
		}
		return &proxy.AVResult{Clean: false, Signature: strings.TrimSpace(sig)}, nil
	default:
		return nil, fmt.Errorf("clamd error response: %q", trimmed)
	}
}
```

- [ ] **Step 4: Run the white-box test to verify it passes**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/scanner/... -run "TestParseClamAV" -v
```

Expected: PASS.

- [ ] **Step 5: Write the black-box Scan test with a mock clamd server**

Create `internal/scanner/clamav_test.go`:

```go
package scanner_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockClamd starts a TCP server that consumes an INSTREAM request and then
// writes the given canned response. Returns a "tcp:host:port" address.
func newMockClamd(t *testing.T, response string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				consumeINSTREAM(c)
				c.Write([]byte(response))
			}(conn)
		}
	}()
	return "tcp:" + ln.Addr().String()
}

// consumeINSTREAM reads the zINSTREAM command and its length-prefixed chunks
// up to (and including) the zero-length terminator.
func consumeINSTREAM(c net.Conn) {
	r := bufio.NewReader(c)
	if _, err := r.ReadBytes(0x00); err != nil { // command up to NUL
		return
	}
	for {
		var size uint32
		if err := binary.Read(r, binary.BigEndian, &size); err != nil {
			return
		}
		if size == 0 {
			return
		}
		if _, err := io.CopyN(io.Discard, r, int64(size)); err != nil {
			return
		}
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifact.bin")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

func TestClamAVScanner_CleanFile(t *testing.T) {
	addr := newMockClamd(t, "stream: OK\x00")
	sc, err := scanner.NewClamAVScanner(addr, 5*time.Second)
	require.NoError(t, err)

	res, err := sc.Scan(context.Background(), writeTempFile(t, "harmless content"))
	require.NoError(t, err)
	assert.True(t, res.Clean)
	assert.Equal(t, "", res.Signature)
}

func TestClamAVScanner_InfectedFile(t *testing.T) {
	addr := newMockClamd(t, "stream: Eicar-Test-Signature FOUND\x00")
	sc, err := scanner.NewClamAVScanner(addr, 5*time.Second)
	require.NoError(t, err)

	res, err := sc.Scan(context.Background(), writeTempFile(t, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"))
	require.NoError(t, err)
	assert.False(t, res.Clean)
	assert.Equal(t, "Eicar-Test-Signature", res.Signature)
}

func TestClamAVScanner_ErrorResponse(t *testing.T) {
	addr := newMockClamd(t, "INSTREAM size limit exceeded. ERROR\x00")
	sc, err := scanner.NewClamAVScanner(addr, 5*time.Second)
	require.NoError(t, err)

	_, err = sc.Scan(context.Background(), writeTempFile(t, "content"))
	assert.Error(t, err)
}

func TestClamAVScanner_ConnectionRefused(t *testing.T) {
	// Port 1 on loopback is not listening — Dial should fail.
	sc, err := scanner.NewClamAVScanner("tcp:127.0.0.1:1", 1*time.Second)
	require.NoError(t, err)

	_, err = sc.Scan(context.Background(), writeTempFile(t, "content"))
	assert.Error(t, err)
}
```

- [ ] **Step 6: Run the full scanner suite**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/scanner/... -v -race
```

Expected: PASS — all clamav tests and the existing osv tests pass.

- [ ] **Step 7: Commit**

```bash
cd /home/neody/Jo-ei
git add internal/scanner/clamav.go internal/scanner/clamav_test.go internal/scanner/clamav_internal_test.go
git commit -m "feat: add ClamAV INSTREAM scanner (proxy.AVScanner)"
```

---

## Task 3: ClamAVConfig

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go` (append a test)
- Modify: `config.yaml`

- [ ] **Step 1: Write the failing test**

Append to `internal/config/config_test.go`:

```go
func TestLoadConfig_ClamAVSection(t *testing.T) {
	path := writeTempConfig(t, `
server:
  listen: ":8080"
clamav:
  enabled: true
  address: "unix:///var/run/clamav/clamd.sock"
  timeout_seconds: 45
`)
	cfg, err := config.Load(path)
	require.NoError(t, err)

	assert.True(t, cfg.ClamAV.Enabled)
	assert.Equal(t, "unix:///var/run/clamav/clamd.sock", cfg.ClamAV.Address)
	assert.Equal(t, 45, cfg.ClamAV.TimeoutSeconds)
}
```

Note: this reuses the existing `writeTempConfig` helper already defined in `internal/config/config_test.go` (line 67).

- [ ] **Step 2: Run test to verify it fails**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/config/... -run TestLoadConfig_ClamAVSection -v
```

Expected: FAIL — `cfg.ClamAV` undefined.

- [ ] **Step 3: Add ClamAVConfig to `internal/config/config.go`**

Add the field to the `Config` struct (after the `CVE CVEConfig` line):

```go
	ClamAV      ClamAVConfig      `mapstructure:"clamav"`
```

Add the new type (after the `CVEConfig` type definition):

```go
// ClamAVConfig configures the ClamAV malware scanner (clamd).
type ClamAVConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	Address        string `mapstructure:"address"`         // "unix:///var/run/clamav/clamd.sock" or "tcp:host:3310"
	TimeoutSeconds int    `mapstructure:"timeout_seconds"` // default 30
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/config/... -v
```

Expected: PASS.

- [ ] **Step 5: Update `config.yaml`**

In `config.yaml`, change the `registries` block so npm and Maven are enabled:

```yaml
registries:
  pypi:
    upstream: "https://pypi.org"
    enabled: true
  npm:
    upstream: "https://registry.npmjs.org"
    enabled: true
  maven:
    upstream: "https://repo1.maven.org/maven2"
    enabled: true
```

Add a `clamav` section after the `cve` section:

```yaml
clamav:
  enabled: true
  address: "unix:///var/run/clamav/clamd.sock"
  timeout_seconds: 30
```

- [ ] **Step 6: Commit**

```bash
cd /home/neody/Jo-ei
git add internal/config/config.go internal/config/config_test.go config.yaml
git commit -m "feat: add ClamAVConfig and enable npm/maven registries in config"
```

---

## Task 4: Wire AVScanner into the handler pipeline

**Files:**
- Modify: `internal/proxy/handler.go`
- Modify: `internal/proxy/handler_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/proxy/handler_test.go`:

```go
// ─── mock AV scanner ──────────────────────────────────────────────────────

type mockAVScanner struct {
	result *proxy.AVResult
	err    error
}

func (m *mockAVScanner) Scan(_ context.Context, _ string) (*proxy.AVResult, error) {
	return m.result, m.err
}

// setupTestProxyAV wires an AV scanner into the handler (no CVE scanner).
func setupTestProxyAV(t *testing.T, upstream *httptest.Server, av proxy.AVScanner) *httptest.Server {
	t.Helper()
	filter := supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil)
	handler := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:   adapters.NewPyPIAdapter(upstream.URL),
		Filter:    filter,
		Cache:     newFakeCache(),
		Logger:    zerolog.Nop(),
		Upstream:  upstream.URL,
		AVScanner: av,
	})
	return httptest.NewServer(handler)
}

func TestHandler_MalwareReturns403(t *testing.T) {
	upstream := makeUpstream(t, "evil-pkg", "1.0.0", 48)
	defer upstream.Close()

	av := &mockAVScanner{result: &proxy.AVResult{Clean: false, Signature: "Win.Test.EICAR"}}
	srv := setupTestProxyAV(t, upstream, av)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/e/evil-pkg/evil_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "package_blocked", body["error"])
	assert.Equal(t, "malware_found", body["reason"])
	assert.Equal(t, "Win.Test.EICAR", body["signature"])
}

func TestHandler_AVScannerErrorFailsClosed(t *testing.T) {
	upstream := makeUpstream(t, "pkg", "1.0.0", 48)
	defer upstream.Close()

	av := &mockAVScanner{err: fmt.Errorf("clamd unavailable")}
	srv := setupTestProxyAV(t, upstream, av)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/p/pkg/pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandler_CleanArtifactPassesAV(t *testing.T) {
	upstream := makeUpstream(t, "safe-pkg", "1.0.0", 48)
	defer upstream.Close()

	av := &mockAVScanner{result: &proxy.AVResult{Clean: true}}
	srv := setupTestProxyAV(t, upstream, av)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/packages/py3/s/safe-pkg/safe_pkg-1.0.0-py3-none-any.whl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/proxy/... -run "TestHandler_Malware|TestHandler_AVScanner|TestHandler_CleanArtifact" -v
```

Expected: FAIL — `HandlerConfig.AVScanner` undefined.

- [ ] **Step 3: Add the AVScanner field to `HandlerConfig`**

In `internal/proxy/handler.go`, add to the `HandlerConfig` struct (after the `Policy` field):

```go
	AVScanner  AVScanner     // optional; nil disables malware scanning
```

- [ ] **Step 4: Insert the AV scan step in `ServeHTTP`**

In `internal/proxy/handler.go`, find the block that downloads to a temp file and caches it. Replace this existing block:

```go
	defer os.Remove(tmpPath)

	// Cache the artifact.
	// Phase 1: scanClean=true (no AV scanner yet).
	// Phase 3 will run AVScanner here before caching.
	if err := h.cfg.Cache.Put(ref, tmpPath, true, ""); err != nil {
```

with:

```go
	defer os.Remove(tmpPath)

	// Antivirus scan — after download, before caching (fail-closed on error).
	if h.cfg.AVScanner != nil {
		avResult, err := h.cfg.AVScanner.Scan(ctx, tmpPath)
		if err != nil {
			log.Error().Err(err).Msg("AV scan failed")
			h.writeError(w, requestID, ref, http.StatusServiceUnavailable, "av_scan_error")
			return
		}
		if !avResult.Clean {
			log.Warn().Str("signature", avResult.Signature).Msg("malware detected")
			h.writeMalwareBlockedResponse(w, requestID, ref, avResult.Signature)
			return
		}
	}

	// Cache the artifact (scan passed).
	if err := h.cfg.Cache.Put(ref, tmpPath, true, ""); err != nil {
```

- [ ] **Step 5: Add the malware block response method**

In `internal/proxy/handler.go`, add at the end of the file:

```go
// writeMalwareBlockedResponse sends a 403 Forbidden response for a malware hit.
func (h *Handler) writeMalwareBlockedResponse(w http.ResponseWriter, requestID string, ref *PackageRef, signature string) {
	body := map[string]any{
		"error":      "package_blocked",
		"package":    ref.Name,
		"version":    ref.Version,
		"reason":     "malware_found",
		"signature":  signature,
		"blocked_by": []string{"malware_scanner"},
		"request_id": requestID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(body)
}
```

- [ ] **Step 6: Run all proxy tests to verify they pass**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/proxy/... -v -race
```

Expected: PASS — new AV tests plus all existing handler/adapter tests.

- [ ] **Step 7: Commit**

```bash
cd /home/neody/Jo-ei
git add internal/proxy/handler.go internal/proxy/handler_test.go
git commit -m "feat: run AVScanner in handler pipeline, block malware with 403"
```

---

## Task 5: npm adapter

**Files:**
- Create: `internal/proxy/adapters/npm.go`
- Create: `internal/proxy/adapters/npm_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/adapters/npm_test.go`:

```go
package adapters_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNPMAdapter_NormalizeRequest_Tarball(t *testing.T) {
	a := adapters.NewNPMAdapter("https://registry.npmjs.org")

	r := httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-4.17.21.tgz", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "npm", ref.Ecosystem)
	assert.Equal(t, "lodash", ref.Name)
	assert.Equal(t, "4.17.21", ref.Version)
}

func TestNPMAdapter_NormalizeRequest_ScopedTarball(t *testing.T) {
	a := adapters.NewNPMAdapter("https://registry.npmjs.org")

	r := httptest.NewRequest(http.MethodGet, "/@babel/core/-/core-7.24.0.tgz", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "@babel/core", ref.Name)
	assert.Equal(t, "7.24.0", ref.Version)
}

func TestNPMAdapter_NormalizeRequest_MetadataNotIntercepted(t *testing.T) {
	a := adapters.NewNPMAdapter("https://registry.npmjs.org")

	r := httptest.NewRequest(http.MethodGet, "/lodash", nil)
	_, ok := a.NormalizeRequest(r)
	assert.False(t, ok)
}

func TestNPMAdapter_FetchMetadata(t *testing.T) {
	publishedAt := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/lodash", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"time": map[string]any{
				"4.17.21": publishedAt.Format(time.RFC3339),
			},
			"versions": map[string]any{
				"4.17.21": map[string]any{
					"license": "MIT",
					"dist":    map[string]any{"shasum": "abc123sha1"},
				},
			},
		})
	}))
	defer srv.Close()

	a := adapters.NewNPMAdapter(srv.URL)
	ref := &proxy.PackageRef{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)

	assert.WithinDuration(t, publishedAt, meta.PublishedAt, time.Second)
	assert.Equal(t, "MIT", meta.License)
	assert.Equal(t, "abc123sha1", meta.Checksum)
}

func TestNPMAdapter_FetchMetadata_VersionMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"time": map[string]any{}, "versions": map[string]any{}})
	}))
	defer srv.Close()

	a := adapters.NewNPMAdapter(srv.URL)
	ref := &proxy.PackageRef{Ecosystem: "npm", Name: "lodash", Version: "9.9.9"}
	_, err := a.FetchMetadata(context.Background(), ref)
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/proxy/adapters/... -run TestNPMAdapter -v
```

Expected: FAIL — `adapters.NewNPMAdapter` undefined.

- [ ] **Step 3: Implement the npm adapter**

Create `internal/proxy/adapters/npm.go`:

```go
package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// npmMetadata is the subset of the npm registry document we consume.
type npmMetadata struct {
	Time     map[string]string `json:"time"`
	Versions map[string]struct {
		License string `json:"license"`
		Dist    struct {
			Shasum string `json:"shasum"`
		} `json:"dist"`
	} `json:"versions"`
}

// NPMAdapter implements proxy.RegistryAdapter for the npm registry.
type NPMAdapter struct {
	upstream   string
	httpClient *http.Client
}

// NewNPMAdapter creates an npm adapter pointing at the given upstream URL.
func NewNPMAdapter(upstream string) *NPMAdapter {
	return &NPMAdapter{
		upstream:   strings.TrimRight(upstream, "/"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *NPMAdapter) Name() string { return "npm" }

// NormalizeRequest intercepts tarball downloads (path contains "/-/" and ends ".tgz").
// Metadata documents (e.g. "/lodash") are proxied transparently.
func (a *NPMAdapter) NormalizeRequest(r *http.Request) (*proxy.PackageRef, bool) {
	path := r.URL.Path
	if !strings.HasSuffix(path, ".tgz") {
		return nil, false
	}
	idx := strings.Index(path, "/-/")
	if idx == -1 {
		return nil, false
	}
	name := strings.TrimPrefix(path[:idx], "/")
	filename := path[idx+len("/-/"):]
	version, ok := parseNPMVersion(name, filename)
	if !ok {
		return nil, false
	}
	return &proxy.PackageRef{Ecosystem: "npm", Name: name, Version: version}, true
}

// parseNPMVersion extracts the version from a tarball filename "<unscoped>-<version>.tgz".
func parseNPMVersion(name, filename string) (string, bool) {
	base := strings.TrimSuffix(filename, ".tgz")
	unscoped := name
	if idx := strings.LastIndex(name, "/"); idx != -1 {
		unscoped = name[idx+1:]
	}
	prefix := unscoped + "-"
	if !strings.HasPrefix(base, prefix) {
		return "", false
	}
	return strings.TrimPrefix(base, prefix), true
}

// FetchMetadata reads the npm registry document and resolves the version's
// publish time, license, and shasum.
func (a *NPMAdapter) FetchMetadata(ctx context.Context, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	apiURL := a.upstream + "/" + ref.Name

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building npm metadata request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching npm metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm returned HTTP %d for %s", resp.StatusCode, ref.Name)
	}

	var doc npmMetadata
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding npm response: %w", err)
	}

	publishedStr, ok := doc.Time[ref.Version]
	if !ok {
		return nil, fmt.Errorf("version %s not found in npm metadata for %s", ref.Version, ref.Name)
	}
	publishedAt, err := time.Parse(time.RFC3339, publishedStr)
	if err != nil {
		return nil, fmt.Errorf("parsing npm publish time %q: %w", publishedStr, err)
	}

	versionInfo := doc.Versions[ref.Version]
	return &proxy.PackageMetadata{
		PublishedAt: publishedAt.UTC(),
		License:     versionInfo.License,
		Checksum:    versionInfo.Dist.Shasum,
	}, nil
}

// UpstreamURL returns the upstream URL for a proxy request.
func (a *NPMAdapter) UpstreamURL(r *http.Request) string {
	return a.upstream + r.URL.RequestURI()
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/proxy/adapters/... -run TestNPMAdapter -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/neody/Jo-ei
git add internal/proxy/adapters/npm.go internal/proxy/adapters/npm_test.go
git commit -m "feat: add npm registry adapter"
```

---

## Task 6: Maven adapter

**Files:**
- Create: `internal/proxy/adapters/maven.go`
- Create: `internal/proxy/adapters/maven_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/adapters/maven_test.go`:

```go
package adapters_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMavenAdapter_NormalizeRequest_Jar(t *testing.T) {
	a := adapters.NewMavenAdapter("https://repo1.maven.org/maven2")

	r := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "maven", ref.Ecosystem)
	assert.Equal(t, "com.google.guava:guava", ref.Name)
	assert.Equal(t, "31.0.1-jre", ref.Version)
}

func TestMavenAdapter_NormalizeRequest_PomNotIntercepted(t *testing.T) {
	a := adapters.NewMavenAdapter("https://repo1.maven.org/maven2")

	r := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.pom", nil)
	_, ok := a.NormalizeRequest(r)
	assert.False(t, ok)
}

func TestMavenAdapter_FetchMetadata_UsesLastModified(t *testing.T) {
	lastModified := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		assert.Equal(t, "/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar", r.URL.Path)
		w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := adapters.NewMavenAdapter(srv.URL)
	ref := &proxy.PackageRef{Ecosystem: "maven", Name: "com.google.guava:guava", Version: "31.0.1-jre"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.WithinDuration(t, lastModified, meta.PublishedAt, time.Second)
}

func TestMavenAdapter_FetchMetadata_NoLastModifiedYieldsZeroTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // no Last-Modified header
	}))
	defer srv.Close()

	a := adapters.NewMavenAdapter(srv.URL)
	ref := &proxy.PackageRef{Ecosystem: "maven", Name: "com.google.guava:guava", Version: "31.0.1-jre"}
	meta, err := a.FetchMetadata(context.Background(), ref)
	require.NoError(t, err)
	assert.True(t, meta.PublishedAt.IsZero())
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/proxy/adapters/... -run TestMavenAdapter -v
```

Expected: FAIL — `adapters.NewMavenAdapter` undefined.

- [ ] **Step 3: Implement the Maven adapter**

Create `internal/proxy/adapters/maven.go`:

```go
package adapters

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// mavenArtifactExts are the binary artifact extensions we intercept and scan.
var mavenArtifactExts = []string{".jar", ".war", ".aar"}

// MavenAdapter implements proxy.RegistryAdapter for a Maven repository.
type MavenAdapter struct {
	upstream   string
	httpClient *http.Client
}

// NewMavenAdapter creates a Maven adapter pointing at the given upstream URL
// (e.g. "https://repo1.maven.org/maven2").
func NewMavenAdapter(upstream string) *MavenAdapter {
	return &MavenAdapter{
		upstream:   strings.TrimRight(upstream, "/"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *MavenAdapter) Name() string { return "maven" }

// NormalizeRequest intercepts binary artifact downloads (.jar/.war/.aar).
// Sidecar files (.pom, .sha1, .md5, .asc) are proxied transparently.
func (a *MavenAdapter) NormalizeRequest(r *http.Request) (*proxy.PackageRef, bool) {
	if !hasMavenArtifactExt(r.URL.Path) {
		return nil, false
	}
	name, version, ok := parseMavenPath(r.URL.Path)
	if !ok {
		return nil, false
	}
	return &proxy.PackageRef{Ecosystem: "maven", Name: name, Version: version}, true
}

func hasMavenArtifactExt(path string) bool {
	for _, ext := range mavenArtifactExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// parseMavenPath parses "/<group/as/path>/<artifact>/<version>/<file>" into
// name "group:artifact" and the version.
func parseMavenPath(path string) (name, version string, ok bool) {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segs) < 4 {
		return "", "", false
	}
	version = segs[len(segs)-2]
	artifact := segs[len(segs)-3]
	group := strings.Join(segs[:len(segs)-3], ".")
	if group == "" || artifact == "" || version == "" {
		return "", "", false
	}
	return group + ":" + artifact, version, true
}

// FetchMetadata issues a HEAD request to the artifact's .jar URL and reads the
// Last-Modified header as the publish time. A missing/unparseable header yields
// a zero PublishedAt (the supply chain filter treats it as old).
func (a *MavenAdapter) FetchMetadata(ctx context.Context, ref *proxy.PackageRef) (*proxy.PackageMetadata, error) {
	parts := strings.SplitN(ref.Name, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid maven name %q (want group:artifact)", ref.Name)
	}
	group, artifact := parts[0], parts[1]
	groupPath := strings.ReplaceAll(group, ".", "/")
	artifactURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s.jar",
		a.upstream, groupPath, artifact, ref.Version, artifact, ref.Version)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, artifactURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building maven HEAD request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching maven artifact head: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("maven returned HTTP %d for %s", resp.StatusCode, ref.Key())
	}

	meta := &proxy.PackageMetadata{}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			meta.PublishedAt = t.UTC()
		}
	}
	return meta, nil
}

// UpstreamURL returns the upstream URL for a proxy request.
func (a *MavenAdapter) UpstreamURL(r *http.Request) string {
	return a.upstream + r.URL.RequestURI()
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/proxy/adapters/... -v
```

Expected: PASS — Maven, npm, and PyPI adapter tests all pass.

- [ ] **Step 5: Commit**

```bash
cd /home/neody/Jo-ei
git add internal/proxy/adapters/maven.go internal/proxy/adapters/maven_test.go
git commit -m "feat: add Maven registry adapter (Last-Modified age check)"
```

---

## Task 7: Router multiplexer (Mux)

**Files:**
- Create: `internal/proxy/mux.go`
- Create: `internal/proxy/mux_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/mux_test.go`:

```go
package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildHandlerFor wires a minimal handler for a single registry adapter.
func buildHandlerFor(adapter proxy.RegistryAdapter, upstream string) *proxy.Handler {
	return proxy.NewHandler(proxy.HandlerConfig{
		Adapter:  adapter,
		Filter:   supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:    newFakeCache(),
		Logger:   zerolog.Nop(),
		Upstream: upstream,
	})
}

func TestMux_StripsPrefixAndRoutesToPyPI(t *testing.T) {
	// Upstream asserts it receives the prefix-stripped path.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/simple/requests/", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>simple</html>"))
	}))
	defer upstream.Close()

	mux := proxy.NewMux(map[string]*proxy.Handler{
		"pypi": buildHandlerFor(adapters.NewPyPIAdapter(upstream.URL), upstream.URL),
	}, zerolog.Nop())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/pypi/simple/requests/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMux_UnknownPrefixReturns404(t *testing.T) {
	mux := proxy.NewMux(map[string]*proxy.Handler{}, zerolog.Nop())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/rubygems/foo")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestMux_HealthEndpoint(t *testing.T) {
	mux := proxy.NewMux(map[string]*proxy.Handler{}, zerolog.Nop())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/proxy/... -run TestMux -v
```

Expected: FAIL — `proxy.NewMux` undefined.

- [ ] **Step 3: Implement the Mux**

Create `internal/proxy/mux.go`:

```go
package proxy

import (
	"net/http"
	"strings"

	"github.com/rs/zerolog"
)

// Mux routes requests to per-registry handlers by URL path prefix.
// A request to /<prefix>/... is dispatched to the handler registered for
// <prefix> with the prefix stripped, so each registry adapter sees the same
// paths it would without the proxy wrapper.
type Mux struct {
	handlers map[string]*Handler
	logger   zerolog.Logger
}

// NewMux creates a Mux from a prefix→handler map, e.g. {"pypi": h1, "npm": h2}.
func NewMux(handlers map[string]*Handler, logger zerolog.Logger) *Mux {
	return &Mux{handlers: handlers, logger: logger}
}

func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	prefix, rest := splitPrefix(r.URL.Path)
	h, ok := m.handlers[prefix]
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"unknown_registry"}`))
		return
	}

	// Strip the prefix so the downstream handler/adapter sees native paths.
	r.URL.Path = rest
	r.URL.RawPath = ""
	h.ServeHTTP(w, r)
}

// splitPrefix splits "/npm/foo/bar" into ("npm", "/foo/bar").
// "/npm" alone → ("npm", "/").
func splitPrefix(path string) (prefix, rest string) {
	trimmed := strings.TrimPrefix(path, "/")
	idx := strings.IndexByte(trimmed, '/')
	if idx == -1 {
		return trimmed, "/"
	}
	return trimmed[:idx], trimmed[idx:]
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./internal/proxy/... -v -race
```

Expected: PASS — Mux tests plus all existing proxy tests.

- [ ] **Step 5: Commit**

```bash
cd /home/neody/Jo-ei
git add internal/proxy/mux.go internal/proxy/mux_test.go
git commit -m "feat: add path-prefix Mux for multi-registry routing"
```

---

## Task 8: Wire everything in main.go

**Files:**
- Modify: `cmd/sca-proxy/main.go`

This task has no new unit test (it is the composition root, exercised by the Phase 3 integration tests in Task 9). The acceptance check is a clean build and `go vet`.

- [ ] **Step 1: Rewrite `runProxy` and add builder helpers in `cmd/sca-proxy/main.go`**

Replace the entire contents of `cmd/sca-proxy/main.go` with:

```go
package main

import (
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

	level, _ := zerolog.ParseLevel(cfg.Logging.Level)
	zerolog.SetGlobalLevel(level)
	logger := log.Logger
	if cfg.Logging.Format == "text" {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).
			With().Timestamp().Logger()
	}

	localCache, err := cache.NewLocalCache(cache.LocalCacheConfig{
		RootPath:  cfg.Cache.Local.Path,
		MaxSizeGB: cfg.Cache.Local.MaxSizeGB,
		TTL:       24 * time.Hour,
	})
	if err != nil {
		return err
	}

	profile := cfg.Policy.Profiles[cfg.Policy.ActiveProfile]

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
	}

	// Build one handler per enabled registry, keyed by routing prefix.
	handlers := map[string]*proxy.Handler{}
	if cfg.Registries.PyPI.Enabled {
		handlers["pypi"] = buildHandler(adapters.NewPyPIAdapter(cfg.Registries.PyPI.Upstream),
			cfg.Registries.PyPI.Upstream, shared)
	}
	if cfg.Registries.NPM.Enabled {
		handlers["npm"] = buildHandler(adapters.NewNPMAdapter(cfg.Registries.NPM.Upstream),
			cfg.Registries.NPM.Upstream, shared)
	}
	if cfg.Registries.Maven.Enabled {
		handlers["maven"] = buildHandler(adapters.NewMavenAdapter(cfg.Registries.Maven.Upstream),
			cfg.Registries.Maven.Upstream, shared)
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
func buildHandler(adapter proxy.RegistryAdapter, upstream string, shared sharedDeps) *proxy.Handler {
	return proxy.NewHandler(proxy.HandlerConfig{
		Adapter:    adapter,
		Filter:     shared.filter,
		Cache:      shared.cache,
		Logger:     shared.logger,
		Upstream:   upstream,
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
```

- [ ] **Step 2: Build and vet**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go build ./... && go vet ./...
```

Expected: no output, no errors.

- [ ] **Step 3: Run the full unit suite to confirm nothing regressed**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./... -race
```

Expected: PASS for all packages.

- [ ] **Step 4: Commit**

```bash
cd /home/neody/Jo-ei
git add cmd/sca-proxy/main.go
git commit -m "feat: wire multi-registry Mux, CVE/policy, and ClamAV into main"
```

---

## Task 9: Phase 3 integration tests

**Files:**
- Create: `integration/phase3_test.go`

These reuse the `localCacheAdapter` helper defined in `integration/phase1_test.go` (same `package integration_test`). Do not redefine it.

- [ ] **Step 1: Write the integration tests**

Create `integration/phase3_test.go`:

```go
//go:build integration

package integration_test

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sca-proxy/sca-proxy/internal/cache"
	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/proxy/adapters"
	"github.com/sca-proxy/sca-proxy/internal/scanner"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockClamd starts a TCP clamd stand-in that returns the given response.
func mockClamd(t *testing.T, response string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				if _, err := r.ReadBytes(0x00); err != nil {
					return
				}
				for {
					var size uint32
					if err := binary.Read(r, binary.BigEndian, &size); err != nil {
						return
					}
					if size == 0 {
						break
					}
					io.CopyN(io.Discard, r, int64(size))
				}
				c.Write([]byte(response))
			}(conn)
		}
	}()
	return "tcp:" + ln.Addr().String()
}

// newNPMRegistry serves an npm metadata document and tarball for one version.
func newNPMRegistry(t *testing.T, name, version string, ageHours int) *httptest.Server {
	t.Helper()
	publishedAt := time.Now().UTC().Add(-time.Duration(ageHours) * time.Hour)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+name {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"time": map[string]any{version: publishedAt.Format(time.RFC3339)},
				"versions": map[string]any{
					version: map[string]any{
						"license": "MIT",
						"dist":    map[string]any{"shasum": "deadbeef"},
					},
				},
			})
			return
		}
		w.Write([]byte("tarball-bytes"))
	}))
}

// newPhase3NPMProxy wires an npm-only proxy with the given AV scanner address.
func newPhase3NPMProxy(t *testing.T, upstream *httptest.Server, clamdAddr string) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)

	av, err := scanner.NewClamAVScanner(clamdAddr, 5*time.Second)
	require.NoError(t, err)

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:   adapters.NewNPMAdapter(upstream.URL),
		Filter:    supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:     &localCacheAdapter{lc: lc},
		Logger:    zerolog.Nop(),
		Upstream:  upstream.URL,
		AVScanner: av,
	})
	mux := proxy.NewMux(map[string]*proxy.Handler{"npm": h}, zerolog.Nop())
	return httptest.NewServer(mux)
}

func TestPhase3_CleanNPMPackageAllowed(t *testing.T) {
	registry := newNPMRegistry(t, "lodash", "4.17.21", 48)
	defer registry.Close()
	clamd := mockClamd(t, "stream: OK\x00")

	srv := newPhase3NPMProxy(t, registry, clamd)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/npm/lodash/-/lodash-4.17.21.tgz")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPhase3_MalwareBlocked(t *testing.T) {
	registry := newNPMRegistry(t, "evil-pkg", "1.0.0", 48)
	defer registry.Close()
	clamd := mockClamd(t, "stream: Eicar-Test-Signature FOUND\x00")

	srv := newPhase3NPMProxy(t, registry, clamd)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/npm/evil-pkg/-/evil-pkg-1.0.0.tgz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "malware_found", body["reason"])
	assert.Equal(t, "Eicar-Test-Signature", body["signature"])
}

func TestPhase3_MavenOldArtifactAllowed(t *testing.T) {
	// Maven repo serving a HEAD with an old Last-Modified, plus the jar bytes.
	lastModified := time.Now().UTC().Add(-72 * time.Hour)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Write([]byte("jar-bytes"))
	}))
	defer registry.Close()
	clamd := mockClamd(t, "stream: OK\x00")

	dir := t.TempDir()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, TTL: time.Hour})
	require.NoError(t, err)
	av, err := scanner.NewClamAVScanner(clamd, 5*time.Second)
	require.NoError(t, err)

	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:   adapters.NewMavenAdapter(registry.URL),
		Filter:    supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:     &localCacheAdapter{lc: lc},
		Logger:    zerolog.Nop(),
		Upstream:  registry.URL,
		AVScanner: av,
	})
	mux := proxy.NewMux(map[string]*proxy.Handler{"maven": h}, zerolog.Nop())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/maven/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
```

- [ ] **Step 2: Run the integration tests**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./integration/... -tags integration -v
```

Expected: PASS — Phase 1, Phase 2, and Phase 3 integration tests all pass.

- [ ] **Step 3: Run the full suite (unit + integration + vet)**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go test ./... -race && go test ./integration/... -tags integration && go vet ./...
```

Expected: PASS, no vet errors.

- [ ] **Step 4: Commit**

```bash
cd /home/neody/Jo-ei
git add integration/phase3_test.go
git commit -m "test: add Phase 3 integration tests (malware block, npm, Maven)"
```

---

## Task 10: README + docs update

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the architecture diagram and intercepted ecosystems**

In `README.md`, the "What gets blocked" list currently mentions only the 24h rule, CVE, and denylist. Add a malware bullet so it reads:

```markdown
**What gets blocked:**
- Packages published less than 24 hours ago (supply chain poisoning protection)
- Packages with CVE severity ≥ configured threshold (`HIGH` by default)
- Packages whose artifact matches a ClamAV malware signature
- Packages on the explicit `denylist`
```

- [ ] **Step 2: Update the Quick Start to use routing prefixes**

In `README.md`, replace the pip and npm configuration snippets in the Quick Start so they target per-registry prefixes. Replace the pip block:

```bash
pip install requests \
  --index-url http://localhost:8080/pypi/simple/ \
  --trusted-host localhost
```

The pip.conf block:

```ini
[global]
index-url = http://localhost:8080/pypi/simple/
trusted-host = localhost
```

The npm blocks:

```bash
npm install lodash --registry http://localhost:8080/npm/
```

```bash
npm config set registry http://localhost:8080/npm/
```

And the smoke-test pip line:

```bash
pip install requests==2.31.0 --index-url http://localhost:8080/pypi/simple/ --trusted-host localhost
```

(The `/health` endpoint stays at `http://localhost:8080/health` — it is not behind a prefix.)

- [ ] **Step 3: Add a malware block-response subsection**

In `README.md`, in the "Understanding Block Responses" section, after the "403 Forbidden — Denylist" subsection, add:

````markdown
### 403 Forbidden — Malware detected

The downloaded artifact matched a ClamAV signature.

```json
{
  "error": "package_blocked",
  "reason": "malware_found",
  "package": "evil-pkg",
  "version": "1.0.0",
  "signature": "Win.Trojan.Agent-123456",
  "blocked_by": ["malware_scanner"],
  "request_id": "req_jkl012"
}
```

**What to do:** Do not install this artifact. If you believe it is a false
positive, verify the package out-of-band and report the signature to your
security team before adding an `allowlist` entry.
````

- [ ] **Step 4: Update the How it Works pipeline**

In `README.md`, in the "How it Works" numbered pipeline, the current step 4 is "Download + Cache". Replace it with two steps so malware scanning is documented:

```markdown
4. **Malware Scan** — the artifact is downloaded to a temp file and streamed to
   ClamAV (clamd `INSTREAM`). If a signature matches, the package is rejected with
   HTTP **403 Forbidden** (`reason: malware_found`) and the artifact is not cached.

5. **Cache + Serve** — a clean artifact is stored in the local cache and served to
   the client.
```

- [ ] **Step 5: Verify the README renders and has no broken fences**

```bash
cd /home/neody/Jo-ei
grep -n "localhost:8080" README.md
```

Expected: every client-facing URL now uses `/pypi/` or `/npm/` (except `/health`).

- [ ] **Step 6: Commit**

```bash
cd /home/neody/Jo-ei
git add README.md
git commit -m "docs: document prefix routing, malware scan step, and malware block response"
```

---

## Final verification

- [ ] **Run the complete suite one last time**

```bash
export PATH="/home/neody/go-sdk/go/bin:$PATH"
cd /home/neody/Jo-ei
go build ./... && go vet ./... && go test ./... -race && go test ./integration/... -tags integration
```

Expected: clean build, no vet errors, all unit and integration tests pass.

---

## Phase 3 result

After completing all tasks:
- `internal/proxy/adapter.go` — `AVResult` + `AVScanner` interface
- `internal/scanner/clamav.go` — clamd INSTREAM client
- `internal/config/config.go` — `ClamAVConfig`
- `internal/proxy/handler.go` — AV scan step, `malware_found` 403 response (fail-closed)
- `internal/proxy/adapters/npm.go` — npm adapter
- `internal/proxy/adapters/maven.go` — Maven adapter (Last-Modified age check)
- `internal/proxy/mux.go` — path-prefix router
- `cmd/sca-proxy/main.go` — multi-registry wiring with CVE/policy + ClamAV
- `integration/phase3_test.go` — malware-block, npm, and Maven end-to-end tests
- `README.md` — prefix routing + malware documentation

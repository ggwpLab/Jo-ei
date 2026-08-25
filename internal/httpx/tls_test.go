package httpx_test

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/httpx"
)

// handshakeTimeoutForTest is well above http.DefaultTransport's 10s default.
// These tests assert on the *kind* of TLS error (x509 verification, or a
// successful HTTP/2 handshake), not on latency. Under a whole-suite parallel
// test run (and doubly so under -race, which CI runs), CPU contention can
// push a real handshake past the default timeout, turning a verification
// assertion into a spurious "TLS handshake timeout" failure. Raising the
// timeout keeps the assertion measuring what it claims to measure.
const handshakeTimeoutForTest = 60 * time.Second

// writeCertPEM writes srv's self-signed certificate to a PEM file and returns
// its path — the same thing an operator does with a corporate CA.
func writeCertPEM(t *testing.T, der []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test-ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("writing PEM: %v", err)
	}
	return path
}

// The feature, end to end: a self-signed mirror is rejected with the system
// roots and accepted once its CA is configured.
func TestNewTransport_SelfSignedRejectedThenTrusted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	systemPool, added, err := httpx.RootPool(nil)
	if err != nil {
		t.Fatalf("RootPool(nil): %v", err)
	}
	if added != 0 {
		t.Fatalf("added = %d with no CA files, want 0", added)
	}
	untrustedTr := httpx.NewTransport(systemPool)
	untrustedTr.TLSHandshakeTimeout = handshakeTimeoutForTest
	untrusted := &http.Client{Transport: untrustedTr}
	if _, err := untrusted.Get(srv.URL); err == nil {
		t.Fatal("self-signed server was accepted without its CA configured")
	} else if !strings.Contains(err.Error(), "x509") {
		t.Fatalf("expected a certificate verification error, got: %v", err)
	}

	caPath := writeCertPEM(t, srv.Certificate().Raw)
	pool, added, err := httpx.RootPool([]string{caPath})
	if err != nil {
		t.Fatalf("RootPool with the test CA: %v", err)
	}
	if added != 1 {
		t.Fatalf("added = %d, want 1", added)
	}
	trustedTr := httpx.NewTransport(pool)
	trustedTr.TLSHandshakeTimeout = handshakeTimeoutForTest
	trusted := &http.Client{Transport: trustedTr}
	resp, err := trusted.Get(srv.URL)
	if err != nil {
		t.Fatalf("configured CA did not make the mirror reachable: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// A custom TLSClientConfig must not silently disable HTTP/2 to upstreams.
func TestNewTransport_KeepsHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	pool, _, err := httpx.RootPool([]string{writeCertPEM(t, srv.Certificate().Raw)})
	if err != nil {
		t.Fatalf("RootPool: %v", err)
	}
	http2Tr := httpx.NewTransport(pool)
	http2Tr.TLSHandshakeTimeout = handshakeTimeoutForTest
	resp, err := (&http.Client{Transport: http2Tr}).Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("proto = %s, want HTTP/2.0", resp.Proto)
	}
}

func TestRootPool_RejectsBadInput(t *testing.T) {
	dir := t.TempDir()

	notPEM := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(notPEM, []byte("-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		files   []string
		wantSub string
	}{
		{"missing file", []string{filepath.Join(dir, "absent.pem")}, "reading CA file"},
		{"a private key, not a certificate", []string{notPEM}, "contains no certificates"},
		{"not PEM at all", []string{garbage}, "contains no certificates"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := httpx.RootPool(tc.files)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantSub)
			}
		})
	}
}

func TestRootPool_CountsEveryCertificateInABundle(t *testing.T) {
	a := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer a.Close()
	b := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer b.Close()

	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Certificate().Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Certificate().Raw})...,
	)
	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}

	_, added, err := httpx.RootPool([]string{path})
	if err != nil {
		t.Fatalf("RootPool: %v", err)
	}
	if added != 2 {
		t.Fatalf("added = %d, want 2 from a two-certificate bundle", added)
	}
}

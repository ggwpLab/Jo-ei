package dockerproxy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

const trivyJSONFixture = `{
  "Results": [
    {"Target":"alpine","Vulnerabilities":[
      {"VulnerabilityID":"CVE-2021-1","PkgName":"openssl","Severity":"HIGH","Title":"bad"},
      {"VulnerabilityID":"CVE-2021-2","PkgName":"musl","Severity":"MEDIUM","Title":"meh"}
    ]},
    {"Target":"node-pkgs","Vulnerabilities":null}
  ]
}`

func TestTrivyScannerParsesFindings(t *testing.T) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name != "trivy" {
			t.Fatalf("expected trivy, got %q", name)
		}
		return []byte(trivyJSONFixture), nil
	}
	s := NewTrivyScannerWithRunner("http://trivy:4954", "vuln,secret", 30*time.Second, run)
	res, err := s.ScanImage(context.Background(), "registry-1.docker.io/library/alpine@sha256:x")
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(res.Findings))
	}
	if res.Findings[0].ID != "CVE-2021-1" || res.Findings[0].Severity != proxy.SeverityHigh {
		t.Errorf("finding[0] = %+v", res.Findings[0])
	}
	if !s.Health().OK || !s.Health().HasData {
		t.Errorf("health after success = %+v", s.Health())
	}
}

func TestTrivyScannerFailClosedOnError(t *testing.T) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("trivy boom")
	}
	s := NewTrivyScannerWithRunner("http://trivy:4954", "vuln", time.Second, run)
	if _, err := s.ScanImage(context.Background(), "x@sha256:y"); err == nil {
		t.Fatal("expected error from failing trivy run")
	}
	if s.Health().OK {
		t.Error("health should be not-OK after failure")
	}
}

package policy_test

import (
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/stretchr/testify/assert"
)

var baseProfile = config.PolicyProfile{
	CVEBlock:       true,
	CVEMinSeverity: "HIGH",
}

func ref(ecosystem, name, version string) *proxy.PackageRef {
	return &proxy.PackageRef{Ecosystem: ecosystem, Name: name, Version: version}
}

func scanWith(findings ...proxy.CVEFinding) *proxy.ScanResult {
	return &proxy.ScanResult{
		Clean:    len(findings) == 0,
		Findings: findings,
	}
}

func TestEngine_CleanPackageAllowed(t *testing.T) {
	e := policy.NewEngine(config.CVEConfig{Enabled: true, BlockOn: "HIGH"}, baseProfile)
	d := e.Evaluate(ref("pypi", "requests", "2.31.0"), scanWith())
	assert.True(t, d.Allowed)
	assert.Equal(t, "ok", d.Reason)
}

func TestEngine_HighCVEBlocked(t *testing.T) {
	e := policy.NewEngine(config.CVEConfig{Enabled: true, BlockOn: "HIGH"}, baseProfile)
	d := e.Evaluate(ref("pypi", "requests", "2.28.0"), scanWith(
		proxy.CVEFinding{ID: "CVE-2024-001", Severity: proxy.SeverityHigh},
	))
	assert.False(t, d.Allowed)
	assert.Equal(t, "cve_found", d.Reason)
	assert.Len(t, d.Findings, 1)
}

func TestEngine_CriticalCVEBlocked(t *testing.T) {
	e := policy.NewEngine(config.CVEConfig{Enabled: true, BlockOn: "HIGH"}, baseProfile)
	d := e.Evaluate(ref("pypi", "pkg", "1.0.0"), scanWith(
		proxy.CVEFinding{ID: "CVE-2024-002", Severity: proxy.SeverityCritical},
	))
	assert.False(t, d.Allowed)
}

func TestEngine_MediumCVEAllowedWhenThresholdIsHigh(t *testing.T) {
	e := policy.NewEngine(config.CVEConfig{Enabled: true, BlockOn: "HIGH"}, baseProfile)
	d := e.Evaluate(ref("pypi", "pkg", "1.0.0"), scanWith(
		proxy.CVEFinding{ID: "CVE-2024-003", Severity: proxy.SeverityMedium},
	))
	assert.True(t, d.Allowed)
	assert.Equal(t, "ok", d.Reason)
}

func TestEngine_ProfileOverridesGlobalThreshold(t *testing.T) {
	// Profile says block on CRITICAL, global says HIGH — profile wins
	profile := config.PolicyProfile{CVEBlock: true, CVEMinSeverity: "CRITICAL"}
	e := policy.NewEngine(config.CVEConfig{Enabled: true, BlockOn: "HIGH"}, profile)
	d := e.Evaluate(ref("pypi", "pkg", "1.0.0"), scanWith(
		proxy.CVEFinding{ID: "CVE-2024-004", Severity: proxy.SeverityHigh},
	))
	assert.True(t, d.Allowed, "HIGH should pass when profile threshold is CRITICAL")

	d2 := e.Evaluate(ref("pypi", "pkg", "1.0.0"), scanWith(
		proxy.CVEFinding{ID: "CVE-2024-005", Severity: proxy.SeverityCritical},
	))
	assert.False(t, d2.Allowed)
}

func TestEngine_CVEBlockDisabled(t *testing.T) {
	profile := config.PolicyProfile{CVEBlock: false, CVEMinSeverity: "HIGH"}
	e := policy.NewEngine(config.CVEConfig{Enabled: true, BlockOn: "HIGH"}, profile)
	d := e.Evaluate(ref("pypi", "pkg", "1.0.0"), scanWith(
		proxy.CVEFinding{ID: "CVE-2024-006", Severity: proxy.SeverityCritical},
	))
	assert.True(t, d.Allowed, "CVEBlock=false should allow even critical CVEs")
	assert.Equal(t, "cve_block_disabled", d.Reason)
}

func TestEngine_DenylistedPackageBlocked(t *testing.T) {
	profile := config.PolicyProfile{
		CVEBlock:       true,
		CVEMinSeverity: "HIGH",
		Denylist:       []string{"npm/evil-pkg"},
	}
	e := policy.NewEngine(config.CVEConfig{Enabled: true, BlockOn: "HIGH"}, profile)
	d := e.Evaluate(ref("npm", "evil-pkg", "1.0.0"), scanWith())
	assert.False(t, d.Allowed)
	assert.Equal(t, "denylisted", d.Reason)
}

func TestEngine_DenylistWithVersion(t *testing.T) {
	profile := config.PolicyProfile{
		CVEBlock:       true,
		CVEMinSeverity: "HIGH",
		Denylist:       []string{"pypi/requests@2.28.0"},
	}
	e := policy.NewEngine(config.CVEConfig{Enabled: true, BlockOn: "HIGH"}, profile)

	// exact version blocked
	d := e.Evaluate(ref("pypi", "requests", "2.28.0"), scanWith())
	assert.False(t, d.Allowed)

	// other version not blocked
	d2 := e.Evaluate(ref("pypi", "requests", "2.31.0"), scanWith())
	assert.True(t, d2.Allowed)
}

func TestEngine_AllowlistedBypassesCVE(t *testing.T) {
	profile := config.PolicyProfile{
		CVEBlock:       true,
		CVEMinSeverity: "HIGH",
		Allowlist:      []string{"pypi/requests"},
	}
	e := policy.NewEngine(config.CVEConfig{Enabled: true, BlockOn: "HIGH"}, profile)
	d := e.Evaluate(ref("pypi", "requests", "2.28.0"), scanWith(
		proxy.CVEFinding{ID: "CVE-2024-007", Severity: proxy.SeverityCritical},
	))
	assert.True(t, d.Allowed)
	assert.Equal(t, "allowlisted_bypass", d.Reason)
}

func TestEngine_AllowlistVersionSpecific(t *testing.T) {
	profile := config.PolicyProfile{
		CVEBlock:       true,
		CVEMinSeverity: "HIGH",
		Allowlist:      []string{"pypi/requests@2.31.0"},
	}
	e := policy.NewEngine(config.CVEConfig{Enabled: true, BlockOn: "HIGH"}, profile)

	// allowlisted version passes
	d := e.Evaluate(ref("pypi", "requests", "2.31.0"), scanWith(
		proxy.CVEFinding{ID: "CVE-2024-008", Severity: proxy.SeverityCritical},
	))
	assert.True(t, d.Allowed)

	// other version still blocked
	d2 := e.Evaluate(ref("pypi", "requests", "2.28.0"), scanWith(
		proxy.CVEFinding{ID: "CVE-2024-008", Severity: proxy.SeverityCritical},
	))
	assert.False(t, d2.Allowed)
}

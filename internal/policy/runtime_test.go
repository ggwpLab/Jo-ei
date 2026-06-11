package policy_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/policy"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

func newRuntime(t *testing.T, fileAllow []string) *policy.Runtime {
	t.Helper()
	return policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{Enabled: true, BlockOn: "CRITICAL"},
		config.PolicyProfile{CVEBlock: true},
		fileAllow,
	)
}

func freshMeta() *proxy.PackageMetadata {
	return &proxy.PackageMetadata{PublishedAt: time.Now().Add(-1 * time.Hour)}
}

// rtRef reuses the ref(eco, name, ver) helper already defined in
// engine_test.go (same package policy_test) — do not redeclare ref here.
func rtRef() *proxy.PackageRef {
	return ref("pypi", "requests", "2.31.0")
}

func highFinding() *proxy.ScanResult {
	return &proxy.ScanResult{Findings: []proxy.CVEFinding{{ID: "CVE-1", Severity: proxy.SeverityHigh}}}
}

func TestRuntimeBootFromConfig(t *testing.T) {
	r := newRuntime(t, nil)
	p := r.Current()
	assert.Equal(t, "enforce", p.Mode)
	assert.Equal(t, 24, p.MinAgeHours)
	assert.Equal(t, "CRITICAL", p.CVEBlockOn)
	assert.Empty(t, p.Allowlist)
	assert.Empty(t, p.Denylist)
}

func TestRuntimeApplySwapsCVEThreshold(t *testing.T) {
	r := newRuntime(t, nil)
	assert.True(t, r.Evaluate(rtRef(), highFinding()).Allowed, "HIGH below CRITICAL threshold")

	p := r.Current()
	p.CVEBlockOn = "HIGH"
	require.NoError(t, r.Apply(p))

	d := r.Evaluate(rtRef(), highFinding())
	assert.False(t, d.Allowed)
	assert.Equal(t, "cve_found", d.Reason)
}

func TestRuntimeApplySwapsSupplyChain(t *testing.T) {
	r := newRuntime(t, nil)
	res := r.Check(context.Background(), rtRef(), freshMeta())
	assert.False(t, res.Allowed, "1h-old package blocked by 24h min age")

	p := r.Current()
	p.MinAgeHours = 0
	require.NoError(t, r.Apply(p))
	assert.True(t, r.Check(context.Background(), rtRef(), freshMeta()).Allowed)

	p.MinAgeHours = 24
	p.Mode = "dry_run"
	require.NoError(t, r.Apply(p))
	res = r.Check(context.Background(), rtRef(), freshMeta())
	assert.True(t, res.Allowed)
	assert.Equal(t, "dry_run", res.Reason)
}

func TestRuntimeApplyDenylist(t *testing.T) {
	r := newRuntime(t, nil)
	p := r.Current()
	p.Denylist = []string{"pypi/requests"}
	require.NoError(t, r.Apply(p))

	d := r.Evaluate(rtRef(), &proxy.ScanResult{Clean: true})
	assert.False(t, d.Allowed)
	assert.Equal(t, "denylisted", d.Reason)
}

func TestRuntimeApplyValidation(t *testing.T) {
	r := newRuntime(t, nil)
	before := r.Current()

	cases := []struct {
		field string
		mut   func(*policy.RuntimeParams)
	}{
		{"mode", func(p *policy.RuntimeParams) { p.Mode = "yolo" }},
		{"min_age_hours", func(p *policy.RuntimeParams) { p.MinAgeHours = -1 }},
		{"cve_block_on", func(p *policy.RuntimeParams) { p.CVEBlockOn = "SEVERE" }},
		{"allowlist[0]", func(p *policy.RuntimeParams) { p.Allowlist = []string{"no-slash"} }},
		{"allowlist[0]", func(p *policy.RuntimeParams) { p.Allowlist = []string{"eco / name"} }},
		{"denylist[0]", func(p *policy.RuntimeParams) { p.Denylist = []string{"/noeco"} }},
	}
	for _, tc := range cases {
		p := r.Current()
		tc.mut(&p)
		err := r.Apply(p)
		var verr *policy.ValidationError
		require.ErrorAs(t, err, &verr, "field %s", tc.field)
		assert.Equal(t, tc.field, verr.Field)
		assert.Equal(t, before, r.Current(), "policy unchanged after invalid Apply")
	}
}

func TestRuntimeFileAllowlistAlwaysMerged(t *testing.T) {
	r := newRuntime(t, []string{"pypi/requests"})
	res := r.Check(context.Background(), rtRef(), freshMeta())
	assert.True(t, res.Allowed)
	assert.Equal(t, "allowlisted", res.Reason)

	// Runtime edit with an empty allowlist must not drop the file entries.
	p := r.Current()
	p.Allowlist = []string{}
	require.NoError(t, r.Apply(p))
	assert.Equal(t, "allowlisted", r.Check(context.Background(), rtRef(), freshMeta()).Reason)
}

func TestRuntimeConcurrentApplyAndEvaluate(t *testing.T) {
	r := newRuntime(t, nil)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			p := r.Current()
			p.MinAgeHours = i % 48
			_ = r.Apply(p)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			r.Evaluate(rtRef(), highFinding())
			r.Check(context.Background(), rtRef(), freshMeta())
		}
	}()
	wg.Wait()
}

func TestRuntimeEmptyBlockOnDefaultsToLow(t *testing.T) {
	r := policy.NewRuntime(
		config.SupplyChainConfig{Mode: "enforce", MinAgeHours: 24},
		config.CVEConfig{Enabled: true}, // no BlockOn
		config.PolicyProfile{CVEBlock: true},
		nil,
	)
	p := r.Current()
	assert.Equal(t, "LOW", p.CVEBlockOn)
	// The boot params must round-trip through Apply unchanged.
	require.NoError(t, r.Apply(p))
}

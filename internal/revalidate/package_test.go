package revalidate_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/revalidate"
)

type fakeCVE struct {
	res *gate.ScanResult
	err error
}

func (f fakeCVE) Scan(context.Context, *gate.PackageRef) (*gate.ScanResult, error) {
	return f.res, f.err
}

type fakePolicy struct{ decision gate.PolicyDecision }

func (f fakePolicy) Evaluate(*gate.PackageRef, *gate.ScanResult) gate.PolicyDecision {
	return f.decision
}

type fakeAV struct {
	res   *gate.AVResult
	err   error
	calls *int
}

func (f fakeAV) Scan(context.Context, string) (*gate.AVResult, error) {
	if f.calls != nil {
		*f.calls++
	}
	return f.res, f.err
}

func entry() cache.RevalEntry {
	return cache.RevalEntry{Ref: gate.PackageRef{Ecosystem: "pypi", Name: "x", Version: "1.0"}, FilePath: "/tmp/x"}
}

func TestPackageRevalidator_CleanKeeps(t *testing.T) {
	r := revalidate.NewPackageRevalidator(
		fakeCVE{res: &gate.ScanResult{Clean: true}},
		fakePolicy{decision: gate.PolicyDecision{Allowed: true}},
		fakeAV{res: &gate.AVResult{Clean: true}},
	)
	out, reason := r.Revalidate(context.Background(), entry())
	assert.Equal(t, revalidate.Keep, out)
	assert.Nil(t, reason)
}

func TestPackageRevalidator_NewCVEEvicts(t *testing.T) {
	finding := gate.CVEFinding{ID: "CVE-1", Severity: gate.SeverityHigh}
	r := revalidate.NewPackageRevalidator(
		fakeCVE{res: &gate.ScanResult{Findings: []gate.CVEFinding{finding}}},
		fakePolicy{decision: gate.PolicyDecision{Allowed: false, Reason: "cve_found", Findings: []gate.CVEFinding{finding}}},
		fakeAV{res: &gate.AVResult{Clean: true}},
	)
	out, reason := r.Revalidate(context.Background(), entry())
	require.Equal(t, revalidate.Evict, out)
	require.NotNil(t, reason)
	assert.Equal(t, gate.GateCVE, reason.Gate)
	assert.Equal(t, "cve", reason.BlockedBy)
	assert.Len(t, reason.Findings, 1)
}

func TestPackageRevalidator_DenylistEvicts(t *testing.T) {
	r := revalidate.NewPackageRevalidator(
		fakeCVE{res: &gate.ScanResult{Clean: true}},
		fakePolicy{decision: gate.PolicyDecision{Allowed: false, Reason: gate.ReasonDenylisted}},
		fakeAV{res: &gate.AVResult{Clean: true}},
	)
	out, reason := r.Revalidate(context.Background(), entry())
	require.Equal(t, revalidate.Evict, out)
	assert.Equal(t, "denylist", reason.BlockedBy)
}

func TestPackageRevalidator_InfectedEvicts(t *testing.T) {
	r := revalidate.NewPackageRevalidator(
		fakeCVE{res: &gate.ScanResult{Clean: true}},
		fakePolicy{decision: gate.PolicyDecision{Allowed: true}},
		fakeAV{res: &gate.AVResult{Clean: false, Engine: "clamav", Signature: "EICAR"}},
	)
	out, reason := r.Revalidate(context.Background(), entry())
	require.Equal(t, revalidate.Evict, out)
	assert.Equal(t, gate.GateMalware, reason.Gate)
	assert.Equal(t, "malware", reason.BlockedBy)
	assert.Equal(t, "EICAR", reason.Signature)
}

func TestPackageRevalidator_CVEErrorRetriesAndSkipsAV(t *testing.T) {
	avCalls := 0
	r := revalidate.NewPackageRevalidator(
		fakeCVE{err: errors.New("osv 500")},
		fakePolicy{decision: gate.PolicyDecision{Allowed: true}},
		fakeAV{res: &gate.AVResult{Clean: true}, calls: &avCalls},
	)
	out, reason := r.Revalidate(context.Background(), entry())
	assert.Equal(t, revalidate.Retry, out)
	assert.Nil(t, reason)
	assert.Equal(t, 0, avCalls, "malware scan must not run after a CVE scan error")
}

func TestPackageRevalidator_AVErrorRetries(t *testing.T) {
	r := revalidate.NewPackageRevalidator(
		fakeCVE{res: &gate.ScanResult{Clean: true}},
		fakePolicy{decision: gate.PolicyDecision{Allowed: true}},
		fakeAV{err: errors.New("clamd timeout")},
	)
	out, _ := r.Revalidate(context.Background(), entry())
	assert.Equal(t, revalidate.Retry, out)
}

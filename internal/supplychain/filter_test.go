package supplychain_test

import (
	"context"
	"testing"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/supplychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newFilter(mode string, allowlist *supplychain.Allowlist) *supplychain.Filter {
	return supplychain.NewFilter(config.SupplyChainConfig{
		MinAgeHours: 24,
		Mode:        mode,
	}, allowlist)
}

func TestFilter_BlocksPackageUnder24h(t *testing.T) {
	f := newFilter("enforce", nil)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now().Add(-1 * time.Hour)}

	result := f.Check(context.Background(), ref, meta)

	require.False(t, result.Allowed)
	assert.Equal(t, "package_version_newer_than_24h", result.Reason)
	assert.False(t, result.BlockUntil.IsZero())
}

func TestFilter_AllowsPackageOver24h(t *testing.T) {
	f := newFilter("enforce", nil)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now().Add(-25 * time.Hour)}

	result := f.Check(context.Background(), ref, meta)

	assert.True(t, result.Allowed)
	assert.Equal(t, "ok", result.Reason)
}

func TestFilter_BoundaryJustUnder24h(t *testing.T) {
	// 23h59m → should be BLOCKED
	f := newFilter("enforce", nil)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "pkg", Version: "1.0.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now().Add(-(24*time.Hour - time.Minute))}

	result := f.Check(context.Background(), ref, meta)
	assert.False(t, result.Allowed)
}

func TestFilter_BoundaryJustOver24h(t *testing.T) {
	// 24h01m → should be ALLOWED
	f := newFilter("enforce", nil)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "pkg", Version: "1.0.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now().Add(-(24*time.Hour + time.Minute))}

	result := f.Check(context.Background(), ref, meta)
	assert.True(t, result.Allowed)
}

func TestFilter_DryRunPassesThroughButIndicates(t *testing.T) {
	f := newFilter("dry_run", nil)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "pkg", Version: "1.0.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now()} // brand new

	result := f.Check(context.Background(), ref, meta)

	assert.True(t, result.Allowed, "dry_run must pass through")
	assert.Equal(t, "dry_run", result.Reason)
}

func TestFilter_ModeOff_AlwaysPasses(t *testing.T) {
	f := newFilter("off", nil)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "pkg", Version: "1.0.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now()}

	result := f.Check(context.Background(), ref, meta)
	assert.True(t, result.Allowed)
}

func TestFilter_AllowlistedPackageBypassesAgeCheck(t *testing.T) {
	al := supplychain.NewAllowlist([]string{"pypi/requests"})
	f := newFilter("enforce", al)

	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now()} // brand new

	result := f.Check(context.Background(), ref, meta)
	assert.True(t, result.Allowed)
	assert.Equal(t, "allowlisted", result.Reason)
}

func TestFilter_AllowlistedVersionSpecific(t *testing.T) {
	// Only this specific version is allowlisted
	al := supplychain.NewAllowlist([]string{"pypi/requests@2.32.0"})
	f := newFilter("enforce", al)

	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0"}
	meta := &proxy.PackageMetadata{PublishedAt: time.Now()}
	result := f.Check(context.Background(), ref, meta)
	assert.True(t, result.Allowed)

	// Different version is NOT allowlisted
	ref2 := &proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.33.0"}
	result2 := f.Check(context.Background(), ref2, meta)
	assert.False(t, result2.Allowed)
}

func TestFilter_BlockUntilIsPublishedAtPlusMinAge(t *testing.T) {
	f := newFilter("enforce", nil)
	publishedAt := time.Now().Add(-2 * time.Hour)
	ref := &proxy.PackageRef{Ecosystem: "pypi", Name: "new-pkg", Version: "0.1.0"}
	meta := &proxy.PackageMetadata{PublishedAt: publishedAt}

	result := f.Check(context.Background(), ref, meta)

	require.False(t, result.Allowed)
	expected := publishedAt.Add(24 * time.Hour)
	assert.WithinDuration(t, expected, result.BlockUntil, time.Second)
}

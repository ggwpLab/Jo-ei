package proxy_test

import (
	"testing"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/stretchr/testify/assert"
)

func TestPackageRef_Key(t *testing.T) {
	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0"}
	assert.Equal(t, "pypi/requests@2.32.0", ref.Key())
}

func TestPackageRef_Key_NormalizesNothing(t *testing.T) {
	// Key() preserves the name exactly — normalization is adapter responsibility
	ref := proxy.PackageRef{Ecosystem: "pypi", Name: "my-package", Version: "1.0.0"}
	assert.Equal(t, "pypi/my-package@1.0.0", ref.Key())
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want proxy.Severity
	}{
		{"CRITICAL", proxy.SeverityCritical},
		{"HIGH", proxy.SeverityHigh},
		{"MEDIUM", proxy.SeverityMedium},
		{"MODERATE", proxy.SeverityMedium}, // OSV uses "MODERATE"
		{"LOW", proxy.SeverityLow},
		{"unknown", proxy.SeverityUnknown},
		{"", proxy.SeverityUnknown},
	}
	for _, c := range cases {
		got := proxy.ParseSeverity(c.in)
		assert.Equal(t, c.want, got, "ParseSeverity(%q)", c.in)
	}
}

func TestSeverityAtLeast(t *testing.T) {
	assert.True(t, proxy.SeverityCritical.AtLeast(proxy.SeverityHigh))
	assert.True(t, proxy.SeverityHigh.AtLeast(proxy.SeverityHigh))
	assert.False(t, proxy.SeverityMedium.AtLeast(proxy.SeverityHigh))
	assert.False(t, proxy.SeverityUnknown.AtLeast(proxy.SeverityLow))
}

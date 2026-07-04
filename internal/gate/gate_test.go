package gate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ggwpLab/Jo-ei/internal/gate"
)

func TestPackageRef_Key(t *testing.T) {
	ref := gate.PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0"}
	assert.Equal(t, "pypi/requests@2.32.0", ref.Key())
}

func TestPackageRef_Key_NormalizesNothing(t *testing.T) {
	// Key() preserves the name exactly — normalization is adapter responsibility
	ref := gate.PackageRef{Ecosystem: "pypi", Name: "my-package", Version: "1.0.0"}
	assert.Equal(t, "pypi/my-package@1.0.0", ref.Key())
}

func TestPackageRef_Key_EmptyClassifierUnchanged(t *testing.T) {
	// A blank classifier must not alter the key, so existing cache entries and
	// non-maven ecosystems keep their historical keys.
	ref := gate.PackageRef{Ecosystem: "maven", Name: "g:a", Version: "1.0"}
	assert.Equal(t, "maven/g:a@1.0", ref.Key())
}

func TestPackageRef_Key_ClassifierDisambiguates(t *testing.T) {
	main := gate.PackageRef{Ecosystem: "maven", Name: "g:a", Version: "1.0"}
	sources := gate.PackageRef{Ecosystem: "maven", Name: "g:a", Version: "1.0", Classifier: "sources"}
	javadoc := gate.PackageRef{Ecosystem: "maven", Name: "g:a", Version: "1.0", Classifier: "javadoc"}

	assert.Equal(t, "maven/g:a@1.0?classifier=sources", sources.Key())
	assert.NotEqual(t, main.Key(), sources.Key())
	assert.NotEqual(t, sources.Key(), javadoc.Key())
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want gate.Severity
	}{
		{"CRITICAL", gate.SeverityCritical},
		{"HIGH", gate.SeverityHigh},
		{"MEDIUM", gate.SeverityMedium},
		{"MODERATE", gate.SeverityMedium}, // OSV uses "MODERATE"
		{"LOW", gate.SeverityLow},
		{"unknown", gate.SeverityUnknown},
		{"", gate.SeverityUnknown},
	}
	for _, c := range cases {
		got := gate.ParseSeverity(c.in)
		assert.Equal(t, c.want, got, "ParseSeverity(%q)", c.in)
	}
}

func TestSeverityAtLeast(t *testing.T) {
	assert.True(t, gate.SeverityCritical.AtLeast(gate.SeverityHigh))
	assert.True(t, gate.SeverityHigh.AtLeast(gate.SeverityHigh))
	assert.False(t, gate.SeverityMedium.AtLeast(gate.SeverityHigh))
	assert.False(t, gate.SeverityUnknown.AtLeast(gate.SeverityLow))
}

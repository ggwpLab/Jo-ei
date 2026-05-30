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

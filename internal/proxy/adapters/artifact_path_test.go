package adapters_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
)

// An artifact path the adapter cannot name must still be recognised as an
// artifact, so the handler refuses it instead of streaming it ungated.
func TestAdapters_IsArtifactPath(t *testing.T) {
	cases := []struct {
		name     string
		adapter  gate.RegistryAdapter
		artifact []string
		other    []string
	}{
		{
			name:    "npm",
			adapter: adapters.NewNPMAdapter([]string{"https://registry.npmjs.org"}),
			artifact: []string{
				"/lodash/-/lodash-4.17.21.tgz",
				"/@types/node/-/@types/node-20.0.0.tgz", // a layout NormalizeRequest does not parse
				"/lodash/-/renamed.tgz",
			},
			other: []string{"/lodash", "/@types/node", "/-/v1/search", "/-/npm/v1/security/advisories/bulk"},
		},
		{
			name:    "rubygems",
			adapter: adapters.NewRubyGemsAdapter([]string{"https://rubygems.org"}),
			artifact: []string{
				"/gems/rails-7.0.4.gem",
				"/gems/sub/rails-7.0.4.gem", // nested: NormalizeRequest declines it
				"/downloads/rails-7.0.4.gem",
				"/gems/nodigits.gem",
			},
			other: []string{"/api/v1/versions/rails.json", "/info/rails", "/versions", "/quick/Marshal.4.8/rails-7.0.4.gemspec.rz"},
		},
		{
			name:    "go",
			adapter: adapters.NewGoAdapter([]string{"https://proxy.golang.org"}),
			artifact: []string{
				"/github.com/foo/bar/@v/v1.0.0.zip",
				"/github.com/!b!a!d!/bar/@v/v1.0.0.zip", // invalid case-encoding
			},
			other: []string{"/github.com/foo/bar/@v/list", "/github.com/foo/bar/@v/v1.0.0.info", "/github.com/foo/bar/@v/v1.0.0.mod", "/github.com/foo/bar/@latest"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, ok := c.adapter.(gate.ArtifactPathMatcher)
			if !assert.True(t, ok, "adapter must implement gate.ArtifactPathMatcher") {
				return
			}
			for _, p := range c.artifact {
				assert.True(t, m.IsArtifactPath(httptest.NewRequest(http.MethodGet, p, nil)), "%s is an artifact", p)
			}
			for _, p := range c.other {
				assert.False(t, m.IsArtifactPath(httptest.NewRequest(http.MethodGet, p, nil)), "%s is not an artifact", p)
			}
		})
	}
}

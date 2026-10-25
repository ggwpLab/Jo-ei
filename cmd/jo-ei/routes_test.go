package main

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

func routesOf(handlers []string, raw []string) proxyRoutes {
	r := proxyRoutes{handlers: map[string]*proxy.Handler{}, raw: map[string]http.Handler{}}
	for _, p := range handlers {
		r.handlers[p] = &proxy.Handler{}
	}
	for _, p := range raw {
		r.raw[p] = http.NotFoundHandler()
	}
	return r
}

func TestRegistryCount(t *testing.T) {
	tests := []struct {
		name     string
		handlers []string
		raw      []string
		want     int
	}{
		{"single registry", []string{"pypi"}, nil, 1},
		{"yarn is an alias of npm", []string{"npm", "yarn"}, nil, 1},
		{"docker counts alongside packages", []string{"npm", "yarn", "maven"}, []string{"v2"}, 3},
		{"docker only", nil, []string{"v2"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, routesOf(tt.handlers, tt.raw).registryCount())
		})
	}
}

func TestPrefixes(t *testing.T) {
	got := routesOf([]string{"npm", "yarn"}, []string{"v2"}).prefixes()
	assert.ElementsMatch(t, []string{"npm", "yarn", "v2"}, got)
}

// Docker enabled without an image scanner is served by nothing; say so at
// startup instead of leaving /v2/ silently missing.
func TestBuildProxyRoutes_WarnsDockerWithoutImageScan(t *testing.T) {
	enableLogs(t)
	var logBuf bytes.Buffer
	cfg := &config.Config{}
	cfg.Registries.Docker.Enabled = true
	cfg.Registries.PyPI.Enabled = true
	cfg.Registries.PyPI.Upstreams = []string{"https://pypi.org"}

	routes, err := buildProxyRoutes(cfg, sharedDeps{logger: zerolog.New(&logBuf)}, scanners{}, upstreamClients{}, nil, nil, nil)
	require.NoError(t, err)

	_, served := routes.raw["v2"]
	assert.False(t, served)
	assert.Contains(t, logBuf.String(), "image_scan is disabled")
}

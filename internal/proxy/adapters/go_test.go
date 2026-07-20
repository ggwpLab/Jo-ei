package adapters_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
)

func TestGoAdapter_NormalizeRequest_Zip(t *testing.T) {
	a := adapters.NewGoAdapter([]string{"https://proxy.golang.org"})
	r := httptest.NewRequest(http.MethodGet, "/github.com/stretchr/testify/@v/v1.9.0.zip", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "go", ref.Ecosystem)
	assert.Equal(t, "github.com/stretchr/testify", ref.Name)
	assert.Equal(t, "v1.9.0", ref.Version)
}

func TestGoAdapter_NormalizeRequest_CaseEncoded(t *testing.T) {
	a := adapters.NewGoAdapter([]string{"https://proxy.golang.org"})
	r := httptest.NewRequest(http.MethodGet, "/github.com/!azure/azure-sdk-for-go/@v/v68.0.0+incompatible.zip", nil)
	ref, ok := a.NormalizeRequest(r)
	require.True(t, ok)
	assert.Equal(t, "github.com/Azure/azure-sdk-for-go", ref.Name)
	assert.Equal(t, "v68.0.0+incompatible", ref.Version)
}

func TestGoAdapter_NormalizeRequest_NotIntercepted(t *testing.T) {
	a := adapters.NewGoAdapter([]string{"https://proxy.golang.org"})
	for _, p := range []string{
		"/github.com/stretchr/testify/@v/list",
		"/github.com/stretchr/testify/@v/v1.9.0.info",
		"/github.com/stretchr/testify/@v/v1.9.0.mod",
		"/github.com/stretchr/testify/@latest",
		"/github.com/stretchr/testify/@v/.zip", // empty version
		"/no-atv-segment.zip",                  // missing /@v/
	} {
		r := httptest.NewRequest(http.MethodGet, p, nil)
		_, ok := a.NormalizeRequest(r)
		assert.False(t, ok, "path %q should not be intercepted", p)
	}
}

func TestGoAdapter_UpstreamURLs(t *testing.T) {
	a := adapters.NewGoAdapter([]string{"https://proxy.golang.org/", "https://mirror.example.org/go"})
	r := httptest.NewRequest(http.MethodGet, "/github.com/stretchr/testify/@v/list", nil)
	urls := a.UpstreamURLs(r)
	require.Len(t, urls, 2)
	assert.Equal(t, "https://proxy.golang.org/github.com/stretchr/testify/@v/list", urls[0])
	assert.Equal(t, "https://mirror.example.org/go/github.com/stretchr/testify/@v/list", urls[1])
}

func TestGoAdapter_Name(t *testing.T) {
	assert.Equal(t, "go", adapters.NewGoAdapter(nil).Name())
}

// keep imports used across Task 2 + Task 3
var _ = context.Background
var _ = json.NewEncoder
var _ = time.Now

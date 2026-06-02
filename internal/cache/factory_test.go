package cache_test

import (
	"testing"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_LocalBackend(t *testing.T) {
	for _, backend := range []string{"", "local"} {
		c, err := cache.New(config.CacheConfig{
			Backend: backend,
			Local:   config.LocalCache{Path: t.TempDir(), MaxSizeGB: 1},
		})
		require.NoError(t, err)
		require.NotNil(t, c)
		require.NoError(t, c.Close())
	}
}

func TestNew_S3NotImplemented(t *testing.T) {
	_, err := cache.New(config.CacheConfig{Backend: "s3"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestNew_UnknownBackend(t *testing.T) {
	_, err := cache.New(config.CacheConfig{Backend: "ftp"})
	require.Error(t, err)
}

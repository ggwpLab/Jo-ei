package cache

import (
	"fmt"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/config"
)

// defaultTTL is the cache entry lifetime when not otherwise specified.
const defaultTTL = 24 * time.Hour

// New constructs the cache backend selected by cfg.Backend.
// "" and "local" build a LocalCache; "s3" is reserved but not yet implemented
// (fail-fast rather than silently falling back to local).
func New(cfg config.CacheConfig) (Cache, error) {
	switch cfg.Backend {
	case "", "local":
		return NewLocalCache(LocalCacheConfig{
			RootPath:  cfg.Local.Path,
			MaxSizeGB: cfg.Local.MaxSizeGB,
			TTL:       defaultTTL,
		})
	case "s3":
		return nil, fmt.Errorf("s3 cache backend not yet implemented")
	default:
		return nil, fmt.Errorf("unknown cache backend %q (want local|s3)", cfg.Backend)
	}
}

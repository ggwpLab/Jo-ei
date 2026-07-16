package cache

import (
	"fmt"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/config"
)

// DefaultStaleAfterDays is the idle threshold applied when
// cache.local.stale_after_days is unset or zero.
const DefaultStaleAfterDays = 30

// New constructs the cache backend selected by cfg.Backend.
// "" and "local" build a LocalCache; "s3" is reserved but not yet implemented
// (fail-fast rather than silently falling back to local).
func New(cfg config.CacheConfig) (Cache, error) {
	switch cfg.Backend {
	case "", "local":
		days := cfg.Local.StaleAfterDays
		if days <= 0 {
			days = DefaultStaleAfterDays
		}
		return NewLocalCache(LocalCacheConfig{
			RootPath:   cfg.Local.Path,
			MaxSizeGB:  cfg.Local.MaxSizeGB,
			StaleAfter: time.Duration(days) * 24 * time.Hour,
		})
	case "s3":
		return nil, fmt.Errorf("s3 cache backend not yet implemented")
	default:
		return nil, fmt.Errorf("unknown cache backend %q (want local|s3)", cfg.Backend)
	}
}

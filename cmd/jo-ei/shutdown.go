package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

// shutdownGroup fixes one process-wide budget at the first shutdown trigger.
type shutdownGroup struct {
	once         sync.Once
	budget       time.Duration
	requestFlush func()
	ctx          context.Context
	cancel       context.CancelFunc
}

func newShutdownGroup(budget time.Duration, requestFlush func()) *shutdownGroup {
	if budget <= 0 {
		budget = defaultDrain
	}
	return &shutdownGroup{budget: budget, requestFlush: requestFlush}
}
func (g *shutdownGroup) Begin() context.Context {
	g.once.Do(func() {
		g.ctx, g.cancel = context.WithTimeout(context.Background(), g.budget)
		if g.requestFlush != nil {
			g.requestFlush()
		}
	})
	return g.ctx
}
func (g *shutdownGroup) Close() {
	if g.cancel != nil {
		g.cancel()
	}
}
func (g *shutdownGroup) httpContext(drain time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(g.Begin(), drain)
}

func (s *state) requestWriterFlush() {
	if s.store != nil {
		s.store.RequestFlush()
	}
	if usage, ok := s.cache.(cache.UsageBatcher); ok {
		usage.RequestUsageFlush()
	}
}

func logWriterDrain(log zerolog.Logger, component string, stats storage.WriterStats, err error) {
	log.Error().Err(err).Str("component", component).Int64("queued_items", stats.Queued).Int64("inflight_items", stats.InFlight).Int64("unsaved_items", stats.UnsavedItems).Uint64("abandoned_items", stats.AbandonedItems).Msg("async writer drain incomplete")
}

// shutdownWriters stops both admission points and drains concurrently under
// the remaining shared HTTP budget. Call before closing databases or logging.
func (s *state) shutdownWriters(ctx context.Context, log zerolog.Logger) error {
	errorsCh := make(chan error, 2)
	var wg sync.WaitGroup
	if s.store != nil {
		wg.Go(func() {
			err := s.store.Shutdown(ctx)
			if err != nil {
				logWriterDrain(log, "telemetry", s.store.WriterStats(), err)
			}
			errorsCh <- err
		})
	}
	if usage, ok := s.cache.(cache.UsageBatcher); ok {
		wg.Go(func() {
			err := usage.Shutdown(ctx)
			if err != nil {
				logWriterDrain(log, "cache_usage", usage.UsageWriterStats(), err)
			}
			errorsCh <- err
		})
	}
	wg.Wait()
	close(errorsCh)
	var result error
	for err := range errorsCh {
		result = errors.Join(result, err)
	}
	return result
}

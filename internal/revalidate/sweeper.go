package revalidate

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// Sweeper periodically re-validates due cache entries and evicts failures.
type Sweeper struct {
	store        RevalidationStore
	revalidators map[string]Revalidator
	recorder     proxy.Recorder
	cfg          Config
	logger       zerolog.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewSweeper builds a sweeper. revalidators is keyed by ecosystem; entries whose
// ecosystem has no revalidator are skipped.
func NewSweeper(store RevalidationStore, revalidators map[string]Revalidator, recorder proxy.Recorder, cfg Config, logger zerolog.Logger) *Sweeper {
	return &Sweeper{store: store, revalidators: revalidators, recorder: recorder, cfg: cfg, logger: logger}
}

// Start launches the background loop. Safe to call once.
func (s *Sweeper) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(s.cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sweepOnce(ctx)
			}
		}
	}()
}

// Close stops the loop and waits for it to exit. Safe to call once.
func (s *Sweeper) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

// sweepOnce processes one batch of due entries.
func (s *Sweeper) sweepOnce(ctx context.Context) {
	cutoff := time.Now().Add(-s.cfg.RevalidateAfter).Unix()
	entries, err := s.store.DueForRevalidation(cutoff, s.cfg.BatchSize)
	if err != nil {
		s.logger.Error().Err(err).Msg("revalidation: querying due entries")
		return
	}
	for _, e := range entries {
		rv, ok := s.revalidators[e.Ref.Ecosystem]
		if !ok {
			continue // no revalidator → skip without bumping last_validated
		}
		outcome, reason := rv.Revalidate(ctx, e)
		switch outcome {
		case Keep:
			if err := s.store.MarkValidated(&e.Ref, time.Now().Unix()); err != nil {
				s.logger.Error().Err(err).Str("package", e.Ref.Key()).Msg("revalidation: marking validated")
			}
		case Evict:
			if err := s.store.Invalidate(&e.Ref); err != nil {
				s.logger.Error().Err(err).Str("package", e.Ref.Key()).Msg("revalidation: invalidating")
			}
			s.recordEviction(e, reason)
			s.logger.Warn().Str("package", e.Ref.Key()).Str("reason", reasonText(reason)).Msg("revalidation evicted artifact")
		case Retry:
			// Leave as-is; re-queried next tick.
		}
	}
}

func reasonText(r *EvictReason) string {
	if r == nil {
		return ""
	}
	return r.Reason
}

func (s *Sweeper) recordEviction(e cache.RevalEntry, r *EvictReason) {
	if s.recorder == nil || r == nil {
		return
	}
	s.recorder.Record(proxy.Event{
		RequestID:        "revalidation",
		Time:             time.Now(),
		Ecosystem:        e.Ref.Ecosystem,
		Package:          e.Ref.Name,
		Version:          e.Ref.Version,
		Verdict:          proxy.VerdictBlock,
		Gate:             r.Gate,
		Reason:           r.Reason,
		BlockedBy:        []string{r.BlockedBy},
		CVEs:             r.Findings,
		MalwareEngine:    r.Engine,
		MalwareSignature: r.Signature,
	})
}

package metrics

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAsyncWriterMetrics_LabelsAndValues(t *testing.T) {
	m := New(BuildInfo{}, zerolog.Nop())
	s := storage.WriterStats{Capacity: 1024, Queued: 7, InFlight: 3, UnsavedItems: 10, LastBatchSize: 128, AttemptedItems: 25, AcceptedItems: 20, DroppedFullItems: 4, DroppedClosedItems: 1, AbandonedItems: 2, CommittedItems: 8, Batches: 2, Failures: 3, Retries: 2, OldestAge: 2 * time.Second, LastSuccessAge: 3 * time.Second, CommitTimeTotal: 1500 * time.Millisecond, LastCommitDuration: time.Second}
	m.RegisterAsyncWriter("telemetry", func() storage.WriterStats { return s })
	m.RegisterAsyncWriter("cache_usage", func() storage.WriterStats { return storage.WriterStats{} })
	m.RegisterAsyncWriter("unbounded-request-id", func() storage.WriterStats { t.Fatal("invalid component registered"); return s })
	var disabled *Metrics
	disabled.RegisterAsyncWriter("telemetry", nil)
	families, err := m.Registry.Gather()
	require.NoError(t, err)
	expected := map[string]float64{"capacity": 1024, "queue_depth": 7, "inflight_items": 3, "unsaved_items": 10, "oldest_age_seconds": 2, "last_success_age_seconds": 3, "attempted_items_total": 25, "accepted_items_total": 20, "committed_items_total": 8, "abandoned_items_total": 2, "batches_total": 2, "failures_total": 3, "retries_total": 2, "commit_seconds_total": 1.5, "last_batch_size": 128, "last_commit_seconds": 1, "dropped_items_total/queue_full": 4, "dropped_items_total/closed": 1}
	seen := map[string]float64{}
	for _, f := range families {
		for _, metric := range f.Metric {
			component, reason := "", ""
			for _, label := range metric.Label {
				switch label.GetName() {
				case "component":
					component = label.GetValue()
				case "reason":
					reason = label.GetValue()
				}
			}
			if component == "" {
				continue
			}
			require.Contains(t, []string{"telemetry", "cache_usage"}, component)
			require.Len(t, metric.Label, 1+boolInt(reason != ""))
			if component != "telemetry" {
				continue
			}
			key := f.GetName()[len("jo_ei_async_write_"):]
			if reason != "" {
				key += "/" + reason
			}
			if metric.Counter != nil {
				seen[key] = metric.Counter.GetValue()
			} else {
				seen[key] = metric.Gauge.GetValue()
			}
		}
	}
	assert.Equal(t, expected, seen)
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

type boundedBatchRepo struct{ telemetry.Repo }

func (r boundedBatchRepo) RecordBatch(ctx context.Context, token string, events []telemetry.BatchEvent) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	return r.Repo.RecordBatch(ctx, token, events)
}

func TestAsyncWriterMetrics_ObservableWithFailedStorage(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "blocked.db"))
	require.NoError(t, err)
	defer db.Close()
	repo, err := telemetry.NewSQLiteRepo(db, 30, 365)
	require.NoError(t, err)
	conn, err := db.SQL().Conn(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	s := telemetry.New(boundedBatchRepo{repo}, zerolog.Nop())
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_ = s.Shutdown(ctx)
	}()
	for range 3000 {
		s.Record(gate.Event{Verdict: gate.VerdictBlock})
	}
	s.RequestFlush()
	require.Eventually(t, func() bool { return s.WriterStats().Failures > 0 }, time.Second, time.Millisecond)
	m := New(BuildInfo{}, zerolog.Nop())
	m.RegisterAsyncWriter("telemetry", s.WriterStats)
	done := make(chan struct{})
	go func() {
		defer close(done)
		families, err := m.Registry.Gather()
		assert.NoError(t, err)
		var loss float64
		for _, f := range families {
			if f.GetName() == "jo_ei_async_write_dropped_items_total" {
				for _, v := range f.Metric {
					loss += v.Counter.GetValue()
				}
			}
		}
		assert.Positive(t, loss)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("metrics waited for SQL or flushed storage")
	}
}

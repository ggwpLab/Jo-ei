//go:build integration

package integration_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/storage/storagetest"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func TestTelemetryPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(storagetest.TempDir(t), "jo-ei.db")
	now := time.Now().UTC()

	// First "process": record (durable at write time), then close.
	{
		db, err := storage.Open(path)
		require.NoError(t, err)
		s, err := telemetry.Open(db, 30, 365, zerolog.Nop())
		require.NoError(t, err)
		s.Record(gate.Event{Time: now, Verdict: gate.VerdictCache, Gate: gate.GateCache})
		s.Record(gate.Event{Time: now, Verdict: gate.VerdictBlock, Gate: gate.GateSupply,
			Reason: "package_younger_than_min_age", Ecosystem: "npm", Package: "p", Version: "1",
			BlockUntil: now.Add(time.Hour)})
		require.NoError(t, s.Close())
		require.NoError(t, db.Close())
	}

	// Second "process": reopen the same file; state restored.
	db, err := storage.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := telemetry.Open(db, 30, 365, zerolog.Nop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	snap := s.Snapshot()
	assert.Equal(t, uint64(2), snap.Requests)
	assert.Equal(t, uint64(1), snap.CacheHits)
	assert.Equal(t, uint64(1), snap.Blocked)
	assert.Equal(t, uint64(1), snap.SupplyBlocked)

	require.Len(t, s.Recent(0), 2)

	q := s.Quarantine(now)
	require.Len(t, q, 1)
	assert.Equal(t, "p", q[0].Package)

	daily, err := s.DailyMetrics(0)
	require.NoError(t, err)
	require.Len(t, daily, 1)
	assert.Equal(t, uint64(2), daily[0].Requests)
}

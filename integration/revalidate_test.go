//go:build integration

package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/cache"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/revalidate"
)

// switchableAV reports clean until flipped to infected.
type switchableAV struct{ infected bool }

func (s *switchableAV) Scan(context.Context, string) (*gate.AVResult, error) {
	if s.infected {
		return &gate.AVResult{Clean: false, Engine: "clamav", Signature: "EICAR"}, nil
	}
	return &gate.AVResult{Clean: true}, nil
}

type recSpy struct{ events []gate.Event }

func (r *recSpy) Record(e gate.Event) { r.events = append(r.events, e) }

func TestRevalidationEvictsNewlyInfected(t *testing.T) {
	dir := t.TempDir()
	lc, err := cache.NewLocalCache(cache.LocalCacheConfig{RootPath: dir, MaxSizeGB: 1, StaleAfter: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lc.Close() })

	// Cache a clean artifact.
	art := filepath.Join(dir, "pkg.whl")
	require.NoError(t, os.WriteFile(art, []byte("payload"), 0o600))
	ref := gate.PackageRef{Ecosystem: "pypi", Name: "victim", Version: "1.0"}
	require.NoError(t, lc.Put(&ref, art, true, ""))

	// Make it due immediately (last_validated far in the past).
	require.NoError(t, lc.MarkValidated(&ref, time.Now().Add(-72*time.Hour).Unix()))

	// Sweep with an AV that now reports infected.
	av := &switchableAV{infected: true}
	rec := &recSpy{}
	sw := revalidate.NewSweeper(
		lc,
		map[string]revalidate.Revalidator{"pypi": revalidate.NewPackageRevalidator(nil, nil, av)},
		rec,
		revalidate.Config{Interval: time.Hour, RevalidateAfter: 24 * time.Hour, BatchSize: 10},
		zerolog.Nop(),
	)
	sw.SweepOnceForTest(context.Background())

	// Entry is gone and a malware block event was recorded.
	_, found := lc.Get(&ref)
	require.False(t, found, "infected artifact must be evicted")
	require.Len(t, rec.events, 1)
	require.Equal(t, gate.VerdictBlock, rec.events[0].Verdict)
	require.Equal(t, gate.GateMalware, rec.events[0].Gate)
}

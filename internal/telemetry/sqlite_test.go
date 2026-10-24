package telemetry_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/storage"
	"github.com/ggwpLab/Jo-ei/internal/storage/storagetest"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func newRepo(t *testing.T) telemetry.Repo {
	t.Helper()
	db, err := storage.Open(filepath.Join(storagetest.TempDir(t), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo, err := telemetry.NewSQLiteRepo(db, 30, 365)
	require.NoError(t, err)
	return repo
}

func TestSQLiteRepo_RecordEventRoundTrips(t *testing.T) {
	repo := newRepo(t)
	ev := gate.Event{
		RequestID: "r1", Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Ecosystem: "npm", Package: "left-pad", Version: "1.0.0",
		Verdict: gate.VerdictBlock, Gate: gate.GateSupply, Reason: "package_younger_than_min_age",
		HTTPStatus: 423, BlockedBy: []string{"supply_chain"},
		PublishedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		BlockUntil:  time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC),
	}
	require.NoError(t, repo.RecordEvent(ev))

	got, err := repo.Recent(100)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "r1", got[0].RequestID)
	assert.Equal(t, "left-pad", got[0].Package)
	assert.Equal(t, gate.VerdictBlock, got[0].Verdict)
	assert.Equal(t, []string{"supply_chain"}, got[0].BlockedBy)
	assert.True(t, got[0].Time.Equal(ev.Time))
	assert.True(t, got[0].BlockUntil.Equal(ev.BlockUntil))
}

func TestSQLiteRepo_RecordEventAccumulatesCountersAndDaily(t *testing.T) {
	repo := newRepo(t)
	today := time.Now().UTC()
	require.NoError(t, repo.RecordEvent(gate.Event{Time: today, Verdict: gate.VerdictCache, Gate: gate.GateCache}))
	require.NoError(t, repo.RecordEvent(gate.Event{Time: today, Verdict: gate.VerdictBlock, Gate: gate.GateSupply,
		Reason: "package_younger_than_min_age", Ecosystem: "npm", Package: "p", Version: "1"}))
	require.NoError(t, repo.RecordEvent(gate.Event{Time: today, Verdict: gate.VerdictBlock, Gate: gate.GateCVE, Reason: "cve_found"}))

	started := time.Now()
	snap, err := repo.Snapshot(started)
	require.NoError(t, err)
	assert.True(t, snap.StartedAt.Equal(started))
	assert.Equal(t, uint64(3), snap.Requests)
	assert.Equal(t, uint64(1), snap.CacheHits)
	assert.Equal(t, uint64(2), snap.Blocked)
	assert.Equal(t, uint64(1), snap.SupplyBlocked)
	assert.Equal(t, uint64(1), snap.CVEBlocked)
	assert.Equal(t, telemetry.GateCounts{Pass: 1, Block: 0}, snap.Gates[gate.GateCache])
	assert.Equal(t, telemetry.GateCounts{Pass: 1, Block: 1}, snap.Gates[gate.GateSupply])
	assert.Equal(t, telemetry.GateCounts{Pass: 0, Block: 1}, snap.Gates[gate.GateCVE])

	rows, err := repo.DailyMetrics(0)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, today.Format("2006-01-02"), rows[0].Day)
	assert.Equal(t, uint64(3), rows[0].Requests)
	assert.Equal(t, telemetry.GateCounts{Pass: 1, Block: 1}, rows[0].Gates[gate.GateSupply])
}

func TestSQLiteRepo_SnapshotEmptyIsZeroValue(t *testing.T) {
	repo := newRepo(t)
	snap, err := repo.Snapshot(time.Now())
	require.NoError(t, err)
	assert.Equal(t, uint64(0), snap.Requests)
	assert.NotNil(t, snap.Gates)
	assert.Equal(t, telemetry.GateCounts{}, snap.Gates[gate.GateSupply])

	recent, err := repo.Recent(100)
	require.NoError(t, err)
	assert.Empty(t, recent)
}

func TestSQLiteRepo_QuarantineDedupesBeforeExpiry(t *testing.T) {
	repo := newRepo(t)
	now := time.Now()
	mk := func(id, ver string, until time.Time) gate.Event {
		return gate.Event{
			RequestID: id, Time: time.Now(), Ecosystem: "npm", Package: "p", Version: ver,
			Verdict: gate.VerdictBlock, Gate: gate.GateSupply, BlockUntil: until,
		}
	}
	require.NoError(t, repo.RecordEvent(mk("r1", "1", now.Add(time.Hour))))
	require.NoError(t, repo.RecordEvent(mk("r2", "1", now.Add(2*time.Hour)))) // newer, same key

	q, err := repo.Quarantine(now)
	require.NoError(t, err)
	require.Len(t, q, 1)
	assert.Equal(t, "r2", q[0].RequestID)

	require.NoError(t, repo.RecordEvent(mk("r3", "1", now.Add(-time.Minute)))) // newest expired
	q, err = repo.Quarantine(now)
	require.NoError(t, err)
	assert.Empty(t, q)
}

func TestSQLiteRepo_DailyMetricsLimit(t *testing.T) {
	repo := newRepo(t)
	for _, d := range []time.Time{
		time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 3, 12, 0, 0, 0, time.UTC),
	} {
		require.NoError(t, repo.RecordEvent(gate.Event{Time: d, Verdict: gate.VerdictPass, Gate: gate.GateMalware}))
	}
	rows, err := repo.DailyMetrics(2)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "2026-01-03", rows[0].Day)
	assert.Equal(t, "2026-01-02", rows[1].Day)
}

func TestSQLiteRepo_PruneRemovesOldEvents(t *testing.T) {
	db, err := storage.Open(filepath.Join(storagetest.TempDir(t), "t.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo, err := telemetry.NewSQLiteRepo(db, 1, 1) // 1-day retention
	require.NoError(t, err)

	require.NoError(t, repo.RecordEvent(gate.Event{RequestID: "old", Time: time.Now().Add(-72 * time.Hour), Verdict: gate.VerdictPass, Gate: gate.GateMalware}))
	require.NoError(t, repo.RecordEvent(gate.Event{RequestID: "fresh", Time: time.Now(), Verdict: gate.VerdictPass, Gate: gate.GateMalware}))
	require.NoError(t, repo.Prune())

	got, err := repo.Recent(100)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "fresh", got[0].RequestID)
}

func TestSQLiteRepo_PagePagesAllWithoutGapsOrDupes(t *testing.T) {
	repo := newRepo(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// 5 events sharing the SAME ts to exercise the (ts, id) tiebreak.
	for i := 1; i <= 5; i++ {
		require.NoError(t, repo.RecordEvent(gate.Event{
			RequestID: fmt.Sprintf("r%d", i), Time: base,
			Verdict: gate.VerdictBlock, Gate: gate.GateSupply,
			Ecosystem: "npm", Package: "p", Version: "1",
		}))
	}

	var ids []string
	cursor := telemetry.Cursor{}
	for {
		evs, next, err := repo.Page(gate.VerdictBlock, "", cursor, 2)
		require.NoError(t, err)
		for _, ev := range evs {
			ids = append(ids, ev.RequestID)
		}
		if next.Zero() {
			break
		}
		cursor = next
	}
	// Newest-first, every row exactly once.
	assert.Equal(t, []string{"r5", "r4", "r3", "r2", "r1"}, ids)
}

func TestSQLiteRepo_PageFiltersByVerdict(t *testing.T) {
	repo := newRepo(t)
	now := time.Now()
	require.NoError(t, repo.RecordEvent(gate.Event{RequestID: "pass1", Time: now, Verdict: gate.VerdictPass, Gate: gate.GateSupply}))
	require.NoError(t, repo.RecordEvent(gate.Event{RequestID: "err1", Time: now.Add(time.Second), Verdict: gate.VerdictError, Gate: gate.GateCache}))
	require.NoError(t, repo.RecordEvent(gate.Event{RequestID: "block1", Time: now.Add(2 * time.Second), Verdict: gate.VerdictBlock, Gate: gate.GateCVE}))

	evs, next, err := repo.Page(gate.VerdictError, "", telemetry.Cursor{}, 10)
	require.NoError(t, err)
	require.Len(t, evs, 1)
	assert.Equal(t, "err1", evs[0].RequestID)
	assert.True(t, next.Zero(), "single matching row is the last page")
}

func TestSQLiteRepo_PageEmptyVerdictReturnsAllNewestFirst(t *testing.T) {
	repo := newRepo(t)
	now := time.Now()
	require.NoError(t, repo.RecordEvent(gate.Event{RequestID: "a", Time: now, Verdict: gate.VerdictPass, Gate: gate.GateSupply}))
	require.NoError(t, repo.RecordEvent(gate.Event{RequestID: "b", Time: now.Add(time.Second), Verdict: gate.VerdictBlock, Gate: gate.GateCVE}))

	evs, next, err := repo.Page("", "", telemetry.Cursor{}, 10)
	require.NoError(t, err)
	require.Len(t, evs, 2)
	assert.Equal(t, "b", evs[0].RequestID, "newest first")
	assert.True(t, next.Zero())
}

func TestSQLiteRepo_PageFiltersByText(t *testing.T) {
	repo := newRepo(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	add := func(i int, id, pkg, ver, verdict string) {
		t.Helper()
		require.NoError(t, repo.RecordEvent(gate.Event{
			RequestID: id, Time: base.Add(time.Duration(i) * time.Second),
			Verdict: verdict, Gate: gate.GateSupply,
			Ecosystem: "npm", Package: pkg, Version: ver,
		}))
	}
	add(1, "req-aaa", "lodash", "4.17.21", gate.VerdictPass)
	add(2, "req-bbb", "left_pad", "1.3.0", gate.VerdictBlock)
	add(3, "req-ccc", "leftxpad", "1.3.0", gate.VerdictPass)
	add(4, "req-ddd", "Lodash.Merge", "4.6.2", gate.VerdictBlock)

	ids := func(verdict, text string) []string {
		t.Helper()
		evs, _, err := repo.Page(verdict, text, telemetry.Cursor{}, 10)
		require.NoError(t, err)
		out := []string{}
		for _, ev := range evs {
			out = append(out, ev.RequestID)
		}
		return out
	}

	assert.Equal(t, []string{"req-ddd", "req-aaa"}, ids("", "LODASH"), "package match is case-insensitive")
	assert.Equal(t, []string{"req-aaa"}, ids("", "lodash@4.17"), "matches across package@version")
	assert.Equal(t, []string{"req-ccc", "req-bbb"}, ids("", "1.3.0"), "matches version")
	assert.Equal(t, []string{"req-bbb"}, ids("", "req-bbb"), "matches request_id")
	assert.Equal(t, []string{"req-bbb"}, ids("", "left_pad"), "_ is literal, not a LIKE wildcard")
	assert.Empty(t, ids("", "%"), "% is literal, not a LIKE wildcard")
	assert.Equal(t, []string{"req-ddd"}, ids(gate.VerdictBlock, "lodash"), "combines with verdict")
	assert.Len(t, ids("", ""), 4, "empty text matches everything")
}

func TestSQLiteRepo_PageTextIsNotSQL(t *testing.T) {
	repo := newRepo(t)
	now := time.Now()
	require.NoError(t, repo.RecordEvent(gate.Event{RequestID: "plain", Time: now, Verdict: gate.VerdictPass, Gate: gate.GateSupply, Package: "lodash", Version: "1"}))
	require.NoError(t, repo.RecordEvent(gate.Event{RequestID: "quoted", Time: now.Add(time.Second), Verdict: gate.VerdictPass, Gate: gate.GateSupply, Package: "it's", Version: "1"}))

	for _, text := range []string{
		`' OR 1=1 --`,
		`" OR ""="`,
		`x'); DROP TABLE events;--`,
		`%' UNION SELECT 1, 1, sqlite_version() --`,
		`\`,
	} {
		evs, _, err := repo.Page("", text, telemetry.Cursor{}, 10)
		require.NoError(t, err, text)
		assert.Empty(t, evs, "%q must match as a literal substring, not as SQL", text)
	}

	evs, _, err := repo.Page("", "it's", telemetry.Cursor{}, 10)
	require.NoError(t, err)
	require.Len(t, evs, 1, "a quote in the text is just a character")
	assert.Equal(t, "quoted", evs[0].RequestID)

	all, err := repo.Recent(10)
	require.NoError(t, err)
	assert.Len(t, all, 2, "the events table survives")
}

func TestSQLiteRepo_PageTextPagesWithCursor(t *testing.T) {
	repo := newRepo(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= 6; i++ {
		pkg := "other"
		if i%2 == 0 {
			pkg = "wanted"
		}
		require.NoError(t, repo.RecordEvent(gate.Event{
			RequestID: fmt.Sprintf("r%d", i), Time: base.Add(time.Duration(i) * time.Second),
			Verdict: gate.VerdictPass, Gate: gate.GateSupply,
			Ecosystem: "npm", Package: pkg, Version: "1",
		}))
	}

	var ids []string
	cursor := telemetry.Cursor{}
	for {
		evs, next, err := repo.Page("", "wanted", cursor, 2)
		require.NoError(t, err)
		for _, ev := range evs {
			ids = append(ids, ev.RequestID)
		}
		if next.Zero() {
			break
		}
		cursor = next
	}
	assert.Equal(t, []string{"r6", "r4", "r2"}, ids)
}

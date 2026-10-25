package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/health"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "ready.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db.SQL()
}

func ready(t *testing.T, db *sql.DB, snap []health.ScannerHealth) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	readinessHandler(db, func() []health.ScannerHealth { return snap }).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return rec.Code, body
}

func TestReady_AllHealthy(t *testing.T) {
	code, body := ready(t, openTestDB(t), []health.ScannerHealth{
		{Name: "clamav", Enabled: true, Status: health.StatusOK},
	})
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "ready", body["status"])
}

// osv.dev is tracked passively and stays unknown until traffic, so unknown
// must not fail readiness; a disabled scanner's state does not matter.
func TestReady_ScannerDown(t *testing.T) {
	code, body := ready(t, openTestDB(t), []health.ScannerHealth{
		{Name: "clamav", Enabled: true, Status: health.StatusDown},
		{Name: "osv.dev", Enabled: true, Status: health.StatusUnknown},
		{Name: "trivy", Enabled: false, Status: health.StatusDown},
	})
	assert.Equal(t, http.StatusServiceUnavailable, code)
	assert.Equal(t, "not_ready", body["status"])
	assert.Equal(t, []any{"clamav"}, body["failing"])
}

func TestReady_DatabaseClosed(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.Close())
	code, body := ready(t, db, nil)
	assert.Equal(t, http.StatusServiceUnavailable, code)
	assert.Contains(t, body["failing"], "database")
}

// A passively tracked engine (osv.dev) reports its last lookup, which on an
// idle instance can stay "down" for hours after one timeout; it must not hold
// readiness down.
func TestReady_PassiveDownDoesNotFail(t *testing.T) {
	code, body := ready(t, openTestDB(t), []health.ScannerHealth{
		{Name: "osv.dev", Enabled: true, Passive: true, Status: health.StatusDown},
	})
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "ready", body["status"])
}

// /ready is public; probes in quick succession share one evaluation instead of
// each taking the single SQLite connection.
func TestReady_CachesBriefly(t *testing.T) {
	calls := 0
	h := readinessHandler(openTestDB(t), func() []health.ScannerHealth { calls++; return nil })
	for range 5 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
		require.Equal(t, http.StatusOK, rec.Code)
	}
	assert.Equal(t, 1, calls)
}

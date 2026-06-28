package settings_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

func newStore(t *testing.T) *settings.Store {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "s.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	st, err := settings.New(db)
	require.NoError(t, err)
	return st
}

func TestGetMissingKey(t *testing.T) {
	st := newStore(t)
	v, ok, err := st.Get("policy")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, v)
}

func TestPutThenGetRoundTrip(t *testing.T) {
	st := newStore(t)
	require.NoError(t, st.Put("policy", []byte(`{"mode":"enforce"}`)))
	v, ok, err := st.Get("policy")
	require.NoError(t, err)
	require.True(t, ok)
	assert.JSONEq(t, `{"mode":"enforce"}`, string(v))
}

func TestPutOverwrites(t *testing.T) {
	st := newStore(t)
	require.NoError(t, st.Put("registries", []byte(`[]`)))
	require.NoError(t, st.Put("registries", []byte(`[{"eco":"pypi"}]`)))
	v, ok, err := st.Get("registries")
	require.NoError(t, err)
	require.True(t, ok)
	assert.JSONEq(t, `[{"eco":"pypi"}]`, string(v))
}

func TestNewIsIdempotent(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "s.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	_, err = settings.New(db)
	require.NoError(t, err)
	_, err = settings.New(db) // second migration apply must be a no-op
	require.NoError(t, err)
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/settings"
	"github.com/ggwpLab/Jo-ei/internal/storage"
)

func testSettings(t *testing.T) *settings.Store {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	st, err := settings.New(db)
	require.NoError(t, err)
	return st
}

func TestResolveJWTSecretPrefersTheEnvironment(t *testing.T) {
	t.Setenv("JOEI_CONSOLE_JWT_SECRET", "env-secret-that-is-long-enough-32")
	st := testSettings(t)

	got, err := resolveJWTSecret("file-secret-that-is-long-enough-3", st, zerolog.New(io.Discard))

	require.NoError(t, err)
	assert.Equal(t, "env-secret-that-is-long-enough-32", string(got))
}

func TestResolveJWTSecretFallsBackToTheFile(t *testing.T) {
	t.Setenv("JOEI_CONSOLE_JWT_SECRET", "")
	st := testSettings(t)

	got, err := resolveJWTSecret("file-secret-that-is-long-enough-3", st, zerolog.New(io.Discard))

	require.NoError(t, err)
	assert.Equal(t, "file-secret-that-is-long-enough-3", string(got))
}

func TestResolveJWTSecretGeneratesAndPersists(t *testing.T) {
	t.Setenv("JOEI_CONSOLE_JWT_SECRET", "")
	st := testSettings(t)

	first, err := resolveJWTSecret("", st, zerolog.New(io.Discard))
	require.NoError(t, err)
	assert.Len(t, first, 32)

	// It must be stored, so a restart against the same database keeps sessions
	// alive rather than logging everyone out.
	raw, ok, err := st.Get(jwtSecretSettingKey)
	require.NoError(t, err)
	require.True(t, ok)
	var encoded string
	require.NoError(t, json.Unmarshal(raw, &encoded))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, first, decoded)

	second, err := resolveJWTSecret("", st, zerolog.New(io.Discard))
	require.NoError(t, err)
	assert.Equal(t, first, second, "a second boot must reuse the stored secret")
}

func TestAuthTTLDefaults(t *testing.T) {
	access, refresh := authTTLs(config.AuthConfig{})
	assert.Equal(t, 15*time.Minute, access)
	assert.Equal(t, 168*time.Hour, refresh)

	access, refresh = authTTLs(config.AuthConfig{AccessTTLMinutes: 5, RefreshTTLHours: 24})
	assert.Equal(t, 5*time.Minute, access)
	assert.Equal(t, 24*time.Hour, refresh)
}

package console

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func TestEncodeCursorRoundTrips(t *testing.T) {
	c := telemetry.Cursor{TS: time.Unix(0, 1718600000000000123), ID: 4213}
	s := encodeCursor(c)
	assert.Equal(t, "1718600000000000123:4213", s)

	got, ok := parseCursor(s)
	assert.True(t, ok)
	assert.Equal(t, int64(1718600000000000123), got.TS.UnixNano())
	assert.Equal(t, int64(4213), got.ID)
}

func TestEncodeCursorZeroIsEmpty(t *testing.T) {
	assert.Equal(t, "", encodeCursor(telemetry.Cursor{}))
}

func TestParseCursorRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "abc", "123", "1:2:3", "x:2", "1:y", "1:0", "1:-3"} {
		_, ok := parseCursor(bad)
		assert.False(t, ok, "cursor %q must be rejected", bad)
	}
}

func TestValidVerdict(t *testing.T) {
	for _, v := range []string{"PASS", "CACHE", "BLOCK", "ERROR"} {
		assert.True(t, validVerdict(v), v)
	}
	for _, v := range []string{"pass", "BOGUS", "", "BLOCKED"} {
		assert.False(t, validVerdict(v), v)
	}
}

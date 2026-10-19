package telemetry_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

// failingRepo fails every write; reads are never reached by this test.
type failingRepo struct{ telemetry.Repo }

func (failingRepo) RecordEvent(gate.Event) error { return errors.New("disk full") }

func TestStore_RecordFailureLogsEventRequestID(t *testing.T) {
	var buf bytes.Buffer
	s := telemetry.New(failingRepo{}, zerolog.New(&buf))
	t.Cleanup(func() { _ = s.Close() })

	s.Record(gate.Event{RequestID: "rid-tel"})

	var line map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line), buf.String())
	assert.Equal(t, "rid-tel", line["request_id"])
	assert.Equal(t, "telemetry", line["component"])
	assert.Equal(t, "recording event", line["message"])
}

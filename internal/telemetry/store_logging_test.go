package telemetry_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

// failingRepo fails every write; reads are never reached by this test.
type failingRepo struct{ telemetry.Repo }

func (failingRepo) RecordBatch(context.Context, string, []telemetry.BatchEvent) error {
	return errors.New("disk full")
}

func TestStore_RecordFailureDoesNotLogOnProducer(t *testing.T) {
	var buf bytes.Buffer
	s := telemetry.New(failingRepo{}, zerolog.New(&buf))

	s.Record(gate.Event{RequestID: "rid-tel"})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.Error(t, s.Shutdown(ctx))
	// Join before inspecting the unsynchronized log buffer.
	assert.Empty(t, buf.String())
	assert.Equal(t, uint64(1), s.WriterStats().AbandonedItems)
}

package telemetry_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/telemetry"
)

func TestBroadcasterDeliversToAllSubscribers(t *testing.T) {
	b := telemetry.NewBroadcaster()
	ch1, cancel1 := b.Subscribe()
	ch2, cancel2 := b.Subscribe()
	defer cancel1()
	defer cancel2()

	b.Publish(evt("r1", gate.VerdictPass, gate.GateSupply, "ok"))

	for _, ch := range []<-chan gate.Event{ch1, ch2} {
		select {
		case got := <-ch:
			assert.Equal(t, "r1", got.RequestID)
		case <-time.After(time.Second):
			t.Fatal("subscriber did not receive event")
		}
	}
}

func TestBroadcasterCancelStopsDelivery(t *testing.T) {
	b := telemetry.NewBroadcaster()
	ch, cancel := b.Subscribe()
	cancel()
	cancel() // idempotent

	b.Publish(evt("r1", gate.VerdictPass, gate.GateSupply, "ok"))

	_, open := <-ch
	assert.False(t, open, "cancelled subscriber channel is closed")
}

func TestBroadcasterSlowSubscriberLosesEventsWithoutBlocking(t *testing.T) {
	b := telemetry.NewBroadcaster()
	ch, cancel := b.Subscribe()
	defer cancel()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ { // far beyond any buffer
			b.Publish(evt("r", gate.VerdictPass, gate.GateSupply, "ok"))
		}
		close(done)
	}()

	select {
	case <-done: // publisher never stalls on the full channel
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Publish blocked on a slow subscriber")
	}
	assert.LessOrEqual(t, len(ch), 16, "slow subscriber only buffers up to its channel depth")
}

func TestHubRecordsAndPublishes(t *testing.T) {
	store := newStore(t)
	b := telemetry.NewBroadcaster()
	hub := &telemetry.Hub{Store: store, Broadcaster: b}
	ch, cancel := b.Subscribe()
	defer cancel()

	hub.Record(evt("r1", gate.VerdictCache, gate.GateCache, "cache_hit"))

	require.Len(t, store.Recent(0), 1)
	select {
	case got := <-ch:
		assert.Equal(t, "r1", got.RequestID)
	case <-time.After(time.Second):
		t.Fatal("hub did not publish")
	}
}

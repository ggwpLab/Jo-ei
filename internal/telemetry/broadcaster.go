package telemetry

import (
	"sync"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

// subscriberBuffer is the per-subscriber channel depth. A subscriber whose
// channel is full misses events rather than stalling the publisher.
const subscriberBuffer = 16

// Broadcaster fans out events to live subscribers (SSE handlers).
// Publish never blocks.
type Broadcaster struct {
	mu   sync.Mutex
	subs map[chan proxy.Event]struct{}
}

// NewBroadcaster creates an empty Broadcaster.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{subs: map[chan proxy.Event]struct{}{}}
}

// Subscribe registers a subscriber. The returned cancel func releases it and
// closes the channel; calling cancel more than once is safe.
func (b *Broadcaster) Subscribe() (<-chan proxy.Event, func()) {
	ch := make(chan proxy.Event, subscriberBuffer)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	cancel := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
	}
	return ch, cancel
}

// Publish delivers ev to every subscriber with buffer room; slow subscribers
// lose the event so the proxy data path never stalls.
func (b *Broadcaster) Publish(ev proxy.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Hub implements proxy.Recorder by recording to Store and publishing to
// Broadcaster. Both fields must be non-nil.
type Hub struct {
	Store       *Store
	Broadcaster *Broadcaster
}

// Record implements proxy.Recorder.
func (h *Hub) Record(ev proxy.Event) {
	h.Store.Record(ev)
	h.Broadcaster.Publish(ev)
}

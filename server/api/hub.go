package api

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/dlenrow/hookmon/pkg/event"
)

// DefaultSubscriberBuffer is how many events a WebSocket subscriber may
// fall behind before the hub drops it.
const DefaultSubscriberBuffer = 256

// Hub fans processed events out to every WebSocket subscriber. Each
// subscriber has its own bounded buffer. Publish never waits: a subscriber
// whose buffer is full is dropped (its channel is closed and Lagged reports
// true), so one slow browser tab can neither block ingestion nor make
// another tab miss events. A dropped tab reconnects and reloads recent
// events over REST, so a connected subscriber has every event since it
// subscribed, in order.
type Hub struct {
	buffer int

	mu     sync.Mutex
	subs   map[*Subscription]struct{}
	closed bool

	published atomic.Uint64
	lagged    atomic.Uint64
}

// Subscription is one subscriber's feed.
type Subscription struct {
	ch     chan *event.HookEvent
	lagged atomic.Bool
}

// Events delivers the subscriber's events. It is closed when the
// subscription ends: by Unsubscribe, by the hub dropping a subscriber that
// fell behind (Lagged is then true), or by the hub shutting down.
func (s *Subscription) Events() <-chan *event.HookEvent { return s.ch }

// Lagged reports whether the hub dropped the subscriber because its buffer
// was full.
func (s *Subscription) Lagged() bool { return s.lagged.Load() }

// NewHub returns a hub whose subscribers each buffer up to buffer events.
// A buffer below 1 means DefaultSubscriberBuffer.
func NewHub(buffer int) *Hub {
	if buffer < 1 {
		buffer = DefaultSubscriberBuffer
	}
	return &Hub{buffer: buffer, subs: make(map[*Subscription]struct{})}
}

// Subscribe adds a subscriber. It returns nil once the hub has shut down.
func (h *Hub) Subscribe() *Subscription {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	s := &Subscription{ch: make(chan *event.HookEvent, h.buffer)}
	h.subs[s] = struct{}{}
	return s
}

// Unsubscribe removes a subscriber and closes its channel. It is safe to
// call more than once, and after the hub dropped the subscriber.
func (h *Hub) Unsubscribe(s *Subscription) {
	if s == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[s]; ok {
		delete(h.subs, s)
		close(s.ch)
	}
}

// Publish hands evt to every subscriber without waiting. A subscriber whose
// buffer is full is dropped.
func (h *Hub) Publish(evt *event.HookEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.published.Add(1)
	for s := range h.subs {
		select {
		case s.ch <- evt:
		default:
			s.lagged.Store(true)
			delete(h.subs, s)
			close(s.ch)
			h.lagged.Add(1)
		}
	}
}

// Run publishes every event from src until ctx is done or src is closed,
// then shuts the hub down, closing every subscriber's channel.
func (h *Hub) Run(ctx context.Context, src <-chan *event.HookEvent) {
	defer h.close()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-src:
			if !ok {
				return
			}
			h.Publish(evt)
		}
	}
}

func (h *Hub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for s := range h.subs {
		delete(h.subs, s)
		close(s.ch)
	}
}

// HubStats are the hub's counts since the server started.
type HubStats struct {
	// Subscribers is the number of WebSocket clients connected now.
	Subscribers int `json:"subscribers"`
	// Published is the number of events handed to the hub.
	Published uint64 `json:"published"`
	// Lagged is the number of subscribers dropped because they fell more
	// than the buffer behind.
	Lagged uint64 `json:"lagged"`
	// Buffer is each subscriber's buffer, in events.
	Buffer int `json:"buffer"`
}

// Stats returns the hub's counts.
func (h *Hub) Stats() HubStats {
	h.mu.Lock()
	n := len(h.subs)
	h.mu.Unlock()
	return HubStats{Subscribers: n, Published: h.published.Load(), Lagged: h.lagged.Load(), Buffer: h.buffer}
}

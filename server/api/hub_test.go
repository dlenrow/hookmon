package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

func dashEvt(i int) *event.HookEvent {
	return &event.HookEvent{ID: fmt.Sprintf("evt-%03d", i), EventType: event.EventBPFLoad, Severity: event.SeverityWarn}
}

// dashDrain reads what is buffered on sub, without waiting, and reports
// whether the channel is closed.
func dashDrain(sub *Subscription) (ids []string, closed bool) {
	for {
		select {
		case e, ok := <-sub.Events():
			if !ok {
				return ids, true
			}
			ids = append(ids, e.ID)
		default:
			return ids, false
		}
	}
}

func TestHub_EverySubscriberGetsEveryEvent(t *testing.T) {
	h := NewHub(200)
	subs := []*Subscription{h.Subscribe(), h.Subscribe(), h.Subscribe()}
	for i := 0; i < 150; i++ {
		h.Publish(dashEvt(i))
	}
	for n, s := range subs {
		ids, closed := dashDrain(s)
		if closed || len(ids) != 150 {
			t.Fatalf("subscriber %d: %d events, closed %v; want 150, open", n, len(ids), closed)
		}
		for i, id := range ids {
			if want := dashEvt(i).ID; id != want {
				t.Fatalf("subscriber %d: event %d is %s, want %s (order)", n, i, id, want)
			}
		}
	}
	if st := h.Stats(); st.Subscribers != 3 || st.Published != 150 || st.Lagged != 0 {
		t.Errorf("stats: %+v", st)
	}
}

// A subscriber that stops reading is dropped once its buffer is full.
// Publish never waits for it, and the others keep every event.
func TestHub_SlowSubscriberDroppedWithoutBlocking(t *testing.T) {
	const buf, n = 4, 1000
	h := NewHub(buf)
	slow, fast := h.Subscribe(), h.Subscribe()

	// The fast subscriber reads each event before the next is published;
	// the slow one never reads.
	var got []string
	published := make(chan time.Duration)
	go func() {
		start := time.Now()
		for i := 0; i < n; i++ {
			h.Publish(dashEvt(i))
			e, ok := <-fast.Events()
			if !ok {
				break
			}
			got = append(got, e.ID)
		}
		published <- time.Since(start)
	}()
	select {
	case d := <-published:
		t.Logf("published %d events in %v with a stalled subscriber", n, d)
	case <-time.After(10 * time.Second):
		t.Fatal("Publish blocked on a subscriber that does not read")
	}
	if len(got) != n || got[n-1] != dashEvt(n-1).ID {
		t.Fatalf("fast subscriber got %d of %d events", len(got), n)
	}

	ids, closed := dashDrain(slow)
	if !closed || !slow.Lagged() {
		t.Fatalf("slow subscriber: closed %v, lagged %v; want both", closed, slow.Lagged())
	}
	if len(ids) != buf {
		t.Errorf("slow subscriber kept %d buffered events, want %d", len(ids), buf)
	}
	if fast.Lagged() {
		t.Error("fast subscriber marked lagged")
	}
	if st := h.Stats(); st.Subscribers != 1 || st.Lagged != 1 || st.Published != n {
		t.Errorf("stats: %+v", st)
	}
	h.Unsubscribe(slow) // after the hub dropped it: no panic
}

func TestHub_Unsubscribe(t *testing.T) {
	h := NewHub(8)
	a, b := h.Subscribe(), h.Subscribe()
	h.Unsubscribe(a)
	h.Unsubscribe(a) // twice: no panic
	h.Unsubscribe(nil)
	h.Publish(dashEvt(1))
	if ids, closed := dashDrain(a); !closed || len(ids) != 0 || a.Lagged() {
		t.Errorf("unsubscribed: %v closed %v lagged %v", ids, closed, a.Lagged())
	}
	if ids, closed := dashDrain(b); closed || len(ids) != 1 {
		t.Errorf("still subscribed: %v closed %v", ids, closed)
	}
	if st := h.Stats(); st.Subscribers != 1 {
		t.Errorf("subscribers: %d, want 1", st.Subscribers)
	}
}

func TestHub_RunPublishesAndShutsDown(t *testing.T) {
	h := NewHub(0)
	if h.Stats().Buffer != DefaultSubscriberBuffer {
		t.Errorf("default buffer: %d", h.Stats().Buffer)
	}
	sub := h.Subscribe()
	src := make(chan *event.HookEvent)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.Run(ctx, src) }()

	src <- dashEvt(1)
	select {
	case e := <-sub.Events():
		if e.ID != dashEvt(1).ID {
			t.Errorf("got %s", e.ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not publish")
	}
	cancel()
	<-done
	if _, closed := dashDrain(sub); !closed || sub.Lagged() {
		t.Errorf("after shutdown: closed %v lagged %v; want closed, not lagged", closed, sub.Lagged())
	}
	if h.Subscribe() != nil {
		t.Error("Subscribe after shutdown returned a subscription")
	}
	h.Publish(dashEvt(2)) // after shutdown: no panic
}

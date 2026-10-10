package connectors

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// siemFake is an in-memory connector. With block set, Send waits until
// block is closed or its context ends.
type siemFake struct {
	name  string
	block chan struct{}

	mu     sync.Mutex
	got    []*event.HookEvent
	closed bool
}

func (f *siemFake) Name() string { return f.name }

func (f *siemFake) Send(ctx context.Context, batch []*event.HookEvent) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	f.got = append(f.got, batch...)
	f.mu.Unlock()
	return nil
}

func (f *siemFake) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *siemFake) ids() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.got {
		out = append(out, e.ID)
	}
	return out
}

// siemSeen is an AlertFilter that admits each ID once.
type siemSeen struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (s *siemSeen) Admit(evt *event.HookEvent) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	key := string(evt.EventType) + "|" + evt.ExePath
	if s.seen[key] {
		return false
	}
	s.seen[key] = true
	return true
}

func siemEvt(id string, sev event.Severity, action event.PolicyAction) *event.HookEvent {
	return &event.HookEvent{
		ID: id, HostID: "h", EventType: event.EventBPFLoad, Severity: sev, ExePath: "/bin/" + id,
		PolicyResult: &event.PolicyResult{Action: action},
	}
}

func siemClose(t *testing.T, d *Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func siemEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestDispatcher_Routing: alert connectors get unallowed events at or
// above their severity, without repeats; event-feed connectors get every
// event at or above theirs, repeats included; watchdog events are never
// repeats.
func TestDispatcher_Routing(t *testing.T) {
	alerts, crit, feed, warn := &siemFake{name: "alert"}, &siemFake{name: "crit"}, &siemFake{name: "feed"}, &siemFake{name: "warn"}
	d := newDispatcher(&siemSeen{}, zap.NewNop())
	d.add(alerts, Delivery{}.withDefaults(1), defaultRetry)
	d.add(crit, Delivery{MinSeverity: "critical"}.withDefaults(1), defaultRetry)
	d.add(feed, Delivery{MinSeverity: event.SeverityInfo}.withDefaults(1), defaultRetry)
	d.add(warn, Delivery{MinSeverity: event.SeverityWarn}.withDefaults(1), defaultRetry)
	d.start()

	d.Send(siemEvt("info-allowed", event.SeverityInfo, event.ActionAllow))
	d.Send(siemEvt("warn-unmatched", event.SeverityWarn, event.ActionAlert))
	d.Send(siemEvt("alert", event.SeverityAlert, event.ActionAlert))
	repeat := siemEvt("alert-repeat", event.SeverityAlert, event.ActionAlert)
	repeat.ExePath = "/bin/alert" // same key as "alert"
	d.Send(repeat)
	d.Send(siemEvt("crit-denied", event.SeverityCritical, event.ActionDeny))
	off := &event.HookEvent{ID: "offline", HostID: "h", EventType: event.EventAgentOffline, Severity: event.SeverityCritical,
		PolicyResult: &event.PolicyResult{Action: event.ActionAlert}}
	d.Dispatch(off)
	off2 := *off
	off2.ID = "offline-again"
	d.Dispatch(&off2)
	siemClose(t, d)

	for _, tc := range []struct {
		f    *siemFake
		want []string
	}{
		{alerts, []string{"alert", "crit-denied", "offline", "offline-again"}},
		{crit, []string{"crit-denied", "offline", "offline-again"}},
		{feed, []string{"info-allowed", "warn-unmatched", "alert", "alert-repeat", "crit-denied", "offline", "offline-again"}},
		{warn, []string{"warn-unmatched", "alert", "alert-repeat", "crit-denied", "offline", "offline-again"}},
	} {
		if got := tc.f.ids(); !siemEqual(got, tc.want) {
			t.Errorf("%s got %v, want %v", tc.f.name, got, tc.want)
		}
		if !tc.f.closed {
			t.Errorf("%s not closed", tc.f.name)
		}
	}
}

// TestDispatcher_SlowSinkDoesNotBlockIngestion: with a sink that never
// returns, Send still returns at once; once the queue is full the extra
// events are dropped and counted, and the other connector gets them all.
func TestDispatcher_SlowSinkDoesNotBlockIngestion(t *testing.T) {
	slow := &siemFake{name: "slow", block: make(chan struct{})}
	fast := &siemFake{name: "fast"}
	d := newDispatcher(nil, zap.NewNop())
	d.add(slow, Delivery{MinSeverity: event.SeverityInfo, QueueSize: 4}.withDefaults(1), defaultRetry)
	d.add(fast, Delivery{MinSeverity: event.SeverityInfo, QueueSize: 100}.withDefaults(1), defaultRetry)
	d.start()

	const n = 50
	// The first event reaches the slow worker, which then blocks in Send.
	d.Send(siemEvt("e", event.SeverityInfo, event.ActionAllow))
	siemWait(t, "the slow worker to take the first event", func() bool { return d.Stats()[0].Queued == 0 })
	start := time.Now()
	for i := 1; i < n; i++ {
		d.Send(siemEvt("e", event.SeverityInfo, event.ActionAllow))
	}
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Errorf("%d Sends took %v with a blocked sink", n, el)
	}
	siemWait(t, "the fast sink", func() bool { return len(fast.ids()) == n })

	st := d.Stats()
	// The slow worker holds one event in Send and 4 in its queue.
	if st[0].Dropped != n-5 || st[0].Queued != 4 {
		t.Errorf("slow stats %+v, want %d dropped and 4 queued", st[0], n-5)
	}
	if st[1].Dropped != 0 || st[1].Sent != n {
		t.Errorf("fast stats %+v", st[1])
	}

	// Close with a short deadline: the blocked delivery is aborted, the
	// queued events fail, and Close returns.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Close(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung on a blocked sink")
	}
	st = d.Stats()
	if st[0].Failed != 5 || st[0].Sent != 0 {
		t.Errorf("slow stats after close %+v, want 5 failed", st[0])
	}
	// Sends after Close are ignored, not a panic.
	d.Send(siemEvt("late", event.SeverityCritical, event.ActionAlert))
}

// TestDispatcher_CloseDrains: events queued before Close are delivered.
func TestDispatcher_CloseDrains(t *testing.T) {
	gate := make(chan struct{})
	f := &siemFake{name: "f", block: gate}
	d := newDispatcher(nil, zap.NewNop())
	d.add(f, Delivery{MinSeverity: event.SeverityInfo, QueueSize: 10}.withDefaults(1), defaultRetry)
	d.start()
	for _, id := range []string{"a", "b", "c"} {
		d.Send(siemEvt(id, event.SeverityInfo, event.ActionAllow))
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(gate)
	}()
	siemClose(t, d)
	if got := f.ids(); !siemEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("delivered %v", got)
	}
}

type siemFailing struct{ calls int }

func (f *siemFailing) Name() string { return "failing" }
func (f *siemFailing) Send(context.Context, []*event.HookEvent) error {
	f.calls++
	return errors.New("bad request")
}
func (f *siemFailing) Close() error { return nil }

// TestDispatcher_NonRetryableNotRetried: a plain error drops the batch
// after one try.
func TestDispatcher_NonRetryableNotRetried(t *testing.T) {
	f := &siemFailing{}
	d := newDispatcher(nil, zap.NewNop())
	d.add(f, Delivery{MinSeverity: event.SeverityInfo}.withDefaults(1), retryPolicy{attempts: 5, base: time.Millisecond})
	d.start()
	d.Send(siemEvt("x", event.SeverityInfo, event.ActionAllow))
	siemClose(t, d)
	if f.calls != 1 || d.Stats()[0].Failed != 1 {
		t.Errorf("calls %d, stats %+v", f.calls, d.Stats()[0])
	}
}

// TestNew_NoConnectors: with no connector configured the dispatcher is a
// no-op.
func TestNew_NoConnectors(t *testing.T) {
	d, err := New(context.Background(), Config{}, nil, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	d.Send(siemEvt("x", event.SeverityCritical, event.ActionAlert))
	d.Dispatch(siemEvt("y", event.SeverityCritical, event.ActionAlert))
	if d.Len() != 0 {
		t.Errorf("Len %d", d.Len())
	}
	siemClose(t, d)
}

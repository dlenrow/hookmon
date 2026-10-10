package policy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/allowlist"
	"github.com/dlenrow/hookmon/pkg/event"
)

// polCandidate is one RecordCandidate call.
type polCandidate struct {
	key    event.LearnedKey
	exe    string
	hostID string
	seen   time.Time
}

// polSink records candidates and keeps one ID per key, as the store does.
type polSink struct {
	mu    sync.Mutex
	calls []polCandidate
	ids   map[event.LearnedKey]string
	err   error
}

func (s *polSink) RecordCandidate(_ context.Context, key event.LearnedKey, exePath, _, hostID string, seen time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return "", s.err
	}
	s.calls = append(s.calls, polCandidate{key, exePath, hostID, seen})
	if s.ids == nil {
		s.ids = map[event.LearnedKey]string{}
	}
	id, ok := s.ids[key]
	if !ok {
		id = "cand-" + allowlist.KeyHash(key)[:8]
		s.ids[key] = id
	}
	return id, nil
}

func (s *polSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// polSource is a policy source whose contents the test changes.
type polSource struct {
	mu      sync.Mutex
	entries []*event.AllowlistEntry
	windows []event.LearningWindow
	err     error
	reads   int
}

func (s *polSource) GetDecidedAllowlist(context.Context) ([]*event.AllowlistEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	return s.entries, s.err
}

func (s *polSource) GetLearningWindows(context.Context) ([]event.LearningWindow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.windows, s.err
}

// polClock is a settable clock.
type polClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *polClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *polClock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func polEngine(src *polSource, sink *polSink, clock *polClock) *Engine {
	e := NewEngine(zap.NewNop())
	e.SetSource(src)
	e.SetCandidateSink(sink)
	e.now = clock.now
	return e
}

func polDlopen(host, lib string) *event.HookEvent {
	return &event.HookEvent{
		ID: "d", Timestamp: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC), HostID: host, Hostname: host,
		EventType: event.EventDlopen, Severity: event.SeverityWarn, PID: 7, UID: 1000,
		ExePath: "/usr/bin/app", ExeHash: "sha256:" + hex64("b"),
		DlopenDetail: &event.DlopenDetail{LibraryPath: lib},
	}
}

var polT0 = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

// TestLearning_StartEndAndScope: learning mode records unmatched events
// only while a window is open, for the fleet or for the one host it names.
func TestLearning_StartEndAndScope(t *testing.T) {
	src, sink, clock := &polSource{}, &polSink{}, &polClock{t: polT0}
	e := polEngine(src, sink, clock)
	ctx := context.Background()

	// No window: nothing is learned.
	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	e.Evaluate(polDlopen("host-a", "/opt/a.so"))
	if sink.count() != 0 {
		t.Fatalf("learned with learning mode off: %+v", sink.calls)
	}

	// A window for host-a only.
	src.windows = []event.LearningWindow{{HostID: "host-a", StartedAt: polT0, EndsAt: polT0.Add(time.Hour)}}
	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.Learning("host-a") || e.Learning("host-b") || e.Learning("") {
		t.Fatalf("Learning: host-a %v, host-b %v, fleet %v; want true, false, false",
			e.Learning("host-a"), e.Learning("host-b"), e.Learning(""))
	}
	res := e.Evaluate(polDlopen("host-a", "/opt/a.so"))
	e.Evaluate(polDlopen("host-b", "/opt/b.so"))
	if sink.count() != 1 || sink.calls[0].hostID != "host-a" {
		t.Fatalf("host window: candidates %+v, want one from host-a", sink.calls)
	}
	if !strings.Contains(res.Reason, "learning mode: PENDING entry cand-") {
		t.Errorf("reason does not name the candidate: %q", res.Reason)
	}
	if res.Action != event.ActionAlert {
		t.Errorf("learning mode changed the action: %s", res.Action)
	}

	// The window ends: nothing more is learned.
	clock.set(polT0.Add(time.Hour))
	e.Evaluate(polDlopen("host-a", "/opt/a2.so"))
	if sink.count() != 1 {
		t.Fatalf("learned after the window ended: %+v", sink.calls)
	}

	// A fleet window covers every host.
	src.windows = []event.LearningWindow{{HostID: "", StartedAt: clock.now(), EndsAt: clock.now().Add(time.Minute)}}
	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	e.Evaluate(polDlopen("host-b", "/opt/b.so"))
	e.Evaluate(polDlopen("host-c", "/opt/c.so"))
	if sink.count() != 3 {
		t.Fatalf("fleet window: %d candidates, want 3", sink.count())
	}
	clock.set(clock.now().Add(time.Minute + time.Nanosecond))
	if e.Learning("host-b") {
		t.Error("fleet window still open after its end")
	}

	// Stopping learning (the window row deleted) takes effect on reload.
	clock.set(polT0)
	src.windows = []event.LearningWindow{{HostID: "", EndsAt: polT0.Add(time.Hour)}}
	_ = e.Reload(ctx)
	if !e.Learning("x") {
		t.Fatal("fleet learning not on")
	}
	src.windows = nil
	_ = e.Reload(ctx)
	if e.Learning("x") {
		t.Error("learning still on after the window was removed and the policy reloaded")
	}
}

// TestLearning_WhatIsLearned: matched events, lifecycle events and inventory
// summaries are never candidates; per-program inventory events are.
func TestLearning_WhatIsLearned(t *testing.T) {
	src, sink, clock := &polSource{}, &polSink{}, &polClock{t: polT0}
	src.windows = []event.LearningWindow{{EndsAt: polT0.Add(time.Hour)}}
	src.entries = []*event.AllowlistEntry{{
		ID: "allow-a", LibraryPath: "/opt/allowed.so", Action: event.ActionAllow, Enabled: true,
	}}
	e := polEngine(src, sink, clock)
	if err := e.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	e.Evaluate(polDlopen("h", "/opt/allowed.so")) // matched
	e.Evaluate(&event.HookEvent{ID: "o", HostID: "h", EventType: event.EventAgentOffline})
	e.Evaluate(&event.HookEvent{ID: "s", HostID: "h", EventType: event.EventBPFInventory,
		BPFInventoryDetail: &event.BPFInventoryDetail{ScanID: "1", Summary: true, ProgCount: 3}})
	if sink.count() != 0 {
		t.Fatalf("candidates: %+v, want none", sink.calls)
	}

	inv := &event.HookEvent{ID: "i", HostID: "h", EventType: event.EventBPFInventory, Severity: event.SeverityInfo,
		BPFDetail:          &event.BPFDetail{ProgID: 9, ProgType: 8, ProgHash: "AABBCCDDEEFF0011"},
		BPFInventoryDetail: &event.BPFInventoryDetail{ScanID: "1"}}
	res := e.Evaluate(inv)
	if sink.count() != 1 || inv.Severity != event.SeverityInfo || res.Action != event.ActionAlert {
		t.Fatalf("inventory program: %d candidates, severity %s, action %s", sink.count(), inv.Severity, res.Action)
	}
	want := event.LearnedKey{EventType: event.EventBPFInventory, SubjectKind: "bpf_tag",
		Subject: "aabbccddeeff0011", ProgType: 8}
	if got := sink.calls[0].key; got != want {
		t.Errorf("inventory key %+v, want %+v", got, want)
	}

	// A rejected candidate matches (action ALERT), so it is not learned again.
	d := polDlopen("h", "/opt/rejected.so")
	src.entries = append(src.entries, &event.AllowlistEntry{
		ID: "rej", Action: event.ActionAlert, Enabled: true, Status: event.StatusRejected,
		Learned: &event.Learned{Key: allowlist.KeyOf(d)},
	})
	_ = e.Reload(context.Background())
	res = e.Evaluate(d)
	if sink.count() != 1 || res.MatchedEntryID != "rej" || res.Action != event.ActionAlert || d.Severity != event.SeverityWarn {
		t.Errorf("rejected key: %d candidates, entry %q, action %s, severity %s; want 1, rej, ALERT, WARN",
			sink.count(), res.MatchedEntryID, res.Action, d.Severity)
	}
}

// TestLearning_SinkErrorStillEvaluates: a failing store does not stop the
// event from being evaluated.
func TestLearning_SinkErrorStillEvaluates(t *testing.T) {
	src, sink, clock := &polSource{}, &polSink{err: errors.New("db down")}, &polClock{t: polT0}
	src.windows = []event.LearningWindow{{EndsAt: polT0.Add(time.Hour)}}
	e := polEngine(src, sink, clock)
	_ = e.Reload(context.Background())
	evt := polDlopen("h", "/opt/x.so")
	res := e.Evaluate(evt)
	if res.Action != event.ActionAlert || evt.Severity != event.SeverityWarn || strings.Contains(res.Reason, "PENDING") {
		t.Errorf("got %+v severity %s", res, evt.Severity)
	}
}

// TestApproveRejectPerScope evaluates events against the entries the store
// leaves after each decision (see store.DecideCandidate): a fleet approval
// allows the key on every host; an approval for one host allows it only
// there; a rejection for one host keeps it alerting there even when it is
// approved for the fleet; and other keys stay unmatched.
func TestApproveRejectPerScope(t *testing.T) {
	src, sink, clock := &polSource{}, &polSink{}, &polClock{t: polT0}
	e := polEngine(src, sink, clock)
	ctx := context.Background()
	key := allowlist.KeyOf(polDlopen("any", "/opt/plugin.so"))
	learned := func(hosts ...string) *event.Learned {
		return &event.Learned{Key: key, Occurrences: 3, Hosts: hosts}
	}
	decide := func(entries ...*event.AllowlistEntry) {
		t.Helper()
		src.entries = entries
		if err := e.Reload(ctx); err != nil {
			t.Fatal(err)
		}
	}
	check := func(what, host, lib string, want event.PolicyAction, wantEntry string) {
		t.Helper()
		res := e.Evaluate(polDlopen(host, lib))
		if res.Action != want || res.MatchedEntryID != wantEntry {
			t.Errorf("%s: %s on %s: got %s by %q, want %s by %q", what, lib, host, res.Action, res.MatchedEntryID, want, wantEntry)
		}
	}

	// PENDING: nothing matches.
	decide(&event.AllowlistEntry{ID: "p", Action: event.ActionAlert, Enabled: true, Status: event.StatusPending, Learned: learned("h1", "h2")})
	check("pending", "h1", "/opt/plugin.so", event.ActionAlert, "")

	// Approved for host h1 only.
	decide(
		&event.AllowlistEntry{ID: "p", Action: event.ActionAlert, Enabled: true, Status: event.StatusPending, Learned: learned("h2")},
		&event.AllowlistEntry{ID: "a-h1", HostID: "h1", Action: event.ActionAllow, Enabled: true, Status: event.StatusApproved, Learned: learned("h1")},
	)
	check("approved for h1", "h1", "/opt/plugin.so", event.ActionAllow, "a-h1")
	check("approved for h1", "h2", "/opt/plugin.so", event.ActionAlert, "")
	check("approved for h1, other key", "h1", "/opt/other.so", event.ActionAlert, "")

	// Rejected for h2.
	decide(
		&event.AllowlistEntry{ID: "a-h1", HostID: "h1", Action: event.ActionAllow, Enabled: true, Status: event.StatusApproved, Learned: learned("h1")},
		&event.AllowlistEntry{ID: "r-h2", HostID: "h2", Action: event.ActionAlert, Enabled: true, Status: event.StatusRejected, Learned: learned("h2")},
	)
	check("rejected for h2", "h2", "/opt/plugin.so", event.ActionAlert, "r-h2")
	check("rejected for h2", "h1", "/opt/plugin.so", event.ActionAllow, "a-h1")

	// Approved for the fleet: every host but the rejected one.
	decide(
		&event.AllowlistEntry{ID: "a-fleet", Action: event.ActionAllow, Enabled: true, Status: event.StatusApproved, Learned: learned("h3")},
		&event.AllowlistEntry{ID: "r-h2", HostID: "h2", Action: event.ActionAlert, Enabled: true, Status: event.StatusRejected, Learned: learned("h2")},
	)
	check("fleet approval", "h9", "/opt/plugin.so", event.ActionAllow, "a-fleet")
	check("fleet approval, host rejection", "h2", "/opt/plugin.so", event.ActionAlert, "r-h2")

	// Rejected for the fleet.
	decide(&event.AllowlistEntry{ID: "r-fleet", Action: event.ActionAlert, Enabled: true, Status: event.StatusRejected, Learned: learned("h1")})
	check("fleet rejection", "h1", "/opt/plugin.so", event.ActionAlert, "r-fleet")
}

// TestReload_ReplacesPolicyAndKeepsOldOnError: Reload swaps in the source's
// current allowlist; a failed read keeps the previous one.
func TestReload_ReplacesPolicyAndKeepsOldOnError(t *testing.T) {
	src, sink, clock := &polSource{}, &polSink{}, &polClock{t: polT0}
	e := polEngine(src, sink, clock)
	ctx := context.Background()
	evt := func() *event.HookEvent { return polDlopen("h", "/opt/x.so") }

	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if res := e.Evaluate(evt()); res.Action != event.ActionAlert {
		t.Fatalf("before: %s", res.Action)
	}
	src.entries = []*event.AllowlistEntry{{ID: "x", LibraryPath: "/opt/x.so", Action: event.ActionAllow, Enabled: true}}
	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if res := e.Evaluate(evt()); res.Action != event.ActionAllow {
		t.Fatalf("after reload: %s", res.Action)
	}
	src.err = errors.New("db down")
	src.entries = nil
	if err := e.Reload(ctx); err == nil {
		t.Fatal("Reload ignored the source error")
	}
	if res := e.Evaluate(evt()); res.Action != event.ActionAllow {
		t.Errorf("a failed reload dropped the allowlist: %s", res.Action)
	}
	if err := NewEngine(zap.NewNop()).Reload(ctx); err == nil {
		t.Error("Reload without a source succeeded")
	}
}

// TestReload_ConcurrentWithEvaluate runs reloads and evaluations at once
// (for -race).
func TestReload_ConcurrentWithEvaluate(t *testing.T) {
	src, sink, clock := &polSource{}, &polSink{}, &polClock{t: polT0}
	src.windows = []event.LearningWindow{{EndsAt: polT0.Add(time.Hour)}}
	e := polEngine(src, sink, clock)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = e.Reload(context.Background())
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				e.Evaluate(polDlopen("h", "/opt/x.so"))
			}
		}()
	}
	wg.Wait()
}

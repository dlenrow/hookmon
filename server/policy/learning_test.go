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
	key     event.LearnedKey
	exe     string
	hostID  string
	eventID string
	seen    time.Time
}

// polSink keeps one PENDING entry per key, as the store does: the first
// call for a key creates it, later ones are repeats. A key in decided
// stands for an entry decided since the engine last loaded the policy.
type polSink struct {
	mu      sync.Mutex
	calls   []polCandidate
	ids     map[event.LearnedKey]string
	decided map[event.LearnedKey]event.PolicyAction
	err     error
}

func (s *polSink) RecordCandidate(_ context.Context, key event.LearnedKey, exePath, _, hostID, eventID string, seen time.Time) (event.CandidateSighting, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return event.CandidateSighting{}, s.err
	}
	if a, ok := s.decided[key]; ok {
		return event.CandidateSighting{DecidedAction: a}, nil
	}
	s.calls = append(s.calls, polCandidate{key, exePath, hostID, eventID, seen})
	if s.ids == nil {
		s.ids = map[event.LearnedKey]string{}
	}
	if id, ok := s.ids[key]; ok {
		return event.CandidateSighting{ID: id}, nil
	}
	id := "cand-" + allowlist.KeyHash(key)[:8]
	s.ids[key] = id
	return event.CandidateSighting{ID: id, Created: true}, nil
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

// TestFirstSighting_RepeatAndKept: the first event of an unmatched key is a
// first sighting, kept and recorded as the PENDING entry's first event;
// later ones, from any host, are repeats of the same entry and not kept. A
// learning window does not change that.
func TestFirstSighting_RepeatAndKept(t *testing.T) {
	src, sink, clock := &polSource{}, &polSink{}, &polClock{t: polT0}
	e := polEngine(src, sink, clock)
	if err := e.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	first := polDlopen("host-a", "/opt/a.so")
	first.ID = "ev-1"
	res := e.Evaluate(first)
	if res.Disposition != event.DispositionFirstSighting || !res.Disposition.Kept() || res.Quiet ||
		res.CandidateID == "" || res.Action != event.ActionAlert || first.Severity != event.SeverityWarn {
		t.Fatalf("first: %+v severity %s", res, first.Severity)
	}
	if !strings.Contains(res.Reason, "first sighting: PENDING entry "+res.CandidateID) {
		t.Errorf("reason does not name the entry: %q", res.Reason)
	}
	if sink.count() != 1 || sink.calls[0].eventID != "ev-1" || sink.calls[0].hostID != "host-a" || !sink.calls[0].seen.Equal(first.Timestamp) {
		t.Errorf("recorded %+v", sink.calls)
	}

	for _, host := range []string{"host-a", "host-b"} {
		res2 := e.Evaluate(polDlopen(host, "/opt/a.so"))
		if res2.Disposition != event.DispositionRepeat || res2.Disposition.Kept() || res2.CandidateID != res.CandidateID ||
			!strings.Contains(res2.Reason, "repeat of PENDING entry") {
			t.Errorf("repeat on %s: %+v", host, res2)
		}
	}
	if sink.count() != 3 {
		t.Errorf("RecordCandidate calls: %d, want 3 (repeats are counted)", sink.count())
	}

	// A different key is a first sighting of its own.
	if res3 := e.Evaluate(polDlopen("host-b", "/opt/b.so")); res3.Disposition != event.DispositionFirstSighting || res3.CandidateID == res.CandidateID {
		t.Errorf("other key: %+v", res3)
	}
}

// TestQuietPeriod_StartEndAndScope: a learning window makes the first
// sightings of the hosts it covers quiet, and no others; it ends at its end
// time or when the window is removed.
func TestQuietPeriod_StartEndAndScope(t *testing.T) {
	src, sink, clock := &polSource{}, &polSink{}, &polClock{t: polT0}
	e := polEngine(src, sink, clock)
	ctx := context.Background()
	quiet := func(host, lib string) bool {
		t.Helper()
		res := e.Evaluate(polDlopen(host, lib))
		if res.Disposition != event.DispositionFirstSighting {
			t.Fatalf("%s %s: disposition %q, want first_sighting", host, lib, res.Disposition)
		}
		return res.Quiet
	}

	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if quiet("host-a", "/opt/0.so") {
		t.Error("quiet with no window")
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
	if !quiet("host-a", "/opt/a.so") || quiet("host-b", "/opt/b.so") {
		t.Error("host window: want host-a quiet and host-b not")
	}

	// The window ends.
	clock.set(polT0.Add(time.Hour))
	if quiet("host-a", "/opt/a2.so") {
		t.Error("quiet after the window ended")
	}

	// A fleet window covers every host.
	src.windows = []event.LearningWindow{{HostID: "", StartedAt: clock.now(), EndsAt: clock.now().Add(time.Minute)}}
	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if !quiet("host-b", "/opt/b2.so") || !quiet("host-c", "/opt/c.so") {
		t.Error("fleet window: want every host quiet")
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

// TestDispositions_WhatIsRecorded: matched events, lifecycle events and
// inventory summaries are never recorded as new hooks; per-program
// inventory events are, at ALERT.
func TestDispositions_WhatIsRecorded(t *testing.T) {
	src, sink, clock := &polSource{}, &polSink{}, &polClock{t: polT0}
	src.entries = []*event.AllowlistEntry{{
		ID: "allow-a", LibraryPath: "/opt/allowed.so", Action: event.ActionAllow, Enabled: true,
	}}
	e := polEngine(src, sink, clock)
	if err := e.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct {
		evt  *event.HookEvent
		want event.Disposition
	}{
		"matched ALLOW": {polDlopen("h", "/opt/allowed.so"), event.DispositionAllowed},
		"offline":       {&event.HookEvent{ID: "o", HostID: "h", EventType: event.EventAgentOffline}, event.DispositionLifecycle},
		"summary": {&event.HookEvent{ID: "s", HostID: "h", EventType: event.EventBPFInventory,
			BPFInventoryDetail: &event.BPFInventoryDetail{ScanID: "1", Summary: true, ProgCount: 3}}, event.DispositionAllowed},
	} {
		if res := e.Evaluate(c.evt); res.Disposition != c.want {
			t.Errorf("%s: disposition %q, want %q", name, res.Disposition, c.want)
		}
	}
	if sink.count() != 0 {
		t.Fatalf("recorded: %+v, want nothing", sink.calls)
	}

	inv := func() *event.HookEvent {
		return &event.HookEvent{ID: "i", HostID: "h", EventType: event.EventBPFInventory, Severity: event.SeverityInfo,
			BPFDetail:          &event.BPFDetail{ProgID: 9, ProgType: 8, ProgHash: "AABBCCDDEEFF0011"},
			BPFInventoryDetail: &event.BPFInventoryDetail{ScanID: "1"}}
	}
	first := inv()
	res := e.Evaluate(first)
	if sink.count() != 1 || first.Severity != event.SeverityAlert || res.Action != event.ActionAlert || res.Disposition != event.DispositionFirstSighting {
		t.Fatalf("inventory program: %d recorded, severity %s, action %s, disposition %s", sink.count(), first.Severity, res.Action, res.Disposition)
	}
	want := event.LearnedKey{EventType: event.EventBPFInventory, SubjectKind: "bpf_tag",
		Subject: "aabbccddeeff0011", ProgType: 8}
	if got := sink.calls[0].key; got != want {
		t.Errorf("inventory key %+v, want %+v", got, want)
	}
	if res := e.Evaluate(inv()); res.Disposition != event.DispositionRepeat {
		t.Errorf("next scan of the same program: %q, want repeat", res.Disposition)
	}

	// A rejected key matches (action ALERT): denied every time, never
	// recorded again.
	d := polDlopen("h", "/opt/rejected.so")
	src.entries = append(src.entries, &event.AllowlistEntry{
		ID: "rej", Action: event.ActionAlert, Enabled: true, Status: event.StatusRejected,
		Learned: &event.Learned{Key: allowlist.KeyOf(d)},
	})
	_ = e.Reload(context.Background())
	before := sink.count()
	for i := 0; i < 2; i++ {
		d := polDlopen("h", "/opt/rejected.so")
		res := e.Evaluate(d)
		if res.Disposition != event.DispositionDenied || !res.Disposition.Kept() || res.MatchedEntryID != "rej" ||
			res.Action != event.ActionAlert || d.Severity != event.SeverityWarn {
			t.Errorf("rejected key, occurrence %d: %+v severity %s; want denied by rej, ALERT, WARN", i, res, d.Severity)
		}
	}
	if sink.count() != before {
		t.Errorf("a rejected key was recorded as a new hook")
	}
}

// TestDisposition_DecidedSinceLoad: when the store finds a decided entry
// the engine has not loaded yet, the event follows that entry.
func TestDisposition_DecidedSinceLoad(t *testing.T) {
	src, sink, clock := &polSource{}, &polSink{}, &polClock{t: polT0}
	e := polEngine(src, sink, clock)
	_ = e.Reload(context.Background())
	allowed, denied := polDlopen("h", "/opt/ok.so"), polDlopen("h", "/opt/bad.so")
	sink.decided = map[event.LearnedKey]event.PolicyAction{
		allowlist.KeyOf(allowed): event.ActionAllow,
		allowlist.KeyOf(denied):  event.ActionAlert,
	}
	if res := e.Evaluate(allowed); res.Disposition != event.DispositionAllowed || res.Action != event.ActionAllow || allowed.Severity != event.SeverityInfo {
		t.Errorf("allowed since load: %+v severity %s", res, allowed.Severity)
	}
	if res := e.Evaluate(denied); res.Disposition != event.DispositionDenied || res.Action != event.ActionAlert || res.CandidateID != "" {
		t.Errorf("denied since load: %+v", res)
	}
}

// TestDisposition_NoSinkOrSinkErrorKeepsTheEvent: without a sink, or when
// the store fails, an unmatched event is kept as a first sighting rather
// than dropped.
func TestDisposition_NoSinkOrSinkErrorKeepsTheEvent(t *testing.T) {
	src, clock := &polSource{}, &polClock{t: polT0}
	failing := polEngine(src, &polSink{err: errors.New("db down")}, clock)
	_ = failing.Reload(context.Background())
	noSink := NewEngine(zap.NewNop())
	for name, e := range map[string]*Engine{"sink error": failing, "no sink": noSink} {
		for i := 0; i < 2; i++ {
			evt := polDlopen("h", "/opt/x.so")
			res := e.Evaluate(evt)
			if res.Disposition != event.DispositionFirstSighting || res.CandidateID != "" || res.Action != event.ActionAlert ||
				evt.Severity != event.SeverityWarn || strings.Contains(res.Reason, "PENDING") {
				t.Errorf("%s, occurrence %d: %+v severity %s", name, i, res, evt.Severity)
			}
		}
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

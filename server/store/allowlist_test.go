package store

// PostgreSQL tests for the allowlist, PENDING candidates and learning
// windows (fix plan step 7c). Like postgres_test.go they need
// HOOKMON_TEST_PG_DSN and skip without it.

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/allowlist"
	"github.com/dlenrow/hookmon/pkg/event"
)

func polMigrated(t *testing.T) (*Store, string) {
	t.Helper()
	s, dsn := secStore(t)
	if err := s.RunMigrations(context.Background()); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	return s, dsn
}

// TestAllowlist_ProgHashPersists: every field the matcher reads survives a
// write and a read, prog_hash included (the INSERT used to drop it, and the
// table had no column for it).
func TestAllowlist_ProgHashPersists(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	pt := uint32(5)
	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	want := &event.AllowlistEntry{
		ID: "al-tag", CreatedAt: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC), CreatedBy: "ops", Description: "hello canary",
		EventTypes:  []event.EventType{event.EventBPFLoad, event.EventBPFInventory},
		ExeHash:     "sha256:" + strings.Repeat("ab", 32),
		ExePath:     "/usr/bin/loader*",
		LibraryHash: "sha256:" + strings.Repeat("cd", 32), LibraryPath: "/opt/*.so",
		ProgName: "hello_*", ProgType: &pt, ProgHash: "a04f5eef06a7f555",
		HostPattern: "web-*", UIDRange: &event.UIDRange{Min: 0, Max: 999}, ContainerImage: "c*",
		AllowedRpaths: []string{"/opt/lib"}, HostID: "host-a",
		Action: event.ActionAllow, Expires: &exp, Enabled: true,
	}
	if err := s.CreateAllowlistEntry(ctx, want); err != nil {
		t.Fatal(err)
	}
	if want.Status != event.StatusApproved {
		t.Errorf("empty status stored as %q, want APPROVED", want.Status)
	}
	var col string
	if err := s.pool.QueryRow(ctx, `SELECT prog_hash FROM allowlist WHERE id = 'al-tag'`).Scan(&col); err != nil || col != "a04f5eef06a7f555" {
		t.Fatalf("prog_hash column: %q, %v", col, err)
	}
	for name, read := range map[string]func() ([]*event.AllowlistEntry, error){
		"GetAllowlist":        func() ([]*event.AllowlistEntry, error) { return s.GetAllowlist(ctx) },
		"GetDecidedAllowlist": func() ([]*event.AllowlistEntry, error) { return s.GetDecidedAllowlist(ctx) },
	} {
		got, err := read()
		if err != nil || len(got) != 1 {
			t.Fatalf("%s: %v, %d entries", name, err, len(got))
		}
		if !reflect.DeepEqual(polUTC(got[0]), want) {
			t.Errorf("%s read back\n %+v\nwant\n %+v", name, got[0], want)
		}
	}
	got, err := s.GetAllowlistEntry(ctx, "al-tag")
	if err != nil || got.ProgHash != want.ProgHash {
		t.Errorf("GetAllowlistEntry: %+v, %v", got, err)
	}
	// The stored entry, without its library criteria (a BPF event has no
	// library), matches a BPF_LOAD of that program on host-a, and not one
	// of another program.
	m := *got
	m.LibraryHash, m.LibraryPath = "", ""
	evt := &event.HookEvent{EventType: event.EventBPFLoad, HostID: "host-a", Hostname: "web-1", UID: 0,
		ExeHash: want.ExeHash, ExePath: "/usr/bin/loader", ContainerID: "c1",
		BPFDetail: &event.BPFDetail{ProgType: 5, ProgName: "hello_count", ProgHash: "a04f5eef06a7f555"}}
	at := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	if !allowlist.MatchesAt(&m, evt, at) {
		t.Error("the stored entry does not match the event it describes")
	}
	evt.BPFDetail.ProgHash = "ffffffffffffffff"
	if allowlist.MatchesAt(&m, evt, at) {
		t.Error("the stored entry matches another program tag")
	}
	if _, err := s.GetAllowlistEntry(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing entry: %v, want ErrNotFound", err)
	}
	if err := s.DeleteAllowlistEntry(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing entry: %v, want ErrNotFound", err)
	}
}

// TestMigration_006KeepsExistingEntries: an allowlist written by a server
// before 006 is still in force after the upgrade, as APPROVED fleet
// entries.
func TestMigration_006KeepsExistingEntries(t *testing.T) {
	s, _ := secStore(t)
	ctx := context.Background()
	secApplyBefore(t, s, "006")
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO allowlist (id, created_by, description, event_types, exe_hash, action, enabled)
		VALUES ('old', 'ops', 'pre-7c', '["DLOPEN"]', 'sha256:`+strings.Repeat("ab", 32)+`', 'ALLOW', TRUE)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.RunMigrations(ctx); err != nil {
			t.Fatalf("RunMigrations (%d): %v", i+1, err)
		}
	}
	got, err := s.GetDecidedAllowlist(ctx)
	if err != nil || len(got) != 1 {
		t.Fatalf("after 006: %v %+v", err, got)
	}
	e := got[0]
	if e.Status != event.StatusApproved || e.HostID != "" || e.ProgHash != "" || e.Learned != nil || e.Action != event.ActionAllow {
		t.Errorf("old entry after 006: %+v", e)
	}
}

// polUTC puts an entry's times in UTC, so read-back entries compare with
// reflect.DeepEqual whatever zone the connection returns.
func polUTC(e *event.AllowlistEntry) *event.AllowlistEntry {
	e.CreatedAt = e.CreatedAt.UTC()
	if e.Expires != nil {
		x := e.Expires.UTC()
		e.Expires = &x
	}
	if e.Learned != nil {
		e.Learned.FirstSeen, e.Learned.LastSeen = e.Learned.FirstSeen.UTC(), e.Learned.LastSeen.UTC()
	}
	return e
}

func polKey(lib string) event.LearnedKey {
	return event.LearnedKey{EventType: event.EventDlopen, ExeHash: "sha256:" + strings.Repeat("ab", 32),
		SubjectKind: allowlist.SubjectLibraryPath, Subject: lib}
}

func polPending(t *testing.T, s *Store) map[string]*event.AllowlistEntry {
	t.Helper()
	entries, err := s.QueryAllowlist(context.Background(), event.StatusPending)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*event.AllowlistEntry{}
	for _, e := range entries {
		out[e.Learned.Key.Subject] = e
	}
	return out
}

func polHosts(e *event.AllowlistEntry) string {
	h := append([]string(nil), e.Learned.Hosts...)
	sort.Strings(h)
	return strings.Join(h, ",")
}

// TestPending_Lifecycle records new hooks as the policy engine does and
// takes one key through per-host approval, per-host rejection and fleet
// approval, checking counts, hosts, times and the first event at each step.
func TestPending_Lifecycle(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	kA, kB := polKey("/opt/a.so"), polKey("/opt/b.so")
	recS := func(k event.LearnedKey, host, eventID string, at time.Time) event.CandidateSighting {
		t.Helper()
		sg, err := s.RecordCandidate(ctx, k, "/usr/bin/app", allowlist.Describe(k, "/usr/bin/app"), host, eventID, at)
		if err != nil {
			t.Fatalf("RecordCandidate: %v", err)
		}
		return sg
	}
	rec := func(k event.LearnedKey, host string, at time.Time) string {
		t.Helper()
		return recS(k, host, "", at).ID
	}

	s1 := recS(kA, "host-a", "ev-1", t0.Add(time.Minute))
	s2 := recS(kA, "host-b", "ev-2", t0.Add(3*time.Minute))
	s3 := recS(kA, "host-a", "ev-3", t0) // arrives late, with an earlier timestamp
	sB := recS(kB, "host-a", "ev-b", t0)
	id1, idB := s1.ID, sB.ID
	if id1 == "" || id1 != s2.ID || id1 != s3.ID || idB == "" || idB == id1 {
		t.Fatalf("ids: %q %q %q %q; want one entry per key", id1, s2.ID, s3.ID, idB)
	}
	if !s1.Created || s2.Created || s3.Created || !sB.Created {
		t.Fatalf("created: %v %v %v %v; want only each key's first event", s1.Created, s2.Created, s3.Created, sB.Created)
	}
	p := polPending(t, s)
	a := p["/opt/a.so"]
	if len(p) != 2 || a.Status != event.StatusPending || a.Action != event.ActionAlert || !a.Enabled ||
		a.Learned.Occurrences != 3 || !a.Learned.FirstSeen.Equal(t0) || !a.Learned.LastSeen.Equal(t0.Add(3*time.Minute)) ||
		polHosts(a) != "host-a,host-b" || a.Learned.Key != kA || a.Learned.ExePath != "/usr/bin/app" ||
		a.Learned.FirstEventID != "ev-1" ||
		a.CreatedBy != LearningCreator || !reflect.DeepEqual(a.EventTypes, []event.EventType{event.EventDlopen}) {
		t.Fatalf("PENDING entry for a.so: %+v learned %+v", a, a.Learned)
	}
	if decided, _ := s.GetDecidedAllowlist(ctx); len(decided) != 0 {
		t.Fatalf("PENDING entries returned as decided: %+v", decided)
	}

	// Approve a.so for host-a only.
	hA, err := s.DecideCandidate(ctx, id1, event.StatusApproved, "host-a")
	if err != nil {
		t.Fatal(err)
	}
	if hA.ID == id1 || hA.HostID != "host-a" || hA.Status != event.StatusApproved || hA.Action != event.ActionAllow ||
		hA.Learned == nil || hA.Learned.Key != kA || polHosts(hA) != "host-a" || hA.Learned.FirstEventID != "ev-1" {
		t.Fatalf("host approval: %+v", hA)
	}
	if a = polPending(t, s)["/opt/a.so"]; a == nil || polHosts(a) != "host-b" || a.Learned.Occurrences != 3 {
		t.Fatalf("PENDING after approving for host-a: %+v", a)
	}
	// host-a is covered now: nothing recorded, and the sighting names the
	// decision. host-c adds to the candidate.
	if sg := recS(kA, "host-a", "", t0.Add(4*time.Minute)); sg.ID != "" || sg.Created || sg.DecidedAction != event.ActionAllow {
		t.Errorf("recorded a key already approved for the host: %+v", sg)
	}
	if id := rec(kA, "host-c", t0.Add(5*time.Minute)); id != id1 {
		t.Errorf("host-c: id %q, want %q", id, id1)
	}
	if a = polPending(t, s)["/opt/a.so"]; polHosts(a) != "host-b,host-c" || a.Learned.Occurrences != 4 {
		t.Fatalf("PENDING after host-c: hosts %s, %d occurrences", polHosts(a), a.Learned.Occurrences)
	}

	// Reject for host-b.
	rB, err := s.DecideCandidate(ctx, id1, event.StatusRejected, "host-b")
	if err != nil || rB.Status != event.StatusRejected || rB.Action != event.ActionAlert || rB.HostID != "host-b" {
		t.Fatalf("host rejection: %+v, %v", rB, err)
	}
	if sg := recS(kA, "host-b", "", t0.Add(6*time.Minute)); sg.ID != "" || sg.DecidedAction != event.ActionAlert {
		t.Errorf("recorded a key rejected for the host: %+v", sg)
	}

	// Approve the rest for the fleet: the PENDING entry itself changes.
	fl, err := s.DecideCandidate(ctx, id1, event.StatusApproved, "")
	if err != nil || fl.ID != id1 || fl.HostID != "" || fl.Status != event.StatusApproved || fl.Action != event.ActionAllow {
		t.Fatalf("fleet approval: %+v, %v", fl, err)
	}
	if _, ok := polPending(t, s)["/opt/a.so"]; ok {
		t.Fatal("a.so still PENDING after fleet approval")
	}
	if id := rec(kA, "host-z", t0.Add(7*time.Minute)); id != "" {
		t.Errorf("recorded a key approved for the fleet: %q", id)
	}
	// On host-b both the fleet approval and the host rejection apply: the
	// rejection, the more restrictive, is the one reported.
	if sg := recS(kA, "host-b", "", t0.Add(7*time.Minute)); sg.ID != "" || sg.DecidedAction != event.ActionAlert {
		t.Errorf("host-b under a fleet approval and a host rejection: %+v, want ALERT", sg)
	}
	if _, err := s.DecideCandidate(ctx, id1, event.StatusRejected, ""); !errors.Is(err, ErrNotPending) {
		t.Errorf("deciding a decided entry: %v, want ErrNotPending", err)
	}
	if _, err := s.DecideCandidate(ctx, "no-such-id", event.StatusApproved, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("deciding a missing entry: %v, want ErrNotFound", err)
	}

	decided, err := s.GetDecidedAllowlist(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range decided {
		got[e.ID] = fmt.Sprintf("%s/%s/%s", e.Status, e.Action, e.HostID)
	}
	want := map[string]string{hA.ID: "APPROVED/ALLOW/host-a", rB.ID: "REJECTED/ALERT/host-b", id1: "APPROVED/ALLOW/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("decided entries %v, want %v", got, want)
	}

	// A candidate seen on one host and approved for it is gone from PENDING.
	if _, err := s.DecideCandidate(ctx, idB, event.StatusApproved, "host-a"); err != nil {
		t.Fatal(err)
	}
	if p := polPending(t, s); len(p) != 0 {
		t.Errorf("PENDING left: %+v", p)
	}

	// A disabled or expired decided entry does not stop a new candidate.
	kC := polKey("/opt/c.so")
	idC := rec(kC, "host-a", t0)
	if _, err := s.DecideCandidate(ctx, idC, event.StatusApproved, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE allowlist SET expires = NOW() - INTERVAL '1 second' WHERE id = $1`, idC); err != nil {
		t.Fatal(err)
	}
	if id := rec(kC, "host-a", t0); id == "" || id == idC {
		t.Errorf("expired approval: candidate id %q", id)
	}
}

// TestPending_ConcurrentRecords: many concurrent events with one key make
// one PENDING entry with the right count.
func TestPending_ConcurrentRecords(t *testing.T) {
	s, _ := polMigrated(t)
	k := polKey("/opt/hot.so")
	var wg sync.WaitGroup
	var created atomic.Int32
	errs := make(chan error, 200)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				sg, err := s.RecordCandidate(context.Background(), k, "/usr/bin/app", "d", fmt.Sprintf("host-%d", g%3), fmt.Sprintf("ev-%d-%d", g, i), time.Now())
				if err != nil {
					errs <- err
				}
				if sg.Created {
					created.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	p := polPending(t, s)
	if len(p) != 1 || p["/opt/hot.so"].Learned.Occurrences != 200 || polHosts(p["/opt/hot.so"]) != "host-0,host-1,host-2" {
		t.Fatalf("PENDING: %d entries, %+v", len(p), p["/opt/hot.so"].Learned)
	}
	if n := created.Load(); n != 1 {
		t.Errorf("first sightings among 200 concurrent events of one key: %d, want 1", n)
	}
}

// TestDecideCandidates_Bulk: several PENDING entries decided in one call,
// for the fleet or for the hosts each was seen on; IDs that are missing,
// not PENDING, repeated or (for seen_hosts) without hosts fail alone.
func TestDecideCandidates_Bulk(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	rec := func(k event.LearnedKey, host, eventID string) string {
		t.Helper()
		sg, err := s.RecordCandidate(ctx, k, "/usr/bin/app", allowlist.Describe(k, "/usr/bin/app"), host, eventID, t0)
		if err != nil || sg.ID == "" {
			t.Fatalf("RecordCandidate: %+v %v", sg, err)
		}
		return sg.ID
	}
	kA, kB, kC, kD := polKey("/opt/a.so"), polKey("/opt/b.so"), polKey("/opt/c.so"), polKey("/opt/d.so")
	idA := rec(kA, "host-a", "ev-a")
	rec(kA, "host-b", "ev-a2")
	idB := rec(kB, "host-a", "ev-b")
	idC := rec(kC, "host-c", "ev-c")
	idD := rec(kD, "host-d", "ev-d")
	if _, err := s.pool.Exec(ctx, `UPDATE allowlist SET seen_hosts = '{}' WHERE id = $1`, idD); err != nil {
		t.Fatal(err)
	}

	// For the hosts each was seen on.
	out, err := s.DecideCandidates(ctx, []string{idA, "no-such-id", idB, idA, idD}, event.StatusApproved, ScopeSeenHosts)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 5 {
		t.Fatalf("%d results, want 5", len(out))
	}
	if d := out[0]; d.ID != idA || d.Err != nil || len(d.Entries) != 2 {
		t.Fatalf("a.so: %+v", d)
	}
	hostsOf := map[string]bool{}
	for _, e := range out[0].Entries {
		hostsOf[e.HostID] = true
		if e.Status != event.StatusApproved || e.Action != event.ActionAllow || e.Learned == nil ||
			e.Learned.Key != kA || e.Learned.FirstEventID != "ev-a" || polHosts(e) != e.HostID {
			t.Errorf("a.so entry: %+v %+v", e, e.Learned)
		}
	}
	if !hostsOf["host-a"] || !hostsOf["host-b"] {
		t.Errorf("a.so entries for hosts %v, want host-a and host-b", hostsOf)
	}
	if !errors.Is(out[1].Err, ErrNotFound) {
		t.Errorf("missing ID: %v", out[1].Err)
	}
	if d := out[2]; d.Err != nil || len(d.Entries) != 1 || d.Entries[0].HostID != "host-a" {
		t.Errorf("b.so: %+v", d)
	}
	if out[3].Err == nil || !strings.Contains(out[3].Err.Error(), "more than once") {
		t.Errorf("repeated ID: %v", out[3].Err)
	}
	if out[4].Err == nil || !strings.Contains(out[4].Err.Error(), "no hosts") {
		t.Errorf("entry without hosts: %v", out[4].Err)
	}
	p := polPending(t, s)
	if _, ok := p["/opt/a.so"]; ok || len(p) != 2 || p["/opt/c.so"] == nil || p["/opt/d.so"] == nil {
		t.Errorf("PENDING after seen_hosts: %v", p)
	}

	// For the fleet: the PENDING entry itself is decided.
	out, err = s.DecideCandidates(ctx, []string{idC, idA}, event.StatusRejected, ScopeFleet)
	if err != nil {
		t.Fatal(err)
	}
	if d := out[0]; d.Err != nil || len(d.Entries) != 1 || d.Entries[0].ID != idC ||
		d.Entries[0].Status != event.StatusRejected || d.Entries[0].Action != event.ActionAlert || d.Entries[0].HostID != "" {
		t.Errorf("c.so for the fleet: %+v", d)
	}
	if !errors.Is(out[1].Err, ErrNotFound) {
		t.Errorf("a.so, no longer PENDING (deleted): %v", out[1].Err)
	}
	cur, err := s.GetAllowlistEntry(ctx, idC)
	if err != nil || cur.Status != event.StatusRejected {
		t.Errorf("c.so as stored: %+v %v", cur, err)
	}
	out, err = s.DecideCandidates(ctx, []string{idC}, event.StatusApproved, ScopeFleet)
	if err != nil || !errors.Is(out[0].Err, ErrNotPending) {
		t.Errorf("deciding a decided entry: %+v %v", out, err)
	}

	if _, err := s.DecideCandidates(ctx, []string{idD}, event.StatusApproved, "host"); err == nil {
		t.Error("accepted scope host")
	}
	if _, err := s.DecideCandidates(ctx, []string{idD}, event.StatusPending, ScopeFleet); err == nil {
		t.Error("accepted decision PENDING")
	}
}

// TestPending_LongSubject: a key with a path longer than a btree index
// entry can hold is still recorded (the index is on the key's SHA-256).
func TestPending_LongSubject(t *testing.T) {
	s, _ := polMigrated(t)
	k := polKey(strings.Repeat("/very-long-directory-name", 400))
	for i := 0; i < 2; i++ {
		if _, err := s.RecordCandidate(context.Background(), k, "", "d", "h", "", time.Now()); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if p := polPending(t, s); len(p) != 1 || p[k.Subject].Learned.Occurrences != 2 {
		t.Fatalf("PENDING: %+v", p)
	}
}

// TestLearningWindows_Persist: windows are stored per scope, replaced on a
// second start, deleted on stop, and still there for a new Store on the
// same database (a restarted server).
func TestLearningWindows_Persist(t *testing.T) {
	s, dsn := polMigrated(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	fleet := event.LearningWindow{HostID: "", StartedAt: t0, EndsAt: t0.Add(time.Hour), StartedBy: "api"}
	host := event.LearningWindow{HostID: "host-a", StartedAt: t0, EndsAt: t0.Add(5 * time.Minute), StartedBy: "api"}
	for _, w := range []event.LearningWindow{fleet, host} {
		if err := s.SetLearningWindow(ctx, w); err != nil {
			t.Fatal(err)
		}
	}
	fleet.EndsAt = t0.Add(2 * time.Hour)
	if err := s.SetLearningWindow(ctx, fleet); err != nil {
		t.Fatal(err)
	}

	restarted := secOpen(t, dsn)
	got, err := restarted.GetLearningWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		got[i].StartedAt, got[i].EndsAt = got[i].StartedAt.UTC(), got[i].EndsAt.UTC()
	}
	if want := []event.LearningWindow{fleet, host}; !reflect.DeepEqual(got, want) {
		t.Fatalf("windows after restart\n %+v\nwant\n %+v", got, want)
	}

	if err := restarted.DeleteLearningWindow(ctx, "host-a"); err != nil {
		t.Fatal(err)
	}
	if err := restarted.DeleteLearningWindow(ctx, "host-a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v, want ErrNotFound", err)
	}
	if got, _ := s.GetLearningWindows(ctx); len(got) != 1 || got[0].HostID != "" {
		t.Errorf("after delete: %+v", got)
	}
}

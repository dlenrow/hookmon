package store

// PostgreSQL tests for store bugs found while writing docs/api-reference.md:
// hosts.last_event_at was never written, a duplicate allowlist entry ID was
// an unclassified error (the API answered 500), and TIMESTAMPTZ values were
// scanned into the server's local zone. Like the other store tests they
// need HOOKMON_TEST_PG_DSN, and each runs in its own schema.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	_ "time/tzdata" // TZ=America/New_York works without the system zone files

	"github.com/dlenrow/hookmon/pkg/allowlist"
	"github.com/dlenrow/hookmon/pkg/event"
)

// apiFixLastEvent returns host id's last_event_at from GetHost.
func apiFixLastEvent(t *testing.T, s *Store, id string) *time.Time {
	t.Helper()
	h, err := s.GetHost(context.Background(), id)
	if err != nil {
		t.Fatalf("GetHost %s: %v", id, err)
	}
	return h.LastEventAt
}

// TestInsertEvent_SetsLastEventAt: storing an event moves its host's
// last_event_at forward to the event's timestamp, never back; GetHost and
// GetHosts return it. A failed insert leaves it alone, and an event for a
// host that is not enrolled is still stored.
func TestInsertEvent_SetsLastEventAt(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	robHost(t, s, "h-1", base.Add(-time.Hour))
	robHost(t, s, "h-2", base.Add(-time.Hour))
	ins := func(id, host string, ts time.Time) error {
		return s.InsertEvent(ctx, &event.HookEvent{ID: id, Timestamp: ts, HostID: host, EventType: event.EventDlopen, Severity: event.SeverityWarn})
	}
	want := func(step, host string, w *time.Time) {
		t.Helper()
		got := apiFixLastEvent(t, s, host)
		switch {
		case w == nil && got != nil:
			t.Errorf("%s: %s last_event_at %v, want none", step, host, *got)
		case w != nil && (got == nil || !got.Equal(*w)):
			t.Errorf("%s: %s last_event_at %v, want %v", step, host, got, *w)
		}
	}
	at := func(d time.Duration) *time.Time { v := base.Add(d); return &v }

	want("enrolled", "h-1", nil)
	if err := ins("e1", "h-1", base); err != nil {
		t.Fatal(err)
	}
	want("first event", "h-1", at(0))
	want("first event, other host", "h-2", nil)

	if err := ins("e2", "h-1", base.Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	want("older event", "h-1", at(0))

	if err := ins("e3", "h-1", base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	want("newer event", "h-1", at(time.Minute))

	// A duplicate ID with a later timestamp is refused, and the host row
	// is not touched: both writes are one statement.
	if err := ins("e3", "h-1", base.Add(time.Hour)); err == nil {
		t.Fatal("InsertEvent stored a duplicate ID")
	}
	want("refused insert", "h-1", at(time.Minute))

	// A host that is not enrolled: the event is stored, nothing else.
	if err := ins("e-orphan", "h-none", base.Add(2*time.Hour)); err != nil {
		t.Fatalf("event for a host that is not enrolled: %v", err)
	}
	if _, err := s.GetEvent(ctx, "e-orphan"); err != nil {
		t.Errorf("event for a host that is not enrolled was not stored: %v", err)
	}
	want("other host's event", "h-1", at(time.Minute))

	// GetHosts carries it too.
	hosts, err := s.GetHosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if h.ID == "h-1" && (h.LastEventAt == nil || !h.LastEventAt.Equal(base.Add(time.Minute))) {
			t.Errorf("GetHosts: h-1 last_event_at %v", h.LastEventAt)
		}
		if h.ID == "h-2" && h.LastEventAt != nil {
			t.Errorf("GetHosts: h-2 last_event_at %v, want none", *h.LastEventAt)
		}
	}

	// Concurrent inserts in any order end at the newest timestamp.
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 0, 39, 1, 38, ...: the newest is neither first nor last.
			n := i / 2
			if i%2 == 1 {
				n = 39 - i/2
			}
			errs <- ins("c-"+strconv.Itoa(i), "h-2", base.Add(time.Duration(n)*time.Second))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	want("40 concurrent events", "h-2", at(39*time.Second))

	// UpsertHost never moves it back either, with an older time or none.
	h1, err := s.GetHost(ctx, "h-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, le := range []*time.Time{nil, at(-24 * time.Hour)} {
		u := *h1
		u.LastEventAt = le
		if err := s.UpsertHost(ctx, &u); err != nil {
			t.Fatal(err)
		}
		want(fmt.Sprintf("UpsertHost with last_event_at %v", le), "h-1", at(time.Minute))
	}
	u := *h1
	u.LastEventAt = at(3 * time.Hour)
	if err := s.UpsertHost(ctx, &u); err != nil {
		t.Fatal(err)
	}
	want("UpsertHost with a later last_event_at", "h-1", at(3*time.Hour))
}

// TestCreateAllowlistEntry_DuplicateIDIsErrConflict: an ID that is taken is
// ErrConflict, so the API can answer 409, and the stored entry is not
// changed. Other failures are not ErrConflict.
func TestCreateAllowlistEntry_DuplicateIDIsErrConflict(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	mk := func(desc string, action event.PolicyAction) *event.AllowlistEntry {
		return &event.AllowlistEntry{ID: "dup", CreatedAt: time.Now().UTC(), Description: desc,
			EventTypes: []event.EventType{event.EventBPFLoad}, Action: action, Enabled: true}
	}
	if err := s.CreateAllowlistEntry(ctx, mk("first", event.ActionAllow)); err != nil {
		t.Fatal(err)
	}
	err := s.CreateAllowlistEntry(ctx, mk("second", event.ActionDeny))
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "dup") {
		t.Errorf("duplicate ID: %v, want ErrConflict naming the ID", err)
	}
	got, err := s.GetAllowlistEntry(ctx, "dup")
	if err != nil {
		t.Fatal(err)
	}
	if got.Description != "first" || got.Action != event.ActionAllow {
		t.Errorf("the refused create changed the entry: %+v", got)
	}

	s.Close()
	if err := s.CreateAllowlistEntry(ctx, mk("closed", event.ActionAllow)); err == nil || errors.Is(err, ErrConflict) {
		t.Errorf("closed pool: %v, want a failure that is not ErrConflict", err)
	}
}

// apiFixTZChild marks the child process TestStore_TimesReadBackInUTC runs.
const apiFixTZChild = "HOOKMON_TEST_TZ_CHILD"

// TestStore_TimesReadBackInUTC: with the process in America/New_York,
// every time a read returns is in UTC (Location() == time.UTC), and so
// marshals with "Z". pgx used to scan TIMESTAMPTZ into the local zone, and
// the API returned offsets such as -04:00. The test runs itself again in a
// child process with TZ set, since the local zone is fixed when a process
// first uses it.
func TestStore_TimesReadBackInUTC(t *testing.T) {
	if os.Getenv(apiFixTZChild) == "" {
		if os.Getenv("HOOKMON_TEST_PG_DSN") == "" {
			t.Skip("HOOKMON_TEST_PG_DSN is not set; skipping the PostgreSQL store test")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestStore_TimesReadBackInUTC$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), apiFixTZChild+"=1", "TZ=America/New_York")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "--- PASS: TestStore_TimesReadBackInUTC") {
			t.Fatalf("child with TZ=America/New_York: %v\n%s", err, out)
		}
		return
	}

	zone, offset := time.Now().Zone()
	if offset == 0 {
		t.Fatalf("TZ=America/New_York did not take effect: local zone %s", zone)
	}
	t.Logf("local zone %s (UTC%+d)", zone, offset/3600)

	s, _ := polMigrated(t)
	ctx := context.Background()
	// Every time written below is in the local (New York) zone, and in the
	// past, so GetStaleHosts returns the host.
	base := time.Date(2026, 3, 2, 8, 0, 0, 0, time.Local)
	expires := base.Add(72 * time.Hour)

	robHost(t, s, "h-1", base)
	if err := s.InsertEvent(ctx, &event.HookEvent{ID: "e1", Timestamp: base.Add(time.Minute), HostID: "h-1",
		EventType: event.EventDlopen, Severity: event.SeverityWarn}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAllowlistEntry(ctx, &event.AllowlistEntry{ID: "a1", CreatedAt: base, Description: "x",
		Action: event.ActionAllow, Enabled: true, Expires: &expires}); err != nil {
		t.Fatal(err)
	}
	key := event.LearnedKey{SubjectKind: allowlist.SubjectDlopen, Subject: "/opt/x.so"}
	sighting, err := s.RecordCandidate(ctx, key, "/usr/bin/app", "learned", "h-1", "e1", base.Add(2*time.Minute))
	pendingID := sighting.ID
	if err != nil || pendingID == "" {
		t.Fatalf("RecordCandidate: %q %v", pendingID, err)
	}
	if err := s.SetLearningWindow(ctx, event.LearningWindow{StartedAt: base, EndsAt: expires, StartedBy: "api"}); err != nil {
		t.Fatal(err)
	}
	change, err := s.RecordHeartbeat(ctx, &event.HostHeartbeat{HostID: "h-1", ReceivedAt: base.Add(3 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}

	// Read everything back through every read the API and engine use.
	ev, err := s.GetEvent(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	evs, err := s.QueryEvents(ctx, EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	host, err := s.GetHost(ctx, "h-1")
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := s.GetHosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := s.GetStaleHosts(ctx, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := s.GetAllowlistEntry(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	all, err := s.QueryAllowlist(ctx)
	if err != nil {
		t.Fatal(err)
	}
	windows, err := s.GetLearningWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	decided, err := s.DecideCandidate(ctx, pendingID, event.StatusApproved, "h-1")
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for name, v := range map[string]any{
		"GetEvent": ev, "QueryEvents": evs, "GetHost": host, "GetHosts": hosts, "GetStaleHosts": stale,
		"GetAllowlistEntry": entry, "QueryAllowlist": all, "GetLearningWindows": windows,
		"DecideCandidate": decided, "RecordHeartbeat": change,
	} {
		apiFixWalkTimes(reflect.ValueOf(v), name, func(path string, tm time.Time) {
			if tm.IsZero() {
				return
			}
			seen[path[strings.LastIndex(path, ".")+1:]] = true
			if tm.Location() != time.UTC {
				t.Errorf("%s = %v: location %v, want UTC", path, tm, tm.Location())
			}
		})
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "-05:00") || strings.Contains(string(b), "-04:00") {
			t.Errorf("%s JSON carries a New York offset: %s", name, b)
		}
	}
	for _, f := range []string{"Timestamp", "EnrolledAt", "LastHeartbeat", "LastEventAt", "CreatedAt", "Expires",
		"FirstSeen", "LastSeen", "StartedAt", "EndsAt", "PrevHeartbeat"} {
		if !seen[f] {
			t.Errorf("no %s was read back; the test does not cover it", f)
		}
	}
	// The instants are unchanged.
	if !ev.Timestamp.Equal(base.Add(time.Minute)) || !entry.Expires.Equal(expires) || !host.EnrolledAt.Equal(base) {
		t.Errorf("instants changed: event %v, expires %v, enrolled %v", ev.Timestamp, entry.Expires, host.EnrolledAt)
	}
}

// apiFixWalkTimes calls visit with every time.Time reachable from v
// through exported fields, pointers, slices and maps.
func apiFixWalkTimes(v reflect.Value, path string, visit func(string, time.Time)) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			apiFixWalkTimes(v.Elem(), path, visit)
		}
	case reflect.Struct:
		if tm, ok := v.Interface().(time.Time); ok {
			visit(path, tm)
			return
		}
		for i := 0; i < v.NumField(); i++ {
			if f := v.Type().Field(i); f.IsExported() {
				apiFixWalkTimes(v.Field(i), path+"."+f.Name, visit)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			apiFixWalkTimes(v.Index(i), fmt.Sprintf("%s[%d]", path, i), visit)
		}
	case reflect.Map:
		for it := v.MapRange(); it.Next(); {
			apiFixWalkTimes(it.Value(), fmt.Sprintf("%s[%v]", path, it.Key()), visit)
		}
	}
}

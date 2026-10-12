package store

// PostgreSQL tests for the store methods and paths the other tests leave
// out (fix plan step 7h): the host list, stale hosts, UpsertHost, every
// event detail type through a write and a read, the event query's filters
// and paging, and connection errors. Like the other store tests they need
// HOOKMON_TEST_PG_DSN, and each runs in its own schema.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"

	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/event"
)

// t7hEvents returns one event of each detail type, with every field set,
// at one-minute steps back from base, on two hosts.
func t7hEvents(base time.Time) []*event.HookEvent {
	u32 := func(v uint32) *uint32 { return &v }
	loaded := base.Add(-time.Hour)
	mk := func(i int, id, host string, et event.EventType, sev event.Severity) *event.HookEvent {
		return &event.HookEvent{
			ID: id, Timestamp: base.Add(-time.Duration(i) * time.Minute), HostID: host, Hostname: "name-" + host,
			EventType: et, Severity: sev,
			PID: 100 + uint32(i), PPID: 1, UID: 1000, GID: 1000, Comm: "comm", Cmdline: "/bin/x --flag",
			ExePath: "/bin/x", ExeHash: "sha256:ab", CgroupPath: "/system.slice/x.service",
			ContainerID: "c0ffee", Namespace: "default",
			PolicyResult: &event.PolicyResult{Action: event.ActionAlert, Reason: "no allowlist entry matched"},
		}
	}
	evs := []*event.HookEvent{
		mk(0, "e-bpf", "h-1", event.EventBPFLoad, event.SeverityCritical),
		mk(1, "e-exec", "h-1", event.EventExecInjection, event.SeverityAlert),
		mk(2, "e-shm", "h-2", event.EventSHMCreate, event.SeverityWarn),
		mk(3, "e-dlopen", "h-2", event.EventDlopen, event.SeverityInfo),
		mk(4, "e-linker", "h-1", event.EventLinkerConfig, event.SeverityCritical),
		mk(5, "e-ptrace", "h-2", event.EventPtraceInject, event.SeverityAlert),
		mk(6, "e-lib", "h-1", event.EventLibIntegrity, event.SeverityAlert),
		mk(7, "e-rpath", "h-2", event.EventElfRpath, event.SeverityWarn),
		mk(8, "e-inv", "h-1", event.EventBPFInventory, event.SeverityInfo),
	}
	evs[0].BPFDetail = &event.BPFDetail{BPFCommand: 5, ProgType: 2, ProgName: "hello_count", AttachType: 1, TargetFD: -1,
		InsnCount: 12, ProgHash: "aa93b500236fde34", ProgID: 77, LoadTime: &loaded, CreatedByUID: u32(0), AttachTarget: "sys_enter_getpid"}
	evs[0].PolicyResult = &event.PolicyResult{Action: event.ActionAllow, MatchedEntryID: "entry-1", Reason: "matched"}
	evs[1].ExecInjectionDetail = &event.ExecInjectionDetail{LibraryPath: "/tmp/evil.so", LibraryHash: "sha256:cd", TargetBinary: "/usr/bin/true",
		SetBy: "env", EnvVar: "LD_PRELOAD", ScanTruncated: true, ValueTruncated: true}
	evs[2].SHMDetail = &event.SHMDetail{SHMName: "/bpftime_maps", Size: 4096, Pattern: "bpftime"}
	evs[3].DlopenDetail = &event.DlopenDetail{LibraryPath: "/opt/x.so", LibraryHash: "sha256:ef", Flags: 2}
	evs[4].LinkerConfigDetail = &event.LinkerConfigDetail{FilePath: "/etc/ld.so.preload", Operation: "write", OldHash: "sha256:01", NewHash: "sha256:02"}
	evs[5].PtraceDetail = &event.PtraceDetail{Request: 4, RequestName: "PTRACE_POKETEXT", TargetPID: 4242, TargetComm: "victim", Addr: 0x7fff0000}
	evs[6].LibIntegrityDetail = &event.LibIntegrityDetail{LibraryPath: "/usr/lib/libz.so.1", Operation: "rename", OldHash: "sha256:03", NewHash: "sha256:04", InLdCache: true}
	evs[7].ElfRpathDetail = &event.ElfRpathDetail{HasRpath: true, HasRunpath: true, RpathRaw: "/tmp/lib", RunpathRaw: "$ORIGIN/../lib",
		Entries:     []event.RpathEntry{{Path: "/tmp/lib", Risk: event.RpathRiskCritical, Reason: "world-writable", Exists: true, IsRpath: true}},
		HighestRisk: event.RpathRiskCritical, UsesOrigin: true, UsesDeprecated: true, IsSetuid: true}
	evs[8].BPFInventoryDetail = &event.BPFInventoryDetail{ScanID: "scan-1", Summary: true, ProgCount: 13, ByType: map[string]uint32{"cgroup_skb": 4, "kprobe": 9}}
	return evs
}

// t7hJSON is an event as JSON, with its timestamp in UTC, as the store
// reads TIMESTAMPTZ back (TestStore_TimesReadBackInUTC).
func t7hJSON(t *testing.T, e *event.HookEvent) string {
	t.Helper()
	c := *e
	c.Timestamp = c.Timestamp.UTC()
	b, err := json.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestEvents_EveryDetailTypeRoundTrips: each detail type, and every
// process field, is read back as written, by GetEvent and by QueryEvents.
func TestEvents_EveryDetailTypeRoundTrips(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	evs := t7hEvents(base)
	for _, e := range evs {
		if err := s.InsertEvent(ctx, e); err != nil {
			t.Fatalf("InsertEvent %s: %v", e.ID, err)
		}
	}
	// A second insert with the same ID is refused.
	if err := s.InsertEvent(ctx, evs[0]); err == nil {
		t.Error("InsertEvent stored a duplicate ID")
	}

	all, err := s.QueryEvents(ctx, EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(evs) {
		t.Fatalf("QueryEvents: %d events, want %d", len(all), len(evs))
	}
	for i, want := range evs {
		// Newest first, which is the order they were made in.
		if got := all[i]; t7hJSON(t, got) != t7hJSON(t, want) {
			t.Errorf("QueryEvents[%d]:\n got %s\nwant %s", i, t7hJSON(t, got), t7hJSON(t, want))
		}
		got, err := s.GetEvent(ctx, want.ID)
		if err != nil {
			t.Fatalf("GetEvent %s: %v", want.ID, err)
		}
		if t7hJSON(t, got) != t7hJSON(t, want) {
			t.Errorf("GetEvent %s:\n got %s\nwant %s", want.ID, t7hJSON(t, got), t7hJSON(t, want))
		}
	}

	// An event with no details and no policy result reads back with nil
	// pointers, not empty structs.
	bare := &event.HookEvent{ID: "e-bare", Timestamp: base.Add(time.Minute), HostID: "h-3", EventType: event.EventAgentOffline, Severity: event.SeverityAlert}
	if err := s.InsertEvent(ctx, bare); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetEvent(ctx, "e-bare")
	if err != nil {
		t.Fatal(err)
	}
	if got.BPFDetail != nil || got.ExecInjectionDetail != nil || got.ElfRpathDetail != nil || got.BPFInventoryDetail != nil || got.PolicyResult != nil {
		t.Errorf("bare event read back with details: %s", t7hJSON(t, got))
	}
}

// TestQueryEvents_FiltersAndPaging: each filter alone and combined, the
// time bounds inclusive, the default and explicit limits, and offsets.
func TestQueryEvents_FiltersAndPaging(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, e := range t7hEvents(base) {
		if err := s.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	// 120 more on a third host, to see the default limit of 100.
	for i := 0; i < 120; i++ {
		e := &event.HookEvent{ID: "bulk-" + strconv.Itoa(i), Timestamp: base.Add(-24*time.Hour - time.Duration(i)*time.Second),
			HostID: "h-bulk", EventType: event.EventSHMCreate, Severity: event.SeverityInfo}
		if err := s.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(f EventFilter) []string {
		t.Helper()
		evs, err := s.QueryEvents(ctx, f)
		if err != nil {
			t.Fatalf("QueryEvents(%+v): %v", f, err)
		}
		var out []string
		for _, e := range evs {
			out = append(out, e.ID)
		}
		return out
	}
	et := func(v event.EventType) *event.EventType { return &v }
	sev := func(v event.Severity) *event.Severity { return &v }
	tm := func(v time.Time) *time.Time { return &v }

	for name, c := range map[string]struct {
		f    EventFilter
		want []string
	}{
		"host":              {EventFilter{HostID: "h-2"}, []string{"e-shm", "e-dlopen", "e-ptrace", "e-rpath"}},
		"type":              {EventFilter{EventType: et(event.EventPtraceInject)}, []string{"e-ptrace"}},
		"severity":          {EventFilter{Severity: sev(event.SeverityCritical)}, []string{"e-bpf", "e-linker"}},
		"host and severity": {EventFilter{HostID: "h-1", Severity: sev(event.SeverityAlert)}, []string{"e-exec", "e-lib"}},
		"since, inclusive":  {EventFilter{Since: tm(base.Add(-2 * time.Minute))}, []string{"e-bpf", "e-exec", "e-shm"}},
		"until, inclusive":  {EventFilter{Until: tm(base.Add(-7 * time.Minute)), HostID: "h-2"}, []string{"e-rpath"}},
		"between":           {EventFilter{Since: tm(base.Add(-5 * time.Minute)), Until: tm(base.Add(-3 * time.Minute))}, []string{"e-dlopen", "e-linker", "e-ptrace"}},
		"limit":             {EventFilter{HostID: "h-1", Limit: 2}, []string{"e-bpf", "e-exec"}},
		"limit and offset":  {EventFilter{HostID: "h-1", Limit: 2, Offset: 2}, []string{"e-linker", "e-lib"}},
		"offset past end":   {EventFilter{HostID: "h-1", Offset: 50}, nil},
		"negative offset":   {EventFilter{HostID: "h-2", Offset: -5, Limit: 1}, []string{"e-shm"}},
		"no match":          {EventFilter{HostID: "h-none"}, nil},
	} {
		if got := ids(c.f); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	if n := len(ids(EventFilter{})); n != 100 {
		t.Errorf("default limit: %d events, want 100", n)
	}
	if n := len(ids(EventFilter{HostID: "h-bulk", Limit: 500})); n != 120 {
		t.Errorf("limit 500 on 120 events: %d", n)
	}
}

// TestHosts_ListUpsertAndStale: GetHosts sorts by hostname and carries the
// sensor snapshot; UpsertHost adds and updates without touching the
// snapshot; GetStaleHosts returns the hosts whose last heartbeat is older
// than the threshold, oldest first.
func TestHosts_ListUpsertAndStale(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	if hosts, err := s.GetHosts(ctx); err != nil || len(hosts) != 0 {
		t.Fatalf("empty GetHosts: %v, %v", hosts, err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	robHost(t, s, "h-b", now.Add(-10*time.Minute))
	robHost(t, s, "h-a", now.Add(-time.Hour))
	robHost(t, s, "h-c", now)
	if _, err := s.RecordHeartbeat(ctx, &event.HostHeartbeat{HostID: "h-c", ReceivedAt: now, AgentVersion: "v1",
		Sensors: []event.SensorHealth{{Name: "bpf_syscall", Status: "alive"}, {Name: "ptrace_monitor", Status: "dead", Reason: "stale"}}}); err != nil {
		t.Fatal(err)
	}

	hosts, err := s.GetHosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, h := range hosts {
		names = append(names, h.Hostname)
	}
	if !reflect.DeepEqual(names, []string{"rob-h-a", "rob-h-b", "rob-h-c"}) {
		t.Errorf("GetHosts order: %v", names)
	}
	c := hosts[2]
	if c.AgentVersion != "v1" || len(c.Sensors) != 2 || c.Sensors[1].Reason != "stale" || c.Status != event.HostOnline {
		t.Errorf("h-c: %+v", c)
	}

	stale, err := s.GetStaleHosts(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var staleIDs []string
	for _, h := range stale {
		staleIDs = append(staleIDs, h.ID)
	}
	if !reflect.DeepEqual(staleIDs, []string{"h-a", "h-b"}) {
		t.Errorf("stale after 5m: %v, want [h-a h-b] (oldest first)", staleIDs)
	}
	if stale, err := s.GetStaleHosts(ctx, 2*time.Hour); err != nil || len(stale) != 0 {
		t.Errorf("stale after 2h: %v, %v", stale, err)
	}

	// UpsertHost: a new host, then an update that keeps the sensors.
	seen := now.Add(-time.Minute)
	nh := &event.Host{ID: "h-new", Hostname: "zz-new", IPAddress: "10.0.0.9", AgentVersion: "v0", OSInfo: "linux",
		Status: event.HostOnline, EnrolledAt: now, LastHeartbeat: now, LastEventAt: &seen}
	if err := s.UpsertHost(ctx, nh); err != nil {
		t.Fatalf("UpsertHost (insert): %v", err)
	}
	got, err := s.GetHost(ctx, "h-new")
	if err != nil {
		t.Fatal(err)
	}
	if got.IPAddress != "10.0.0.9" || got.OSInfo != "linux" || got.LastEventAt == nil || !got.LastEventAt.Equal(seen) {
		t.Errorf("upserted host: %+v", got)
	}
	upd := *c
	upd.Hostname, upd.IPAddress, upd.Status = "rob-h-c-renamed", "10.0.0.3", event.HostUnresponsive
	if err := s.UpsertHost(ctx, &upd); err != nil {
		t.Fatalf("UpsertHost (update): %v", err)
	}
	got, err = s.GetHost(ctx, "h-c")
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "rob-h-c-renamed" || got.IPAddress != "10.0.0.3" || got.Status != event.HostUnresponsive || len(got.Sensors) != 2 {
		t.Errorf("updated host: %+v (the sensor snapshot must survive)", got)
	}
	if !got.EnrolledAt.Equal(c.EnrolledAt) {
		t.Errorf("UpsertHost changed enrolled_at: %v, was %v", got.EnrolledAt, c.EnrolledAt)
	}
}

// TestEnrollHost_SingleUseAndDuplicates: a single-use token fingerprint is
// consumed once; the second enrollment adds no host. A host ID can enroll
// only once.
func TestEnrollHost_SingleUseAndDuplicates(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	now := time.Now().UTC()
	h1 := &event.Host{ID: "h-1", Hostname: "one", Status: event.HostOnline, EnrolledAt: now, LastHeartbeat: now}
	h2 := &event.Host{ID: "h-2", Hostname: "two", Status: event.HostOnline, EnrolledAt: now, LastHeartbeat: now}
	if err := s.EnrollHost(ctx, h1, "once", "fp-1"); err != nil {
		t.Fatalf("first single-use enrollment: %v", err)
	}
	if err := s.EnrollHost(ctx, h2, "once", "fp-1"); !errors.Is(err, hcrypto.ErrTokenUsed) {
		t.Errorf("reused single-use token: %v, want ErrTokenUsed", err)
	}
	if _, err := s.GetHost(ctx, "h-2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the refused enrollment added a host: %v", err)
	}
	// A failed host insert rolls back the token use, so the token is still
	// usable.
	if err := s.EnrollHost(ctx, h1, "once-b", "fp-2"); err == nil {
		t.Error("EnrollHost enrolled the same host ID twice")
	}
	if err := s.EnrollHost(ctx, h2, "once-b", "fp-2"); err != nil {
		t.Errorf("fp-2 after a rolled-back use: %v", err)
	}
	var uses int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM enrollment_token_uses`).Scan(&uses); err != nil || uses != 2 {
		t.Errorf("enrollment_token_uses rows: %d, %v; want 2", uses, err)
	}
}

// TestDeleteAllowlistEntry_Missing: deleting a missing entry is
// ErrNotFound, and deleting twice fails the second time.
func TestDeleteAllowlistEntry_Missing(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	if err := s.DeleteAllowlistEntry(ctx, "no-such-entry"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing entry: %v", err)
	}
	e := &event.AllowlistEntry{ID: "e-1", CreatedAt: time.Now().UTC(), Description: "x", EventTypes: []event.EventType{event.EventBPFLoad},
		Action: event.ActionAllow, Enabled: true}
	if err := s.CreateAllowlistEntry(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAllowlistEntry(ctx, "e-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAllowlistEntry(ctx, "e-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

// TestStore_DatabaseFailures: a bad DSN, an unreachable server and a closed
// pool are errors from every call, never ErrNotFound or a panic.
func TestStore_DatabaseFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := NewStore(ctx, "postgres://%zz", zap.NewNop()); err == nil {
		t.Error("NewStore accepted a malformed DSN")
	}
	if _, err := NewStore(ctx, "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=2", zap.NewNop()); err == nil {
		t.Error("NewStore succeeded with nothing listening")
	}

	s, _ := polMigrated(t)
	s.Close()
	now := time.Now().UTC()
	for name, err := range map[string]error{
		"RunMigrations":         s.RunMigrations(ctx),
		"InsertEvent":           s.InsertEvent(ctx, &event.HookEvent{ID: "x", Timestamp: now, EventType: event.EventBPFLoad}),
		"UpsertHost":            s.UpsertHost(ctx, &event.Host{ID: "x"}),
		"EnrollHost":            s.EnrollHost(ctx, &event.Host{ID: "x"}, "t", "fp"),
		"DeleteAllowlistEntry":  s.DeleteAllowlistEntry(ctx, "x"),
		"SetLearningWindow":     s.SetLearningWindow(ctx, event.LearningWindow{StartedAt: now, EndsAt: now.Add(time.Hour)}),
		"DeleteLearningWindow":  s.DeleteLearningWindow(ctx, ""),
		"CreateAllowlistEntry":  s.CreateAllowlistEntry(ctx, &event.AllowlistEntry{ID: "x", Action: event.ActionAllow}),
		"UpdateAllowlistEntry":  s.UpdateAllowlistEntry(ctx, &event.AllowlistEntry{ID: "x", Action: event.ActionAllow}),
		"UpdateHostHeartbeat":   s.UpdateHostHeartbeat(ctx, &event.HostHeartbeat{HostID: "x", ReceivedAt: now}),
		"QueryEvents":           t7hErr(s.QueryEvents(ctx, EventFilter{})),
		"GetHosts":              t7hErr(s.GetHosts(ctx)),
		"GetStaleHosts":         t7hErr(s.GetStaleHosts(ctx, time.Minute)),
		"QueryAllowlist":        t7hErr(s.QueryAllowlist(ctx)),
		"GetLearningWindows":    t7hErr(s.GetLearningWindows(ctx)),
		"GetAllowlistEntry":     t7hErr(s.GetAllowlistEntry(ctx, "x")),
		"DecideCandidate":       t7hErr(s.DecideCandidate(ctx, "x", event.StatusApproved, "")),
		"MarkHostUnresponsive":  t7hErr(s.MarkHostUnresponsive(ctx, "x", now)),
		"RecordCandidate":       t7hErr(s.RecordCandidate(ctx, event.LearnedKey{EventType: event.EventBPFLoad}, "/x", "d", "h", "e", now)),
		"DecideCandidates":      t7hErr(s.DecideCandidates(ctx, []string{"x"}, event.StatusApproved, ScopeFleet)),
		"RecordHeartbeat (raw)": t7hErr(s.RecordHeartbeat(ctx, &event.HostHeartbeat{HostID: "x", ReceivedAt: now})),
	} {
		if err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("%s on a closed pool: %v, want a failure that is not ErrNotFound", name, err)
		}
	}
}

// t7hErr drops a call's value and keeps its error.
func t7hErr[T any](_ T, err error) error { return err }

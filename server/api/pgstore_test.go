package api_test

// The REST API over the real PostgreSQL store and the real policy engine
// (fix plan step 7h): query parameters reach SQL, hosts and events read
// back as stored, and every policy and learning write through the API
// changes what the engine decides, with no restart. Needs
// HOOKMON_TEST_PG_DSN, like the store tests; each test gets its own schema.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/api"
	"github.com/dlenrow/hookmon/server/policy"
	"github.com/dlenrow/hookmon/server/store"
)

const t7hToken = "t7h-api-token"

// t7hPGDSN creates a schema for the test, dropped afterwards, and returns
// a DSN that uses it. It skips the test without HOOKMON_TEST_PG_DSN.
func t7hPGDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("HOOKMON_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("HOOKMON_TEST_PG_DSN is not set; skipping the PostgreSQL API test")
	}
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	schema := "t7h_api_" + hex.EncodeToString(b)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to HOOKMON_TEST_PG_DSN: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Errorf("cleanup connect: %v", err)
			return
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		return dsn + sep + "search_path=" + schema
	}
	return dsn + " search_path=" + schema
}

// t7hStack is the API router over a migrated store and a policy engine
// that reads from it and records learning candidates in it.
type t7hStack struct {
	store  *store.Store
	engine *policy.Engine
	h      http.Handler
}

func t7hNewStack(t *testing.T) *t7hStack {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.NewStore(ctx, t7hPGDSN(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.RunMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(zaptest.NewLogger(t, zaptest.Level(zap.WarnLevel)))
	eng.SetSource(st)
	eng.SetCandidateSink(st)
	if err := eng.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	srv := api.NewServer(st, zap.NewNop(), nil)
	srv.SetPolicyReloader(eng)
	return &t7hStack{store: st, engine: eng, h: srv.Router([]string{t7hToken}, nil)}
}

// do sends an authenticated request and decodes a JSON answer into out.
func (s *t7hStack) do(t *testing.T, method, target, body string, out any) int {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+t7hToken)
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	if out != nil && rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: decode %q: %v", method, target, rec.Body, err)
		}
	}
	return rec.Code
}

func t7hIDs(evs []*event.HookEvent) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.ID)
	}
	return out
}

// TestAPI_RealStore_EventsAndHosts: the event list's query parameters
// select the rows PostgreSQL holds, newest first, and hosts read back as
// enrolled.
func TestAPI_RealStore_EventsAndHosts(t *testing.T) {
	s := t7hNewStack(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, h := range []*event.Host{
		{ID: "h-b", Hostname: "bravo", Status: event.HostOnline, EnrolledAt: base, LastHeartbeat: base},
		{ID: "h-a", Hostname: "alpha", Status: event.HostOnline, EnrolledAt: base, LastHeartbeat: base},
	} {
		if err := s.store.EnrollHost(ctx, h, "t7h", ""); err != nil {
			t.Fatal(err)
		}
	}
	type ev struct {
		id   string
		host string
		et   event.EventType
		sev  event.Severity
		ago  time.Duration
	}
	for _, e := range []ev{
		{"e1", "h-a", event.EventBPFLoad, event.SeverityCritical, 1 * time.Minute},
		{"e2", "h-a", event.EventDlopen, event.SeverityWarn, 2 * time.Minute},
		{"e3", "h-b", event.EventBPFLoad, event.SeverityAlert, 3 * time.Minute},
		{"e4", "h-b", event.EventSHMCreate, event.SeverityInfo, 4 * time.Minute},
		{"e5", "h-a", event.EventBPFLoad, event.SeverityAlert, 5 * time.Minute},
	} {
		hev := &event.HookEvent{ID: e.id, Timestamp: base.Add(-e.ago), HostID: e.host, Hostname: e.host,
			EventType: e.et, Severity: e.sev, ExePath: "/usr/bin/" + e.id}
		if e.et == event.EventBPFLoad {
			hev.BPFDetail = &event.BPFDetail{ProgName: "prog_" + e.id, ProgHash: "0123456789abcdef"}
		}
		if err := s.store.InsertEvent(ctx, hev); err != nil {
			t.Fatal(err)
		}
	}

	for q, want := range map[string][]string{
		"":                                 {"e1", "e2", "e3", "e4", "e5"},
		"?host_id=h-a":                     {"e1", "e2", "e5"},
		"?event_type=BPF_LOAD":             {"e1", "e3", "e5"},
		"?severity=ALERT":                  {"e3", "e5"},
		"?event_type=BPF_LOAD&host_id=h-b": {"e3"},
		"?since=2026-10-10T11:57:00Z":      {"e1", "e2", "e3"},
		"?until=2026-10-10T07:56:00-04:00": {"e4", "e5"},
		"?limit=2":                         {"e1", "e2"},
		"?limit=2&offset=2":                {"e3", "e4"},
		"?host_id=nobody":                  nil,
	} {
		var got []*event.HookEvent
		if code := s.do(t, http.MethodGet, "/api/v1/events"+q, "", &got); code != http.StatusOK {
			t.Fatalf("GET events%s: %d", q, code)
		}
		if ids := t7hIDs(got); !reflect.DeepEqual(ids, want) {
			t.Errorf("GET events%s: %v, want %v", q, ids, want)
		}
	}

	var one event.HookEvent
	if code := s.do(t, http.MethodGet, "/api/v1/events/e3", "", &one); code != http.StatusOK ||
		one.BPFDetail == nil || one.BPFDetail.ProgName != "prog_e3" || !one.Timestamp.Equal(base.Add(-3*time.Minute)) {
		t.Errorf("GET events/e3: %d %+v", code, one)
	}
	if code := s.do(t, http.MethodGet, "/api/v1/events/nope", "", nil); code != http.StatusNotFound {
		t.Errorf("GET a missing event: %d", code)
	}

	var hosts []*event.Host
	if code := s.do(t, http.MethodGet, "/api/v1/hosts", "", &hosts); code != http.StatusOK || len(hosts) != 2 ||
		hosts[0].Hostname != "alpha" || hosts[1].Hostname != "bravo" {
		t.Errorf("GET hosts: %d %+v", code, hosts)
	}
	var h event.Host
	if code := s.do(t, http.MethodGet, "/api/v1/hosts/h-b", "", &h); code != http.StatusOK || h.Hostname != "bravo" || h.Status != event.HostOnline {
		t.Errorf("GET hosts/h-b: %d %+v", code, h)
	}
	// last_event_at is each host's newest event (it used to be absent).
	if len(hosts) == 2 {
		for _, c := range []struct {
			got  *time.Time
			name string
			want time.Time
		}{
			{hosts[0].LastEventAt, "alpha (list)", base.Add(-1 * time.Minute)},
			{hosts[1].LastEventAt, "bravo (list)", base.Add(-3 * time.Minute)},
			{h.LastEventAt, "bravo (one)", base.Add(-3 * time.Minute)},
		} {
			if c.got == nil || !c.got.Equal(c.want) {
				t.Errorf("%s: last_event_at %v, want %v", c.name, c.got, c.want)
			}
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/h-b", nil)
	req.Header.Set("Authorization", "Bearer "+t7hToken)
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"last_event_at":"2026-10-10T11:57:00Z"`) {
		t.Errorf("GET hosts/h-b: want last_event_at in UTC: %s", rec.Body)
	}
	if code := s.do(t, http.MethodGet, "/api/v1/hosts/nope", "", nil); code != http.StatusNotFound {
		t.Errorf("GET a missing host: %d", code)
	}
}

// TestAPI_RealStore_DuplicateIDIs409: over the real store, a second POST
// with an ID that is taken is 409, not 500, and the first entry stays.
func TestAPI_RealStore_DuplicateIDIs409(t *testing.T) {
	s := t7hNewStack(t)
	body := `{"id":"fixed-id","description":"first","event_types":["DLOPEN"],"action":"ALLOW","enabled":true}`
	if code := s.do(t, http.MethodPost, "/api/v1/policies", body, nil); code != http.StatusCreated {
		t.Fatalf("first POST: %d", code)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader(strings.Replace(body, "first", "second", 1)))
	req.Header.Set("Authorization", "Bearer "+t7hToken)
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `already exists`) {
		t.Errorf("second POST: %d %s, want 409", rec.Code, rec.Body)
	}
	var stored []*event.AllowlistEntry
	if s.do(t, http.MethodGet, "/api/v1/policies", "", &stored); len(stored) != 1 || stored[0].Description != "first" {
		t.Errorf("entries after the refused POST: %+v", stored)
	}
}

// t7hDlopen is an unmatched dlopen event from a host.
func t7hDlopen(id, host, lib string) *event.HookEvent {
	return &event.HookEvent{ID: id, Timestamp: time.Now().UTC(), HostID: host, Hostname: host, EventType: event.EventDlopen,
		Severity: event.SeverityWarn, UID: 1000, ExePath: "/usr/bin/app", ExeHash: "sha256:" + strings.Repeat("ab", 32),
		DlopenDetail: &event.DlopenDetail{LibraryPath: lib}}
}

// TestAPI_RealStore_PolicyWritesReachTheEngine: each policy and learning
// write through the API is stored and changes the engine's next decision.
func TestAPI_RealStore_PolicyWritesReachTheEngine(t *testing.T) {
	s := t7hNewStack(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"h-1", "h-2"} {
		if err := s.store.EnrollHost(ctx, &event.Host{ID: id, Hostname: id, Status: event.HostOnline, EnrolledAt: now, LastHeartbeat: now}, "t7h", ""); err != nil {
			t.Fatal(err)
		}
	}
	action := func(e *event.HookEvent) (event.PolicyAction, string) {
		r := s.engine.Evaluate(e)
		return r.Action, r.MatchedEntryID
	}

	// Create: an ALLOW entry for one library path.
	var created event.AllowlistEntry
	code := s.do(t, http.MethodPost, "/api/v1/policies",
		`{"description":"ok lib","event_types":["DLOPEN"],"library_path":"/opt/ok/*.so","action":"ALLOW","enabled":true}`, &created)
	if code != http.StatusCreated || created.ID == "" {
		t.Fatalf("POST policies: %d %+v", code, created)
	}
	if a, id := action(t7hDlopen("x1", "h-1", "/opt/ok/a.so")); a != event.ActionAllow || id != created.ID {
		t.Errorf("after create: %s %s, want ALLOW by %s", a, id, created.ID)
	}

	// Patch: disabled entries never match.
	var patched event.AllowlistEntry
	if code := s.do(t, http.MethodPatch, "/api/v1/policies/"+created.ID, `{"enabled":false}`, &patched); code != http.StatusOK || patched.Enabled {
		t.Fatalf("PATCH: %d %+v", code, patched)
	}
	if a, id := action(t7hDlopen("x2", "h-1", "/opt/ok/a.so")); a == event.ActionAllow || id != "" {
		t.Errorf("after disable: %s %s, want no match", a, id)
	}

	// Put: replace with a DENY entry for another path.
	var replaced event.AllowlistEntry
	if code := s.do(t, http.MethodPut, "/api/v1/policies/"+created.ID,
		`{"description":"deny bad","event_types":["DLOPEN"],"library_path":"/opt/bad/*.so","action":"DENY","enabled":true}`, &replaced); code != http.StatusOK {
		t.Fatalf("PUT: %d", code)
	}
	if a, id := action(t7hDlopen("x3", "h-2", "/opt/bad/b.so")); a != event.ActionDeny || id != created.ID {
		t.Errorf("after replace: %s %s, want DENY", a, id)
	}
	var stored []*event.AllowlistEntry
	if s.do(t, http.MethodGet, "/api/v1/policies", "", &stored); len(stored) != 1 || stored[0].LibraryPath != "/opt/bad/*.so" || stored[0].CreatedAt.IsZero() {
		t.Errorf("GET policies after PUT: %+v", stored)
	}

	// Delete, twice.
	if code := s.do(t, http.MethodDelete, "/api/v1/policies/"+created.ID, "", nil); code != http.StatusNoContent {
		t.Errorf("DELETE: %d", code)
	}
	if code := s.do(t, http.MethodDelete, "/api/v1/policies/"+created.ID, "", nil); code != http.StatusNotFound {
		t.Errorf("second DELETE: %d", code)
	}
	if a, id := action(t7hDlopen("x4", "h-2", "/opt/bad/b.so")); a == event.ActionDeny || id != "" {
		t.Errorf("after delete: %s %s", a, id)
	}

	// Every unmatched key becomes a PENDING entry, the first time it is
	// seen; repeats only count. A learning window (quiet period) for one
	// host marks that host's first sightings quiet, and no other host's.
	var lv map[string]any
	if code := s.do(t, http.MethodPut, "/api/v1/learning/hosts/h-1", `{"duration":"1h"}`, &lv); code != http.StatusOK {
		t.Fatalf("PUT learning: %d", code)
	}
	if !s.engine.Learning("h-1") || s.engine.Learning("h-2") {
		t.Fatalf("learning: h-1 %v, h-2 %v", s.engine.Learning("h-1"), s.engine.Learning("h-2"))
	}
	var learnedResults []*event.PolicyResult
	for i := 0; i < 3; i++ {
		learnedResults = append(learnedResults, s.engine.Evaluate(t7hDlopen("l1", "h-1", "/opt/learned/x.so")))
	}
	if r := learnedResults[0]; r.Disposition != event.DispositionFirstSighting || !r.Quiet || r.CandidateID == "" {
		t.Errorf("first l1 in h-1's quiet period: %+v", r)
	}
	if r := learnedResults[2]; r.Disposition != event.DispositionRepeat || r.CandidateID != learnedResults[0].CandidateID {
		t.Errorf("third l1: %+v", r)
	}
	if r := s.engine.Evaluate(t7hDlopen("l2", "h-2", "/opt/other/y.so")); r.Disposition != event.DispositionFirstSighting || r.Quiet {
		t.Errorf("l2 on h-2, outside any quiet period: %+v", r)
	}
	var pending []*event.AllowlistEntry
	if code := s.do(t, http.MethodGet, "/api/v1/policies?status=PENDING", "", &pending); code != http.StatusOK {
		t.Fatalf("PENDING: %d", code)
	}
	var p *event.AllowlistEntry
	for _, e := range pending {
		if e.ID == learnedResults[0].CandidateID {
			p = e
		}
	}
	if p == nil || p.Learned == nil || p.Learned.Occurrences != 3 || !reflect.DeepEqual(p.Learned.Hosts, []string{"h-1"}) ||
		p.Learned.Key.Subject == "" || p.Learned.FirstEventID != "l1" {
		t.Fatalf("PENDING entry for l1: %+v in %d entries", p, len(pending))
	}
	var windows struct {
		Windows []struct {
			HostID string `json:"host_id"`
			Active bool   `json:"active"`
		} `json:"windows"`
	}
	if s.do(t, http.MethodGet, "/api/v1/learning", "", &windows); len(windows.Windows) != 1 || windows.Windows[0].HostID != "h-1" || !windows.Windows[0].Active {
		t.Errorf("GET learning: %+v", windows)
	}

	// Approve it for h-1 only: h-1's next event is allowed, h-2's is not.
	var approved event.AllowlistEntry
	if code := s.do(t, http.MethodPost, "/api/v1/policies/"+p.ID+"/approve", `{"scope":"host","host_id":"h-1"}`, &approved); code != http.StatusOK ||
		approved.Status != event.StatusApproved || approved.HostID != "h-1" {
		t.Fatalf("approve: %d %+v", code, approved)
	}
	// A host-scoped decision is a new entry for that host; the PENDING
	// entry, seen on h-1 only, is gone.
	if a, id := action(t7hDlopen("l3", "h-1", "/opt/learned/x.so")); a != event.ActionAllow || id != approved.ID || id == p.ID {
		t.Errorf("h-1 after approve: %s %s", a, id)
	}
	if a, _ := action(t7hDlopen("l4", "h-2", "/opt/learned/x.so")); a == event.ActionAllow {
		t.Error("the host-scoped approval allowed another host's event")
	}
	if code := s.do(t, http.MethodPost, "/api/v1/policies/"+p.ID+"/reject", `{"scope":"fleet"}`, nil); code != http.StatusNotFound {
		t.Errorf("deciding the used-up PENDING entry: %d, want 404", code)
	}
	if code := s.do(t, http.MethodPost, "/api/v1/policies/"+approved.ID+"/reject", `{"scope":"fleet"}`, nil); code != http.StatusConflict {
		t.Errorf("rejecting an approved entry: %d, want 409", code)
	}

	// Stop the quiet period: first sightings are no longer quiet, and are
	// still recorded.
	if code := s.do(t, http.MethodDelete, "/api/v1/learning/hosts/h-1", "", nil); code != http.StatusNoContent {
		t.Errorf("DELETE learning: %d", code)
	}
	if s.engine.Learning("h-1") {
		t.Error("learning still on after DELETE")
	}
	if r := s.engine.Evaluate(t7hDlopen("l5", "h-1", "/opt/after/z.so")); r.Disposition != event.DispositionFirstSighting || r.Quiet {
		t.Errorf("l5 after the quiet period: %+v", r)
	}

	// "Allowlist this event", from a stored event, for the fleet.
	stored0 := t7hDlopen("ev-store", "h-2", "/opt/store/s.so")
	s.engine.Evaluate(stored0)
	if err := s.store.InsertEvent(ctx, stored0); err != nil {
		t.Fatal(err)
	}
	var fromEvent event.AllowlistEntry
	if code := s.do(t, http.MethodPost, "/api/v1/events/ev-store/allowlist", `{"scope":"fleet"}`, &fromEvent); code != http.StatusCreated {
		t.Fatalf("allowlist event: %d", code)
	}
	if a, id := action(t7hDlopen("ev-2", "h-1", "/opt/store/s.so")); a != event.ActionAllow || id != fromEvent.ID {
		t.Errorf("after allowlisting the event: %s %s, want ALLOW by %s", a, id, fromEvent.ID)
	}
}

// TestAPI_RealStore_AllowlistEventDecidesPending: "Allowlist this event" on
// a new hook's first sighting decides the hook's PENDING entry instead of
// adding a second entry, so the hook leaves the list of new hooks. For the
// fleet the PENDING entry itself is approved; for one host a host-scoped
// entry is made and the host comes off the PENDING entry, which is deleted
// when no host is left.
func TestAPI_RealStore_AllowlistEventDecidesPending(t *testing.T) {
	s := t7hNewStack(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"h-1", "h-2"} {
		if err := s.store.EnrollHost(ctx, &event.Host{ID: id, Hostname: id, Status: event.HostOnline, EnrolledAt: now, LastHeartbeat: now}, "t7h", ""); err != nil {
			t.Fatal(err)
		}
	}
	// ingest evaluates an event and stores it if the server would.
	ingest := func(e *event.HookEvent) *event.PolicyResult {
		t.Helper()
		r := s.engine.Evaluate(e)
		if r.Disposition.Kept() {
			if err := s.store.InsertEvent(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
		return r
	}
	pendingEntry := func(id string) *event.AllowlistEntry {
		t.Helper()
		var pending []*event.AllowlistEntry
		if code := s.do(t, http.MethodGet, "/api/v1/policies?status=PENDING", "", &pending); code != http.StatusOK {
			t.Fatalf("PENDING: %d", code)
		}
		for _, p := range pending {
			if p.ID == id {
				return p
			}
		}
		return nil
	}

	// Fleet: the PENDING entry itself is approved.
	first := ingest(t7hDlopen("fs-1", "h-1", "/opt/fleet/a.so"))
	if first.Disposition != event.DispositionFirstSighting || first.CandidateID == "" {
		t.Fatalf("fs-1: %+v", first)
	}
	if r := ingest(t7hDlopen("fs-2", "h-2", "/opt/fleet/a.so")); r.Disposition != event.DispositionRepeat {
		t.Fatalf("fs-2: %+v", r)
	}
	var fleet event.AllowlistEntry
	if code := s.do(t, http.MethodPost, "/api/v1/events/fs-1/allowlist", `{"scope":"fleet"}`, &fleet); code != http.StatusCreated {
		t.Fatalf("allowlist fs-1 for the fleet: %d", code)
	}
	if fleet.ID != first.CandidateID || fleet.Status != event.StatusApproved || fleet.HostID != "" ||
		fleet.Learned == nil || fleet.Learned.FirstEventID != "fs-1" {
		t.Errorf("fleet answer: %+v %+v", fleet, fleet.Learned)
	}
	if p := pendingEntry(first.CandidateID); p != nil {
		t.Errorf("still PENDING after allowlisting its event: %+v", p)
	}
	var inForce []*event.AllowlistEntry
	s.do(t, http.MethodGet, "/api/v1/policies", "", &inForce)
	if len(inForce) != 1 || inForce[0].ID != first.CandidateID {
		t.Errorf("entries in force: %+v, want only the approved PENDING entry", inForce)
	}
	if r := ingest(t7hDlopen("fs-3", "h-2", "/opt/fleet/a.so")); r.Disposition != event.DispositionAllowed || r.MatchedEntryID != fleet.ID {
		t.Errorf("fs-3 after the fleet approval: %+v", r)
	}

	// One host at a time: a hook seen on h-1 and h-2.
	hs := ingest(t7hDlopen("hs-1", "h-1", "/opt/host/b.so"))
	ingest(t7hDlopen("hs-2", "h-2", "/opt/host/b.so"))
	var forH1 event.AllowlistEntry
	if code := s.do(t, http.MethodPost, "/api/v1/events/hs-1/allowlist", `{"scope":"host","description":"plugin ok"}`, &forH1); code != http.StatusCreated {
		t.Fatalf("allowlist hs-1 for its host: %d", code)
	}
	if forH1.HostID != "h-1" || forH1.ID == hs.CandidateID || forH1.Status != event.StatusApproved || forH1.Description != "plugin ok" {
		t.Errorf("host answer: %+v", forH1)
	}
	if p := pendingEntry(hs.CandidateID); p == nil || !reflect.DeepEqual(p.Learned.Hosts, []string{"h-2"}) {
		t.Errorf("PENDING after h-1's decision: %+v, want h-2 left", p)
	}
	if r := ingest(t7hDlopen("hs-3", "h-1", "/opt/host/b.so")); r.Disposition != event.DispositionAllowed || r.MatchedEntryID != forH1.ID {
		t.Errorf("hs-3 on h-1: %+v", r)
	}
	if r := s.engine.Evaluate(t7hDlopen("hs-4", "h-2", "/opt/host/b.so")); r.Disposition != event.DispositionRepeat {
		t.Errorf("hs-4 on h-2, still undecided there: %+v", r)
	}
	// An event from h-2 with the key (stored as a denied one would be).
	if err := s.store.InsertEvent(ctx, t7hDlopen("hs-5", "h-2", "/opt/host/b.so")); err != nil {
		t.Fatal(err)
	}
	var forH2 event.AllowlistEntry
	if code := s.do(t, http.MethodPost, "/api/v1/events/hs-5/allowlist", `{"scope":"host"}`, &forH2); code != http.StatusCreated || forH2.HostID != "h-2" {
		t.Fatalf("allowlist hs-5 for its host: %d %+v", code, forH2)
	}
	if p := pendingEntry(hs.CandidateID); p != nil {
		t.Errorf("PENDING entry left after its last host was decided: %+v", p)
	}
}

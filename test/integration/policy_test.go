package integration_test

// Policy and learning mode (fix plan step 7c) through the real server: TLS
// REST, the mutual-TLS event stream from enrolled buses, the policy engine
// and PostgreSQL. Like enroll_test.go these need HOOKMON_TEST_PG_DSN.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dlenrow/hookmon/agent/transport"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/test/enrpki"
)

const polTag = "a04f5eef06a7f555"

var polExeHash = "sha256:" + strings.Repeat("ab", 32)

// polDo sends an authenticated REST request with a JSON body over TLS and
// decodes a JSON answer into out.
func polDo(t *testing.T, s *enrServer, method, path, body string, out any) int {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://"+s.HTTPAddr()+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+enrAPIToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("%s %s: decode %q: %v", method, path, data, err)
		}
	}
	if resp.StatusCode >= 300 {
		t.Logf("%s %s: %d %s", method, path, resp.StatusCode, bytes.TrimSpace(data))
	}
	return resp.StatusCode
}

func polDlopen(lib string) *event.HookEvent {
	return &event.HookEvent{
		ID: uuid.New().String(), Timestamp: time.Now(), Hostname: "bus",
		EventType: event.EventDlopen, Severity: event.SeverityWarn, PID: 4242, UID: 1000, Comm: "app",
		ExePath: "/usr/bin/app", ExeHash: polExeHash,
		DlopenDetail: &event.DlopenDetail{LibraryPath: lib},
	}
}

func polBPFLoad() *event.HookEvent {
	return &event.HookEvent{
		ID: uuid.New().String(), Timestamp: time.Now(), Hostname: "bus",
		EventType: event.EventBPFLoad, Severity: event.SeverityWarn, PID: 4343, UID: 0, Comm: "loader",
		ExePath: "/usr/bin/loader", ExeHash: polExeHash,
		BPFDetail: &event.BPFDetail{BPFCommand: 5, ProgType: 5, ProgName: "hello_count", ProgHash: polTag, ProgID: 9},
	}
}

// polSend sends evt through the bus transport and waits until the server
// has stored it, then returns it as stored, with its policy result.
func polSend(t *testing.T, s *enrServer, tr *transport.GRPCTransport, hostID string, evt *event.HookEvent) *event.HookEvent {
	t.Helper()
	if err := tr.SendEvent(evt); err != nil {
		t.Fatal(err)
	}
	var got *event.HookEvent
	enrWaitFor(t, 10*time.Second, "event "+evt.ID+" in the store", func() bool {
		var e event.HookEvent
		if enrGet(t, s, "/api/v1/events/"+evt.ID, &e) != http.StatusOK {
			return false
		}
		got = &e
		return true
	})
	if got.HostID != hostID || got.PolicyResult == nil {
		t.Fatalf("stored event: host %s, result %+v", got.HostID, got.PolicyResult)
	}
	return got
}

func polPending(t *testing.T, s *enrServer) map[string]*event.AllowlistEntry {
	t.Helper()
	var entries []*event.AllowlistEntry
	if code := polDo(t, s, http.MethodGet, "/api/v1/policies?status=PENDING", "", &entries); code != http.StatusOK {
		t.Fatalf("GET PENDING: %d", code)
	}
	out := map[string]*event.AllowlistEntry{}
	for _, e := range entries {
		if e.Learned == nil {
			t.Fatalf("PENDING entry without learned data: %+v", e)
		}
		if strings.HasPrefix(e.Learned.Key.Subject, polBarrierDir) {
			continue
		}
		out[e.Learned.Key.Subject] = e
	}
	return out
}

// polBarrierDir holds the libraries of barrier events (see polBarrier).
// polPending leaves their PENDING entries out.
const polBarrierDir = "/opt/hookmon-test-barrier/"

// polBarrier sends a dlopen of a library no event has named before, a
// first sighting the server stores, and waits until it is stored. The
// server handles one bus's events in order, so every event sent before
// the barrier has been evaluated, stored or not, when polBarrier returns.
func polBarrier(t *testing.T, s *enrServer, tr *transport.GRPCTransport, hostID string) {
	t.Helper()
	polSend(t, s, tr, hostID, polDlopen(polBarrierDir+uuid.New().String()+".so"))
}

// polSendDropped sends evt and checks that the server evaluated it and did
// not store it: a repeat of a new hook still waiting for a decision, or an
// allowed hook.
func polSendDropped(t *testing.T, s *enrServer, tr *transport.GRPCTransport, hostID string, evt *event.HookEvent) {
	t.Helper()
	if err := tr.SendEvent(evt); err != nil {
		t.Fatal(err)
	}
	polBarrier(t, s, tr, hostID)
	if code := enrGet(t, s, "/api/v1/events/"+evt.ID, nil); code != http.StatusNotFound {
		t.Errorf("event %s (%s) was stored (GET: %d); want it dropped", evt.ID, evt.EventType, code)
	}
}

func polSorted(hosts []string) string {
	h := append([]string(nil), hosts...)
	sort.Strings(h)
	return strings.Join(h, ",")
}

// TestIntegration_FirstSightingApproveReject: the first unmatched event of
// a key from either of two enrolled hosts is stored as a first sighting and
// makes one PENDING entry; repeats only count. Approving for one host,
// rejecting for the other and approving for the fleet each change what
// happens to the next event: allowed events and repeats are not stored,
// denied ones are stored every time.
func TestIntegration_FirstSightingApproveReject(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	s := enrStartServer(t, enrServerConfig(pki, dsn, tok))
	busA := enrEnroll(t, s, pki, tok.reusable)
	busB := enrEnroll(t, s, pki, tok.reusable)
	trA, _ := enrRunBus(t, busA, nil)
	trB, _ := enrRunBus(t, busB, nil)
	a, b := busA.HostID, busB.HostID
	ab := polSorted([]string{a, b})

	first := polSend(t, s, trA, a, polDlopen("/opt/plugin.so"))
	polSendDropped(t, s, trB, b, polDlopen("/opt/plugin.so"))
	polSendDropped(t, s, trA, a, polDlopen("/opt/plugin.so"))
	bpf := polSend(t, s, trA, a, polBPFLoad())
	if r := first.PolicyResult; r.Action != event.ActionAlert || r.Disposition != event.DispositionFirstSighting ||
		r.CandidateID == "" || r.Quiet || !strings.Contains(r.Reason, "first sighting: PENDING entry "+r.CandidateID) {
		t.Errorf("first unmatched event: %+v", r)
	}
	if bpf.Severity != event.SeverityCritical || bpf.PolicyResult.Disposition != event.DispositionFirstSighting {
		t.Errorf("unmatched BPF load from root: severity %s, %+v; want CRITICAL first sighting", bpf.Severity, bpf.PolicyResult)
	}

	p := polPending(t, s)
	plug, tag := p["/opt/plugin.so"], p[polTag]
	if len(p) != 2 || plug == nil || tag == nil {
		t.Fatalf("PENDING: %+v", p)
	}
	if plug.ID != first.PolicyResult.CandidateID || plug.Learned.FirstEventID != first.ID || plug.Learned.Occurrences != 3 ||
		polSorted(plug.Learned.Hosts) != ab || plug.Learned.FirstSeen.After(plug.Learned.LastSeen) {
		t.Errorf("plugin.so entry: %+v %+v", plug, plug.Learned)
	}
	if tag.Learned.Key.ProgType != 5 || tag.Learned.Key.SubjectKind != "bpf_tag" || tag.Learned.Occurrences != 1 || tag.Learned.FirstEventID != bpf.ID {
		t.Errorf("BPF entry: %+v", tag.Learned)
	}
	t.Logf("PENDING: %s (%d on %s), %s (%d)", plug.Description, plug.Learned.Occurrences, polSorted(plug.Learned.Hosts),
		tag.Description, tag.Learned.Occurrences)

	// Approve plugin.so for host A only: A's next one is dropped as
	// allowed; B's is a repeat, counted and dropped.
	var decided event.AllowlistEntry
	if code := polDo(t, s, http.MethodPost, "/api/v1/policies/"+plug.ID+"/approve",
		`{"scope":"host","host_id":"`+a+`"}`, &decided); code != http.StatusOK {
		t.Fatalf("approve for host A: %d", code)
	}
	polSendDropped(t, s, trA, a, polDlopen("/opt/plugin.so"))
	polSendDropped(t, s, trB, b, polDlopen("/opt/plugin.so"))
	if got := polPending(t, s)["/opt/plugin.so"]; got == nil || polSorted(got.Learned.Hosts) != b || got.Learned.Occurrences != 4 {
		t.Fatalf("PENDING after host approval: %+v", got)
	}

	// Reject it for host B: stored and alerting every time.
	var rejected event.AllowlistEntry
	if code := polDo(t, s, http.MethodPost, "/api/v1/policies/"+plug.ID+"/reject",
		`{"scope":"host","host_id":"`+b+`"}`, &rejected); code != http.StatusOK || rejected.Status != event.StatusRejected {
		t.Fatalf("reject for host B: %d %+v", code, rejected)
	}
	for i := 0; i < 2; i++ {
		r := polSend(t, s, trB, b, polDlopen("/opt/plugin.so"))
		if r.PolicyResult.Action != event.ActionAlert || r.PolicyResult.Disposition != event.DispositionDenied ||
			r.PolicyResult.MatchedEntryID != rejected.ID || r.Severity != event.SeverityWarn {
			t.Errorf("host B after rejection, occurrence %d: %s %+v", i, r.Severity, r.PolicyResult)
		}
	}
	if _, ok := polPending(t, s)["/opt/plugin.so"]; ok {
		t.Error("plugin.so still PENDING after a decision for each host it was seen on")
	}

	// Approve the BPF program for the fleet.
	if code := polDo(t, s, http.MethodPost, "/api/v1/policies/"+tag.ID+"/approve", `{"scope":"fleet"}`, nil); code != http.StatusOK {
		t.Fatalf("approve for the fleet: %d", code)
	}
	polSendDropped(t, s, trB, b, polBPFLoad())
	if code := polDo(t, s, http.MethodPost, "/api/v1/policies/"+tag.ID+"/approve", `{"scope":"fleet"}`, nil); code != http.StatusConflict {
		t.Errorf("approving twice: %d, want 409", code)
	}

	// A fleet learning window is a quiet period: first sightings are still
	// stored and recorded, and marked quiet until it stops.
	var win map[string]any
	if code := polDo(t, s, http.MethodPut, "/api/v1/learning/fleet", `{"duration":"1h"}`, &win); code != http.StatusOK || win["active"] != true {
		t.Fatalf("start learning: %d %v", code, win)
	}
	if r := polSend(t, s, trA, a, polDlopen("/opt/quiet.so")).PolicyResult; r.Disposition != event.DispositionFirstSighting || !r.Quiet {
		t.Errorf("first sighting in a quiet period: %+v", r)
	}
	if code := polDo(t, s, http.MethodDelete, "/api/v1/learning/fleet", "", nil); code != http.StatusNoContent {
		t.Fatalf("stop learning: %d", code)
	}
	if r := polSend(t, s, trA, a, polDlopen("/opt/after.so")).PolicyResult; r.Disposition != event.DispositionFirstSighting || r.Quiet {
		t.Errorf("first sighting after the quiet period: %+v", r)
	}
	if p := polPending(t, s); len(p) != 2 || p["/opt/quiet.so"] == nil || p["/opt/after.so"] == nil {
		t.Errorf("PENDING: %+v, want quiet.so and after.so", p)
	}
}

// TestIntegration_BulkDecide: every new hook an update brought, decided in
// one call: the hooks then stay silent, on the hosts they were seen on.
func TestIntegration_BulkDecide(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	s := enrStartServer(t, enrServerConfig(pki, dsn, tok))
	busA := enrEnroll(t, s, pki, tok.reusable)
	busB := enrEnroll(t, s, pki, tok.reusable)
	trA, _ := enrRunBus(t, busA, nil)
	trB, _ := enrRunBus(t, busB, nil)
	a, b := busA.HostID, busB.HostID

	libs := []string{"/opt/update/one.so", "/opt/update/two.so", "/opt/update/three.so"}
	for _, lib := range libs {
		polSend(t, s, trA, a, polDlopen(lib))
	}
	polSendDropped(t, s, trB, b, polDlopen(libs[0]))
	p := polPending(t, s)
	var ids []string
	for _, lib := range libs {
		if p[lib] == nil {
			t.Fatalf("no PENDING entry for %s: %+v", lib, p)
		}
		ids = append(ids, `"`+p[lib].ID+`"`)
	}

	var resp struct {
		Results []struct {
			ID      string                  `json:"id"`
			OK      bool                    `json:"ok"`
			Entries []*event.AllowlistEntry `json:"entries"`
			Error   string                  `json:"error"`
		} `json:"results"`
	}
	body := `{"ids":[` + strings.Join(ids, ",") + `,"no-such-entry"],"decision":"approve","scope":"seen_hosts"}`
	if code := polDo(t, s, http.MethodPost, "/api/v1/policies/decide", body, &resp); code != http.StatusOK || len(resp.Results) != 4 {
		t.Fatalf("decide: %d %+v", code, resp)
	}
	for i, r := range resp.Results[:3] {
		want := 1
		if i == 0 {
			want = 2 // one.so was seen on both hosts
		}
		if !r.OK || len(r.Entries) != want {
			t.Errorf("%s: %+v", libs[i], r)
		}
	}
	if r := resp.Results[3]; r.OK || r.Error == "" {
		t.Errorf("unknown ID: %+v", r)
	}
	if p := polPending(t, s); len(p) != 0 {
		t.Errorf("PENDING after the bulk decision: %+v", p)
	}
	for _, lib := range libs {
		polSendDropped(t, s, trA, a, polDlopen(lib))
	}
	polSendDropped(t, s, trB, b, polDlopen(libs[0]))
	// two.so was not seen on B: there it is still a new hook.
	if r := polSend(t, s, trB, b, polDlopen(libs[1])).PolicyResult; r.Disposition != event.DispositionFirstSighting {
		t.Errorf("two.so on host B: %+v", r)
	}
}

// TestIntegration_QuietPeriodSurvivesRestart: a learning window for one
// host is stored in the database, so a restarted server keeps that host's
// first sightings quiet until the window ends, and no other host's.
func TestIntegration_QuietPeriodSurvivesRestart(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	cfg := enrServerConfig(pki, dsn, tok)
	s := enrStartServer(t, cfg)
	busA := enrEnroll(t, s, pki, tok.reusable)
	busB := enrEnroll(t, s, pki, tok.reusable)
	if code := polDo(t, s, http.MethodPut, "/api/v1/learning/hosts/"+busA.HostID, `{"duration":"1h"}`, nil); code != http.StatusOK {
		t.Fatalf("start host learning: %d", code)
	}
	if code := polDo(t, s, http.MethodPut, "/api/v1/learning/hosts/not-enrolled", `{"duration":"1h"}`, nil); code != http.StatusNotFound {
		t.Errorf("learning for an unknown host: %d, want 404", code)
	}
	s.stop()

	s2 := enrStartServer(t, cfg)
	busA.ServerAddr, busB.ServerAddr = s2.GRPCAddr(), s2.GRPCAddr()
	trA, _ := enrRunBus(t, busA, nil)
	trB, _ := enrRunBus(t, busB, nil)
	if r := polSend(t, s2, trA, busA.HostID, polDlopen("/opt/a.so")).PolicyResult; !r.Quiet {
		t.Errorf("host A after restart: %+v, want quiet", r)
	}
	if r := polSend(t, s2, trB, busB.HostID, polDlopen("/opt/b.so")).PolicyResult; r.Quiet {
		t.Errorf("host B after restart: %+v, want not quiet", r)
	}
	if p := polPending(t, s2); len(p) != 2 {
		t.Fatalf("PENDING after restart: %+v", p)
	}
}

// TestIntegration_PolicyChangeWithin1s measures how long a policy change
// through the API takes to apply on the real server, with no restart: from
// the start of the POST until an event sent once the POST returned has
// been evaluated and dropped as allowed (not stored, so not alerted).
func TestIntegration_PolicyChangeWithin1s(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	s := enrStartServer(t, enrServerConfig(pki, dsn, tok))
	bus := enrEnroll(t, s, pki, tok.reusable)
	tr, _ := enrRunBus(t, bus, nil)

	if r := polSend(t, s, tr, bus.HostID, polBPFLoad()); r.PolicyResult.Action != event.ActionAlert {
		t.Fatalf("before: %+v", r.PolicyResult)
	}
	occurrences := func() int64 {
		t.Helper()
		e := polPending(t, s)[polTag]
		if e == nil {
			t.Fatal("no PENDING entry for the BPF program")
		}
		return e.Learned.Occurrences
	}

	start := time.Now()
	var created event.AllowlistEntry
	if code := polDo(t, s, http.MethodPost, "/api/v1/policies",
		`{"description":"hello canary","event_types":["BPF_LOAD"],"prog_hash":"`+strings.ToUpper(polTag)+`","prog_type":5,"action":"ALLOW","enabled":true}`,
		&created); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	posted := time.Since(start)
	before := occurrences()
	polSendDropped(t, s, tr, bus.HostID, polBPFLoad())
	inEffect := time.Since(start)
	if after := occurrences(); after != before {
		t.Errorf("the event after the POST counted as a repeat (%d to %d), not allowed", before, after)
	}
	t.Logf("POST answered after %v (the engine reloads before it answers); the next event was evaluated and dropped as allowed %v after the POST started",
		posted, inEffect)
	if inEffect > time.Second {
		t.Errorf("policy change took %v to apply, want under 1s", inEffect)
	}
}

// TestIntegration_SIGHUPReload: an allowlist entry written straight into
// the database takes effect on SIGHUP, with no restart.
func TestIntegration_SIGHUPReload(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	s := enrStartServer(t, enrServerConfig(pki, dsn, tok))
	bus := enrEnroll(t, s, pki, tok.reusable)
	tr, _ := enrRunBus(t, bus, nil)

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `
		INSERT INTO allowlist (id, created_by, description, event_types, prog_hash, prog_type, action, enabled)
		VALUES ('sql-entry', 'psql', 'written in SQL', '["BPF_LOAD"]', $1, 5, 'ALLOW', TRUE)`, polTag); err != nil {
		t.Fatal(err)
	}
	if r := polSend(t, s, tr, bus.HostID, polBPFLoad()); r.PolicyResult.Action != event.ActionAlert {
		t.Fatalf("entry applied without a reload: %+v", r.PolicyResult)
	}
	// Until the reload, each load is a repeat of the new hook: counted.
	// Once the SQL entry applies, it is allowed: not counted.
	occurrences := func() int64 {
		t.Helper()
		return polPending(t, s)[polTag].Learned.Occurrences
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		before := occurrences()
		polSendDropped(t, s, tr, bus.HostID, polBPFLoad())
		if occurrences() == before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SQL entry not applied 5s after SIGHUP")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

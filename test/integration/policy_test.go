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
		out[e.Learned.Key.Subject] = e
	}
	return out
}

func polSorted(hosts []string) string {
	h := append([]string(nil), hosts...)
	sort.Strings(h)
	return strings.Join(h, ",")
}

// TestIntegration_LearningApproveReject: learning mode for the fleet turns
// unmatched events from two enrolled hosts into PENDING entries with counts
// and hosts; approving for one host, rejecting for the other and approving
// for the fleet each change how the next event is decided; stopping
// learning stops new candidates.
func TestIntegration_LearningApproveReject(t *testing.T) {
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

	// Learning off: nothing is recorded.
	polSend(t, s, trA, a, polDlopen("/opt/before.so"))
	if p := polPending(t, s); len(p) != 0 {
		t.Fatalf("PENDING with learning off: %+v", p)
	}

	var win map[string]any
	if code := polDo(t, s, http.MethodPut, "/api/v1/learning/fleet", `{"duration":"1h"}`, &win); code != http.StatusOK || win["active"] != true {
		t.Fatalf("start learning: %d %v", code, win)
	}

	first := polSend(t, s, trA, a, polDlopen("/opt/plugin.so"))
	polSend(t, s, trB, b, polDlopen("/opt/plugin.so"))
	polSend(t, s, trA, a, polDlopen("/opt/plugin.so"))
	bpf := polSend(t, s, trA, a, polBPFLoad())
	if first.PolicyResult.Action != event.ActionAlert || !strings.Contains(first.PolicyResult.Reason, "learning mode: PENDING entry") {
		t.Errorf("first unmatched event: %+v", first.PolicyResult)
	}
	if bpf.Severity != event.SeverityCritical {
		t.Errorf("unmatched BPF load from root: severity %s, want CRITICAL", bpf.Severity)
	}

	p := polPending(t, s)
	plug, tag := p["/opt/plugin.so"], p[polTag]
	if len(p) != 2 || plug == nil || tag == nil {
		t.Fatalf("PENDING: %+v", p)
	}
	if plug.Learned.Occurrences != 3 || polSorted(plug.Learned.Hosts) != ab || plug.Learned.FirstSeen.After(plug.Learned.LastSeen) {
		t.Errorf("plugin.so candidate: %+v", plug.Learned)
	}
	if tag.Learned.Key.ProgType != 5 || tag.Learned.Key.SubjectKind != "bpf_tag" || tag.Learned.Occurrences != 1 {
		t.Errorf("BPF candidate: %+v", tag.Learned)
	}
	t.Logf("PENDING: %s (%d on %s), %s (%d)", plug.Description, plug.Learned.Occurrences, polSorted(plug.Learned.Hosts),
		tag.Description, tag.Learned.Occurrences)

	// Approve plugin.so for host A only.
	var decided event.AllowlistEntry
	if code := polDo(t, s, http.MethodPost, "/api/v1/policies/"+plug.ID+"/approve",
		`{"scope":"host","host_id":"`+a+`"}`, &decided); code != http.StatusOK {
		t.Fatalf("approve for host A: %d", code)
	}
	if r := polSend(t, s, trA, a, polDlopen("/opt/plugin.so")); r.PolicyResult.Action != event.ActionAllow ||
		r.PolicyResult.MatchedEntryID != decided.ID || r.Severity != event.SeverityInfo {
		t.Errorf("host A after approval: %s %+v", r.Severity, r.PolicyResult)
	}
	if r := polSend(t, s, trB, b, polDlopen("/opt/plugin.so")); r.PolicyResult.Action != event.ActionAlert || r.PolicyResult.MatchedEntryID != "" {
		t.Errorf("host B after host A's approval: %+v", r.PolicyResult)
	}
	if got := polPending(t, s)["/opt/plugin.so"]; got == nil || polSorted(got.Learned.Hosts) != b || got.Learned.Occurrences != 4 {
		t.Fatalf("PENDING after host approval: %+v", got)
	}

	// Reject it for host B.
	var rejected event.AllowlistEntry
	if code := polDo(t, s, http.MethodPost, "/api/v1/policies/"+plug.ID+"/reject",
		`{"scope":"host","host_id":"`+b+`"}`, &rejected); code != http.StatusOK || rejected.Status != event.StatusRejected {
		t.Fatalf("reject for host B: %d %+v", code, rejected)
	}
	if r := polSend(t, s, trB, b, polDlopen("/opt/plugin.so")); r.PolicyResult.Action != event.ActionAlert ||
		r.PolicyResult.MatchedEntryID != rejected.ID || r.Severity != event.SeverityWarn {
		t.Errorf("host B after rejection: %s %+v", r.Severity, r.PolicyResult)
	}
	if _, ok := polPending(t, s)["/opt/plugin.so"]; ok {
		t.Error("plugin.so still PENDING after a decision for each host it was seen on")
	}

	// Approve the BPF program for the fleet.
	if code := polDo(t, s, http.MethodPost, "/api/v1/policies/"+tag.ID+"/approve", `{"scope":"fleet"}`, nil); code != http.StatusOK {
		t.Fatalf("approve for the fleet: %d", code)
	}
	if r := polSend(t, s, trB, b, polBPFLoad()); r.PolicyResult.Action != event.ActionAllow || r.PolicyResult.MatchedEntryID != tag.ID {
		t.Errorf("host B BPF load after fleet approval: %+v", r.PolicyResult)
	}
	if code := polDo(t, s, http.MethodPost, "/api/v1/policies/"+tag.ID+"/approve", `{"scope":"fleet"}`, nil); code != http.StatusConflict {
		t.Errorf("approving twice: %d, want 409", code)
	}

	// Stop learning: new keys are not recorded.
	if code := polDo(t, s, http.MethodDelete, "/api/v1/learning/fleet", "", nil); code != http.StatusNoContent {
		t.Fatalf("stop learning: %d", code)
	}
	polSend(t, s, trA, a, polDlopen("/opt/after.so"))
	if p := polPending(t, s); len(p) != 0 {
		t.Errorf("PENDING after learning stopped: %+v", p)
	}
}

// TestIntegration_LearningSurvivesRestart: a learning window for one host
// is stored in the database, so a restarted server keeps learning for that
// host until the window ends, and not for other hosts.
func TestIntegration_LearningSurvivesRestart(t *testing.T) {
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
	polSend(t, s2, trA, busA.HostID, polDlopen("/opt/a.so"))
	polSend(t, s2, trB, busB.HostID, polDlopen("/opt/b.so"))
	p := polPending(t, s2)
	if len(p) != 1 || p["/opt/a.so"] == nil || polSorted(p["/opt/a.so"].Learned.Hosts) != busA.HostID {
		t.Fatalf("PENDING after restart: %+v", p)
	}
}

// TestIntegration_PolicyChangeWithin1s measures how long a policy change
// through the API takes to apply on the real server, with no restart: from
// the start of the POST to an event, sent once the POST returned, being
// stored as decided by the new entry.
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

	start := time.Now()
	var created event.AllowlistEntry
	if code := polDo(t, s, http.MethodPost, "/api/v1/policies",
		`{"description":"hello canary","event_types":["BPF_LOAD"],"prog_hash":"`+strings.ToUpper(polTag)+`","prog_type":5,"action":"ALLOW","enabled":true}`,
		&created); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	posted := time.Since(start)

	evt := polBPFLoad()
	if err := tr.SendEvent(evt); err != nil {
		t.Fatal(err)
	}
	var got event.HookEvent
	deadline := time.Now().Add(10 * time.Second)
	for enrGet(t, s, "/api/v1/events/"+evt.ID, &got) != http.StatusOK {
		if time.Now().After(deadline) {
			t.Fatal("event not stored")
		}
		time.Sleep(5 * time.Millisecond)
	}
	inEffect := time.Since(start)
	if got.PolicyResult == nil || got.PolicyResult.Action != event.ActionAllow || got.PolicyResult.MatchedEntryID != created.ID {
		t.Fatalf("first event after the POST: %+v", got.PolicyResult)
	}
	t.Logf("POST answered after %v (the engine reloads before it answers); the next event was stored as ALLOW %v after the POST started",
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
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r := polSend(t, s, tr, bus.HostID, polBPFLoad())
		if r.PolicyResult.MatchedEntryID == "sql-entry" && r.PolicyResult.Action == event.ActionAllow {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("SQL entry not applied 5s after SIGHUP: %+v", r.PolicyResult)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

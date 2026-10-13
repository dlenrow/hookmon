package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/allowlist"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/policy"
)

// dashSeed puts an approved, a rejected and a pending entry in st.
func dashSeed(st *polStore) {
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	learned := &event.Learned{Key: event.LearnedKey{SubjectKind: allowlist.SubjectDlopen, Subject: "/opt/x.so"}, Occurrences: 3, Hosts: []string{"host-a"}}
	st.entries = []*event.AllowlistEntry{
		{ID: "ok", CreatedAt: created, CreatedBy: "alice", Description: "cilium", EventTypes: []event.EventType{event.EventBPFLoad},
			ExePath: "/usr/bin/cilium*", Action: event.ActionAllow, Enabled: true, Status: event.StatusApproved},
		{ID: "rej", CreatedAt: created, CreatedBy: "learning-mode", Description: "learned", Action: event.ActionAlert, Enabled: true,
			Status: event.StatusRejected, Learned: learned},
		{ID: "pend", CreatedAt: created, CreatedBy: "learning-mode", Action: event.ActionAlert, Enabled: true, Status: event.StatusPending, Learned: learned},
	}
}

func dashEntry(t *testing.T, st *polStore, id string) *event.AllowlistEntry {
	t.Helper()
	e, err := st.GetAllowlistEntry(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestReplacePolicy(t *testing.T) {
	st, rl := newPolStore(), &polReloader{}
	dashSeed(st)
	h := polRouter(st, rl)

	// A GET-modify-PUT round trip: server-owned fields in the body are kept
	// from the stored entry.
	code, body := polDo(t, h, http.MethodPut, "/api/v1/policies/ok",
		`{"id":"ok","created_at":"2020-01-01T00:00:00Z","created_by":"mallory","status":"APPROVED",
		  "description":"cilium agent","event_types":["BPF_LOAD","BPF_ATTACH"],"exe_path":"/usr/bin/cilium-agent",
		  "prog_hash":"AA93B500236FDE34","prog_type":5,"host_id":"host-a","action":"ALERT","enabled":false}`)
	if code != http.StatusOK {
		t.Fatalf("PUT: %d %s", code, body)
	}
	got := dashEntry(t, st, "ok")
	if got.Description != "cilium agent" || got.ExePath != "/usr/bin/cilium-agent" || len(got.EventTypes) != 2 ||
		got.ProgHash != "aa93b500236fde34" || got.ProgType == nil || *got.ProgType != 5 || got.HostID != "host-a" ||
		got.Action != event.ActionAlert || got.Enabled {
		t.Errorf("stored after PUT: %+v", got)
	}
	if got.CreatedBy != "alice" || got.CreatedAt.Year() != 2026 || got.Status != event.StatusApproved {
		t.Errorf("PUT changed server-owned fields: %+v", got)
	}
	var echoed event.AllowlistEntry
	if json.Unmarshal([]byte(body), &echoed) != nil || echoed.ID != "ok" || echoed.CreatedBy != "alice" {
		t.Errorf("PUT response: %s", body)
	}
	if rl.n() != 1 || st.updates != 1 {
		t.Errorf("reloads %d, updates %d; want 1, 1", rl.n(), st.updates)
	}

	for name, c := range map[string]struct {
		id, body string
		code     int
	}{
		"no action":           {"ok", `{"enabled":true}`, http.StatusBadRequest},
		"bad action":          {"ok", `{"action":"PERMIT","enabled":true}`, http.StatusBadRequest},
		"lower-case action":   {"ok", `{"action":"allow","enabled":true}`, http.StatusBadRequest},
		"unknown field":       {"ok", `{"action":"ALLOW","exe_pth":"/bin/x"}`, http.StatusBadRequest},
		"bad hash":            {"ok", `{"action":"ALLOW","exe_hash":"abc"}`, http.StatusBadRequest},
		"id mismatch":         {"ok", `{"id":"other","action":"ALLOW"}`, http.StatusBadRequest},
		"status change":       {"ok", `{"status":"REJECTED","action":"ALERT"}`, http.StatusBadRequest},
		"rejected made ALLOW": {"rej", `{"action":"ALLOW","enabled":true}`, http.StatusBadRequest},
		"pending":             {"pend", `{"action":"ALLOW","enabled":true}`, http.StatusConflict},
		"missing":             {"nope", `{"action":"ALLOW","enabled":true}`, http.StatusNotFound},
		"trailing data":       {"ok", `{"action":"ALLOW"} {}`, http.StatusBadRequest},
		"not JSON":            {"ok", `{`, http.StatusBadRequest},
	} {
		if code, body := polDo(t, h, http.MethodPut, "/api/v1/policies/"+c.id, c.body); code != c.code {
			t.Errorf("%s: %d %s, want %d", name, code, body, c.code)
		}
	}
	if rl.n() != 1 || st.updates != 1 {
		t.Errorf("refused PUTs wrote or reloaded: %d reloads, %d updates", rl.n(), st.updates)
	}

	// A REJECTED entry can be edited while it stays ALERT; its learned key
	// is kept.
	if code, body := polDo(t, h, http.MethodPut, "/api/v1/policies/rej", `{"description":"still alerting","action":"ALERT","enabled":true}`); code != http.StatusOK {
		t.Errorf("PUT rejected: %d %s", code, body)
	}
	if got := dashEntry(t, st, "rej"); got.Learned == nil || got.Learned.Key.Subject != "/opt/x.so" || got.Description != "still alerting" {
		t.Errorf("rejected after PUT: %+v", got)
	}
}

func TestPatchPolicy(t *testing.T) {
	st, rl := newPolStore(), &polReloader{}
	dashSeed(st)
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	st.entries[0].Expires = &exp
	h := polRouter(st, rl)

	if code, body := polDo(t, h, http.MethodPatch, "/api/v1/policies/ok", `{"enabled":false}`); code != http.StatusOK {
		t.Fatalf("disable: %d %s", code, body)
	}
	got := dashEntry(t, st, "ok")
	if got.Enabled || got.Description != "cilium" || got.ExePath != "/usr/bin/cilium*" || got.Action != event.ActionAllow ||
		got.Expires == nil || !got.Expires.Equal(exp) {
		t.Errorf("after disable, other fields changed: %+v", got)
	}
	if code, body := polDo(t, h, http.MethodPatch, "/api/v1/policies/ok", `{"enabled":true,"expires":null,"action":"DENY"}`); code != http.StatusOK {
		t.Fatalf("enable: %d %s", code, body)
	}
	if got := dashEntry(t, st, "ok"); !got.Enabled || got.Expires != nil || got.Action != event.ActionDeny {
		t.Errorf("after enable: %+v", got)
	}
	if rl.n() != 2 {
		t.Errorf("reloads: %d, want 2", rl.n())
	}

	for name, c := range map[string]struct {
		id, body string
		code     int
	}{
		"bad action":     {"ok", `{"action":"BOGUS"}`, http.StatusBadRequest},
		"no action":      {"ok", `{"action":""}`, http.StatusBadRequest},
		"status":         {"ok", `{"status":"PENDING"}`, http.StatusBadRequest},
		"id":             {"ok", `{"id":"x"}`, http.StatusBadRequest},
		"learned":        {"ok", `{"learned":null}`, http.StatusBadRequest},
		"created_by":     {"ok", `{"created_by":"x"}`, http.StatusBadRequest},
		"unknown":        {"ok", `{"enabeld":false}`, http.StatusBadRequest},
		"wrong type":     {"ok", `{"enabled":"no"}`, http.StatusBadRequest},
		"bad hash":       {"ok", `{"library_hash":"sha256:12"}`, http.StatusBadRequest},
		"empty":          {"ok", `{}`, http.StatusBadRequest},
		"null":           {"ok", `null`, http.StatusBadRequest},
		"array":          {"ok", `[]`, http.StatusBadRequest},
		"rejected ALLOW": {"rej", `{"action":"ALLOW"}`, http.StatusBadRequest},
		"pending":        {"pend", `{"enabled":false}`, http.StatusConflict},
		"missing":        {"nope", `{"enabled":false}`, http.StatusNotFound},
	} {
		if code, body := polDo(t, h, http.MethodPatch, "/api/v1/policies/"+c.id, c.body); code != c.code {
			t.Errorf("%s: %d %s, want %d", name, code, body, c.code)
		}
	}
	if rl.n() != 2 || st.updates != 2 {
		t.Errorf("refused PATCHes wrote or reloaded: %d reloads, %d updates", rl.n(), st.updates)
	}
	if code, _ := polDo(t, h, http.MethodPatch, "/api/v1/policies/rej", `{"enabled":false}`); code != http.StatusOK {
		t.Errorf("disable a rejected entry: %d", code)
	}
}

// A disabled entry stops matching as soon as the PATCH answers.
func TestPatchPolicy_DisableTakesEffect(t *testing.T) {
	st := newPolStore()
	st.entries = []*event.AllowlistEntry{{ID: "allow-tag", ProgHash: "a04f5eef06a7f555", Action: event.ActionAllow, Enabled: true, Status: event.StatusApproved}}
	engine := policy.NewEngine(zap.NewNop())
	engine.SetSource(st)
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := polRouter(st, engine)
	evt := &event.HookEvent{ID: "e", HostID: "host-a", EventType: event.EventBPFLoad, Severity: event.SeverityWarn, UID: 1000,
		ExeHash: "sha256:" + strings.Repeat("1", 64), BPFDetail: &event.BPFDetail{ProgType: 5, ProgHash: "a04f5eef06a7f555"}}
	if res := engine.Evaluate(evt); res.Action != event.ActionAllow {
		t.Fatalf("before: %s", res.Action)
	}
	if code, body := polDo(t, h, http.MethodPatch, "/api/v1/policies/allow-tag", `{"enabled":false}`); code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", code, body)
	}
	if res := engine.Evaluate(evt); res.Action == event.ActionAllow {
		t.Errorf("after disabling: %+v", res)
	}
}

func TestCreatePolicy_ActionAndFields(t *testing.T) {
	st := newPolStore()
	h := polRouter(st, nil)
	for name, b := range map[string]string{
		"no action":     `{"enabled":true}`,
		"bad action":    `{"action":"YES","enabled":true}`,
		"unknown field": `{"action":"ALLOW","exe_pth":"/bin/x"}`,
		"trailing data": `{"action":"ALLOW"}x`,
	} {
		if code, body := polDo(t, h, http.MethodPost, "/api/v1/policies", b); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, code, body)
		}
	}
	for _, a := range []string{"ALLOW", "ALERT", "DENY"} {
		if code, body := polDo(t, h, http.MethodPost, "/api/v1/policies", `{"action":"`+a+`","enabled":true}`); code != http.StatusCreated {
			t.Errorf("%s: %d %s", a, code, body)
		}
	}
	if len(st.entries) != 3 {
		t.Errorf("entries: %d, want 3", len(st.entries))
	}
	// A generated created_at is in UTC, not the server's local zone.
	for _, e := range st.entries {
		if e.CreatedAt.IsZero() || e.CreatedAt.Location() != time.UTC {
			t.Errorf("created_at %v (%v), want a UTC time", e.CreatedAt, e.CreatedAt.Location())
		}
	}
}

// TestCreatePolicy_DuplicateIDIs409: creating an entry with an ID that is
// taken is 409 with a JSON error naming the ID, and changes nothing. It
// used to be 500 "failed to create policy".
func TestCreatePolicy_DuplicateIDIs409(t *testing.T) {
	st, rl := newPolStore(), &polReloader{}
	h := polRouter(st, rl)
	first := `{"id":"dup","description":"first","action":"ALLOW","enabled":true}`
	if code, body := polDo(t, h, http.MethodPost, "/api/v1/policies", first); code != http.StatusCreated {
		t.Fatalf("first create: %d %s", code, body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
		strings.NewReader(`{"id":"dup","description":"second","action":"DENY","enabled":true}`))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var e struct {
		Error string `json:"error"`
	}
	if rec.Code != http.StatusConflict || rec.Header().Get("Content-Type") != "application/json" ||
		json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.Error != `an allowlist entry with id "dup" already exists` {
		t.Errorf("second create: %d %q %s, want 409 naming the ID", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
	if len(st.entries) != 1 || st.entries[0].Description != "first" || st.entries[0].Action != event.ActionAllow {
		t.Errorf("entries after the refused create: %+v", st.entries)
	}
	if rl.n() != 1 {
		t.Errorf("reloads: %d, want 1 (the refused create must not reload)", rl.n())
	}
}

// Every write refuses a body over MaxWriteBody with 413 and stores nothing.
func TestWrites_BodyLimit(t *testing.T) {
	st, rl := newPolStore(), &polReloader{}
	dashSeed(st)
	st.events = map[string]*event.HookEvent{"e1": {ID: "e1", HostID: "host-a", EventType: event.EventBPFLoad}}
	h := polRouter(st, rl)
	pad := strings.Repeat(" ", MaxWriteBody)
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/policies", `{"action":"ALLOW","description":"` + pad + `"}`},
		{http.MethodPut, "/api/v1/policies/ok", `{"action":"ALLOW","description":"` + pad + `"}`},
		{http.MethodPatch, "/api/v1/policies/ok", `{"description":"` + pad + `"}`},
		{http.MethodPost, "/api/v1/policies/pend/approve", `{"scope":"fleet"}` + pad + `x`},
		{http.MethodPut, "/api/v1/learning/fleet", `{"duration":"1h"}` + pad + `x`},
		{http.MethodPost, "/api/v1/events/e1/allowlist", `{"scope":"fleet","description":"` + pad + `"}`},
	} {
		if code, body := polDo(t, h, c.method, c.path, c.body); code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s %s: %d %.200s, want 413", c.method, c.path, code, body)
		}
	}
	if len(st.entries) != 3 || st.updates != 0 || len(st.decisions) != 0 || len(st.windows) != 0 || rl.n() != 0 {
		t.Errorf("oversized writes had an effect: %d entries, %d updates, %d decisions, %d windows, %d reloads",
			len(st.entries), st.updates, len(st.decisions), len(st.windows), rl.n())
	}
	// Just under the limit is fine.
	under := `{"action":"ALLOW","description":"` + strings.Repeat("d", MaxWriteBody-64) + `"}`
	if code, _ := polDo(t, h, http.MethodPost, "/api/v1/policies", under); code != http.StatusCreated {
		t.Errorf("body under the limit: %d", code)
	}
}

// List endpoints answer [] when there is nothing to list, never null.
func TestListEndpoints_EmptyIsArray(t *testing.T) {
	h := polRouter(newPolStore(), nil)
	for _, p := range []string{"/api/v1/events", "/api/v1/hosts", "/api/v1/policies", "/api/v1/policies?status=PENDING"} {
		code, body := polDo(t, h, http.MethodGet, p, "")
		if code != http.StatusOK || body != "[]\n" {
			t.Errorf("%s: %d %q, want 200 []", p, code, body)
		}
	}
	code, body := polDo(t, h, http.MethodGet, "/api/v1/learning", "")
	if code != http.StatusOK || !strings.Contains(body, `"windows":[]`) {
		t.Errorf("learning: %d %s", code, body)
	}
	code, body = polDo(t, h, http.MethodGet, "/api/v1/settings", "")
	if code != http.StatusOK || !strings.Contains(body, `"connectors":[]`) || !strings.Contains(body, `"tokens":[]`) ||
		!strings.Contains(body, `"allowed_origins":[]`) {
		t.Errorf("settings: %d %s", code, body)
	}
}

func TestAllowlistEvent(t *testing.T) {
	st := newPolStore()
	bpf := &event.HookEvent{ID: "e1", HostID: "host-a", Timestamp: time.Now().UTC(), EventType: event.EventBPFLoad,
		Severity: event.SeverityWarn, UID: 1000, ExePath: "/usr/bin/loader", ExeHash: "sha256:" + strings.Repeat("ab", 32),
		BPFDetail: &event.BPFDetail{ProgType: 5, ProgName: "hello", ProgHash: "a04f5eef06a7f555"}}
	st.events = map[string]*event.HookEvent{
		"e1":     bpf,
		"off":    {ID: "off", HostID: "host-a", EventType: event.EventAgentOffline},
		"nohost": {ID: "nohost", EventType: event.EventSHMCreate, SHMDetail: &event.SHMDetail{SHMName: "x", Pattern: "unknown"}},
	}
	engine := policy.NewEngine(zap.NewNop())
	engine.SetSource(st)
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := polRouter(st, engine)

	code, body := polDo(t, h, http.MethodPost, "/api/v1/events/e1/allowlist", `{"scope":"host"}`)
	if code != http.StatusCreated {
		t.Fatalf("host scope: %d %s", code, body)
	}
	var e event.AllowlistEntry
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatal(err)
	}
	if e.HostID != "host-a" || e.Action != event.ActionAllow || e.Status != event.StatusApproved || !e.Enabled ||
		e.Learned == nil || e.Learned.Key != allowlist.KeyOf(bpf) || len(e.EventTypes) != 3 ||
		!strings.Contains(e.Description, "from event e1") || !strings.Contains(e.Description, "a04f5eef06a7f555") {
		t.Errorf("entry: %+v", e)
	}

	// The engine now allows the same event on that host only, and not a
	// different program from the same binary.
	if res := engine.Evaluate(bpf); res.Action != event.ActionAllow || res.MatchedEntryID != e.ID {
		t.Errorf("same event: %+v", res)
	}
	other := *bpf
	other.HostID = "host-b"
	if res := engine.Evaluate(&other); res.Action == event.ActionAllow {
		t.Errorf("same event on another host: %+v", res)
	}
	changed := *bpf
	changed.BPFDetail = &event.BPFDetail{ProgType: 5, ProgName: "hello", ProgHash: "1111111111111111"}
	if res := engine.Evaluate(&changed); res.Action == event.ActionAllow {
		t.Errorf("another program: %+v", res)
	}

	if code, body := polDo(t, h, http.MethodPost, "/api/v1/events/e1/allowlist", `{"scope":"host","host_id":"host-a"}`); code != http.StatusConflict ||
		!strings.Contains(body, e.ID) {
		t.Errorf("duplicate: %d %s", code, body)
	}
	code, body = polDo(t, h, http.MethodPost, "/api/v1/events/e1/allowlist", `{"scope":"fleet","description":"loader is fine"}`)
	if code != http.StatusCreated {
		t.Fatalf("fleet scope: %d %s", code, body)
	}
	var f event.AllowlistEntry
	json.Unmarshal([]byte(body), &f)
	if f.HostID != "" || f.Description != "loader is fine" {
		t.Errorf("fleet entry: %+v", f)
	}
	if res := engine.Evaluate(&other); res.Action != event.ActionAllow {
		t.Errorf("fleet entry, other host: %+v", res)
	}

	for name, c := range map[string]struct {
		path, body string
		code       int
	}{
		"no scope":        {"/api/v1/events/e1/allowlist", `{}`, http.StatusBadRequest},
		"bad scope":       {"/api/v1/events/e1/allowlist", `{"scope":"world"}`, http.StatusBadRequest},
		"other host":      {"/api/v1/events/e1/allowlist", `{"scope":"host","host_id":"host-b"}`, http.StatusBadRequest},
		"fleet with host": {"/api/v1/events/e1/allowlist", `{"scope":"fleet","host_id":"host-a"}`, http.StatusBadRequest},
		"unknown field":   {"/api/v1/events/e1/allowlist", `{"scope":"fleet","action":"DENY"}`, http.StatusBadRequest},
		"offline event":   {"/api/v1/events/off/allowlist", `{"scope":"fleet"}`, http.StatusBadRequest},
		"no host":         {"/api/v1/events/nohost/allowlist", `{"scope":"host"}`, http.StatusBadRequest},
		"missing event":   {"/api/v1/events/nope/allowlist", `{"scope":"fleet"}`, http.StatusNotFound},
	} {
		if code, body := polDo(t, h, http.MethodPost, c.path, c.body); code != c.code {
			t.Errorf("%s: %d %s, want %d", name, code, body, c.code)
		}
	}
	if len(st.entries) != 2 {
		t.Errorf("entries: %d, want 2", len(st.entries))
	}
}

// TestAllowlistEvent_DecidesPendingEntry: allowlisting an event whose key
// has a PENDING entry (a new hook's first sighting) decides that entry, for
// the fleet or the event's host, instead of creating a second entry. The
// Postgres test TestAPI_RealStore_AllowlistEventDecidesPending checks what
// the store then holds.
func TestAllowlistEvent_DecidesPendingEntry(t *testing.T) {
	st := newPolStore()
	bpf := &event.HookEvent{ID: "e1", HostID: "host-a", Timestamp: time.Now().UTC(), EventType: event.EventBPFLoad,
		Severity: event.SeverityWarn, UID: 1000, ExePath: "/usr/bin/loader", ExeHash: "sha256:" + strings.Repeat("ab", 32),
		BPFDetail: &event.BPFDetail{ProgType: 5, ProgName: "hello", ProgHash: "a04f5eef06a7f555"}}
	st.events = map[string]*event.HookEvent{"e1": bpf}
	st.entries = []*event.AllowlistEntry{
		{ID: "other", Action: event.ActionAlert, Enabled: true, Status: event.StatusPending,
			Learned: &event.Learned{Key: event.LearnedKey{SubjectKind: allowlist.SubjectDlopen, Subject: "/opt/x.so"}, Hosts: []string{"host-a"}}},
		{ID: "pend", Action: event.ActionAlert, Enabled: true, Status: event.StatusPending,
			Learned: &event.Learned{Key: allowlist.KeyOf(bpf), Hosts: []string{"host-a", "host-b"}, FirstEventID: "e1"}},
	}
	rl := &polReloader{}
	h := polRouter(st, rl)

	for _, c := range []struct{ body, want string }{
		{`{"scope":"host"}`, `pend APPROVED "host-a"`},
		{`{"scope":"fleet"}`, `pend APPROVED ""`},
	} {
		st.decisions = nil
		code, body := polDo(t, h, http.MethodPost, "/api/v1/events/e1/allowlist", c.body)
		if code != http.StatusCreated {
			t.Fatalf("%s: %d %s", c.body, code, body)
		}
		if got := strings.Join(st.decisions, "; "); got != c.want {
			t.Errorf("%s: decisions %q, want %q", c.body, got, c.want)
		}
		var e event.AllowlistEntry
		if err := json.Unmarshal([]byte(body), &e); err != nil || e.ID != "pend" || e.Status != event.StatusApproved {
			t.Errorf("%s: answered %+v (%v), want the decided entry", c.body, e, err)
		}
	}
	if len(st.entries) != 2 {
		t.Errorf("entries: %d, want 2 (no second entry for the key)", len(st.entries))
	}
	if rl.n() != 2 {
		t.Errorf("reloads: %d, want 2", rl.n())
	}
}

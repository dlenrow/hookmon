package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/policy"
	"github.com/dlenrow/hookmon/server/store"
)

// polStore is an in-memory Store, and a policy.Source over the same data.
type polStore struct {
	mu        sync.Mutex
	entries   []*event.AllowlistEntry
	windows   map[string]event.LearningWindow
	hosts     map[string]*event.Host
	queried   [][]event.EntryStatus
	decisions []string
	bulk      []string
	decideErr error
	events    map[string]*event.HookEvent
	updates   int
}

func newPolStore() *polStore {
	return &polStore{windows: map[string]event.LearningWindow{}, hosts: map[string]*event.Host{"host-a": {ID: "host-a"}}}
}

func (s *polStore) InsertEvent(context.Context, *event.HookEvent) error { return nil }
func (s *polStore) QueryEvents(context.Context, store.EventFilter) ([]*event.HookEvent, error) {
	return nil, nil
}
func (s *polStore) GetEvent(_ context.Context, id string) (*event.HookEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.events[id]; ok {
		return e, nil
	}
	return nil, store.ErrNotFound
}

func (s *polStore) GetAllowlistEntry(_ context.Context, id string) (*event.AllowlistEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.ID == id {
			c := *e
			return &c, nil
		}
	}
	return nil, fmt.Errorf("allowlist entry %s: %w", id, store.ErrNotFound)
}

// UpdateAllowlistEntry writes the editable fields, as the real store does.
func (s *polStore) UpdateAllowlistEntry(_ context.Context, e *event.AllowlistEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, cur := range s.entries {
		if cur.ID != e.ID {
			continue
		}
		if cur.Status == event.StatusPending {
			return fmt.Errorf("allowlist entry %s: %w", e.ID, store.ErrPending)
		}
		c := *e
		c.CreatedAt, c.CreatedBy, c.Status, c.Learned = cur.CreatedAt, cur.CreatedBy, cur.Status, cur.Learned
		s.entries[i] = &c
		s.updates++
		return nil
	}
	return fmt.Errorf("allowlist entry %s: %w", e.ID, store.ErrNotFound)
}
func (s *polStore) GetHosts(context.Context) ([]*event.Host, error) { return nil, nil }
func (s *polStore) GetHost(_ context.Context, id string) (*event.Host, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.hosts[id]; ok {
		return h, nil
	}
	return nil, fmt.Errorf("host %s: %w", id, store.ErrNotFound)
}

func (s *polStore) QueryAllowlist(_ context.Context, statuses ...event.EntryStatus) ([]*event.AllowlistEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queried = append(s.queried, statuses)
	var out []*event.AllowlistEntry
	for _, e := range s.entries {
		if len(statuses) == 0 {
			out = append(out, e)
			continue
		}
		for _, st := range statuses {
			if e.Status == st {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (s *polStore) GetDecidedAllowlist(ctx context.Context) ([]*event.AllowlistEntry, error) {
	return s.QueryAllowlist(ctx, event.StatusApproved, event.StatusRejected)
}

// CreateAllowlistEntry refuses an ID that is taken, as the real store does.
func (s *polStore) CreateAllowlistEntry(_ context.Context, e *event.AllowlistEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cur := range s.entries {
		if cur.ID == e.ID {
			return fmt.Errorf("allowlist entry %s: %w", e.ID, store.ErrConflict)
		}
	}
	c := *e
	s.entries = append(s.entries, &c)
	return nil
}

func (s *polStore) DeleteAllowlistEntry(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.entries {
		if e.ID == id {
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("allowlist entry %s: %w", id, store.ErrNotFound)
}

func (s *polStore) DecideCandidate(_ context.Context, id string, decision event.EntryStatus, hostID string) (*event.AllowlistEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decisions = append(s.decisions, fmt.Sprintf("%s %s %q", id, decision, hostID))
	if s.decideErr != nil {
		return nil, s.decideErr
	}
	return &event.AllowlistEntry{ID: id, Status: decision, HostID: hostID}, nil
}

// DecideCandidates decides the PENDING entries among s.entries, as the
// store does for the fleet: unknown IDs and decided entries fail alone.
func (s *polStore) DecideCandidates(_ context.Context, ids []string, decision event.EntryStatus, scope string) ([]store.CandidateDecision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bulk = append(s.bulk, fmt.Sprintf("%v %s %s", ids, decision, scope))
	if s.decideErr != nil {
		return nil, s.decideErr
	}
	out := make([]store.CandidateDecision, 0, len(ids))
	for _, id := range ids {
		d := store.CandidateDecision{ID: id}
		var found *event.AllowlistEntry
		for _, e := range s.entries {
			if e.ID == id {
				found = e
			}
		}
		switch {
		case found == nil:
			d.Err = fmt.Errorf("allowlist entry %s: %w", id, store.ErrNotFound)
		case found.Status != event.StatusPending:
			d.Err = fmt.Errorf("allowlist entry %s is %s: %w", id, found.Status, store.ErrNotPending)
		default:
			found.Status = decision
			c := *found
			d.Entries = []*event.AllowlistEntry{&c}
		}
		out = append(out, d)
	}
	return out, nil
}

func (s *polStore) GetLearningWindows(context.Context) ([]event.LearningWindow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []event.LearningWindow
	for _, w := range s.windows {
		out = append(out, w)
	}
	return out, nil
}

func (s *polStore) SetLearningWindow(_ context.Context, w event.LearningWindow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.windows[w.HostID] = w
	return nil
}

func (s *polStore) DeleteLearningWindow(_ context.Context, hostID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.windows[hostID]; !ok {
		return fmt.Errorf("learning window: %w", store.ErrNotFound)
	}
	delete(s.windows, hostID)
	return nil
}

// polReloader counts reloads and can fail.
type polReloader struct {
	mu    sync.Mutex
	count int
	err   error
}

func (r *polReloader) Reload(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	return r.err
}

func (r *polReloader) n() int { r.mu.Lock(); defer r.mu.Unlock(); return r.count }

func polRouter(st Store, rl PolicyReloader) http.Handler {
	s := NewServer(st, zap.NewNop(), nil)
	if rl != nil {
		s.SetPolicyReloader(rl)
	}
	return s.Router([]string{"tok"}, nil)
}

func polDo(t *testing.T, h http.Handler, method, target, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestCreatePolicy_NormalizesValidatesAndReloads(t *testing.T) {
	st, rl := newPolStore(), &polReloader{}
	h := polRouter(st, rl)
	hex := strings.Repeat("AB", 32)

	code, body := polDo(t, h, http.MethodPost, "/api/v1/policies",
		`{"exe_hash":"`+hex+`","prog_hash":"A04F5EEF06A7F555","prog_type":5,"host_id":"host-a","action":"ALLOW","enabled":true}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	got := st.entries[0]
	if got.ExeHash != "sha256:"+strings.ToLower(hex) || got.ProgHash != "a04f5eef06a7f555" ||
		got.Status != event.StatusApproved || got.HostID != "host-a" || got.ProgType == nil || *got.ProgType != 5 {
		t.Errorf("stored entry: %+v", got)
	}
	if rl.n() != 1 {
		t.Errorf("reloads after create: %d, want 1", rl.n())
	}

	for name, b := range map[string]string{
		"bad exe hash":        `{"exe_hash":"sha256:abc","action":"ALLOW","enabled":true}`,
		"sha256 prog hash":    `{"prog_hash":"sha256:` + strings.Repeat("ab", 32) + `","action":"ALLOW","enabled":true}`,
		"PENDING status":      `{"status":"PENDING","action":"ALLOW","enabled":true}`,
		"learned set by hand": `{"learned":{"key":{"event_type":"DLOPEN"}},"action":"ALLOW","enabled":true}`,
		"not JSON":            `{`,
	} {
		if code, body := polDo(t, h, http.MethodPost, "/api/v1/policies", b); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, code, body)
		}
	}
	if len(st.entries) != 1 || rl.n() != 1 {
		t.Errorf("rejected writes stored or reloaded: %d entries, %d reloads", len(st.entries), rl.n())
	}

	if code, _ := polDo(t, h, http.MethodDelete, "/api/v1/policies/"+got.ID, ""); code != http.StatusNoContent {
		t.Errorf("delete: %d", code)
	}
	if code, _ := polDo(t, h, http.MethodDelete, "/api/v1/policies/nope", ""); code != http.StatusNotFound {
		t.Errorf("delete missing: %d, want 404", code)
	}
	if rl.n() != 2 {
		t.Errorf("reloads after delete: %d, want 2", rl.n())
	}

	// A reload that fails is reported, not hidden.
	rl.err = errors.New("db down")
	if code, body := polDo(t, h, http.MethodPost, "/api/v1/policies", `{"action":"ALLOW","enabled":true}`); code != http.StatusInternalServerError ||
		!strings.Contains(body, "reloading the policy failed") {
		t.Errorf("failed reload: %d %s", code, body)
	}
}

func TestListPolicies_StatusFilter(t *testing.T) {
	st := newPolStore()
	h := polRouter(st, nil)
	cases := []struct {
		query string
		code  int
		want  []event.EntryStatus
	}{
		{"", http.StatusOK, []event.EntryStatus{event.StatusApproved, event.StatusRejected}},
		{"?status=PENDING", http.StatusOK, []event.EntryStatus{event.StatusPending}},
		{"?status=pending,rejected", http.StatusOK, []event.EntryStatus{event.StatusPending, event.StatusRejected}},
		{"?status=ALL", http.StatusOK, nil},
		{"?status=bogus", http.StatusBadRequest, nil},
	}
	for _, c := range cases {
		st.queried = nil
		code, body := polDo(t, h, http.MethodGet, "/api/v1/policies"+c.query, "")
		if code != c.code {
			t.Errorf("%q: %d %s", c.query, code, body)
			continue
		}
		if code != http.StatusOK {
			continue
		}
		if body != "[]\n" {
			t.Errorf("%q: empty list encoded as %q, want []", c.query, body)
		}
		if len(st.queried) != 1 || fmt.Sprint(st.queried[0]) != fmt.Sprint(c.want) {
			t.Errorf("%q: queried %v, want %v", c.query, st.queried, c.want)
		}
	}
}

func TestDecide_ScopesAndErrors(t *testing.T) {
	st, rl := newPolStore(), &polReloader{}
	h := polRouter(st, rl)

	ok := []struct{ path, body, want string }{
		{"/api/v1/policies/p1/approve", `{"scope":"fleet"}`, `p1 APPROVED ""`},
		{"/api/v1/policies/p1/approve", `{"scope":"host","host_id":"host-a"}`, `p1 APPROVED "host-a"`},
		{"/api/v1/policies/p2/reject", `{"scope":"fleet"}`, `p2 REJECTED ""`},
		{"/api/v1/policies/p2/reject", `{"scope":"host","host_id":"host-a"}`, `p2 REJECTED "host-a"`},
	}
	for _, c := range ok {
		if code, body := polDo(t, h, http.MethodPost, c.path, c.body); code != http.StatusOK {
			t.Errorf("%s %s: %d %s", c.path, c.body, code, body)
		}
	}
	if got := strings.Join(st.decisions, "; "); got != `p1 APPROVED ""; p1 APPROVED "host-a"; p2 REJECTED ""; p2 REJECTED "host-a"` {
		t.Errorf("decisions: %s", got)
	}
	if rl.n() != 4 {
		t.Errorf("reloads: %d, want 4", rl.n())
	}

	bad := []struct {
		body string
		code int
	}{
		{`{}`, http.StatusBadRequest},
		{`{"scope":"host"}`, http.StatusBadRequest},
		{`{"scope":"fleet","host_id":"host-a"}`, http.StatusBadRequest},
		{`{"scope":"host","host_id":"no-such-host"}`, http.StatusNotFound},
		{`nope`, http.StatusBadRequest},
	}
	for _, c := range bad {
		if code, body := polDo(t, h, http.MethodPost, "/api/v1/policies/p1/approve", c.body); code != c.code {
			t.Errorf("approve %s: %d %s, want %d", c.body, code, body, c.code)
		}
	}
	st.decideErr = fmt.Errorf("x: %w", store.ErrNotPending)
	if code, _ := polDo(t, h, http.MethodPost, "/api/v1/policies/p1/approve", `{"scope":"fleet"}`); code != http.StatusConflict {
		t.Errorf("not pending: %d, want 409", code)
	}
	st.decideErr = fmt.Errorf("x: %w", store.ErrNotFound)
	if code, _ := polDo(t, h, http.MethodPost, "/api/v1/policies/p1/reject", `{"scope":"fleet"}`); code != http.StatusNotFound {
		t.Errorf("missing: %d, want 404", code)
	}
	if rl.n() != 4 {
		t.Errorf("failed decisions reloaded the policy: %d reloads", rl.n())
	}
}

func TestLearningAPI(t *testing.T) {
	st, rl := newPolStore(), &polReloader{}
	h := polRouter(st, rl)

	before := time.Now()
	code, body := polDo(t, h, http.MethodPut, "/api/v1/learning/fleet", `{"duration":"7d"}`)
	if code != http.StatusOK {
		t.Fatalf("start fleet: %d %s", code, body)
	}
	var v learningView
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	if v.Scope != "fleet" || !v.Active || v.EndsAt.Before(before.Add(7*24*time.Hour-time.Minute)) || v.StartedBy != "api" {
		t.Errorf("fleet window: %+v", v)
	}
	end := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if code, body := polDo(t, h, http.MethodPut, "/api/v1/learning/hosts/host-a", `{"ends_at":"`+end.Format(time.RFC3339)+`"}`); code != http.StatusOK {
		t.Fatalf("start host: %d %s", code, body)
	}
	if w := st.windows["host-a"]; !w.EndsAt.Equal(end) {
		t.Errorf("host window ends %v, want %v", w.EndsAt, end)
	}
	if rl.n() != 2 {
		t.Errorf("reloads: %d, want 2", rl.n())
	}

	for name, c := range map[string]struct {
		path, body string
		code       int
	}{
		"unknown host": {"/api/v1/learning/hosts/nope", `{"duration":"1h"}`, http.StatusNotFound},
		"no end":       {"/api/v1/learning/fleet", `{}`, http.StatusBadRequest},
		"both ends":    {"/api/v1/learning/fleet", `{"duration":"1h","ends_at":"` + end.Format(time.RFC3339) + `"}`, http.StatusBadRequest},
		"end in past":  {"/api/v1/learning/fleet", `{"ends_at":"2020-01-01T00:00:00Z"}`, http.StatusBadRequest},
		"bad duration": {"/api/v1/learning/fleet", `{"duration":"soon"}`, http.StatusBadRequest},
		"negative":     {"/api/v1/learning/fleet", `{"duration":"-1h"}`, http.StatusBadRequest},
		"not JSON":     {"/api/v1/learning/fleet", `x`, http.StatusBadRequest},
	} {
		if code, body := polDo(t, h, http.MethodPut, c.path, c.body); code != c.code {
			t.Errorf("%s: %d %s, want %d", name, code, body, c.code)
		}
	}

	code, body = polDo(t, h, http.MethodGet, "/api/v1/learning", "")
	var got struct {
		Windows []learningView `json:"windows"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &got) != nil || len(got.Windows) != 2 {
		t.Fatalf("GET learning: %d %s", code, body)
	}

	if code, _ := polDo(t, h, http.MethodDelete, "/api/v1/learning/hosts/host-a", ""); code != http.StatusNoContent {
		t.Errorf("stop host: %d", code)
	}
	if code, _ := polDo(t, h, http.MethodDelete, "/api/v1/learning/fleet", ""); code != http.StatusNoContent {
		t.Errorf("stop fleet: %d", code)
	}
	if code, _ := polDo(t, h, http.MethodDelete, "/api/v1/learning/fleet", ""); code != http.StatusNotFound {
		t.Errorf("stop fleet again: %d, want 404", code)
	}
	if rl.n() != 4 {
		t.Errorf("reloads: %d, want 4", rl.n())
	}
}

func TestParseLearningDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "90m": 90 * time.Minute, "36h": 36 * time.Hour, "1h30m": 90 * time.Minute} {
		if got, err := ParseLearningDuration(in); err != nil || got != want {
			t.Errorf("%s: %v %v, want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "d", "1.5d", "0", "0d", "-2h", "week"} {
		if _, err := ParseLearningDuration(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// TestPolicyChangeTakesEffectWithin1s measures how long a policy change
// through the API takes to reach the policy engine the server uses: from
// the start of the POST to the first event evaluated under the new entry.
// The API reloads the engine before it answers, so the next event is
// already decided by the new entry. The Postgres integration test
// (TestIntegration_PolicyChangeWithin1s) measures the same over TLS with
// the real store.
func TestPolicyChangeTakesEffectWithin1s(t *testing.T) {
	st := newPolStore()
	engine := policy.NewEngine(zap.NewNop())
	engine.SetSource(st)
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := polRouter(st, engine)
	evt := func() *event.HookEvent {
		return &event.HookEvent{ID: "e", HostID: "host-a", EventType: event.EventBPFLoad, Severity: event.SeverityWarn, UID: 1000,
			ExeHash: "sha256:" + strings.Repeat("1", 64), BPFDetail: &event.BPFDetail{ProgType: 5, ProgHash: "a04f5eef06a7f555"}}
	}
	if res := engine.Evaluate(evt()); res.Action != event.ActionAlert {
		t.Fatalf("before: %s", res.Action)
	}

	start := time.Now()
	code, body := polDo(t, h, http.MethodPost, "/api/v1/policies",
		`{"id":"allow-tag","prog_hash":"a04f5eef06a7f555","prog_type":5,"action":"ALLOW","enabled":true}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	res := engine.Evaluate(evt())
	elapsed := time.Since(start)
	if res.Action != event.ActionAllow || res.MatchedEntryID != "allow-tag" {
		t.Fatalf("first event after the POST: %+v", res)
	}
	t.Logf("policy change in effect %v after the POST started", elapsed)
	if elapsed > time.Second {
		t.Errorf("policy change took %v, want under 1s", elapsed)
	}

	start = time.Now()
	if code, _ := polDo(t, h, http.MethodDelete, "/api/v1/policies/allow-tag", ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if res := engine.Evaluate(evt()); res.Action != event.ActionAlert || time.Since(start) > time.Second {
		t.Errorf("after delete: %s in %v", res.Action, time.Since(start))
	}
}

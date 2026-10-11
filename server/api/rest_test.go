package api

// REST handlers and error paths the other tests leave out (fix plan step
// 7h): token checks, the event list's query parameters, the host list,
// settings, and every write and list answering 500, without the store's
// error text, when the store fails.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/store"
)

// t7hEventStore records the filter of each event query and answers with
// events or an error.
type t7hEventStore struct {
	*polStore
	mu      sync.Mutex
	filters []store.EventFilter
	result  []*event.HookEvent
	err     error
	hosts   []*event.Host
}

func (s *t7hEventStore) QueryEvents(_ context.Context, f store.EventFilter) ([]*event.HookEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filters = append(s.filters, f)
	return s.result, s.err
}

func (s *t7hEventStore) GetHosts(context.Context) ([]*event.Host, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hosts, s.err
}

func (s *t7hEventStore) lastFilter(t *testing.T) store.EventFilter {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.filters) == 0 {
		t.Fatal("QueryEvents was not called")
	}
	return s.filters[len(s.filters)-1]
}

// t7hDBDown is the error t7hBrokenStore returns from every call.
var t7hDBDown = errors.New("pq: t7h-secret-detail: connection reset")

// t7hBrokenStore fails every call except GetHost (so host-scoped requests
// reach the call under test) and GetAllowlistEntry (so edits reach the
// write).
type t7hBrokenStore struct {
	*polStore
}

func (t7hBrokenStore) QueryEvents(context.Context, store.EventFilter) ([]*event.HookEvent, error) {
	return nil, t7hDBDown
}
func (t7hBrokenStore) GetHosts(context.Context) ([]*event.Host, error) { return nil, t7hDBDown }
func (t7hBrokenStore) QueryAllowlist(context.Context, ...event.EntryStatus) ([]*event.AllowlistEntry, error) {
	return nil, t7hDBDown
}
func (t7hBrokenStore) CreateAllowlistEntry(context.Context, *event.AllowlistEntry) error {
	return t7hDBDown
}
func (t7hBrokenStore) UpdateAllowlistEntry(context.Context, *event.AllowlistEntry) error {
	return t7hDBDown
}
func (t7hBrokenStore) DeleteAllowlistEntry(context.Context, string) error { return t7hDBDown }
func (t7hBrokenStore) DecideCandidate(context.Context, string, event.EntryStatus, string) (*event.AllowlistEntry, error) {
	return nil, t7hDBDown
}
func (t7hBrokenStore) GetLearningWindows(context.Context) ([]event.LearningWindow, error) {
	return nil, t7hDBDown
}
func (t7hBrokenStore) SetLearningWindow(context.Context, event.LearningWindow) error {
	return t7hDBDown
}
func (t7hBrokenStore) DeleteLearningWindow(context.Context, string) error { return t7hDBDown }

// TestAuth_Tokens: every API route but health needs a configured token.
func TestAuth_Tokens(t *testing.T) {
	h := NewServer(newPolStore(), zap.NewNop(), nil).Router([]string{"tok-1", "tok-2"}, nil)
	for _, c := range []struct {
		name, header string
		code         int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"prefix of a token", "Bearer tok-", http.StatusUnauthorized},
		{"token with a suffix", "Bearer tok-1x", http.StatusUnauthorized},
		{"basic auth", "Basic dG9rLTE=", http.StatusUnauthorized},
		{"empty bearer", "Bearer ", http.StatusUnauthorized},
		{"first token", "Bearer tok-1", http.StatusOK},
		{"second token", "Bearer tok-2", http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
		if c.header != "" {
			req.Header.Set("Authorization", c.header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.code {
			t.Errorf("%s: status %d, want %d (%s)", c.name, rec.Code, c.code, rec.Body)
		}
		if c.code == http.StatusUnauthorized && !strings.Contains(rec.Body.String(), `"error"`) {
			t.Errorf("%s: body %q is not a JSON error", c.name, rec.Body)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: Content-Type %q, want application/json", c.name, ct)
		}
	}

	// Health needs no token; with no tokens configured nothing else opens.
	none := NewServer(newPolStore(), zap.NewNop(), nil).Router(nil, nil)
	if code, _ := polDo(t, none, http.MethodGet, "/api/v1/health", ""); code != http.StatusOK {
		t.Errorf("health: %d", code)
	}
	if code, _ := polDo(t, none, http.MethodGet, "/api/v1/hosts", ""); code != http.StatusUnauthorized {
		t.Errorf("no tokens configured: %d, want 401", code)
	}
}

// TestAuth_EmptyTokenNeverAuthenticates: an empty or whitespace-only token
// in the configuration is dropped, and an empty bearer token is refused,
// on REST and on the WebSocket. Before, NewAuthMiddleware stored "" from
// --api-tokens "x," and "Authorization: Bearer " (kept as sent over
// HTTP/2) got 200.
func TestAuth_EmptyTokenNeverAuthenticates(t *testing.T) {
	m := NewAuthMiddleware([]string{"tok", "", "   ", "\t"})
	if len(m.tokens) != 1 || !m.tokens["tok"] {
		t.Errorf("stored tokens %v, want only \"tok\"", m.tokens)
	}
	for _, tok := range []string{"", " ", "   ", "\t"} {
		if m.validateToken(tok) {
			t.Errorf("validateToken(%q) = true", tok)
		}
	}
	if !m.validateToken("tok") {
		t.Error(`validateToken("tok") = false`)
	}
	// Even a middleware whose map somehow held "" refuses an empty token.
	forced := &AuthMiddleware{tokens: map[string]bool{"": true, " ": true}}
	if forced.validateToken("") || forced.validateToken(" ") {
		t.Error("validateToken accepted an empty token that was in the map")
	}

	s := NewServer(newPolStore(), zap.NewNop(), NewHub(4))
	h := s.Router([]string{"tok", "", "  "}, nil)
	for _, c := range []struct {
		name, path, header string
		code               int
	}{
		{"REST, empty bearer", "/api/v1/hosts", "Bearer ", http.StatusUnauthorized},
		{"REST, spaces after Bearer", "/api/v1/hosts", "Bearer   ", http.StatusUnauthorized},
		{"REST, bare space", "/api/v1/hosts", " ", http.StatusUnauthorized},
		{"REST, good token", "/api/v1/hosts", "Bearer tok", http.StatusOK},
		{"WebSocket, empty bearer", "/api/v1/ws/events", "Bearer ", http.StatusUnauthorized},
		{"WebSocket, spaces after Bearer", "/api/v1/ws/events", "Bearer   ", http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		req.Header.Set("Authorization", c.header)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.code {
			t.Errorf("%s: status %d, want %d (%s)", c.name, rec.Code, c.code, rec.Body)
		}
		if c.code == http.StatusUnauthorized && rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: Content-Type %q", c.name, rec.Header().Get("Content-Type"))
		}
	}

	// The WebSocket's subprotocol form, with an empty token encoded.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ws/events", nil)
	req.Header.Set("Sec-WebSocket-Protocol", WSProtocol+", "+WSTokenProtocolPrefix)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("WebSocket, empty subprotocol token: status %d (%s)", rec.Code, rec.Body)
	}
}

// TestListEvents_QueryParameters: each query parameter reaches the store
// filter; a malformed value is a 400 naming the parameter, and the store is
// not queried. (These used to be ignored: a bad since or until returned
// events outside the range asked for, and a bad limit or offset became the
// default.)
func TestListEvents_QueryParameters(t *testing.T) {
	st := &t7hEventStore{polStore: newPolStore(), result: []*event.HookEvent{{ID: "e1", EventType: event.EventBPFLoad}}}
	h := polRouter(st, nil)

	code, body := polDo(t, h, http.MethodGet,
		"/api/v1/events?limit=5&offset=10&host_id=h-1&event_type=BPF_LOAD&severity=ALERT&since=2026-01-02T03:04:05Z&until=2026-02-03T04:05:06%2B02:00", "")
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var got []event.HookEvent
	if err := json.Unmarshal([]byte(body), &got); err != nil || len(got) != 1 || got[0].ID != "e1" {
		t.Errorf("body %s (%v)", body, err)
	}
	f := st.lastFilter(t)
	since := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	until := time.Date(2026, 2, 3, 2, 5, 6, 0, time.UTC)
	if f.Limit != 5 || f.Offset != 10 || f.HostID != "h-1" ||
		f.EventType == nil || *f.EventType != event.EventBPFLoad ||
		f.Severity == nil || *f.Severity != event.SeverityAlert ||
		f.Since == nil || !f.Since.Equal(since) || f.Until == nil || !f.Until.Equal(until) {
		t.Errorf("filter %+v", f)
	}

	// Absent or empty parameters are the defaults.
	for _, q := range []string{"", "?limit=&offset=&since=&until="} {
		if code, body := polDo(t, h, http.MethodGet, "/api/v1/events"+q, ""); code != http.StatusOK {
			t.Fatalf("%q: %d %s", q, code, body)
		}
		f := st.lastFilter(t)
		if !reflect.DeepEqual(f, store.EventFilter{Limit: 100}) {
			t.Errorf("%q: filter %+v, want the defaults", q, f)
		}
	}

	// Malformed values are refused, each with its parameter named.
	st.mu.Lock()
	queries := len(st.filters)
	st.mu.Unlock()
	for q, param := range map[string]string{
		"?limit=abc":                       "limit",
		"?limit=-1":                        "limit",
		"?limit=1.5":                       "limit",
		"?limit=99999999999999999999":      "limit",
		"?offset=-3":                       "offset",
		"?offset=ten":                      "offset",
		"?since=yesterday":                 "since",
		"?since=2026-10-11":                "since",
		"?since=2026-10-11T02:58:00+00:00": "since", // the + decodes to a space
		"?until=2026-13-01T00:00:00Z":      "until",
		"?until=1760000000":                "until",
		"?limit=5&since=2026-01-02T03:04:05Z&until=x": "until",
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/events"+q, nil)
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var e struct {
			Error string `json:"error"`
		}
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Content-Type") != "application/json" ||
			json.Unmarshal(rec.Body.Bytes(), &e) != nil || !strings.HasPrefix(e.Error, param+" must be") {
			t.Errorf("%s: %d %q %s, want 400 with an error naming %s", q, rec.Code, rec.Header().Get("Content-Type"), rec.Body, param)
		}
	}
	if _, body := polDo(t, h, http.MethodGet, "/api/v1/events?since=2026-10-11T02:58:00+00:00", ""); !strings.Contains(body, "%2B") {
		t.Errorf("a + turned into a space: the error does not say to write %%2B: %s", body)
	}
	st.mu.Lock()
	if len(st.filters) != queries {
		t.Errorf("the store was queried %d times for refused requests", len(st.filters)-queries)
	}
	st.mu.Unlock()

	// Zero is a valid limit and offset: the store reads limit 0 as 100.
	if code, body := polDo(t, h, http.MethodGet, "/api/v1/events?limit=0&offset=0", ""); code != http.StatusOK {
		t.Errorf("limit=0&offset=0: %d %s", code, body)
	}

	// No events is [], not null.
	st.result = nil
	if _, body := polDo(t, h, http.MethodGet, "/api/v1/events?host_id=none", ""); body != "[]\n" {
		t.Errorf("no events: %q", body)
	}
}

// TestListHosts: the host list as the store returns it.
func TestListHosts(t *testing.T) {
	seen := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	st := &t7hEventStore{polStore: newPolStore(), hosts: []*event.Host{
		{ID: "h-1", Hostname: "alpha", Status: event.HostOnline, LastHeartbeat: seen,
			Sensors: []event.SensorHealth{{Name: "bpf_syscall", Status: "alive"}}},
		{ID: "h-2", Hostname: "beta", Status: event.HostUnresponsive},
	}}
	code, body := polDo(t, polRouter(st, nil), http.MethodGet, "/api/v1/hosts", "")
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var got []*event.Host
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Hostname != "alpha" || got[1].Status != event.HostUnresponsive ||
		len(got[0].Sensors) != 1 || got[0].Sensors[0].Name != "bpf_syscall" || !got[0].LastHeartbeat.Equal(seen) {
		t.Errorf("hosts %s", body)
	}
}

// TestStoreFailures_Are500: when the store fails, every list and write
// answers 500 with a generic message, never the store's error text, and
// the policy is not reloaded.
func TestStoreFailures_Are500(t *testing.T) {
	st := t7hBrokenStore{newPolStore()}
	st.entries = []*event.AllowlistEntry{{ID: "e1", Action: event.ActionAllow, Enabled: true, Status: event.StatusApproved, EventTypes: []event.EventType{event.EventBPFLoad}}}
	st.windows[""] = event.LearningWindow{EndsAt: time.Now().Add(time.Hour)}
	rl := &polReloader{}
	h := polRouter(st, rl)
	entry := `{"description":"x","event_types":["BPF_LOAD"],"action":"ALLOW","enabled":true}`
	for _, r := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/events", ""},
		{http.MethodGet, "/api/v1/hosts", ""},
		{http.MethodGet, "/api/v1/policies", ""},
		{http.MethodGet, "/api/v1/policies?status=PENDING", ""},
		{http.MethodPost, "/api/v1/policies", entry},
		{http.MethodPut, "/api/v1/policies/e1", entry},
		{http.MethodPatch, "/api/v1/policies/e1", `{"enabled":false}`},
		{http.MethodDelete, "/api/v1/policies/e1", ""},
		{http.MethodPost, "/api/v1/policies/e1/approve", `{"scope":"fleet"}`},
		{http.MethodPost, "/api/v1/policies/e1/reject", `{"scope":"host","host_id":"host-a"}`},
		{http.MethodGet, "/api/v1/learning", ""},
		{http.MethodPut, "/api/v1/learning/fleet", `{"duration":"1h"}`},
		{http.MethodPut, "/api/v1/learning/hosts/host-a", `{"duration":"1h"}`},
		{http.MethodDelete, "/api/v1/learning/fleet", ""},
		{http.MethodDelete, "/api/v1/learning/hosts/host-a", ""},
	} {
		code, body := polDo(t, h, r.method, r.path, r.body)
		if code != http.StatusInternalServerError {
			t.Errorf("%s %s: %d %s, want 500", r.method, r.path, code, body)
		}
		if strings.Contains(body, "t7h-secret-detail") {
			t.Errorf("%s %s: the store error reached the client: %s", r.method, r.path, body)
		}
	}
	if n := rl.n(); n != 0 {
		t.Errorf("policy reloaded %d times after failed writes", n)
	}

	// The event list's 500 is a JSON error like the others; it used to be
	// sent with Content-Type text/plain.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Content-Type") != "application/json" ||
		strings.TrimSpace(rec.Body.String()) != `{"error":"internal server error"}` {
		t.Errorf("GET events, store down: %d %q %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
}

// TestLearning_MissingScopes: learning for a host that is not enrolled is
// 404, as is stopping learning that is not running; a failed host lookup
// is 500.
func TestLearning_MissingScopes(t *testing.T) {
	h := polRouter(newPolStore(), &polReloader{})
	for _, r := range []struct {
		method, path, body string
		code               int
	}{
		{http.MethodPut, "/api/v1/learning/hosts/no-such-host", `{"duration":"1h"}`, http.StatusNotFound},
		{http.MethodDelete, "/api/v1/learning/fleet", "", http.StatusNotFound},
		{http.MethodDelete, "/api/v1/learning/hosts/host-a", "", http.StatusNotFound},
		{http.MethodPut, "/api/v1/learning/hosts/host-a", `{"duration":"1h"}`, http.StatusOK},
		{http.MethodDelete, "/api/v1/learning/hosts/host-a", "", http.StatusNoContent},
	} {
		if code, body := polDo(t, h, r.method, r.path, r.body); code != r.code {
			t.Errorf("%s %s: %d %s, want %d", r.method, r.path, code, body, r.code)
		}
	}
	failing := polRouter(robFailingStore{newPolStore()}, &polReloader{})
	if code, body := polDo(t, failing, http.MethodPut, "/api/v1/learning/hosts/host-a", `{"duration":"1h"}`); code != http.StatusInternalServerError {
		t.Errorf("host lookup failing: %d %s, want 500", code, body)
	}
}

// TestWrites_ReloadFailure: a write that is stored but whose policy reload
// fails says so with a 500.
func TestWrites_ReloadFailure(t *testing.T) {
	st := newPolStore()
	dashSeed(st)
	rl := &polReloader{err: errors.New("reload failed")}
	h := polRouter(st, rl)
	for _, r := range []struct{ method, path, body string }{
		{http.MethodPatch, "/api/v1/policies/ok", `{"enabled":false}`},
		{http.MethodDelete, "/api/v1/policies/ok", ""},
		{http.MethodPut, "/api/v1/learning/fleet", `{"duration":"1h"}`},
		{http.MethodDelete, "/api/v1/learning/fleet", ""},
	} {
		code, body := polDo(t, h, r.method, r.path, r.body)
		if code != http.StatusInternalServerError || !strings.Contains(body, "SIGHUP") {
			t.Errorf("%s %s: %d %s, want 500 naming SIGHUP", r.method, r.path, code, body)
		}
	}
	if rl.n() != 4 {
		t.Errorf("%d reloads, want 4", rl.n())
	}
}

// TestSettings: the settings source, the WebSocket feed's protocol and
// allowed origins (sorted), and the hub's counts.
func TestSettings(t *testing.T) {
	hub := NewHub(8)
	s := NewServer(newPolStore(), zap.NewNop(), hub)
	if err := s.SetAllowedOrigins([]string{"https://b.example:8443", "HTTPS://A.Example"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAllowedOrigins([]string{"not an origin"}); err == nil {
		t.Error("SetAllowedOrigins accepted a malformed origin")
	}
	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetSettingsSource(func() Settings {
		return Settings{
			Version: "v-test", TLS: true, GRPCAddr: "[::]:9443", EnrollAddr: "[::]:9444", HTTPAddr: "[::]:8443",
			Enrollment: EnrollmentSettings{Enabled: true, Tokens: []EnrollmentTokenStatus{{Name: "fleet", Expires: exp, SingleUse: true}}},
			Connectors: []ConnectorStatus{{Name: "webhook", MinSeverity: "ALERT", Sent: 3}},
		}
	})
	sub := hub.Subscribe()
	defer hub.Unsubscribe(sub)
	hub.Publish(&event.HookEvent{ID: "e1"})

	h := s.Router([]string{"tok"}, nil)
	code, body := polDo(t, h, http.MethodGet, "/api/v1/settings", "")
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var got Settings
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "v-test" || !got.TLS || got.GRPCAddr != "[::]:9443" || got.EnrollAddr != "[::]:9444" ||
		len(got.Enrollment.Tokens) != 1 || got.Enrollment.Tokens[0].Name != "fleet" || !got.Enrollment.Tokens[0].Expires.Equal(exp) ||
		len(got.Connectors) != 1 || got.Connectors[0].Sent != 3 {
		t.Errorf("settings %s", body)
	}
	if strings.Contains(strings.ToLower(body), "secret") {
		t.Errorf("settings mention a secret: %s", body)
	}
	ws := got.WebSocket
	if ws.Protocol != WSProtocol || ws.TokenProtocolPrefix != WSTokenProtocolPrefix ||
		!reflect.DeepEqual(ws.AllowedOrigins, []string{"https://a.example", "https://b.example:8443"}) ||
		ws.Subscribers != 1 || ws.Published != 1 || ws.Buffer != 8 {
		t.Errorf("websocket settings %+v", ws)
	}

	// No source and no hub: empty lists, never null.
	_, body = polDo(t, polRouter(newPolStore(), nil), http.MethodGet, "/api/v1/settings", "")
	for _, want := range []string{`"connectors":[]`, `"tokens":[]`, `"allowed_origins":[]`} {
		if !strings.Contains(body, want) {
			t.Errorf("empty settings lack %s: %s", want, body)
		}
	}
}

// TestDashboard_IndexRemoved: Dir reports the directory, and a dashboard
// whose index.html disappears after start answers 500, not an empty page.
func TestDashboard_IndexRemoved(t *testing.T) {
	dir := secDashDir(t)
	d, err := NewDashboard(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d.Dir() != dir {
		t.Errorf("Dir() = %q, want %q", d.Dir(), dir)
	}
	if err := os.Remove(filepath.Join(dir, "index.html")); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hosts", nil))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "index.html is missing") {
		t.Errorf("index removed: %d %q", rec.Code, rec.Body)
	}
	// Files still there are still served.
	rec = httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != secAppJS {
		t.Errorf("asset: %d %q", rec.Code, rec.Body)
	}
}

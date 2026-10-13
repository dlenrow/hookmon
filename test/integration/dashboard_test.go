package integration_test

// The API and dashboard work of fix plan step 7e through the real server
// (TLS REST and WebSocket, the hub, the policy engine and PostgreSQL) and
// an enrolled bus. Like enroll_test.go these need HOOKMON_TEST_PG_DSN.

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/api"
	"github.com/dlenrow/hookmon/test/enrpki"
)

// dashRaw does an authenticated REST GET over TLS and returns the body.
func dashRaw(t *testing.T, s *enrServer, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+s.HTTPAddr()+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+enrAPIToken)
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// dashDial opens the WebSocket feed over TLS the way the dashboard does:
// the token as a subprotocol, with an Origin header.
func dashDial(t *testing.T, s *enrServer, pki *enrpki.PKI, origin, token string) (*websocket.Conn, int) {
	t.Helper()
	protocols := []string{api.WSProtocol}
	if token != "" {
		protocols = append(protocols, api.WSTokenProtocolPrefix+base64.RawURLEncoding.EncodeToString([]byte(token)))
	}
	d := websocket.Dialer{
		TLSClientConfig:  &tls.Config{RootCAs: pki.CAPool()},
		Subprotocols:     protocols,
		HandshakeTimeout: 10 * time.Second,
	}
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	conn, resp, err := d.Dial("wss://"+s.HTTPAddr()+"/api/v1/ws/events", h)
	if resp == nil {
		t.Fatalf("dial: %v", err)
	}
	return conn, resp.StatusCode
}

// TestIntegration_WebSocketFanOut: two WebSocket clients (two dashboard
// tabs) on the real TLS server both receive every event the server stores
// from an enrolled bus, in order. A handshake without a valid token, or from another
// site's page, is refused. List endpoints answer [] when empty.
func TestIntegration_WebSocketFanOut(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	s := enrStartServer(t, enrServerConfig(pki, dsn, tok))

	for _, p := range []string{"/api/v1/hosts", "/api/v1/events", "/api/v1/policies", "/api/v1/policies?status=PENDING"} {
		if code, body := dashRaw(t, s, p); code != http.StatusOK || body != "[]\n" {
			t.Errorf("%s on an empty server: %d %q, want []", p, code, body)
		}
	}

	bus := enrEnroll(t, s, pki, tok.reusable)
	tr, _ := enrRunBus(t, bus, nil)
	self := "https://" + s.HTTPAddr()

	for name, c := range map[string]struct {
		origin, token string
		code          int
	}{
		"no token":     {self, "", http.StatusUnauthorized},
		"wrong token":  {self, "not-the-token", http.StatusUnauthorized},
		"another site": {"https://evil.example", enrAPIToken, http.StatusForbidden},
	} {
		conn, code := dashDial(t, s, pki, c.origin, c.token)
		if conn != nil {
			conn.Close()
		}
		if code != c.code {
			t.Errorf("%s: status %d, want %d", name, code, c.code)
		}
	}

	var tabs []*websocket.Conn
	for i := 0; i < 2; i++ {
		conn, code := dashDial(t, s, pki, self, enrAPIToken)
		if code != http.StatusSwitchingProtocols || conn == nil {
			t.Fatalf("tab %d: status %d", i, code)
		}
		defer conn.Close()
		if conn.Subprotocol() != api.WSProtocol {
			t.Errorf("tab %d: subprotocol %q", i, conn.Subprotocol())
		}
		tabs = append(tabs, conn)
	}

	// Each event names its own library, so each is a first sighting: the
	// feed carries only stored events.
	const n = 40
	var sent []string
	for i := 0; i < n; i++ {
		evt := polDlopen(fmt.Sprintf("/opt/fanout-%d.so", i))
		if err := tr.SendEvent(evt); err != nil {
			t.Fatal(err)
		}
		sent = append(sent, evt.ID)
	}
	for k, conn := range tabs {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		for i := 0; i < n; i++ {
			var evt event.HookEvent
			if err := conn.ReadJSON(&evt); err != nil {
				t.Fatalf("tab %d, event %d: %v", k, i, err)
			}
			if evt.ID != sent[i] || evt.HostID != bus.HostID || evt.PolicyResult == nil {
				t.Fatalf("tab %d, event %d: %s on %s (%+v), want %s on %s", k, i, evt.ID, evt.HostID, evt.PolicyResult, sent[i], bus.HostID)
			}
		}
	}
	t.Logf("both tabs received all %d events in order", n)
}

// TestIntegration_PolicyEditAndAllowlistEvent: an event allowlisted from
// the dashboard, then disabled with PATCH and re-enabled with PUT, decides
// the next identical event each time, through PostgreSQL. Writes are
// validated and size-limited, and /settings shows the real addresses
// without secrets.
func TestIntegration_PolicyEditAndAllowlistEvent(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	s := enrStartServer(t, enrServerConfig(pki, dsn, tok))
	bus := enrEnroll(t, s, pki, tok.reusable)
	tr, _ := enrRunBus(t, bus, nil)
	host := bus.HostID

	first := polSend(t, s, tr, host, polBPFLoad())
	if first.PolicyResult.Action != event.ActionAlert || first.PolicyResult.Disposition != event.DispositionFirstSighting {
		t.Fatalf("before: %+v", first.PolicyResult)
	}

	// Allowlisting the first sighting decides its PENDING entry for this
	// host: the new hook leaves the PENDING list.
	var entry event.AllowlistEntry
	if code := polDo(t, s, http.MethodPost, "/api/v1/events/"+first.ID+"/allowlist", `{"scope":"host"}`, &entry); code != http.StatusCreated {
		t.Fatalf("allowlist event: %d", code)
	}
	if entry.HostID != host || entry.Learned == nil || entry.Learned.Key.Subject != polTag || entry.Status != event.StatusApproved ||
		entry.Learned.FirstEventID != first.ID {
		t.Errorf("entry from event: %+v", entry)
	}
	if p := polPending(t, s); len(p) != 0 {
		t.Errorf("PENDING after allowlisting the first sighting: %+v", p)
	}
	if code := polDo(t, s, http.MethodPost, "/api/v1/events/"+first.ID+"/allowlist", `{"scope":"host"}`, nil); code != http.StatusConflict {
		t.Errorf("allowlisting twice: %d, want 409", code)
	}
	polSendDropped(t, s, tr, host, polBPFLoad())
	other := polBPFLoad()
	other.BPFDetail.ProgHash = "1111111111111111"
	if got := polSend(t, s, tr, host, other); got.PolicyResult.Action == event.ActionAllow {
		t.Errorf("another program was allowed: %+v", got.PolicyResult)
	}

	// Disabled, the entry no longer matches: the program is a new hook again.
	if code := polDo(t, s, http.MethodPatch, "/api/v1/policies/"+entry.ID, `{"enabled":false}`, nil); code != http.StatusOK {
		t.Fatalf("disable: %d", code)
	}
	if got := polSend(t, s, tr, host, polBPFLoad()); got.PolicyResult.Action == event.ActionAllow ||
		got.PolicyResult.Disposition != event.DispositionFirstSighting {
		t.Errorf("after disabling: %+v", got.PolicyResult)
	}

	var stored []*event.AllowlistEntry
	polDo(t, s, http.MethodGet, "/api/v1/policies", "", &stored)
	if len(stored) != 1 || stored[0].Enabled {
		t.Fatalf("policies after PATCH: %+v", stored)
	}
	body, _ := json.Marshal(stored[0])
	edited := strings.Replace(string(body), `"enabled":false`, `"enabled":true`, 1)
	edited = strings.Replace(edited, `"description":"`, `"description":"edited: `, 1)
	var replaced event.AllowlistEntry
	if code := polDo(t, s, http.MethodPut, "/api/v1/policies/"+entry.ID, edited, &replaced); code != http.StatusOK {
		t.Fatalf("PUT: %d", code)
	}
	// The entry came from the server's record of the new hook.
	if !replaced.Enabled || !strings.HasPrefix(replaced.Description, "edited: ") || replaced.Learned == nil || replaced.CreatedBy != "learning-mode" {
		t.Errorf("after PUT: %+v", replaced)
	}
	polSendDropped(t, s, tr, host, polBPFLoad())

	for name, c := range map[string]struct {
		method, path, body string
		code               int
	}{
		"bad action":        {http.MethodPatch, "/api/v1/policies/" + entry.ID, `{"action":"BOGUS"}`, http.StatusBadRequest},
		"status":            {http.MethodPatch, "/api/v1/policies/" + entry.ID, `{"status":"PENDING"}`, http.StatusBadRequest},
		"create, no action": {http.MethodPost, "/api/v1/policies", `{"enabled":true}`, http.StatusBadRequest},
		"too large":         {http.MethodPost, "/api/v1/policies", `{"action":"ALLOW","description":"` + strings.Repeat("x", api.MaxWriteBody) + `"}`, http.StatusRequestEntityTooLarge},
		"missing":           {http.MethodPut, "/api/v1/policies/" + uuid.New().String(), `{"action":"ALLOW"}`, http.StatusNotFound},
	} {
		if code := polDo(t, s, c.method, c.path, c.body, nil); code != c.code {
			t.Errorf("%s: %d, want %d", name, code, c.code)
		}
	}

	var st api.Settings
	code, raw := dashRaw(t, s, "/api/v1/settings")
	if code != http.StatusOK || json.Unmarshal([]byte(raw), &st) != nil {
		t.Fatalf("settings: %d %s", code, raw)
	}
	if !st.TLS || st.GRPCAddr != s.GRPCAddr() || st.EnrollAddr != s.EnrollAddr() || st.HTTPAddr != s.HTTPAddr() ||
		!st.Enrollment.Enabled || len(st.Enrollment.Tokens) != 3 || st.WebSocket.Protocol != api.WSProtocol {
		t.Errorf("settings: %s", raw)
	}
	for _, secret := range []string{tok.reusable, tok.singleUse, tok.expired, enrAPIToken} {
		if strings.Contains(raw, secret) {
			t.Errorf("settings expose a secret: %s", raw)
		}
	}
}

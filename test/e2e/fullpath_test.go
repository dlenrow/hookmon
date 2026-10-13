//go:build linux && e2e

package e2e

// The full server path (fix plan step 7h). Every other e2e test runs the
// bus with --console; this one runs a BPF canary through all of it:
//
//	root hookmon-bus (not console mode)
//	  -> enrollment (TLS, single-use token from a 0600 file)
//	  -> gRPC over mutual TLS
//	  -> hookmon-server (the real binary)
//	  -> PostgreSQL
//	  -> policy (an allowlist entry added through the REST API mid-test)
//	  -> a webhook connector (an HTTP receiver in this test)
//	  -> the WebSocket live feed (a client in this test)
//
// and checks each hop by event ID: the row in PostgreSQL with its policy
// result, the webhook body, and the WebSocket message. The canary is loaded
// twice. The first load is a first sighting: it reaches every hop with the
// same policy result, and its PENDING entry names it as the first event.
// After that entry is approved through the API, the second load reaches
// none of them: an allowed hook is dropped.
//
// It needs, besides what every e2e test needs:
//   - HOOKMON_TEST_PG_DSN: a PostgreSQL the test can create a schema in
//   - HOOKMON_SERVER_BIN: a built hookmon-server
//
// Without them it skips. `make test-e2e-full` starts a PostgreSQL container,
// builds the server and runs this test.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"

	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/api"
	"github.com/dlenrow/hookmon/test/enrpki"
)

// t7hHook is a webhook receiver: it keeps every event POSTed to it.
type t7hHook struct {
	mu      sync.Mutex
	events  []*event.HookEvent
	headers []http.Header
	srv     *httptest.Server
}

func t7hNewHook(t *testing.T) *t7hHook {
	t.Helper()
	h := &t7hHook{}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || r.Method != http.MethodPost {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// One event per POST (an object), or a batch (an array).
		var batch []*event.HookEvent
		if strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
			err = json.Unmarshal(body, &batch)
		} else {
			var one event.HookEvent
			err = json.Unmarshal(body, &one)
			batch = []*event.HookEvent{&one}
		}
		if err != nil {
			t.Errorf("webhook body is not an event: %v: %.300s", err, body)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		h.events = append(h.events, batch...)
		h.headers = append(h.headers, r.Header.Clone())
		h.mu.Unlock()
	}))
	t.Cleanup(h.srv.Close)
	return h
}

// find returns the received event with this ID, or nil.
func (h *t7hHook) find(id string) (*event.HookEvent, http.Header) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, e := range h.events {
		if e.ID == id {
			// Headers are per POST; with batch_size 1 they line up.
			if i < len(h.headers) {
				return e, h.headers[i]
			}
			return e, nil
		}
	}
	return nil, nil
}

func (h *t7hHook) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.events)
}

// t7hFeed is a WebSocket client on the live feed; it keeps every event.
type t7hFeed struct {
	mu     sync.Mutex
	events []*event.HookEvent
	err    error
}

func t7hDialFeed(t *testing.T, httpAddr string, roots *x509.CertPool, token string) *t7hFeed {
	t.Helper()
	d := websocket.Dialer{
		TLSClientConfig:  &tls.Config{RootCAs: roots},
		Subprotocols:     []string{api.WSProtocol, api.WSTokenProtocolPrefix + base64.RawURLEncoding.EncodeToString([]byte(token))},
		HandshakeTimeout: 10 * time.Second,
	}
	h := http.Header{}
	h.Set("Origin", "https://"+httpAddr) // as the dashboard, served by the server itself
	conn, resp, err := d.Dial("wss://"+httpAddr+"/api/v1/ws/events", h)
	if err != nil {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		t.Fatalf("WebSocket dial: %v (HTTP %d)", err, code)
	}
	if conn.Subprotocol() != api.WSProtocol {
		t.Errorf("WebSocket subprotocol %q, want %q", conn.Subprotocol(), api.WSProtocol)
	}
	f := &t7hFeed{}
	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				f.mu.Lock()
				f.err = err
				f.mu.Unlock()
				return
			}
			var e event.HookEvent
			if err := json.Unmarshal(msg, &e); err != nil {
				continue
			}
			f.mu.Lock()
			f.events = append(f.events, &e)
			f.mu.Unlock()
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return f
}

// wait returns the first received event that matches, waiting up to d.
func (f *t7hFeed) wait(t *testing.T, d time.Duration, what string, match func(*event.HookEvent) bool) *event.HookEvent {
	t.Helper()
	end := time.Now().Add(d)
	for {
		f.mu.Lock()
		for _, e := range f.events {
			if match(e) {
				f.mu.Unlock()
				return e
			}
		}
		err, n := f.err, len(f.events)
		f.mu.Unlock()
		if err != nil {
			t.Fatalf("WebSocket closed while waiting for %s: %v", what, err)
		}
		if time.Now().After(end) {
			t.Fatalf("no %s on the WebSocket after %v (%d events received)", what, d, n)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// t7hRow is an event row as PostgreSQL holds it.
type t7hRow struct {
	hostID, severity string
	policy           event.PolicyResult
	bpf              event.BPFDetail
}

func t7hDBRow(t *testing.T, dsn, id string) *t7hRow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to the test schema: %v", err)
	}
	defer conn.Close(ctx)
	var r t7hRow
	var pol, bpf []byte
	err = conn.QueryRow(ctx, `SELECT host_id, severity, policy_result, bpf_detail FROM events WHERE id = $1`, id).
		Scan(&r.hostID, &r.severity, &pol, &bpf)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		t.Fatalf("query event %s: %v", id, err)
	}
	if err := json.Unmarshal(pol, &r.policy); err != nil {
		t.Fatalf("event %s policy_result %q: %v", id, pol, err)
	}
	if err := json.Unmarshal(bpf, &r.bpf); err != nil {
		t.Fatalf("event %s bpf_detail %q: %v", id, bpf, err)
	}
	return &r
}

// t7hWaitRow waits for the event's row, since the WebSocket can see an
// event a moment before its insert is visible to another connection.
func t7hWaitRow(t *testing.T, dsn, id string) *t7hRow {
	t.Helper()
	end := time.Now().Add(10 * time.Second)
	for {
		if r := t7hDBRow(t, dsn, id); r != nil {
			return r
		}
		if time.Now().After(end) {
			t.Fatalf("event %s is not in PostgreSQL", id)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func t7hWaitHook(t *testing.T, h *t7hHook, id string, d time.Duration) (*event.HookEvent, http.Header) {
	t.Helper()
	end := time.Now().Add(d)
	for {
		if e, hdr := h.find(id); e != nil {
			return e, hdr
		}
		if time.Now().After(end) {
			t.Fatalf("event %s did not reach the webhook after %v (%d events received)", id, d, h.count())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestFullPath_CanaryThroughBusServerPostgresPolicyWebhookWebSocket(t *testing.T) {
	dsn := os.Getenv("HOOKMON_TEST_PG_DSN")
	serverBin := os.Getenv("HOOKMON_SERVER_BIN")
	if dsn == "" || serverBin == "" {
		t.Skip("set HOOKMON_TEST_PG_DSN and HOOKMON_SERVER_BIN to run the full-path test (make test-e2e-full)")
	}
	dir := t.TempDir()
	hook := t7hNewHook(t)

	// Server: TLS everywhere, a single-use enrollment token, and the
	// webhook as an event feed (min_severity INFO), so it receives allowed
	// events too and each canary load can be found there by ID.
	pki := enrpki.New(t)
	apiToken, enrollToken := siemRandHex(t, 32), siemRandHex(t, 32)
	grpcAddr := fmt.Sprintf("127.0.0.1:%d", siemFreePort(t))
	enrollAddr := fmt.Sprintf("127.0.0.1:%d", siemFreePort(t))
	httpAddr := fmt.Sprintf("127.0.0.1:%d", siemFreePort(t))
	schemaDSN := siemSchema(t, dsn)
	serverYAML := filepath.Join(dir, "server.yaml")
	siemWrite(t, serverYAML, fmt.Sprintf(`grpc_addr: %q
enroll_addr: %q
http_addr: %q
dashboard_dir: ""
tls:
  cert_file: %s
  key_file: %s
  ca_file: %s
  ca_key_file: %s
database:
  url: %q
api:
  tokens: [%q]
enrollment:
  cert_validity: 24h
  tokens:
    - name: fullpath-e2e
      secret: %q
      expires: %s
      single_use: true
watchdog:
  check_interval: 1s
  heartbeat_timeout: 30s
connectors:
  webhook:
    url: "%s/hook"
    min_severity: INFO
    headers:
      X-HookMon-Test: fullpath-e2e
`, grpcAddr, enrollAddr, httpAddr, pki.ServerCertFile, pki.ServerKeyFile, pki.CACertFile, pki.CAKeyFile,
		schemaDSN, apiToken, enrollToken, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), hook.srv.URL))
	siemStart(t, filepath.Join(dir, "server.log"), serverBin, "--config", serverYAML)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pki.CACertPEM)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	apiCall := func(method, path, body string, out any) int {
		req, _ := http.NewRequest(method, "https://"+httpAddr+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+apiToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		if out != nil && resp.StatusCode < 300 {
			json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}
	waitFor := func(what string, d time.Duration, cond func() bool) {
		t.Helper()
		end := time.Now().Add(d)
		for !cond() {
			if time.Now().After(end) {
				t.Fatalf("timed out after %v waiting for %s", d, what)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	waitFor("the server", 30*time.Second, func() bool { return apiCall(http.MethodGet, "/api/v1/health", "", nil) == http.StatusOK })

	// The WebSocket subscriber connects before the bus starts, so it sees
	// every event from the first one.
	feed := t7hDialFeed(t, httpAddr, roots, apiToken)

	// Hop 1, enrollment: a root bus, not in console mode, with the token in
	// a 0600 file.
	tokenFile := filepath.Join(dir, "enroll-token")
	siemWrite(t, tokenFile, enrollToken+"\n")
	stateDir := filepath.Join(dir, "state")
	busYAML := filepath.Join(dir, "bus.yaml")
	siemWrite(t, busYAML, fmt.Sprintf("server_addr: %q\nenroll_addr: %q\nstate_dir: %s\nheartbeat_interval: 2s\ntls:\n  ca_file: %s\n",
		grpcAddr, enrollAddr, stateDir, pki.CACertFile))
	busArgs := []string{"--config", busYAML, "--enroll-token-file", tokenFile}
	if p := statusPort(); p != "" {
		busArgs = append(busArgs, "--status-port", p)
	}
	siemStart(t, filepath.Join(dir, "bus.log"), busBin(), busArgs...)

	var host event.Host
	waitFor("the bus to enroll and come online", 60*time.Second, func() bool {
		var hosts []*event.Host
		if apiCall(http.MethodGet, "/api/v1/hosts", "", &hosts) != http.StatusOK {
			return false
		}
		for _, h := range hosts {
			if h.Status == event.HostOnline {
				host = *h
				return true
			}
		}
		return false
	})
	t.Logf("hop 1, enrollment: host %s (%s) is ONLINE", host.ID, host.Hostname)
	for _, name := range []string{"bus.key", "bus.crt", "ca.crt"} {
		st, err := os.Stat(filepath.Join(stateDir, name))
		if err != nil {
			t.Fatalf("enrolled state: %v", err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v, want 0600", name, st.Mode().Perm())
		}
	}
	certPEM, err := os.ReadFile(filepath.Join(stateDir, "bus.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("bus.crt is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := hcrypto.HostIDFromCert(cert); err != nil || id != host.ID {
		t.Errorf("bus certificate names host %q (%v), the server lists %q", id, err, host.ID)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("bus certificate does not verify against the CA as a client certificate: %v", err)
	}
	func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, schemaDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		var usedBy string
		if err := conn.QueryRow(ctx, `SELECT host_id FROM enrollment_token_uses WHERE token_name = 'fullpath-e2e'`).Scan(&usedBy); err != nil || usedBy != host.ID {
			t.Errorf("single-use token use in PostgreSQL: %q, %v; want host %s", usedBy, err, host.ID)
		}
	}()

	// Hop 2, gRPC: heartbeats carry the sensor registry; the canary needs
	// bpf_syscall alive.
	waitFor("bpf_syscall alive in the host's heartbeat", 60*time.Second, func() bool {
		var h event.Host
		if apiCall(http.MethodGet, "/api/v1/hosts/"+host.ID, "", &h) != http.StatusOK {
			return false
		}
		host = h
		for _, s := range h.Sensors {
			if s.Name == "bpf_syscall" && s.Status == "alive" {
				return true
			}
		}
		return false
	})
	var sensors []string
	for _, s := range host.Sensors {
		sensors = append(sensors, s.Name+"="+s.Status)
	}
	t.Logf("hop 2, gRPC heartbeat: %d sensors: %s", len(host.Sensors), strings.Join(sensors, " "))
	if len(host.Sensors) != len(expectedSensors) {
		t.Errorf("heartbeat reports %d sensors, want %d", len(host.Sensors), len(expectedSensors))
	}

	isCanary := func(exclude ...string) func(*event.HookEvent) bool {
		return func(e *event.HookEvent) bool {
			if e.EventType != event.EventBPFLoad || e.BPFDetail == nil || e.BPFDetail.ProgName != "hello_count" {
				return false
			}
			for _, x := range exclude {
				if e.ID == x {
					return false
				}
			}
			return true
		}
	}
	// check follows one canary event through PostgreSQL and the webhook,
	// and checks that every hop holds the same policy result.
	check := func(label string, ws *event.HookEvent, wantAction event.PolicyAction, wantEntry string, wantSev event.Severity) {
		t.Helper()
		if ws.HostID != host.ID || ws.PolicyResult == nil || ws.PolicyResult.Action != wantAction ||
			ws.PolicyResult.MatchedEntryID != wantEntry || ws.Severity != wantSev || ws.BPFDetail.ProgHash == "" {
			t.Errorf("%s, WebSocket: host %s severity %s policy %+v tag %q; want host %s, %s, %s by %q, a tag",
				label, ws.HostID, ws.Severity, ws.PolicyResult, ws.BPFDetail.ProgHash, host.ID, wantSev, wantAction, wantEntry)
			return
		}
		row := t7hWaitRow(t, schemaDSN, ws.ID)
		if row.hostID != host.ID || row.severity != string(wantSev) || row.policy != *ws.PolicyResult ||
			row.bpf.ProgName != "hello_count" || row.bpf.ProgHash != ws.BPFDetail.ProgHash {
			t.Errorf("%s, PostgreSQL row %s: host %s severity %s policy %+v bpf %+v", label, ws.ID, row.hostID, row.severity, row.policy, row.bpf)
		}
		got, hdr := t7hWaitHook(t, hook, ws.ID, 15*time.Second)
		if got.HostID != host.ID || got.Severity != wantSev || got.PolicyResult == nil || *got.PolicyResult != *ws.PolicyResult ||
			got.BPFDetail == nil || got.BPFDetail.ProgHash != ws.BPFDetail.ProgHash {
			t.Errorf("%s, webhook: %+v", label, got)
		}
		if hdr.Get("X-HookMon-Test") != "fullpath-e2e" || !strings.HasPrefix(hdr.Get("Content-Type"), "application/json") {
			t.Errorf("%s, webhook headers: %v", label, hdr)
		}
		t.Logf("%s: event %s, tag %s: PostgreSQL %s %s (entry %q); webhook and WebSocket agree",
			label, ws.ID, ws.BPFDetail.ProgHash, row.severity, row.policy.Action, row.policy.MatchedEntryID)
	}

	// Hop 3: the canary with no allowlist entry. It runs as root, so it is
	// CRITICAL, and the policy result is ALERT.
	if err := LoadCanary(canaryBinDir()+"/load_canary", canaryDir()+"/hello_bpf.o",
		"syscalls", "sys_enter_getpid", "hello_count"); err != nil {
		t.Fatalf("load canary: %v", err)
	}
	first := feed.wait(t, 30*time.Second, "the first canary BPF_LOAD", isCanary())
	check("canary 1, no entry", first, event.ActionAlert, "", event.SeverityCritical)
	if r := first.PolicyResult; r.Disposition != event.DispositionFirstSighting || r.CandidateID == "" {
		t.Fatalf("canary 1: %+v, want a first sighting with a candidate", r)
	}

	// Hop 4, policy: the canary's first sighting made a PENDING entry,
	// whose first event is the canary event. Approving it for the fleet
	// through the REST API takes effect without a restart.
	var pending []*event.AllowlistEntry
	if code := apiCall(http.MethodGet, "/api/v1/policies?status=PENDING", "", &pending); code != http.StatusOK {
		t.Fatalf("GET PENDING: %d", code)
	}
	var cand *event.AllowlistEntry
	for _, p := range pending {
		if p.ID == first.PolicyResult.CandidateID {
			cand = p
		}
	}
	if cand == nil || cand.Learned == nil || cand.Learned.FirstEventID != first.ID || cand.Learned.Key.Subject != first.BPFDetail.ProgHash {
		t.Fatalf("PENDING entry %s: %+v, want first_event_id %s", first.PolicyResult.CandidateID, cand, first.ID)
	}
	var entry event.AllowlistEntry
	if code := apiCall(http.MethodPost, "/api/v1/policies/"+cand.ID+"/approve", `{"scope":"fleet"}`, &entry); code != http.StatusOK ||
		entry.ID != cand.ID || entry.Status != event.StatusApproved {
		t.Fatalf("approve %s: %d %+v", cand.ID, code, entry)
	}
	t.Logf("hop 4, policy: approved PENDING entry %s (%s) for the fleet", entry.ID, entry.Description)

	// The canary again: allowed, so dropped. A different program loaded
	// after it (hello_count_v2, a new hook) is the marker: the bus sends its
	// events in order, so once the marker is stored and delivered, the
	// second canary load has been evaluated.
	if err := LoadCanary(canaryBinDir()+"/load_canary", canaryDir()+"/hello_bpf.o",
		"syscalls", "sys_enter_getpid", "hello_count"); err != nil {
		t.Fatalf("load canary: %v", err)
	}
	if err := LoadCanary(canaryBinDir()+"/load_canary", canaryDir()+"/hello_bpf_v2.o",
		"syscalls", "sys_enter_getpid", "hello_count_v2"); err != nil {
		t.Fatalf("load marker canary: %v", err)
	}
	marker := feed.wait(t, 30*time.Second, "the marker BPF_LOAD (hello_count_v2)", func(e *event.HookEvent) bool {
		return e.EventType == event.EventBPFLoad && e.BPFDetail != nil && e.BPFDetail.ProgName == "hello_count_v2"
	})
	if r := marker.PolicyResult; r == nil || r.Disposition != event.DispositionFirstSighting {
		t.Errorf("marker: %+v, want a first sighting", r)
	}
	t7hWaitRow(t, schemaDSN, marker.ID)
	t7hWaitHook(t, hook, marker.ID, 15*time.Second)

	// The second canary load reached none of the three.
	canaryLoads := func(evts []*event.HookEvent) int {
		n := 0
		for _, e := range evts {
			if isCanary()(e) {
				n++
			}
		}
		return n
	}
	feed.mu.Lock()
	onFeed := canaryLoads(feed.events)
	n := len(feed.events)
	feed.mu.Unlock()
	if onFeed != 1 {
		t.Errorf("canary BPF_LOADs on the WebSocket: %d, want 1 (the allowed second load is dropped)", onFeed)
	}
	hook.mu.Lock()
	atHook := canaryLoads(hook.events)
	hook.mu.Unlock()
	if atHook != 1 {
		t.Errorf("canary BPF_LOADs at the webhook: %d, want 1", atHook)
	}
	if rows := t7hCanaryRows(t, schemaDSN); rows != 1 {
		t.Errorf("canary BPF_LOAD rows in PostgreSQL: %d, want 1", rows)
	}
	t.Logf("second canary load: on the WebSocket %d, at the webhook %d, in PostgreSQL %d (each only the first); WebSocket received %d events, the webhook %d",
		onFeed, atHook, t7hCanaryRows(t, schemaDSN), n, hook.count())
}

// t7hCanaryRows counts the stored BPF_LOAD events of the hello_count canary.
func t7hCanaryRows(t *testing.T, dsn string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to the test schema: %v", err)
	}
	defer conn.Close(ctx)
	var n int
	if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM events WHERE event_type = 'BPF_LOAD' AND bpf_detail->>'prog_name' = 'hello_count'`).Scan(&n); err != nil {
		t.Fatalf("count canary rows: %v", err)
	}
	return n
}

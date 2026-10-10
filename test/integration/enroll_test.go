// Package integration_test runs the real hookmon-server (server.Server, with
// its listeners, TLS, store and watchdog) against a real PostgreSQL, and the
// real bus enrollment and transport code against it over TLS on localhost.
//
// The tests need a PostgreSQL the test can create schemas in. Set
// HOOKMON_TEST_PG_DSN, for example
//
//	HOOKMON_TEST_PG_DSN='postgres://postgres:pw@127.0.0.1:55432/postgres?sslmode=disable'
//
// Without it every test skips. Each test runs in its own schema, dropped
// afterwards.
package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dlenrow/hookmon/agent/config"
	"github.com/dlenrow/hookmon/agent/transport"
	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server"
	"github.com/dlenrow/hookmon/test/enrpki"
)

const enrAPIToken = "integration-api-token"

func enrRandHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// enrPGDSN returns a DSN for a fresh schema, or skips the test.
func enrPGDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("HOOKMON_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("HOOKMON_TEST_PG_DSN is not set; skipping the PostgreSQL integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to HOOKMON_TEST_PG_DSN: %v", err)
	}
	defer conn.Close(ctx)
	schema := "enr_" + enrRandHex(t, 6)
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

// enrTokens are the enrollment secrets one test's server accepts.
type enrTokens struct {
	reusable, singleUse, expired string
}

func enrNewTokens(t *testing.T) enrTokens {
	return enrTokens{reusable: enrRandHex(t, 32), singleUse: enrRandHex(t, 32), expired: enrRandHex(t, 32)}
}

func enrServerConfig(pki *enrpki.PKI, dsn string, tok enrTokens) server.Config {
	cfg := server.DefaultConfig()
	cfg.GRPCAddr = "127.0.0.1:0"
	cfg.EnrollAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.DashboardDir = ""
	cfg.TLS = server.TLSConfig{
		CertFile:  pki.ServerCertFile,
		KeyFile:   pki.ServerKeyFile,
		CAFile:    pki.CACertFile,
		CAKeyFile: pki.CAKeyFile,
	}
	cfg.Database.URL = dsn
	cfg.API.Tokens = []string{enrAPIToken}
	now := time.Now()
	cfg.Enrollment.Tokens = []hcrypto.EnrollmentToken{
		{Name: "reusable", Secret: tok.reusable, Expires: now.Add(time.Hour)},
		{Name: "single-use", Secret: tok.singleUse, Expires: now.Add(time.Hour), SingleUse: true},
		{Name: "expired", Secret: tok.expired, Expires: now.Add(-time.Minute)},
	}
	cfg.Watchdog = server.WatchdogConfig{CheckInterval: 200 * time.Millisecond, HeartbeatTimeout: 2 * time.Second}
	return cfg
}

// enrServer is a running server.Server.
type enrServer struct {
	*server.Server
	stop func()
	// client reaches the REST API over TLS, trusting the server's CA.
	client *http.Client
}

func enrStartServer(t *testing.T, cfg server.Config) *enrServer {
	t.Helper()
	caPEM, err := os.ReadFile(cfg.TLS.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("parse CA certificate")
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	srv := server.New(cfg, zaptest.NewLogger(t, zaptest.Level(zap.WarnLevel)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	select {
	case <-srv.Ready():
	case err := <-done:
		cancel()
		t.Fatalf("server exited before it was ready: %v", err)
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatal("server not ready after 30s")
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("server Run: %v", err)
				}
			case <-time.After(30 * time.Second):
				t.Error("server did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return &enrServer{Server: srv, stop: stop, client: client}
}

// enrBusConfig is one bus's config, for a bus about to enroll with s.
func enrBusConfig(t *testing.T, s *enrServer, caFile, token string) *config.AgentConfig {
	t.Helper()
	dir := t.TempDir()
	return &config.AgentConfig{
		ServerAddr:      s.GRPCAddr(),
		EnrollAddr:      s.EnrollAddr(),
		StateDir:        filepath.Join(dir, "state"),
		EnrollToken:     token,
		FallbackLogPath: filepath.Join(dir, "fallback.jsonl"),
		TLS:             config.TLSConfig{CAFile: caFile},
	}
}

var enrRetry = transport.RetryConfig{InitialDelay: 20 * time.Millisecond, MaxDelay: 200 * time.Millisecond, Multiplier: 2, MaxAttempts: 3}

func enrEnroll(t *testing.T, s *enrServer, pki *enrpki.PKI, token string) *config.AgentConfig {
	t.Helper()
	cfg := enrBusConfig(t, s, pki.CACertFile, token)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := transport.EnsureIdentity(ctx, cfg, zap.NewNop(), enrRetry); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return cfg
}

// enrRunBus runs a real bus transport for cfg. The returned stop func stops
// it, as stopping the bus would.
func enrRunBus(t *testing.T, cfg *config.AgentConfig, sensors []event.SensorHealth) (*transport.GRPCTransport, func()) {
	t.Helper()
	tr := transport.NewGRPCTransport(cfg, zaptest.NewLogger(t, zaptest.Level(zap.ErrorLevel)),
		transport.RetryConfig{InitialDelay: 20 * time.Millisecond, MaxDelay: 200 * time.Millisecond, Multiplier: 2})
	tr.SetSensorSource(func() []event.SensorHealth { return sensors })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = tr.Run(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			<-done
			tr.Close()
		})
	}
	t.Cleanup(stop)
	enrWaitFor(t, 10*time.Second, "bus to connect over mutual TLS", tr.IsConnected)
	return tr, stop
}

func enrWaitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// enrGet does an authenticated REST GET over TLS and decodes the JSON
// response.
func enrGet(t *testing.T, s *enrServer, path string, out any) int {
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
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK && out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			t.Fatalf("GET %s: decode %q: %v", path, body, err)
		}
	}
	return resp.StatusCode
}

func enrHost(t *testing.T, s *enrServer, id string) *event.Host {
	t.Helper()
	var h event.Host
	if code := enrGet(t, s, "/api/v1/hosts/"+id, &h); code != http.StatusOK {
		t.Fatalf("GET host %s: status %d", id, code)
	}
	return &h
}

func enrEvents(t *testing.T, s *enrServer, query string) []*event.HookEvent {
	t.Helper()
	var evts []*event.HookEvent
	if code := enrGet(t, s, "/api/v1/events?"+query, &evts); code != http.StatusOK {
		t.Fatalf("GET events?%s: status %d", query, code)
	}
	return evts
}

func enrEvent(id string) *event.HookEvent {
	return &event.HookEvent{
		ID:        id,
		Timestamp: time.Now(),
		HostID:    "claimed-by-the-message",
		Hostname:  "bus",
		EventType: event.EventBPFLoad,
		Severity:  event.SeverityWarn,
		PID:       42,
		Comm:      "loader",
	}
}

// TestIntegration_EnrollAppearsInInventory: a fresh host enrolls with a
// valid token, appears in the hosts API, and its events and heartbeat,
// with the sensor snapshot, are recorded under its certificate's host ID.
func TestIntegration_EnrollAppearsInInventory(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	s := enrStartServer(t, enrServerConfig(pki, dsn, tok))

	var hosts []*event.Host
	if code := enrGet(t, s, "/api/v1/hosts", &hosts); code != http.StatusOK || len(hosts) != 0 {
		t.Fatalf("inventory before enrollment: status %d, %d hosts", code, len(hosts))
	}

	bus := enrEnroll(t, s, pki, tok.reusable)
	hostname, _ := os.Hostname()

	if code := enrGet(t, s, "/api/v1/hosts", &hosts); code != http.StatusOK || len(hosts) != 1 {
		t.Fatalf("inventory after enrollment: status %d, %d hosts", code, len(hosts))
	}
	h := hosts[0]
	if h.ID != bus.HostID || h.Hostname != hostname || h.Status != event.HostOnline || h.IPAddress != "127.0.0.1" {
		t.Errorf("enrolled host: %+v (bus host ID %s)", h, bus.HostID)
	}

	sensors := []event.SensorHealth{
		{Name: "bpf_syscall", Status: "alive"},
		{Name: "dlopen_monitor", Status: "dead", Reason: "heartbeat map did not advance"},
	}
	tr, _ := enrRunBus(t, bus, sensors)
	if err := tr.SendEvent(enrEvent("int-evt-1")); err != nil {
		t.Fatal(err)
	}
	if err := tr.SendHeartbeat(); err != nil {
		t.Fatal(err)
	}
	enrWaitFor(t, 10*time.Second, "heartbeat with sensors in the inventory", func() bool {
		return len(enrHost(t, s, bus.HostID).Sensors) == 2
	})
	if got := enrHost(t, s, bus.HostID).Sensors; got[0] != sensors[0] || got[1] != sensors[1] {
		t.Errorf("stored sensors: %+v, want %+v", got, sensors)
	}
	enrWaitFor(t, 10*time.Second, "event in the store", func() bool {
		return len(enrEvents(t, s, "host_id="+bus.HostID)) == 1
	})
	if evts := enrEvents(t, s, "host_id=claimed-by-the-message"); len(evts) != 0 {
		t.Errorf("event recorded under the host ID in the message: %+v", evts)
	}
}

// TestIntegration_TokenRejections: invalid, expired and reused single-use
// tokens are rejected; the single-use token stays used after a restart.
func TestIntegration_TokenRejections(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	s := enrStartServer(t, enrServerConfig(pki, dsn, tok))

	try := func(s *enrServer, token string) error {
		cfg := enrBusConfig(t, s, pki.CACertFile, token)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return transport.EnsureIdentity(ctx, cfg, zap.NewNop(), enrRetry)
	}
	wantDenied := func(what string, err error, msg string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "PermissionDenied") || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: got %v, want PermissionDenied %q", what, err, msg)
		}
	}

	wantDenied("invalid token", try(s, enrRandHex(t, 32)), "invalid enrollment token")
	wantDenied("expired token", try(s, tok.expired), "enrollment token expired")

	if err := try(s, tok.singleUse); err != nil {
		t.Fatalf("first use of the single-use token: %v", err)
	}
	wantDenied("reused single-use token", try(s, tok.singleUse), "already used")

	// Restart the server on the same database: still used.
	s.stop()
	s2 := enrStartServer(t, enrServerConfig(pki, dsn, tok))
	wantDenied("single-use token after restart", try(s2, tok.singleUse), "already used")

	// The reusable token still works, for more than one host.
	if err := try(s2, tok.reusable); err != nil {
		t.Errorf("reusable token: %v", err)
	}
	if err := try(s2, tok.reusable); err != nil {
		t.Errorf("reusable token, second host: %v", err)
	}

	var hosts []*event.Host
	enrGet(t, s2, "/api/v1/hosts", &hosts)
	if len(hosts) != 3 {
		t.Errorf("inventory: %d hosts, want 3 (single-use once, reusable twice)", len(hosts))
	}
}

// TestIntegration_HostCannotSendAsAnother: host A, with its own enrolled
// certificate, sends an event and a heartbeat that name host B. They are
// recorded as A's; B's inventory record does not change. Connections
// without a certificate, or with one from another CA, are refused.
func TestIntegration_HostCannotSendAsAnother(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	s := enrStartServer(t, enrServerConfig(pki, dsn, tok))

	busA := enrEnroll(t, s, pki, tok.reusable)
	busB := enrEnroll(t, s, pki, tok.reusable)
	before := enrHost(t, s, busB.HostID)

	// A raw client with host A's enrolled certificate, so the messages can
	// carry any host ID.
	creds, err := hcrypto.LoadClientTLS(busA.TLS.CertFile, busA.TLS.KeyFile, busA.TLS.CAFile, "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(s.GRPCAddr(), grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := hookmonv1.NewAgentServiceClient(conn).StreamEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*hookmonv1.AgentMessage{
		{Payload: &hookmonv1.AgentMessage_Event{Event: &hookmonv1.HookEvent{
			Id: "spoof-1", Timestamp: timestamppb.Now(), HostId: busB.HostID, Hostname: "b",
			EventType: hookmonv1.EventType_EVENT_TYPE_BPF_LOAD, Severity: hookmonv1.Severity_SEVERITY_ALERT,
		}}},
		{Payload: &hookmonv1.AgentMessage_Heartbeat{Heartbeat: &hookmonv1.Heartbeat{
			HostId: busB.HostID, AgentVersion: "spoofed",
			Sensors: []*hookmonv1.SensorHealth{{Name: "bpf_syscall", Status: "alive"}},
		}}},
	} {
		if err := stream.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	if resp, err := stream.Recv(); err != nil || !resp.GetAck().GetAccepted() {
		t.Fatalf("ack: %v %v", resp, err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}

	evts := enrEvents(t, s, "host_id="+busA.HostID)
	if len(evts) != 1 || evts[0].ID != "spoof-1" {
		t.Errorf("host A's events: %+v, want spoof-1", evts)
	}
	if evts := enrEvents(t, s, "host_id="+busB.HostID); len(evts) != 0 {
		t.Errorf("host A's event was recorded as host B's: %+v", evts)
	}
	after := enrHost(t, s, busB.HostID)
	if !after.LastHeartbeat.Equal(before.LastHeartbeat) || after.AgentVersion != before.AgentVersion || len(after.Sensors) != 0 {
		t.Errorf("host A's heartbeat changed host B: before %+v, after %+v", before, after)
	}
	if a := enrHost(t, s, busA.HostID); a.AgentVersion != "spoofed" || len(a.Sensors) != 1 {
		t.Errorf("host A's heartbeat was not recorded as A's: %+v", a)
	}

	// No client certificate, and a certificate from another CA: the TLS
	// handshake on the event listener refuses both.
	other := enrpki.New(t)
	foreign := other.ClientCert(t, busB.HostID, hcrypto.HostCertOrganization)
	for name, cert := range map[string]*tls.Certificate{"no certificate": nil, "other CA": &foreign} {
		tlsCfg := pki.ClientTLS(cert)
		tlsCfg.ServerName = "127.0.0.1"
		conn, err := grpc.NewClient(s.GRPCAddr(), grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
		if err != nil {
			t.Fatal(err)
		}
		stream, err := hookmonv1.NewAgentServiceClient(conn).StreamEvents(ctx)
		if err == nil {
			_ = stream.Send(&hookmonv1.AgentMessage{Payload: &hookmonv1.AgentMessage_Heartbeat{Heartbeat: &hookmonv1.Heartbeat{}}})
			_, err = stream.Recv()
		}
		conn.Close()
		if c := status.Code(err); c != codes.Unavailable && c != codes.Unauthenticated {
			t.Errorf("%s: got %v, want the connection refused", name, err)
		}
	}
	if after2 := enrHost(t, s, busB.HostID); !after2.LastHeartbeat.Equal(before.LastHeartbeat) {
		t.Error("an unauthenticated connection updated host B")
	}
}

// TestIntegration_WatchdogOfflineAlert: stopping the bus raises an
// AGENT_OFFLINE alert within the watchdog timeout (plus one check
// interval), and marks the host UNRESPONSIVE. A heartbeat brings it back.
func TestIntegration_WatchdogOfflineAlert(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	cfg := enrServerConfig(pki, dsn, tok)
	s := enrStartServer(t, cfg)
	bus := enrEnroll(t, s, pki, tok.reusable)

	tr, stopBus := enrRunBus(t, bus, []event.SensorHealth{{Name: "bpf_syscall", Status: "alive"}})
	beat := func(d time.Duration) {
		end := time.Now().Add(d)
		for time.Now().Before(end) {
			if err := tr.SendHeartbeat(); err != nil {
				t.Fatalf("heartbeat: %v", err)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	// Heartbeat for longer than the timeout: the host must stay online.
	beat(cfg.Watchdog.HeartbeatTimeout + time.Second)
	if h := enrHost(t, s, bus.HostID); h.Status != event.HostOnline {
		t.Fatalf("host status while heartbeating: %s", h.Status)
	}
	if evts := enrEvents(t, s, "event_type=AGENT_OFFLINE&host_id="+bus.HostID); len(evts) != 0 {
		t.Fatalf("offline alert while the bus was heartbeating: %+v", evts)
	}

	stopBus()
	stopped := time.Now()
	limit := cfg.Watchdog.HeartbeatTimeout + cfg.Watchdog.CheckInterval + time.Second
	enrWaitFor(t, limit, "AGENT_OFFLINE alert", func() bool {
		return len(enrEvents(t, s, "event_type=AGENT_OFFLINE&host_id="+bus.HostID)) == 1
	})
	t.Logf("AGENT_OFFLINE %v after the bus stopped (timeout %v, check interval %v)",
		time.Since(stopped).Round(10*time.Millisecond), cfg.Watchdog.HeartbeatTimeout, cfg.Watchdog.CheckInterval)
	evt := enrEvents(t, s, "event_type=AGENT_OFFLINE&host_id="+bus.HostID)[0]
	if evt.Severity != event.SeverityCritical {
		t.Errorf("offline alert severity: %s", evt.Severity)
	}
	if h := enrHost(t, s, bus.HostID); h.Status != event.HostUnresponsive {
		t.Errorf("host status after the bus stopped: %s", h.Status)
	}

	// One alert per outage, not one per check.
	time.Sleep(4 * cfg.Watchdog.CheckInterval)
	if n := len(enrEvents(t, s, "event_type=AGENT_OFFLINE&host_id="+bus.HostID)); n != 1 {
		t.Errorf("offline alerts: %d, want 1", n)
	}

	// The bus comes back.
	tr2, _ := enrRunBus(t, bus, nil)
	if err := tr2.SendHeartbeat(); err != nil {
		t.Fatal(err)
	}
	enrWaitFor(t, 10*time.Second, "host back online", func() bool {
		return enrHost(t, s, bus.HostID).Status == event.HostOnline
	})
}

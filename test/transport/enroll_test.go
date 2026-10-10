package transport_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"

	"github.com/dlenrow/hookmon/agent/config"
	"github.com/dlenrow/hookmon/agent/transport"
	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/ingestion"
	"github.com/dlenrow/hookmon/test/enrpki"
)

const enrSecret = "transport-test-token-0123456789abcdef0123456789"

// enrStore is an in-memory ingestion.Store and ingestion.EnrollStore.
type enrStore struct {
	mu         sync.Mutex
	hosts      map[string]*event.Host
	events     map[string]*event.HookEvent
	heartbeats map[string]*event.HostHeartbeat
}

func newEnrStore() *enrStore {
	return &enrStore{
		hosts:      make(map[string]*event.Host),
		events:     make(map[string]*event.HookEvent),
		heartbeats: make(map[string]*event.HostHeartbeat),
	}
}

func (m *enrStore) EnrollHost(_ context.Context, h *event.Host, _, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hosts[h.ID] = h
	return nil
}

func (m *enrStore) InsertEvent(_ context.Context, evt *event.HookEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[evt.ID] = evt
	return nil
}

func (m *enrStore) UpdateHostHeartbeat(_ context.Context, hb *event.HostHeartbeat) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.heartbeats[hb.HostID] = hb
	return nil
}

func (m *enrStore) hostCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.hosts)
}

// enrServeEnroll serves an Enroller with the production enrollment
// credentials (server authentication only) on lis.
func enrServeEnroll(t *testing.T, pki *enrpki.PKI, store *enrStore, lis net.Listener) {
	t.Helper()
	ca, err := hcrypto.LoadCA(pki.CACertFile, pki.CAKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := hcrypto.NewTokenSet([]hcrypto.EnrollmentToken{
		{Name: "test", Secret: enrSecret, Expires: time.Now().Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	creds, err := hcrypto.LoadEnrollServerTLS(pki.ServerCertFile, pki.ServerKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	hookmonv1.RegisterAgentServiceServer(srv, ingestion.NewEnroller(ingestion.EnrollerConfig{
		Store: store, Tokens: tokens, CA: ca,
	}))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
}

// enrServeStream serves the event stream with the production mutual-TLS
// credentials and returns its address.
func enrServeStream(t *testing.T, pki *enrpki.PKI, store *enrStore) string {
	t.Helper()
	creds, err := hcrypto.LoadServerTLS(pki.ServerCertFile, pki.ServerKeyFile, pki.CACertFile)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	hookmonv1.RegisterAgentServiceServer(srv, ingestion.NewIngestionServer(ingestion.IngestionConfig{Store: store}))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func enrListen(t *testing.T) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return lis
}

func enrBusConfig(t *testing.T, serverAddr, enrollAddr, caFile, token string) *config.AgentConfig {
	t.Helper()
	return &config.AgentConfig{
		ServerAddr:      serverAddr,
		EnrollAddr:      enrollAddr,
		StateDir:        filepath.Join(t.TempDir(), "state"),
		EnrollToken:     token,
		FallbackLogPath: filepath.Join(t.TempDir(), "fallback.jsonl"),
		TLS:             config.TLSConfig{CAFile: caFile},
	}
}

var enrFastRetry = transport.RetryConfig{InitialDelay: 20 * time.Millisecond, MaxDelay: 100 * time.Millisecond, Multiplier: 2}

// TestEnrollThenStream runs the bus's enrollment and transport code against
// the real enroller and ingestion server over TLS on localhost: the bus
// enrolls, stores its identity with mode 0600, connects with mutual TLS,
// and its events and heartbeat (with the sensor snapshot) are recorded
// under the host ID the server assigned, not the one the bus sends.
func TestEnrollThenStream(t *testing.T) {
	pki := enrpki.New(t)
	store := newEnrStore()
	enrollLis := enrListen(t)
	enrServeEnroll(t, pki, store, enrollLis)
	streamAddr := enrServeStream(t, pki, store)
	logger := zaptest.NewLogger(t, zaptest.Level(zap.WarnLevel))

	cfg := enrBusConfig(t, streamAddr, enrollLis.Addr().String(), pki.CACertFile, enrSecret)
	cfg.HostID = "self-chosen-id"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := transport.EnsureIdentity(ctx, cfg, logger, enrFastRetry); err != nil {
		t.Fatalf("EnsureIdentity: %v", err)
	}

	store.mu.Lock()
	_, enrolled := store.hosts[cfg.HostID]
	store.mu.Unlock()
	if !enrolled || store.hostCount() != 1 {
		t.Fatalf("bus host ID %q is not the enrolled host (hosts: %d)", cfg.HostID, store.hostCount())
	}

	if fi, err := os.Stat(cfg.StateDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode: %v %v, want 0700", fi.Mode().Perm(), err)
	}
	for _, name := range []string{transport.KeyFileName, transport.CertFileName, transport.CAFileName} {
		fi, err := os.Stat(filepath.Join(cfg.StateDir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode: got %v, want 0600", name, fi.Mode().Perm())
		}
	}
	if cfg.TLS.CertFile != filepath.Join(cfg.StateDir, transport.CertFileName) ||
		cfg.TLS.KeyFile != filepath.Join(cfg.StateDir, transport.KeyFileName) {
		t.Errorf("TLS config not pointed at the enrolled identity: %+v", cfg.TLS)
	}
	entries, _ := os.ReadDir(cfg.StateDir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temporary file left in state dir: %s", e.Name())
		}
	}

	tr := transport.NewGRPCTransport(cfg, logger, enrFastRetry)
	tr.SetSensorSource(func() []event.SensorHealth {
		return []event.SensorHealth{{Name: "bpf_syscall", Status: "alive"}, {Name: "lib_integrity", Status: "failed", Reason: "fanotify"}}
	})
	runCtx, stopRun := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = tr.Run(runCtx) }()
	defer func() { stopRun(); <-runDone; tr.Close() }()

	waitFor(t, 10*time.Second, "mutual-TLS connect", tr.IsConnected)
	evt := newEvent("enr-evt-1")
	evt.HostID = "someone-else"
	if err := tr.SendEvent(evt); err != nil {
		t.Fatal(err)
	}
	if err := tr.SendHeartbeat(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "event and heartbeat", func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return store.events["enr-evt-1"] != nil && store.heartbeats[cfg.HostID] != nil
	})

	store.mu.Lock()
	defer store.mu.Unlock()
	if got := store.events["enr-evt-1"].HostID; got != cfg.HostID {
		t.Errorf("event host ID: got %q, want the certificate's %q", got, cfg.HostID)
	}
	hb := store.heartbeats[cfg.HostID]
	if len(hb.Sensors) != 2 || hb.Sensors[1] != (event.SensorHealth{Name: "lib_integrity", Status: "failed", Reason: "fanotify"}) {
		t.Errorf("heartbeat sensors: %+v", hb.Sensors)
	}
}

// TestEnrollOnceThenReuse checks a restarted bus uses the stored identity:
// no token needed, no second enrollment, same host ID.
func TestEnrollOnceThenReuse(t *testing.T) {
	pki := enrpki.New(t)
	store := newEnrStore()
	enrollLis := enrListen(t)
	enrServeEnroll(t, pki, store, enrollLis)
	logger := zaptest.NewLogger(t, zaptest.Level(zap.WarnLevel))
	ctx := context.Background()

	cfg := enrBusConfig(t, "127.0.0.1:1", enrollLis.Addr().String(), pki.CACertFile, enrSecret)
	if err := transport.EnsureIdentity(ctx, cfg, logger, enrFastRetry); err != nil {
		t.Fatal(err)
	}
	first := cfg.HostID

	// Restart: same state dir, no token, no CA flag.
	restarted := enrBusConfig(t, "127.0.0.1:1", enrollLis.Addr().String(), "", "")
	restarted.StateDir = cfg.StateDir
	if err := transport.EnsureIdentity(ctx, restarted, logger, enrFastRetry); err != nil {
		t.Fatal(err)
	}
	if restarted.HostID != first || restarted.TLS.CAFile != filepath.Join(cfg.StateDir, transport.CAFileName) {
		t.Errorf("restart: host %q CA %q, want host %q and the stored CA", restarted.HostID, restarted.TLS.CAFile, first)
	}

	// Restart with the token again: still no second enrollment.
	again := enrBusConfig(t, "127.0.0.1:1", enrollLis.Addr().String(), pki.CACertFile, enrSecret)
	again.StateDir = cfg.StateDir
	if err := transport.EnsureIdentity(ctx, again, logger, enrFastRetry); err != nil {
		t.Fatal(err)
	}
	if again.HostID != first || store.hostCount() != 1 {
		t.Errorf("token given again: host %q, %d hosts enrolled; want %q and 1", again.HostID, store.hostCount(), first)
	}
}

// TestEnrollRejected checks a refused token fails at once, without
// retrying, and leaves no certificate behind.
func TestEnrollRejected(t *testing.T) {
	pki := enrpki.New(t)
	store := newEnrStore()
	enrollLis := enrListen(t)
	enrServeEnroll(t, pki, store, enrollLis)

	cfg := enrBusConfig(t, "127.0.0.1:1", enrollLis.Addr().String(), pki.CACertFile, "wrong-token-0123456789abcdef0123456789")
	slow := transport.RetryConfig{InitialDelay: time.Hour, MaxDelay: time.Hour, Multiplier: 2}
	start := time.Now()
	err := transport.EnsureIdentity(context.Background(), cfg, zap.NewNop(), slow)
	if err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("got %v, want a PermissionDenied error", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("a rejected token was retried")
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, transport.CertFileName)); !os.IsNotExist(err) {
		t.Errorf("certificate written after a rejected enrollment: %v", err)
	}
	if store.hostCount() != 0 {
		t.Errorf("hosts enrolled: %d", store.hostCount())
	}
}

// TestEnrollVerifiesServer gives the bus a different CA than the one that
// signed the server's certificate. The bus must refuse to send its token.
func TestEnrollVerifiesServer(t *testing.T) {
	pki := enrpki.New(t)
	other := enrpki.New(t)
	store := newEnrStore()
	enrollLis := enrListen(t)
	enrServeEnroll(t, pki, store, enrollLis)

	cfg := enrBusConfig(t, "127.0.0.1:1", enrollLis.Addr().String(), other.CACertFile, enrSecret)
	retry := enrFastRetry
	retry.MaxAttempts = 2
	err := transport.EnsureIdentity(context.Background(), cfg, zap.NewNop(), retry)
	if err == nil {
		t.Fatal("enrolled with a server whose certificate the bus's CA did not sign")
	}
	if !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Errorf("got %v, want a server certificate verification failure", err)
	}
	if store.hostCount() != 0 {
		t.Errorf("hosts enrolled: %d", store.hostCount())
	}
}

// TestEnrollRetriesUntilServerUp starts the bus's enrollment before the
// enrollment server listens; it must keep trying and succeed.
func TestEnrollRetriesUntilServerUp(t *testing.T) {
	pki := enrpki.New(t)
	store := newEnrStore()
	lis := enrListen(t)
	addr := lis.Addr().String()
	lis.Close()

	cfg := enrBusConfig(t, "127.0.0.1:1", addr, pki.CACertFile, enrSecret)
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() { done <- transport.EnsureIdentity(ctx, cfg, zap.NewNop(), enrFastRetry) }()

	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("EnsureIdentity returned before the server was up: %v", err)
	default:
	}
	var relis net.Listener
	deadline := time.Now().Add(5 * time.Second)
	for {
		var err error
		if relis, err = net.Listen("tcp", addr); err == nil || time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("relisten %s: %v", addr, err)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	enrServeEnroll(t, pki, store, relis)

	if err := <-done; err != nil {
		t.Fatalf("EnsureIdentity: %v", err)
	}
	if store.hostCount() != 1 {
		t.Errorf("hosts enrolled: %d, want 1", store.hostCount())
	}
}

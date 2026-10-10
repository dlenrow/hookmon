// Package transport_test runs the sensor bus gRPC transport against a real
// server/ingestion server on a localhost TCP port, so a test can stop the
// server and start a new one on the same address. It lives outside
// agent/transport because agent/transport must not import server code.
package transport_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"

	"github.com/dlenrow/hookmon/agent/config"
	"github.com/dlenrow/hookmon/agent/transport"
	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/ingestion"
)

const hostID = "host-test"

// memStore is an in-memory ingestion.Store.
type memStore struct {
	mu         sync.Mutex
	events     map[string]bool
	heartbeats map[string]time.Time
}

func newMemStore() *memStore {
	return &memStore{events: make(map[string]bool), heartbeats: make(map[string]time.Time)}
}

func (m *memStore) InsertEvent(_ context.Context, evt *event.HookEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[evt.ID] = true
	return nil
}

func (m *memStore) UpdateHostHeartbeat(_ context.Context, hb *event.HostHeartbeat) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.heartbeats[hb.HostID] = hb.ReceivedAt
	return nil
}

func (m *memStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func (m *memStore) has(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.events[id]
}

func (m *memStore) hasHeartbeat(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.heartbeats[id]
	return ok
}

// startServer serves a real IngestionServer on addr and returns the server
// and the address it bound.
func startServer(t *testing.T, addr string, store *memStore) (*grpc.Server, string) {
	t.Helper()
	var lis net.Listener
	var err error
	// Rebinding a port that a stopped server just released can briefly fail.
	deadline := time.Now().Add(5 * time.Second)
	for {
		lis, err = net.Listen("tcp", addr)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	// These tests exercise reconnection over plaintext gRPC, so the server
	// runs in its insecure development mode, where the host ID comes from
	// each message. enroll_test.go covers mutual TLS.
	srv := grpc.NewServer()
	hookmonv1.RegisterAgentServiceServer(srv, ingestion.NewIngestionServer(ingestion.IngestionConfig{Store: store, Insecure: true}))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return srv, lis.Addr().String()
}

// startTransport runs a real bus transport against addr. The returned stop
// func cancels Run, waits for it to return, and closes the transport; it also
// runs at cleanup.
func startTransport(t *testing.T, addr string, logger *zap.Logger) (tr *transport.GRPCTransport, fallbackPath string, stop func()) {
	t.Helper()
	fallbackPath = filepath.Join(t.TempDir(), "fallback.jsonl")
	cfg := &config.AgentConfig{
		HostID:          hostID,
		ServerAddr:      addr,
		FallbackLogPath: fallbackPath,
		TLS:             config.TLSConfig{Insecure: true},
	}
	retry := transport.RetryConfig{InitialDelay: 20 * time.Millisecond, MaxDelay: 200 * time.Millisecond, Multiplier: 2}
	tr = transport.NewGRPCTransport(cfg, logger, retry)

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- tr.Run(ctx) }()

	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-runDone:
				if err != nil {
					t.Errorf("Run returned error: %v", err)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("Run did not return after cancel (deadlock?)")
			}
			if err := tr.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
	t.Cleanup(stop)
	return tr, fallbackPath, stop
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func newEvent(id string) *event.HookEvent {
	return &event.HookEvent{
		ID:        id,
		Timestamp: time.Now(),
		HostID:    hostID,
		Hostname:  "bus-test",
		EventType: event.EventBPFLoad,
		Severity:  event.SeverityWarn,
		PID:       42,
		Comm:      "loader",
	}
}

func readFallback(t *testing.T, path string) map[string]bool {
	t.Helper()
	ids := make(map[string]bool)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return ids
	}
	if err != nil {
		t.Fatalf("open fallback log: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var evt event.HookEvent
		if err := json.Unmarshal(sc.Bytes(), &evt); err != nil {
			t.Fatalf("parse fallback line %q: %v", sc.Text(), err)
		}
		ids[evt.ID] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read fallback log: %v", err)
	}
	return ids
}

// TestReconnectAfterServerRestart stops the server under a connected bus,
// sends during the outage, starts a new server on the same address, and
// checks that the bus reconnects and delivers again.
func TestReconnectAfterServerRestart(t *testing.T) {
	store1 := newMemStore()
	srv1, addr := startServer(t, "127.0.0.1:0", store1)
	tr, fallbackPath, stopTr := startTransport(t, addr, zaptest.NewLogger(t, zaptest.Level(zap.WarnLevel)))

	waitFor(t, 10*time.Second, "initial connect", tr.IsConnected)
	for i := 0; i < 20; i++ {
		if err := tr.SendEvent(newEvent(fmt.Sprintf("before-%d", i))); err != nil {
			t.Fatalf("SendEvent before outage: %v", err)
		}
	}
	waitFor(t, 10*time.Second, "events before outage to reach server 1", func() bool {
		return store1.count() == 20
	})

	srv1.Stop()
	waitFor(t, 10*time.Second, "bus to notice the outage", func() bool { return !tr.IsConnected() })

	var outage []string
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("outage-%d", i)
		outage = append(outage, id)
		if err := tr.SendEvent(newEvent(id)); err != nil {
			t.Fatalf("SendEvent during outage: %v", err)
		}
	}
	if err := tr.SendHeartbeat(); err == nil {
		t.Error("SendHeartbeat during outage: expected an error")
	}

	store2 := newMemStore()
	startServer(t, addr, store2)
	waitFor(t, 10*time.Second, "reconnect to server 2", tr.IsConnected)

	for i := 0; i < 20; i++ {
		if err := tr.SendEvent(newEvent(fmt.Sprintf("after-%d", i))); err != nil {
			t.Fatalf("SendEvent after restart: %v", err)
		}
	}
	if err := tr.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat after restart: %v", err)
	}
	waitFor(t, 10*time.Second, "events after restart to reach server 2", func() bool {
		for i := 0; i < 20; i++ {
			if !store2.has(fmt.Sprintf("after-%d", i)) {
				return false
			}
		}
		return true
	})
	waitFor(t, 10*time.Second, "heartbeat after restart to reach server 2", func() bool {
		return store2.hasHeartbeat(hostID)
	})

	stopTr()
	fallback := readFallback(t, fallbackPath)
	for _, id := range outage {
		if !fallback[id] {
			t.Errorf("event %s sent during the outage is missing from the fallback log", id)
		}
		if store2.has(id) {
			t.Errorf("event %s sent during the outage reached server 2; the fallback log is not replayed", id)
		}
	}
}

// TestConcurrentSendersAcrossRestart has many goroutines call SendEvent,
// SendHeartbeat and IsConnected while the server is stopped and restarted.
// Run it under -race. Every event must end up on a server or in the fallback
// log.
func TestConcurrentSendersAcrossRestart(t *testing.T) {
	store1 := newMemStore()
	srv1, addr := startServer(t, "127.0.0.1:0", store1)
	tr, fallbackPath, stopTr := startTransport(t, addr, zap.NewNop())
	waitFor(t, 10*time.Second, "initial connect", tr.IsConnected)

	const senders = 16
	stop := make(chan struct{})
	sent := make([][]string, senders)
	var wg sync.WaitGroup
	for g := 0; g < senders; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				id := fmt.Sprintf("g%d-%d", g, i)
				if err := tr.SendEvent(newEvent(id)); err != nil {
					t.Errorf("SendEvent %s: %v", id, err)
				}
				sent[g] = append(sent[g], id)
				if i%10 == 0 {
					_ = tr.SendHeartbeat()
					_ = tr.IsConnected()
				}
				time.Sleep(200 * time.Microsecond)
			}
		}(g)
	}

	waitFor(t, 10*time.Second, "traffic on server 1", func() bool { return store1.count() >= 300 })
	srv1.Stop()
	waitFor(t, 10*time.Second, "bus to notice the outage", func() bool { return !tr.IsConnected() })
	time.Sleep(50 * time.Millisecond)

	store2 := newMemStore()
	startServer(t, addr, store2)
	waitFor(t, 10*time.Second, "traffic on server 2", func() bool { return store2.count() >= 300 })

	close(stop)
	wg.Wait()
	stopTr()

	fallback := readFallback(t, fallbackPath)
	if len(fallback) == 0 {
		t.Error("expected events sent during the outage in the fallback log")
	}
	total, missing := 0, 0
	for _, ids := range sent {
		for _, id := range ids {
			total++
			if !store1.has(id) && !store2.has(id) && !fallback[id] {
				missing++
				if missing <= 5 {
					t.Errorf("event %s was lost: not on either server and not in the fallback log", id)
				}
			}
		}
	}
	if missing > 0 {
		t.Errorf("%d of %d events lost", missing, total)
	}
	if !store1.hasHeartbeat(hostID) || !store2.hasHeartbeat(hostID) {
		t.Error("expected heartbeats on both servers")
	}
	t.Logf("sent %d events: server1=%d server2=%d fallback=%d", total, store1.count(), store2.count(), len(fallback))
}

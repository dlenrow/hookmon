package ingestion

import (
	"context"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	"github.com/dlenrow/hookmon/pkg/event"
)

// memStore is an in-memory Store that records every call for assertions.
type memStore struct {
	mu         sync.Mutex
	events     []*event.HookEvent
	hosts      []*event.Host
	heartbeats map[string]time.Time
}

func newMemStore() *memStore {
	return &memStore{heartbeats: make(map[string]time.Time)}
}

func (m *memStore) InsertEvent(_ context.Context, evt *event.HookEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, evt)
	return nil
}

func (m *memStore) UpsertHost(_ context.Context, host *event.Host) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hosts = append(m.hosts, host)
	return nil
}

func (m *memStore) UpdateHostHeartbeat(_ context.Context, hostID string, ts time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.heartbeats[hostID] = ts
	return nil
}

// startWireServer serves a real IngestionServer over an in-memory bufconn
// listener and returns a client connected to it through the real gRPC codec.
func startWireServer(t *testing.T, store Store) (*IngestionServer, hookmonv1.AgentServiceClient) {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	ing := NewIngestionServer(IngestionConfig{
		Store:           store,
		EnrollmentToken: "enroll-secret",
		CACert:          []byte("ca-cert-pem"),
	})
	srv := grpc.NewServer()
	hookmonv1.RegisterAgentServiceServer(srv, ing)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return ing, hookmonv1.NewAgentServiceClient(conn)
}

func TestWire_StreamEvents(t *testing.T) {
	store := newMemStore()
	ing, client := startWireServer(t, store)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ts := time.Date(2025, 6, 15, 12, 0, 0, 123456789, time.UTC)
	hbTS := ts.Add(5 * time.Second)

	execEvt := &hookmonv1.HookEvent{
		Id:          "evt-exec-1",
		Timestamp:   timestamppb.New(ts),
		HostId:      "host-1",
		Hostname:    "web-01",
		EventType:   hookmonv1.EventType_EVENT_TYPE_EXEC_INJECTION,
		Severity:    hookmonv1.Severity_SEVERITY_ALERT,
		Pid:         4242,
		Ppid:        1,
		Uid:         1000,
		Gid:         1000,
		Comm:        "target",
		Cmdline:     "/usr/bin/target --flag",
		ExePath:     "/usr/bin/target",
		ExeHash:     "sha256:exe",
		CgroupPath:  "/sys/fs/cgroup/user.slice",
		ContainerId: "ctr-abc",
		Namespace:   "prod",
		ExecInjectionDetail: &hookmonv1.ExecInjectionDetail{
			LibraryPath:  "/tmp/evil.so",
			LibraryHash:  "sha256:lib",
			TargetBinary: "/usr/bin/target",
			SetBy:        "env",
			EnvVar:       "LD_PRELOAD",
		},
	}
	rpathEvt := &hookmonv1.HookEvent{
		Id:        "evt-rpath-1",
		Timestamp: timestamppb.New(ts),
		HostId:    "host-1",
		Hostname:  "web-01",
		EventType: hookmonv1.EventType_EVENT_TYPE_ELF_RPATH,
		Severity:  hookmonv1.Severity_SEVERITY_CRITICAL,
		Pid:       4243,
		ExePath:   "/opt/app/bin/app",
		ElfRpathDetail: &hookmonv1.ElfRpathDetail{
			HasRpath:   true,
			HasRunpath: true,
			RpathRaw:   "/tmp/evil:$ORIGIN/../lib",
			RunpathRaw: "/opt/app/lib",
			Entries: []*hookmonv1.RpathEntry{
				{Path: "/tmp/evil", Risk: "CRITICAL", Reason: "world-writable", Exists: true, IsRpath: true},
				{Path: "$ORIGIN/../lib", Risk: "LOW", Reason: "origin-relative", Exists: true, IsRpath: true},
				{Path: "/opt/app/lib", Risk: "MEDIUM", Reason: "non-standard", Exists: false, IsRpath: false},
			},
			HighestRisk:    "CRITICAL",
			UsesOrigin:     true,
			UsesDeprecated: true,
			IsSetuid:       true,
		},
	}
	// Missing host_id, so the server must reject it with a negative ack.
	invalidEvt := &hookmonv1.HookEvent{
		Id:        "evt-invalid",
		Timestamp: timestamppb.New(ts),
		EventType: hookmonv1.EventType_EVENT_TYPE_BPF_LOAD,
	}

	stream, err := client.StreamEvents(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	for _, pe := range []*hookmonv1.HookEvent{execEvt, rpathEvt, invalidEvt} {
		msg := &hookmonv1.AgentMessage{Payload: &hookmonv1.AgentMessage_Event{Event: pe}}
		if err := stream.Send(msg); err != nil {
			t.Fatalf("send event %s: %v", pe.Id, err)
		}
	}
	hb := &hookmonv1.AgentMessage{Payload: &hookmonv1.AgentMessage_Heartbeat{Heartbeat: &hookmonv1.Heartbeat{
		HostId:        "host-1",
		Timestamp:     timestamppb.New(hbTS),
		AgentVersion:  "1.2.3",
		EventsSent:    2,
		UptimeSeconds: 60,
	}}}
	if err := stream.Send(hb); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}

	wantAcks := []struct {
		id       string
		accepted bool
	}{
		{"evt-exec-1", true},
		{"evt-rpath-1", true},
		{"evt-invalid", false},
	}
	for _, want := range wantAcks {
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv ack for %s: %v", want.id, err)
		}
		ack := resp.GetAck()
		if ack == nil {
			t.Fatalf("expected ack for %s, got %T", want.id, resp.GetPayload())
		}
		if ack.GetEventId() != want.id || ack.GetAccepted() != want.accepted {
			t.Errorf("ack: got (%q, %v), want (%q, %v)",
				ack.GetEventId(), ack.GetAccepted(), want.id, want.accepted)
		}
	}

	// Half-close and drain: the server handler returns only after it has
	// processed every message, including the trailing heartbeat.
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("expected io.EOF after close, got %v", err)
	}

	wantExec := &event.HookEvent{
		ID:          "evt-exec-1",
		Timestamp:   ts,
		HostID:      "host-1",
		Hostname:    "web-01",
		EventType:   event.EventExecInjection,
		Severity:    event.SeverityAlert,
		PID:         4242,
		PPID:        1,
		UID:         1000,
		GID:         1000,
		Comm:        "target",
		Cmdline:     "/usr/bin/target --flag",
		ExePath:     "/usr/bin/target",
		ExeHash:     "sha256:exe",
		CgroupPath:  "/sys/fs/cgroup/user.slice",
		ContainerID: "ctr-abc",
		Namespace:   "prod",
		ExecInjectionDetail: &event.ExecInjectionDetail{
			LibraryPath:  "/tmp/evil.so",
			LibraryHash:  "sha256:lib",
			TargetBinary: "/usr/bin/target",
			SetBy:        "env",
			EnvVar:       "LD_PRELOAD",
		},
	}
	wantRpath := &event.HookEvent{
		ID:        "evt-rpath-1",
		Timestamp: ts,
		HostID:    "host-1",
		Hostname:  "web-01",
		EventType: event.EventElfRpath,
		Severity:  event.SeverityCritical,
		PID:       4243,
		ExePath:   "/opt/app/bin/app",
		ElfRpathDetail: &event.ElfRpathDetail{
			HasRpath:   true,
			HasRunpath: true,
			RpathRaw:   "/tmp/evil:$ORIGIN/../lib",
			RunpathRaw: "/opt/app/lib",
			Entries: []event.RpathEntry{
				{Path: "/tmp/evil", Risk: event.RpathRiskCritical, Reason: "world-writable", Exists: true, IsRpath: true},
				{Path: "$ORIGIN/../lib", Risk: event.RpathRiskLow, Reason: "origin-relative", Exists: true, IsRpath: true},
				{Path: "/opt/app/lib", Risk: event.RpathRiskMedium, Reason: "non-standard", Exists: false, IsRpath: false},
			},
			HighestRisk:    event.RpathRiskCritical,
			UsesOrigin:     true,
			UsesDeprecated: true,
			IsSetuid:       true,
		},
	}

	store.mu.Lock()
	gotEvents := store.events
	gotHB, hbOK := store.heartbeats["host-1"]
	store.mu.Unlock()

	if len(gotEvents) != 2 {
		t.Fatalf("stored events: got %d, want 2", len(gotEvents))
	}
	for i, want := range []*event.HookEvent{wantExec, wantRpath} {
		got := *gotEvents[i]
		if !got.Timestamp.Equal(want.Timestamp) {
			t.Errorf("%s timestamp: got %v, want %v", want.ID, got.Timestamp, want.Timestamp)
		}
		got.Timestamp = want.Timestamp
		if !reflect.DeepEqual(&got, want) {
			t.Errorf("%s converted event mismatch:\n got  %+v\n want %+v", want.ID, &got, want)
		}
	}

	if !hbOK {
		t.Fatal("heartbeat was not persisted to the store")
	}
	if !gotHB.Equal(hbTS) {
		t.Errorf("stored heartbeat: got %v, want %v", gotHB, hbTS)
	}
	if last, ok := ing.GetHostLastHeartbeat("host-1"); !ok || !last.Equal(hbTS) {
		t.Errorf("tracked heartbeat: got (%v, %v), want (%v, true)", last, ok, hbTS)
	}

	// Accepted events are also broadcast on the event channel.
	for _, wantID := range []string{"evt-exec-1", "evt-rpath-1"} {
		select {
		case evt := <-ing.GetEventChannel():
			if evt.ID != wantID {
				t.Errorf("broadcast event: got %q, want %q", evt.ID, wantID)
			}
		default:
			t.Fatalf("broadcast event %s missing", wantID)
		}
	}
}

func TestWire_Enroll(t *testing.T) {
	store := newMemStore()
	_, client := startWireServer(t, store)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Enroll(ctx, &hookmonv1.EnrollRequest{
		EnrollmentToken: "enroll-secret",
		Hostname:        "web-02",
		Csr:             []byte("csr-der"),
		OsInfo:          "Ubuntu 24.04",
		AgentVersion:    "1.2.3",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if resp.GetHostId() == "" {
		t.Error("expected a host ID in the enroll response")
	}
	if string(resp.GetCaCert()) != "ca-cert-pem" {
		t.Errorf("CaCert: got %q", resp.GetCaCert())
	}

	store.mu.Lock()
	hosts := store.hosts
	store.mu.Unlock()
	if len(hosts) != 1 {
		t.Fatalf("registered hosts: got %d, want 1", len(hosts))
	}
	h := hosts[0]
	if h.ID != resp.GetHostId() || h.Hostname != "web-02" || h.OSInfo != "Ubuntu 24.04" || h.AgentVersion != "1.2.3" {
		t.Errorf("registered host mismatch: %+v", h)
	}

	_, err = client.Enroll(ctx, &hookmonv1.EnrollRequest{
		EnrollmentToken: "wrong",
		Hostname:        "web-03",
		Csr:             []byte("csr-der"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("bad token: got %v, want PermissionDenied", err)
	}
}

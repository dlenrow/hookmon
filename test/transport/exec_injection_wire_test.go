package transport_test

import (
	"net"
	"reflect"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"

	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/ingestion"
)

// TestExecInjWireRoundTrip sends EXEC_INJECTION events carrying
// every ExecInjectionDetail field, including the scan and value truncation
// flags, through the real bus transport, gRPC and the real ingestion
// server, and checks the server stores them unchanged.
func TestExecInjWireRoundTrip(t *testing.T) {
	store := &bpfEventStore{events: make(map[string]*event.HookEvent)}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	hookmonv1.RegisterAgentServiceServer(srv, ingestion.NewIngestionServer(ingestion.IngestionConfig{Store: store}))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	tr, _, _ := startTransport(t, lis.Addr().String(), zaptest.NewLogger(t, zaptest.Level(zap.WarnLevel)))
	waitFor(t, 5*time.Second, "transport to connect", tr.IsConnected)

	ts := time.Date(2026, 10, 10, 9, 0, 0, 123456789, time.UTC)
	base := func(id string, d *event.ExecInjectionDetail) *event.HookEvent {
		return &event.HookEvent{
			ID:                  id,
			Timestamp:           ts,
			HostID:              hostID,
			Hostname:            "bus-test",
			EventType:           event.EventExecInjection,
			Severity:            event.SeverityAlert,
			PID:                 4321,
			PPID:                4320,
			UID:                 1000,
			GID:                 1000,
			Comm:                "true",
			ExecInjectionDetail: d,
		}
	}
	found := base("exec-inj-1", &event.ExecInjectionDetail{
		LibraryPath:  "/tmp/evil.so",
		LibraryHash:  "sha256:0123456789abcdef",
		TargetBinary: "/dev/fd/3",
		SetBy:        "env",
		EnvVar:       "LD_PRELOAD",
	})
	longValue := base("exec-inj-2", &event.ExecInjectionDetail{
		LibraryPath:    "/usr/lib/libgood.so /tmp/padding",
		TargetBinary:   "/bin/true",
		SetBy:          "env",
		EnvVar:         "LD_PRELOAD",
		ValueTruncated: true,
	})
	truncated := base("exec-inj-3", &event.ExecInjectionDetail{
		TargetBinary:  "/bin/true",
		SetBy:         "env",
		ScanTruncated: true,
	})

	sent := []*event.HookEvent{found, longValue, truncated}
	for _, evt := range sent {
		if err := tr.SendEvent(evt); err != nil {
			t.Fatalf("send %s: %v", evt.ID, err)
		}
	}
	for _, want := range sent {
		waitFor(t, 5*time.Second, "server to store "+want.ID, func() bool { return store.get(want.ID) != nil })
		got := store.get(want.ID)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s changed on the wire:\n got  %+v\n want %+v", want.ID, got, want)
			if got.ExecInjectionDetail != nil {
				t.Errorf("%s ExecInjectionDetail:\n got  %+v\n want %+v", want.ID, *got.ExecInjectionDetail, *want.ExecInjectionDetail)
			}
		}
	}
}

// TestExecInjValidation checks that the server accepts a truncation event,
// which names no variable, and rejects an EXEC_INJECTION event that neither
// names a variable nor is a truncation event.
func TestExecInjValidation(t *testing.T) {
	evt := func(d *event.ExecInjectionDetail) *event.HookEvent {
		return &event.HookEvent{
			ID: "exec-inj-v", Timestamp: time.Now(), HostID: hostID,
			EventType: event.EventExecInjection, ExecInjectionDetail: d,
		}
	}
	if err := ingestion.ValidateEvent(evt(&event.ExecInjectionDetail{EnvVar: "LD_PRELOAD"})); err != nil {
		t.Errorf("event naming a variable rejected: %v", err)
	}
	if err := ingestion.ValidateEvent(evt(&event.ExecInjectionDetail{ScanTruncated: true})); err != nil {
		t.Errorf("truncation event rejected: %v", err)
	}
	for name, d := range map[string]*event.ExecInjectionDetail{
		"no detail":                  nil,
		"no variable, not truncated": {LibraryPath: "/tmp/evil.so"},
	} {
		if err := ingestion.ValidateEvent(evt(d)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

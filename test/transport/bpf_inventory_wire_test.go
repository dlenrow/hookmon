package transport_test

import (
	"context"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"

	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/ingestion"
)

// bpfEventStore is an ingestion.Store that keeps every event it is given.
type bpfEventStore struct {
	mu     sync.Mutex
	events map[string]*event.HookEvent
}

func (m *bpfEventStore) InsertEvent(_ context.Context, evt *event.HookEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[evt.ID] = evt
	return nil
}

func (m *bpfEventStore) UpdateHostHeartbeat(context.Context, *event.HostHeartbeat) error { return nil }

func (m *bpfEventStore) get(id string) *event.HookEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.events[id]
}

// TestWire_BPFInventoryAndDetail sends BPF_INVENTORY events and a BPF event
// carrying every BPFDetail field through the real bus transport, gRPC and
// the real ingestion server, and checks the server stores them unchanged.
func TestWire_BPFInventoryAndDetail(t *testing.T) {
	store := &bpfEventStore{events: make(map[string]*event.HookEvent)}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	// Plaintext, so the insecure development mode (see startServer).
	hookmonv1.RegisterAgentServiceServer(srv, ingestion.NewIngestionServer(ingestion.IngestionConfig{Store: store, Insecure: true}))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	tr, _, _ := startTransport(t, lis.Addr().String(), zaptest.NewLogger(t, zaptest.Level(zap.WarnLevel)))
	waitFor(t, 5*time.Second, "transport to connect", tr.IsConnected)

	ts := time.Date(2026, 10, 9, 12, 0, 0, 123456789, time.UTC)
	loaded := time.Date(2026, 10, 9, 11, 58, 30, 987654321, time.UTC)
	rootUID := uint32(0) // a set zero must arrive as set, not as absent

	prog := &event.HookEvent{
		ID:        "inv-prog-1",
		Timestamp: ts,
		HostID:    hostID,
		Hostname:  "bus-test",
		EventType: event.EventBPFInventory,
		Severity:  event.SeverityInfo,
		BPFDetail: &event.BPFDetail{
			ProgType:     5,
			ProgName:     "hello_count",
			ProgHash:     "a04f5eef06a7f555",
			ProgID:       4242,
			LoadTime:     &loaded,
			CreatedByUID: &rootUID,
		},
		BPFInventoryDetail: &event.BPFInventoryDetail{ScanID: "scan-1"},
	}
	summary := &event.HookEvent{
		ID:        "inv-summary-1",
		Timestamp: ts,
		HostID:    hostID,
		Hostname:  "bus-test",
		EventType: event.EventBPFInventory,
		Severity:  event.SeverityInfo,
		BPFInventoryDetail: &event.BPFInventoryDetail{
			ScanID:    "scan-1",
			Summary:   true,
			ProgCount: 3,
			ByType:    map[string]uint32{"TracePoint": 2, "CGroupSKB": 1},
		},
	}
	// An attach whose program was gone before the bus could read it: no
	// load time or creator UID, and those must stay absent.
	attach := &event.HookEvent{
		ID:        "attach-1",
		Timestamp: ts,
		HostID:    hostID,
		Hostname:  "bus-test",
		EventType: event.EventBPFAttach,
		Severity:  event.SeverityWarn,
		PID:       1234,
		PPID:      1,
		UID:       1000,
		GID:       1000,
		Comm:      "loader",
		BPFDetail: &event.BPFDetail{
			BPFCommand:   17,
			ProgType:     17,
			ProgName:     "raw_tp_prog",
			TargetFD:     -1,
			ProgHash:     "0011223344556677",
			ProgID:       4243,
			AttachTarget: "sys_enter",
		},
	}

	for _, evt := range []*event.HookEvent{prog, summary, attach} {
		if err := tr.SendEvent(evt); err != nil {
			t.Fatalf("send %s: %v", evt.ID, err)
		}
	}

	for _, want := range []*event.HookEvent{prog, summary, attach} {
		waitFor(t, 5*time.Second, "server to store "+want.ID, func() bool { return store.get(want.ID) != nil })
		got := store.get(want.ID)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s changed on the wire:\n got  %+v\n want %+v", want.ID, got, want)
			if got.BPFDetail != nil && want.BPFDetail != nil {
				t.Errorf("%s BPFDetail:\n got  %+v\n want %+v", want.ID, *got.BPFDetail, *want.BPFDetail)
			}
			if got.BPFInventoryDetail != nil && want.BPFInventoryDetail != nil {
				t.Errorf("%s BPFInventoryDetail:\n got  %+v\n want %+v", want.ID, *got.BPFInventoryDetail, *want.BPFInventoryDetail)
			}
		}
	}
}

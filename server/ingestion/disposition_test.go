package ingestion

import (
	"context"
	"crypto/tls"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/test/enrpki"
)

// dispEngine gives each event the disposition its ID names: the ID is
// "<disposition>-<n>".
type dispEngine struct{}

func (dispEngine) Evaluate(evt *event.HookEvent) *event.PolicyResult {
	d := event.Disposition(evt.ID[:strings.LastIndex(evt.ID, "-")])
	res := &event.PolicyResult{Action: event.ActionAlert, Disposition: d}
	if d == event.DispositionAllowed {
		res.Action = event.ActionAllow
	}
	return res
}

// dispConnector records the IDs it is sent.
type dispConnector struct {
	mu  sync.Mutex
	ids []string
}

func (c *dispConnector) Send(evt *event.HookEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ids = append(c.ids, evt.ID)
	return nil
}

// TestDisposition_OnlyKeptEventsGoOn: a first sighting and a denied event
// are stored, sent to the connectors and published to the live feed; a
// repeat and an allowed event are not, and are counted as dropped. Every
// one is acknowledged, so the bus does not keep it for a retry.
func TestDisposition_OnlyKeptEventsGoOn(t *testing.T) {
	store := newMemStore()
	conn := &dispConnector{}
	pki := enrpki.New(t)
	ing := NewIngestionServer(IngestionConfig{Store: store, PolicyEngine: dispEngine{}, Connectors: []Connector{conn}})
	w := enrServe(t, pki, ing, tls.RequireAndVerifyClientCert, false)
	hostID := uuid.New().String()
	store.hosts = append(store.hosts, &event.Host{ID: hostID, Hostname: "web-01"})
	client := w.enrDial(t, enrHostCert(t, pki, hostID), false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.StreamEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"first_sighting-1", "repeat-1", "allowed-1", "denied-1", "repeat-2", "lifecycle-1"}
	for _, id := range ids {
		if err := stream.Send(&hookmonv1.AgentMessage{Payload: &hookmonv1.AgentMessage_Event{Event: &hookmonv1.HookEvent{
			Id: id, Timestamp: timestamppb.Now(), EventType: hookmonv1.EventType_EVENT_TYPE_DLOPEN,
			Severity: hookmonv1.Severity_SEVERITY_WARN, Pid: 7, ExePath: "/usr/bin/app",
			DlopenDetail: &hookmonv1.DlopenDetail{LibraryPath: "/opt/x.so"},
		}}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range ids {
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("ack for %s: %v", id, err)
		}
		if ack := resp.GetAck(); ack == nil || ack.EventId != id || !ack.Accepted {
			t.Fatalf("ack for %s: %+v", id, resp)
		}
	}

	want := "first_sighting-1 denied-1 lifecycle-1"
	store.mu.Lock()
	var stored []string
	for _, e := range store.events {
		stored = append(stored, e.ID)
	}
	store.mu.Unlock()
	if got := strings.Join(stored, " "); got != want {
		t.Errorf("stored %q, want %q", got, want)
	}
	conn.mu.Lock()
	sent := strings.Join(conn.ids, " ")
	conn.mu.Unlock()
	if sent != want {
		t.Errorf("sent to connectors %q, want %q", sent, want)
	}
	var published []string
	for len(published) < 3 {
		select {
		case e := <-ing.GetEventChannel():
			published = append(published, e.ID)
		case <-time.After(2 * time.Second):
			t.Fatalf("published %v, want 3 events", published)
		}
	}
	select {
	case e := <-ing.GetEventChannel():
		t.Errorf("published a dropped event: %s", e.ID)
	default:
	}
	if got := strings.Join(published, " "); got != want {
		t.Errorf("published %q, want %q", got, want)
	}
	if n := ing.Dropped(); n != 3 {
		t.Errorf("Dropped() = %d, want 3", n)
	}
}

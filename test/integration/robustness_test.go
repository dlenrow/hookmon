package integration_test

// Fix plan step 7f through the real server, PostgreSQL and an enrolled bus:
// AGENT_OFFLINE and AGENT_RECOVERED reach a WebSocket subscriber and a
// connector, and events carry the hostname recorded at enrollment. Like
// enroll_test.go these need HOOKMON_TEST_PG_DSN.

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/connectors"
	"github.com/dlenrow/hookmon/test/enrpki"
)

// robFeed reads a WebSocket feed in the background and keeps every event.
type robFeed struct {
	mu   sync.Mutex
	evts []*event.HookEvent
	err  error
}

func robReadFeed(conn *websocket.Conn) *robFeed {
	f := &robFeed{}
	go func() {
		for {
			var evt event.HookEvent
			if err := conn.ReadJSON(&evt); err != nil {
				f.mu.Lock()
				f.err = err
				f.mu.Unlock()
				return
			}
			f.mu.Lock()
			f.evts = append(f.evts, &evt)
			f.mu.Unlock()
		}
	}()
	return f
}

func (f *robFeed) find(et event.EventType, hostID string) []*event.HookEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*event.HookEvent
	for _, e := range f.evts {
		if e.EventType == et && e.HostID == hostID {
			out = append(out, e)
		}
	}
	return out
}

// TestIntegration_OfflineAndRecoveredReachFeedAndConnector: stopping the
// bus raises AGENT_OFFLINE; starting it again raises AGENT_RECOVERED on its
// first heartbeat, and only on that one. Each is stored once, and reaches a
// WebSocket subscriber and the webhook connector. The webhook is an alert
// connector (min_severity ALERT, the default), and still gets the INFO
// recovery. Two outages give two pairs. Every event carries the hostname
// the host enrolled with, not the one the bus sends.
func TestIntegration_OfflineAndRecoveredReachFeedAndConnector(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	hookRx := siemStartWebhook(t)
	cfg := enrServerConfig(pki, dsn, tok)
	cfg.Connectors = connectors.Config{
		Webhook: &connectors.WebhookConfig{URL: hookRx.URL, Headers: map[string]string{"Authorization": "Bearer siem-test"}},
	}
	s := enrStartServer(t, cfg)
	bus := enrEnroll(t, s, pki, tok.reusable)
	enrolledName, _ := os.Hostname()

	conn, code := dashDial(t, s, pki, "https://"+s.HTTPAddr(), enrAPIToken)
	if code != http.StatusSwitchingProtocols || conn == nil {
		t.Fatalf("WebSocket: status %d", code)
	}
	defer conn.Close()
	feed := robReadFeed(conn)

	limit := cfg.Watchdog.HeartbeatTimeout + cfg.Watchdog.CheckInterval + 5*time.Second
	count := func(et event.EventType) int {
		return len(enrEvents(t, s, "event_type="+string(et)+"&host_id="+bus.HostID))
	}
	// runBus starts the bus, sends a heartbeat and an event whose message
	// names another hostname, and returns the stop func.
	runBus := func(eventID string) func() {
		tr, stop := enrRunBus(t, bus, nil)
		if err := tr.SendHeartbeat(); err != nil {
			t.Fatal(err)
		}
		evt := enrEvent(eventID)
		evt.Hostname = "not-the-enrolled-name"
		// Its own program, so each round's event is a first sighting and
		// stored, not a repeat of the last round's.
		evt.BPFDetail = &event.BPFDetail{ProgName: eventID}
		if err := tr.SendEvent(evt); err != nil {
			t.Fatal(err)
		}
		enrWaitFor(t, 10*time.Second, "event "+eventID+" in the store", func() bool {
			return enrGet(t, s, "/api/v1/events/"+eventID, nil) == http.StatusOK
		})
		return func() {
			if err := tr.SendHeartbeat(); err != nil { // a second heartbeat: no second recovery
				t.Fatal(err)
			}
			time.Sleep(300 * time.Millisecond)
			stop()
		}
	}

	for round := 1; round <= 2; round++ {
		stop := runBus("rob-hostname-" + string(rune('0'+round)))
		if round == 2 {
			// The first heartbeat after the round 1 outage.
			enrWaitFor(t, 10*time.Second, "AGENT_RECOVERED in the store", func() bool { return count(event.EventAgentRecovered) == 1 })
		}
		if h := enrHost(t, s, bus.HostID); h.Status != event.HostOnline {
			t.Errorf("round %d: host status %s while the bus runs", round, h.Status)
		}
		stop()
		stopped := time.Now()
		enrWaitFor(t, limit, "AGENT_OFFLINE in the store", func() bool { return count(event.EventAgentOffline) == round })
		t.Logf("round %d: AGENT_OFFLINE stored %v after the bus stopped", round, time.Since(stopped).Round(10*time.Millisecond))
		if n := count(event.EventAgentRecovered); n != round-1 {
			t.Errorf("round %d: %d AGENT_RECOVERED stored, want %d", round, n, round-1)
		}
	}
	// The bus comes back after the second outage.
	tr, _ := enrRunBus(t, bus, nil)
	restarted := time.Now()
	if err := tr.SendHeartbeat(); err != nil {
		t.Fatal(err)
	}
	enrWaitFor(t, 10*time.Second, "the second AGENT_RECOVERED", func() bool { return count(event.EventAgentRecovered) == 2 })
	t.Logf("AGENT_RECOVERED stored %v after the bus restarted", time.Since(restarted).Round(10*time.Millisecond))

	offline := enrEvents(t, s, "event_type=AGENT_OFFLINE&host_id="+bus.HostID)
	recovered := enrEvents(t, s, "event_type=AGENT_RECOVERED&host_id="+bus.HostID)
	if len(offline) != 2 || len(recovered) != 2 {
		t.Fatalf("stored: %d AGENT_OFFLINE, %d AGENT_RECOVERED; want 2 of each", len(offline), len(recovered))
	}
	for _, e := range append(offline, recovered...) {
		if e.Hostname != enrolledName {
			t.Errorf("%s %s: hostname %q, want the enrolled %q", e.EventType, e.ID, e.Hostname, enrolledName)
		}
	}
	for _, e := range recovered {
		if e.Severity != event.SeverityInfo || e.PolicyResult == nil || !strings.Contains(e.PolicyResult.Reason, "UNRESPONSIVE") {
			t.Errorf("AGENT_RECOVERED %+v %+v", e, e.PolicyResult)
		}
	}

	// The WebSocket subscriber and the webhook each got every one of them.
	enrWaitFor(t, 10*time.Second, "status events on the WebSocket feed", func() bool {
		return len(feed.find(event.EventAgentOffline, bus.HostID)) == 2 && len(feed.find(event.EventAgentRecovered, bus.HostID)) == 2
	})
	enrWaitFor(t, 10*time.Second, "status events at the webhook", func() bool {
		return len(hookRx.find(func(e *event.HookEvent) bool {
			return e.HostID == bus.HostID && e.EventType == event.EventAgentOffline
		})) == 2 && len(hookRx.find(func(e *event.HookEvent) bool {
			return e.HostID == bus.HostID && e.EventType == event.EventAgentRecovered
		})) == 2
	})
	for _, want := range append(offline, recovered...) {
		if got := hookRx.byID(want.ID); len(got) != 1 {
			t.Errorf("%s %s reached the webhook %d times", want.EventType, want.ID, len(got))
		}
	}

	// The bus's events carry the enrolled hostname too.
	for _, id := range []string{"rob-hostname-1", "rob-hostname-2"} {
		var got event.HookEvent
		if code := enrGet(t, s, "/api/v1/events/"+id, &got); code != http.StatusOK {
			t.Fatalf("GET event %s: %d", id, code)
		}
		if got.Hostname != enrolledName || got.HostID != bus.HostID {
			t.Errorf("event %s: host %s %q, want %s %q", id, got.HostID, got.Hostname, bus.HostID, enrolledName)
		}
	}
	if code := enrGet(t, s, "/api/v1/events/no-such-event", nil); code != http.StatusNotFound {
		t.Errorf("missing event: %d, want 404", code)
	}
}

package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/agent/config"
	"github.com/dlenrow/hookmon/agent/observability"
	"github.com/dlenrow/hookmon/agent/registry"
	"github.com/dlenrow/hookmon/agent/sensors"
	"github.com/dlenrow/hookmon/pkg/event"
)

type chanSensor struct{ ch chan *event.HookEvent }

func (s *chanSensor) Name() string                    { return "ptrace_monitor" }
func (s *chanSensor) Type() sensors.SensorType        { return sensors.SensorTypeBPF }
func (s *chanSensor) Start() error                    { return nil }
func (s *chanSensor) Stop() error                     { return nil }
func (s *chanSensor) Events() <-chan *event.HookEvent { return s.ch }

type recordingTransport struct {
	mu   sync.Mutex
	sent []*event.HookEvent
	got  chan struct{}
}

func (t *recordingTransport) Run(ctx context.Context) error { <-ctx.Done(); return nil }
func (t *recordingTransport) SendHeartbeat() error          { return nil }
func (t *recordingTransport) IsConnected() bool             { return true }
func (t *recordingTransport) Close() error                  { return nil }
func (t *recordingTransport) SendEvent(evt *event.HookEvent) error {
	t.mu.Lock()
	t.sent = append(t.sent, evt)
	t.mu.Unlock()
	t.got <- struct{}{}
	return nil
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func scrape(t *testing.T, port int) string {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	var lastErr error
	for i := 0; i < 50; i++ {
		resp, err := http.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return string(body)
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("scrape %s: %v", url, lastErr)
	return ""
}

// Events from the bus itself and from its probe children must be dropped
// before they reach the transport or hookmon_events_total. Otherwise the
// probes would count as activity and the "no events in 24h" alert could
// never fire.
func TestProbeEventsNotSentOrCounted(t *testing.T) {
	const busPID = 5000000 // above any pid_max, so enrichment finds nothing

	port := freePort(t)
	m, err := observability.NewMetricsOn("127.0.0.1", port, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	cfg := config.DefaultConfig()
	cfg.Sensors.ElfRpath = false
	tr := &recordingTransport{got: make(chan struct{}, 10)}
	a := &Agent{
		cfg:        cfg,
		logger:     zap.NewNop(),
		transport:  tr,
		registry:   registry.New([]string{"ptrace_monitor"}),
		rpathCache: sensors.NewRpathCache(10),
		filter:     probeFilter{self: busPID},
		metrics:    m,
	}
	s := &chanSensor{ch: make(chan *event.HookEvent, 10)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.wg.Add(1)
	go a.forwardEvents(ctx, s)

	mk := func(pid, ppid uint32, comm string) *event.HookEvent {
		return &event.HookEvent{
			EventType: event.EventPtraceInject, Severity: event.SeverityAlert,
			PID: pid, PPID: ppid, Comm: comm,
		}
	}
	s.ch <- mk(busPID, 1, "hookmon-bus")          // the bus itself
	s.ch <- mk(busPID+1, busPID, "hookmon-probe") // a probe child
	s.ch <- mk(busPID+2, 1, "attacker")           // a real detection

	// forwardEvents handles events in order, so once the real detection
	// arrives the two probe events have already been handled.
	select {
	case <-tr.got:
	case <-time.After(5 * time.Second):
		t.Fatal("real event never reached the transport")
	}
	select {
	case <-tr.got:
		t.Fatal("more than one event reached the transport")
	case <-time.After(100 * time.Millisecond):
	}
	tr.mu.Lock()
	if len(tr.sent) != 1 || tr.sent[0].Comm != "attacker" {
		t.Errorf("transport got %d events, want only the attacker's", len(tr.sent))
	}
	tr.mu.Unlock()

	text := scrape(t, port)
	if !strings.Contains(text, `comm="attacker",event_type="PTRACE_INJECT",severity="ALERT"} 1`) {
		t.Errorf("hookmon_events_total missing the real event:\n%s", grepLines(text, "hookmon_events_total"))
	}
	for _, comm := range []string{"hookmon-bus", "hookmon-probe"} {
		if strings.Contains(text, `comm="`+comm+`"`) {
			t.Errorf("hookmon_events_total counted a %s event:\n%s", comm, grepLines(text, "hookmon_events_total"))
		}
	}
}

func grepLines(text, substr string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, substr) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

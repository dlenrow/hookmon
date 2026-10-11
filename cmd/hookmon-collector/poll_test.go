package main

// The collector's HTTP poll path (fix plan step 7h): it polls each bus's
// real /status handler, writes the fleet summary file and pushes the fleet
// metrics to a Pushgateway. The buses and the Pushgateway are httptest
// servers.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/dlenrow/hookmon/agent/observability"
	"github.com/dlenrow/hookmon/agent/registry"
)

// t7hBus serves a real bus /status handler for a registry in which the
// sensors named in alive have beaten and the rest failed to start.
func t7hBus(t *testing.T, sensors []string, alive ...string) *httptest.Server {
	t.Helper()
	reg := registry.New(sensors)
	beats := map[string]bool{}
	for _, s := range alive {
		reg.Beat(s)
		beats[s] = true
	}
	for _, s := range sensors {
		if !beats[s] {
			reg.Fail(s, "test: not started")
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/status", observability.StatusHandler(reg, "bus", "v-test"))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// t7hGateway records what is pushed to it.
type t7hGateway struct {
	mu     sync.Mutex
	pushes []t7hPush
	status int
}

type t7hPush struct {
	method, path, contentType, body string
}

func (g *t7hGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	g.pushes = append(g.pushes, t7hPush{r.Method, r.URL.Path, r.Header.Get("Content-Type"), string(b)})
	status := g.status
	g.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
}

func (g *t7hGateway) last(t *testing.T) t7hPush {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.pushes) == 0 {
		t.Fatal("nothing was pushed to the Pushgateway")
	}
	return g.pushes[len(g.pushes)-1]
}

func t7hLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.DebugLevel)
	return zap.New(core), logs
}

// TestPollAll_FleetSummaryAndPush: three reachable buses (alive, one
// sensor failed, every sensor failed) and four unreachable hosts (HTTP 500,
// a body that is not JSON, no address configured, nothing listening). The
// fleet file and the pushed metrics must agree with each host's state.
func TestPollAll_FleetSummaryAndPush(t *testing.T) {
	sensors := []string{"bpf_syscall", "exec_injection"}
	alive := t7hBus(t, sensors, sensors...)
	degraded := t7hBus(t, sensors, "bpf_syscall")
	dead := t7hBus(t, sensors)
	fail500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer fail500.Close()
	notJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html>not a bus</html>")
	}))
	defer notJSON.Close()
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close()

	gw := &t7hGateway{}
	gwSrv := httptest.NewServer(gw)
	defer gwSrv.Close()

	statusFile := filepath.Join(t.TempDir(), "fleet-status.json")
	cfg := &CollectorConfig{
		PollInterval:    time.Hour,
		PushGateway:     gwSrv.URL + "/",
		FleetStatusFile: statusFile,
		Hosts: []HostConfig{
			{Hostname: "alive", StatusURL: alive.URL + "/status"},
			{Hostname: "degraded", StatusURL: degraded.URL + "/status"},
			{Hostname: "dead", StatusURL: dead.URL + "/status"},
			{Hostname: "http500", StatusURL: fail500.URL + "/status"},
			{Hostname: "notjson", StatusURL: notJSON.URL + "/status"},
			{Hostname: "unconfigured"},
			{Hostname: "gone", StatusURL: goneURL + "/status"},
		},
	}
	logger, logs := t7hLogger()
	pollAll(context.Background(), cfg, logger)

	raw, err := os.ReadFile(statusFile)
	if err != nil {
		t.Fatalf("fleet status file: %v", err)
	}
	var fleet FleetStatus
	if err := json.Unmarshal(raw, &fleet); err != nil {
		t.Fatalf("fleet status JSON: %v\n%s", err, raw)
	}
	// A reachable bus that is not fully alive counts as degraded, "dead"
	// included; its per-host status says which.
	if fleet.TotalHosts != 7 || fleet.AliveHosts != 1 || fleet.DegradedHosts != 2 || fleet.UnreachableHosts != 4 {
		t.Errorf("fleet counts: total %d alive %d degraded %d unreachable %d; want 7, 1, 2, 4",
			fleet.TotalHosts, fleet.AliveHosts, fleet.DegradedHosts, fleet.UnreachableHosts)
	}
	if time.Since(fleet.PollTime) > time.Minute || fleet.PollTime.Location() != time.UTC {
		t.Errorf("poll time %v", fleet.PollTime)
	}
	want := []struct {
		host, overall, errPart string
		reachable              bool
		sensors                int
	}{
		{"alive", "alive", "", true, 2},
		{"degraded", "degraded", "", true, 2},
		{"dead", "dead", "", true, 2},
		{"http500", "", "HTTP 500", false, 0},
		{"notjson", "", "invalid status JSON", false, 0},
		{"unconfigured", "", "no status_url or ssh_host configured", false, 0},
		{"gone", "", "connect", false, 0},
	}
	if len(fleet.Hosts) != len(want) {
		t.Fatalf("%d hosts in the file, want %d", len(fleet.Hosts), len(want))
	}
	for i, w := range want {
		h := fleet.Hosts[i]
		if h.Hostname != w.host || h.Reachable != w.reachable || h.Overall != w.overall || len(h.Sensors) != w.sensors ||
			!strings.Contains(h.Error, w.errPart) || (w.errPart == "" && h.Error != "") {
			t.Errorf("host %d: %+v; want %+v", i, h, w)
		}
		if w.reachable && h.BusVersion != "v-test" {
			t.Errorf("%s: bus version %q", h.Hostname, h.BusVersion)
		}
	}

	p := gw.last(t)
	if p.method != http.MethodPost || p.path != "/metrics/job/hookmon-collector" || p.contentType != "text/plain" {
		t.Errorf("push: %s %s (%s)", p.method, p.path, p.contentType)
	}
	for _, line := range []string{
		"hookmon_fleet_hosts_total 7",
		"hookmon_fleet_hosts_alive 1",
		"hookmon_fleet_hosts_degraded 2",
		"hookmon_fleet_hosts_unreachable 4",
		`hookmon_fleet_host_reachable{host="alive"} 1`,
		`hookmon_fleet_host_reachable{host="gone"} 0`,
		`hookmon_fleet_host_status{host="alive",status="alive"} 1`,
		`hookmon_fleet_host_status{host="degraded",status="degraded"} 1`,
		`hookmon_fleet_host_status{host="degraded",status="alive"} 0`,
		`hookmon_fleet_host_status{host="dead",status="dead"} 1`,
		`hookmon_fleet_host_status{host="http500",status="dead"} 0`,
		`hookmon_fleet_sensor_alive{host="alive",sensor="exec_injection"} 1`,
		`hookmon_fleet_sensor_alive{host="degraded",sensor="bpf_syscall"} 1`,
		`hookmon_fleet_sensor_alive{host="degraded",sensor="exec_injection"} 0`,
	} {
		if !strings.Contains("\n"+p.body, "\n"+line+"\n") {
			t.Errorf("pushed metrics lack %q", line)
		}
	}
	// Every sample line is "name{labels} value" or "name value", after its
	// HELP and TYPE.
	declared := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(p.body), "\n") {
		if f := strings.Fields(l); len(f) >= 3 && f[0] == "#" && f[1] == "TYPE" {
			declared[f[2]] = true
			continue
		}
		if strings.HasPrefix(l, "#") {
			continue
		}
		name := l
		if i := strings.IndexAny(l, "{ "); i >= 0 {
			name = l[:i]
		}
		if !declared[name] {
			t.Errorf("sample before its TYPE line: %q", l)
		}
	}
	if logs.FilterMessage("host unreachable").Len() != 2 {
		t.Errorf("want 2 'host unreachable' warnings (HTTP 500 and nothing listening), got %d", logs.FilterMessage("host unreachable").Len())
	}
}

// TestPollAll_NoPushGateway: without push_gateway the collector only
// writes the file.
func TestPollAll_NoPushGateway(t *testing.T) {
	bus := t7hBus(t, []string{"bpf_syscall"}, "bpf_syscall")
	statusFile := filepath.Join(t.TempDir(), "fleet.json")
	logger, logs := t7hLogger()
	pollAll(context.Background(), &CollectorConfig{
		FleetStatusFile: statusFile,
		Hosts:           []HostConfig{{Hostname: "a", StatusURL: bus.URL + "/status"}},
	}, logger)
	if _, err := os.Stat(statusFile); err != nil {
		t.Fatal(err)
	}
	if n := logs.FilterMessageSnippet("pushgateway").Len(); n != 0 {
		t.Errorf("%d pushgateway log lines without a push_gateway", n)
	}
}

// TestPushToGateway_Failures: a Pushgateway that answers with an error, or
// is not there, is logged and does not stop the collector.
func TestPushToGateway_Failures(t *testing.T) {
	fleet := &FleetStatus{TotalHosts: 1, Hosts: []HostResult{{Hostname: "a"}}}

	gw := &t7hGateway{status: http.StatusBadRequest}
	srv := httptest.NewServer(gw)
	defer srv.Close()
	logger, logs := t7hLogger()
	pushToGateway(srv.URL, fleet, logger)
	if e := logs.FilterMessage("pushgateway returned error").All(); len(e) != 1 || e[0].ContextMap()["status"] != int64(http.StatusBadRequest) {
		t.Errorf("error status: %v", e)
	}

	srv.Close()
	logger, logs = t7hLogger()
	pushToGateway(srv.URL, fleet, logger)
	if logs.FilterMessage("pushgateway push failed").Len() != 1 {
		t.Errorf("unreachable gateway was not logged: %v", logs.All())
	}
}

// TestWriteFleetStatus_Unwritable: a file that cannot be written is logged.
func TestWriteFleetStatus_Unwritable(t *testing.T) {
	logger, logs := t7hLogger()
	path := filepath.Join(t.TempDir(), "no-such-dir", "fleet.json")
	writeFleetStatus(path, &FleetStatus{}, logger)
	if e := logs.FilterMessage("failed to write fleet status file").All(); len(e) != 1 || e[0].ContextMap()["path"] != path {
		t.Errorf("unwritable file: %v", logs.All())
	}
}

// TestRunPollLoop_PollsUntilCancelled: the loop polls at once, then every
// interval, and returns when its context ends.
func TestRunPollLoop_PollsUntilCancelled(t *testing.T) {
	var polls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if polls.Add(1) == 3 {
			cancel()
		}
		io.WriteString(w, `{"overall":"alive","sensors":[]}`)
	}))
	defer srv.Close()
	cfg := &CollectorConfig{
		PollInterval:    20 * time.Millisecond,
		FleetStatusFile: filepath.Join(t.TempDir(), "fleet.json"),
		Hosts:           []HostConfig{{Hostname: "a", StatusURL: srv.URL}},
	}
	done := make(chan struct{})
	go func() {
		runPollLoop(ctx, cfg, zap.NewNop())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("runPollLoop did not return after cancel; %d polls", polls.Load())
	}
	if n := polls.Load(); n < 3 {
		t.Errorf("%d polls, want at least 3", n)
	}
}

// TestPollHost_HTTPCancelled: a poll whose context ends fails at once
// rather than waiting for a hung bus.
func TestPollHost_HTTPCancelled(t *testing.T) {
	hung := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hung:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(hung)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := pollHost(ctx, HostConfig{Hostname: "hung", StatusURL: srv.URL}, zap.NewNop())
	if r.Reachable || !strings.Contains(r.Error, "context deadline exceeded") {
		t.Errorf("hung bus: %+v", r)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("poll took %v", d)
	}
}

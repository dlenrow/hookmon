//go:build linux && e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/agent/observability"
	"github.com/dlenrow/hookmon/agent/registry"
)

// Heartbeat and tamper-detection tests (fix plan step 3). Each test runs its
// own bus on its own status port so they never collide with the bus on 2112.

// expectedSensors is every sensor enabled by default.
var expectedSensors = []string{
	"bpf_syscall", "exec_injection", "shm_monitor", "dlopen_monitor",
	"linker_config", "ptrace_monitor", "lib_integrity", "elf_rpath",
}

func getStatus(port string) (*observability.StatusResponse, error) {
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var st observability.StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	return &st, nil
}

func sensorMap(st *observability.StatusResponse) map[string]registry.SensorStatus {
	m := make(map[string]registry.SensorStatus, len(st.Sensors))
	for _, s := range st.Sensors {
		m[s.Name] = s
	}
	return m
}

func describe(st *observability.StatusResponse) string {
	var parts []string
	for _, s := range st.Sensors {
		p := s.Name + "=" + s.Status
		if s.Reason != "" {
			p += "(" + s.Reason + ")"
		}
		parts = append(parts, p)
	}
	return st.Overall + " [" + strings.Join(parts, " ") + "]"
}

// waitStatus polls /status every 500 ms until cond holds or timeout passes.
func waitStatus(t *testing.T, port string, timeout time.Duration, cond func(*observability.StatusResponse) bool) *observability.StatusResponse {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last *observability.StatusResponse
	var lastErr error
	for time.Now().Before(deadline) {
		st, err := getStatus(port)
		if err == nil && cond(st) {
			return st
		}
		last, lastErr = st, err
		time.Sleep(500 * time.Millisecond)
	}
	if last != nil {
		t.Fatalf("status condition not met within %v; last status: %s", timeout, describe(last))
	}
	t.Fatalf("status condition not met within %v; last error: %v", timeout, lastErr)
	return nil
}

func allAlive(st *observability.StatusResponse) bool {
	if st.Overall != "alive" || len(st.Sensors) != len(expectedSensors) {
		return false
	}
	m := sensorMap(st)
	for _, n := range expectedSensors {
		if m[n].Status != registry.StatusAlive {
			return false
		}
	}
	return true
}

// busLink returns the ID of the BPF link the bus process holds for the named
// program, read from /proc/<pid>/fdinfo. bpftool on Ubuntu's 5.19 kernel
// does not list owning PIDs for links, and other buses on the host load
// programs with the same names.
func busLink(t *testing.T, pid int, progName string) string {
	t.Helper()
	fdDir := fmt.Sprintf("/proc/%d/fdinfo", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		t.Fatalf("read %s: %v", fdDir, err)
	}
	// The kernel truncates object names to 15 characters; bpftool shows the
	// full name when the program carries BTF.
	short := progName
	if len(short) > 15 {
		short = short[:15]
	}
	for _, e := range entries {
		f, err := os.Open(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		var linkID, progID string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) == 2 && fields[0] == "link_id:" {
				linkID = fields[1]
			}
			if len(fields) == 2 && fields[0] == "prog_id:" {
				progID = fields[1]
			}
		}
		f.Close()
		if linkID == "" || progID == "" {
			continue
		}
		out, err := exec.Command("bpftool", "-j", "prog", "show", "id", progID).Output()
		if err != nil {
			continue
		}
		var info struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(out, &info) == nil && (info.Name == progName || info.Name == short) {
			return linkID
		}
	}
	t.Fatalf("bus pid %d holds no link for program %s", pid, progName)
	return ""
}

// TestHeartbeat_IdleAllAlive: an idle host shows every sensor alive, with no
// flap, for 10 minutes (HOOKMON_E2E_IDLE_DURATION overrides), and none of
// the bus's probes shows up as an event.
func TestHeartbeat_IdleAllAlive(t *testing.T) {
	if os.Getenv("HOOKMON_E2E_LONG") != "1" {
		t.Skip("set HOOKMON_E2E_LONG=1 to run the 10-minute idle test")
	}
	duration := 10 * time.Minute
	if v := os.Getenv("HOOKMON_E2E_IDLE_DURATION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("HOOKMON_E2E_IDLE_DURATION: %v", err)
		}
		duration = d
	}
	const port = "2194"
	bus, err := StartBusArgs(busBin(), "--status-port", port)
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()
	pid := uint32(bus.PID())

	// Drain events for the whole run; count any caused by the bus itself.
	selfEvents, total := make(chan int, 1), make(chan int, 1)
	stopDrain := make(chan struct{})
	go func() {
		n, all := 0, 0
		for {
			select {
			case evt := <-bus.events:
				all++
				if evt.PID == pid || evt.PPID == pid {
					n++
					t.Logf("bus-caused event leaked: %s pid=%d ppid=%d comm=%s", evt.EventType, evt.PID, evt.PPID, evt.Comm)
				}
			case <-stopDrain:
				selfEvents <- n
				total <- all
				return
			}
		}
	}()

	waitStatus(t, port, 20*time.Second, allAlive)
	start := time.Now()
	polls := 0
	for time.Since(start) < duration {
		time.Sleep(5 * time.Second)
		st, err := getStatus(port)
		if err != nil {
			t.Fatalf("after %v: /status: %v", time.Since(start).Round(time.Second), err)
		}
		polls++
		if !allAlive(st) {
			t.Fatalf("after %v (poll %d): not all alive: %s", time.Since(start).Round(time.Second), polls, describe(st))
		}
	}
	close(stopDrain)
	if n := <-selfEvents; n != 0 {
		t.Errorf("%d events were caused by the bus or its probe children", n)
	}
	t.Logf("PASS: all %d sensors alive at every one of %d polls over %v; %d host events seen, 0 from the bus or its probes",
		len(expectedSensors), polls, duration, <-total)
}

// TestHeartbeat_LinkDetach runs the plan's tamper action, `bpftool link
// detach`, against the bus's ptrace_monitor link. If the kernel detaches it,
// ptrace_monitor must be reported dead within 30 s while the rest stay
// alive. Kernels that refuse BPF_LINK_DETACH for perf_event links (5.19
// returns EOPNOTSUPP) leave the hook running; then the sensor must stay
// alive, and the dead path is left to the agent unit tests.
func TestHeartbeat_LinkDetach(t *testing.T) {
	const port = "2191"
	bus, err := StartBusArgs(busBin(), "--status-port", port)
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()
	waitStatus(t, port, 20*time.Second, allAlive)

	linkID := busLink(t, bus.PID(), "trace_ptrace_enter")
	detachAt := time.Now()
	out, err := exec.Command("bpftool", "link", "detach", "id", linkID).CombinedOutput()
	result := strings.TrimSpace(string(out))
	t.Logf("bpftool link detach id %s: err=%v output=%q", linkID, err, result)

	if err == nil {
		st := waitStatus(t, port, 30*time.Second, func(st *observability.StatusResponse) bool {
			return sensorMap(st)["ptrace_monitor"].Status == registry.StatusDead
		})
		elapsed := time.Since(detachAt)
		m := sensorMap(st)
		for _, n := range expectedSensors {
			if n != "ptrace_monitor" && m[n].Status != registry.StatusAlive {
				t.Errorf("%s: %s, want alive", n, m[n].Status)
			}
		}
		t.Logf("PASS: ptrace_monitor dead %v after detach (%s)", elapsed.Round(time.Millisecond), m["ptrace_monitor"].Reason)
		return
	}

	if !strings.Contains(result, "Operation not supported") {
		t.Fatalf("bpftool link detach failed unexpectedly: %v: %s", err, result)
	}
	// Nothing was detached. Two missed checks would mark the sensor dead
	// within 20 s, so check it is still alive after 21 s.
	time.Sleep(21 * time.Second)
	st, err := getStatus(port)
	if err != nil {
		t.Fatalf("/status: %v", err)
	}
	if !allAlive(st) {
		t.Fatalf("detach was refused but status is %s", describe(st))
	}
	t.Skipf("kernel refused BPF_LINK_DETACH for the perf_event link (%q); the hook kept running and "+
		"ptrace_monitor stayed alive, which is correct. Detach-to-dead cannot be exercised on this kernel.", result)
}

// TestHeartbeat_KillBusCollectorUnreachable: kill -9 on the bus makes
// hookmon-collector report the host unreachable within one poll.
func TestHeartbeat_KillBusCollectorUnreachable(t *testing.T) {
	const port = "2192"
	const pollInterval = 2 * time.Second
	bus, err := StartBusArgs(busBin(), "--status-port", port)
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()
	waitStatus(t, port, 20*time.Second, allAlive)

	dir := t.TempDir()
	fleetFile := filepath.Join(dir, "fleet.json")
	cfgFile := filepath.Join(dir, "collector.yaml")
	cfg := fmt.Sprintf("poll_interval: %s\nfleet_status_file: %s\nhosts:\n  - hostname: e2e-bus\n    status_url: http://127.0.0.1:%s/status\n",
		pollInterval, fleetFile, port)
	if err := os.WriteFile(cfgFile, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	coll := exec.Command(collectorBin(t), "--config", cfgFile)
	coll.Stderr = os.Stderr
	if err := coll.Start(); err != nil {
		t.Fatalf("start collector: %v", err)
	}
	defer func() {
		coll.Process.Kill()
		coll.Wait()
	}()

	type fleet struct {
		PollTime time.Time `json:"poll_time"`
		Hosts    []struct {
			Reachable bool   `json:"reachable"`
			Overall   string `json:"overall"`
			Error     string `json:"error"`
		} `json:"hosts"`
	}
	readFleet := func() (*fleet, error) {
		data, err := os.ReadFile(fleetFile)
		if err != nil {
			return nil, err
		}
		var f fleet
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, err
		}
		if len(f.Hosts) != 1 {
			return nil, fmt.Errorf("fleet has %d hosts", len(f.Hosts))
		}
		return &f, nil
	}
	waitFleet := func(timeout time.Duration, cond func(*fleet) bool) *fleet {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if f, err := readFleet(); err == nil && cond(f) {
				return f
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("collector fleet status condition not met within %v", timeout)
		return nil
	}

	waitFleet(10*time.Second, func(f *fleet) bool { return f.Hosts[0].Reachable && f.Hosts[0].Overall == "alive" })

	killAt := time.Now()
	if err := syscall.Kill(bus.PID(), syscall.SIGKILL); err != nil {
		t.Fatalf("kill -9 bus: %v", err)
	}
	f := waitFleet(3*pollInterval, func(f *fleet) bool { return !f.Hosts[0].Reachable && f.PollTime.After(killAt) })
	elapsed := f.PollTime.Sub(killAt)
	if elapsed > pollInterval+time.Second {
		t.Errorf("collector reported unreachable %v after kill -9, want within one poll (%v)", elapsed, pollInterval)
	}
	t.Logf("PASS: collector reported host unreachable %v after kill -9 (poll interval %v): %s",
		elapsed.Round(time.Millisecond), pollInterval, f.Hosts[0].Error)
}

// collectorBin returns HOOKMON_COLLECTOR_BIN, bin/hookmon-collector from
// `make build-all`, or a freshly built collector.
func collectorBin(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("HOOKMON_COLLECTOR_BIN"); v != "" {
		return v
	}
	if p, err := filepath.Abs("../../bin/hookmon-collector"); err == nil {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	out := filepath.Join(t.TempDir(), "hookmon-collector")
	build := exec.Command("go", "build", "-o", out, "github.com/dlenrow/hookmon/cmd/hookmon-collector")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build collector: %v", err)
	}
	return out
}

// TestHeartbeat_DlopenProbeMissing: without the dlopen helper the bus cannot
// fire the dlopen uprobe, so dlopen_monitor is reported unverifiable with a
// reason, never alive, and the host is degraded.
func TestHeartbeat_DlopenProbeMissing(t *testing.T) {
	const port = "2193"
	const missing = "/nonexistent/hookmon-dlopen-probe"
	bus, err := StartBusArgs(busBin(), "--status-port", port, "--dlopen-probe", missing)
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	st := waitStatus(t, port, 20*time.Second, func(st *observability.StatusResponse) bool {
		m := sensorMap(st)
		for _, n := range expectedSensors {
			if n != "dlopen_monitor" && m[n].Status != registry.StatusAlive {
				return false
			}
		}
		return m["dlopen_monitor"].Status == registry.StatusUnverifiable
	})
	d := sensorMap(st)["dlopen_monitor"]
	if !strings.Contains(d.Reason, missing) {
		t.Errorf("dlopen_monitor reason %q does not name the missing helper", d.Reason)
	}
	if st.Overall != "degraded" {
		t.Errorf("overall = %s, want degraded", st.Overall)
	}

	// It must stay unverifiable, not drift to alive from other processes'
	// dlopen calls.
	time.Sleep(11 * time.Second)
	st, err = getStatus(port)
	if err != nil {
		t.Fatalf("/status: %v", err)
	}
	if s := sensorMap(st)["dlopen_monitor"].Status; s != registry.StatusUnverifiable {
		t.Errorf("dlopen_monitor after another cycle = %s, want unverifiable", s)
	}
	t.Logf("PASS: %s", describe(st))
}

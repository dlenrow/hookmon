//go:build linux && e2e

package e2e

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/agent/suppress"
	"github.com/dlenrow/hookmon/pkg/event"
)

// The bus reports only what could be a stealth hook. These tests check each
// source filter both ways: the harmless case is dropped and counted in
// hookmon_events_suppressed_total, and the dangerous one is still reported.
// A busy host adds its own suppressions to the counts, so a test asserts
// that its own event is absent; the count only has to move.

// suppressedCount returns hookmon_events_suppressed_total{sensor,reason}
// from the /metrics of the bus serving status on port, or 0 before the bus
// has counted one.
func suppressedCount(t *testing.T, port, sensor, reason string) float64 {
	t.Helper()
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	const name = "hookmon_events_suppressed_total{"
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		labels, value, ok := strings.Cut(strings.TrimPrefix(line, name), "} ")
		if !strings.HasPrefix(line, name) || !ok ||
			!strings.Contains(labels, `sensor="`+sensor+`"`) || !strings.Contains(labels, `reason="`+reason+`"`) {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		return v
	}
	return 0
}

// waitSuppressed waits until the count is above before.
func waitSuppressed(t *testing.T, port, sensor, reason string, before float64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for suppressedCount(t, port, sensor, reason) <= before {
		if time.Now().After(deadline) {
			t.Fatalf("%s counted no %s suppression within %s", sensor, reason, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// noEvent fails if the bus reported an event match accepts within wait.
func noEvent(t *testing.T, bus *BusProcess, what string, wait time.Duration, match func(*event.HookEvent) bool) {
	t.Helper()
	if e, err := bus.WaitForEvent(match, wait); err == nil {
		t.Errorf("%s was reported: pid %d comm %s severity %s", what, e.PID, e.Comm, e.Severity)
	}
}

func execInjLibraryPath(pid uint32, value string) func(*event.HookEvent) bool {
	return func(e *event.HookEvent) bool {
		return e.EventType == event.EventExecInjection && e.PID == pid && e.ExecInjectionDetail != nil &&
			e.ExecInjectionDetail.EnvVar == "LD_LIBRARY_PATH" && e.ExecInjectionDetail.LibraryPath == value
	}
}

// TestSignal_LibraryPathRiskyIsReported: an LD_LIBRARY_PATH with an entry a
// non-root user could fill is reported, including containerd's
// "/opt/containerd/lib:", whose empty entry is the working directory.
func TestSignal_LibraryPathRiskyIsReported(t *testing.T) {
	bus := startFileBus(t, "2201", "exec_injection")
	for _, value := range []string{"/opt/containerd/lib:", "/usr/lib:/tmp/hookmon-e2e", "/usr/lib::/usr/share"} {
		pid := execInjRun(t, []string{"LD_LIBRARY_PATH=" + value})
		if _, err := bus.WaitForEvent(execInjLibraryPath(pid, value), 15*time.Second); err != nil {
			t.Errorf("LD_LIBRARY_PATH=%s not reported: %v", value, err)
		}
	}
}

// TestSignal_LibraryPathSafeIsSuppressed: an LD_LIBRARY_PATH of standard and
// root-only directories is dropped and counted.
func TestSignal_LibraryPathSafeIsSuppressed(t *testing.T) {
	const port = "2202"
	bus := startFileBus(t, port, "exec_injection")
	before := suppressedCount(t, port, "exec_injection", suppress.SafeSearchPath)
	value := "/usr/lib:/usr/share"
	pid := execInjRun(t, []string{"LD_LIBRARY_PATH=" + value})
	waitSuppressed(t, port, "exec_injection", suppress.SafeSearchPath, before, 15*time.Second)
	noEvent(t, bus, "LD_LIBRARY_PATH="+value, 2*time.Second, execInjLibraryPath(pid, value))

	// LD_PRELOAD is always reported, even of a system library.
	lib, _ := execInjLib(t)
	pid = execInjRun(t, []string{"LD_PRELOAD=" + lib})
	if _, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventExecInjection && e.PID == pid && e.ExecInjectionDetail != nil &&
			e.ExecInjectionDetail.EnvVar == "LD_PRELOAD"
	}, 15*time.Second); err != nil {
		t.Errorf("LD_PRELOAD not reported: %v", err)
	}
}

func dlopenOf(path string) func(*event.HookEvent) bool {
	return func(e *event.HookEvent) bool {
		return e.EventType == event.EventDlopen && e.DlopenDetail != nil && e.DlopenDetail.LibraryPath == path
	}
}

// signalHostLibm returns the host's libm, a library only root can change.
func signalHostLibm(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/usr/lib/x86_64-linux-gnu/libm.so.6", "/usr/lib64/libm.so.6", "/usr/lib/aarch64-linux-gnu/libm.so.6"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no libm at a known path")
	return ""
}

// TestSignal_DlopenRootOnlyIsSuppressed: a dlopen of a library only root
// can change is dropped and counted; the same library copied into a
// directory another user owns is reported.
func TestSignal_DlopenRootOnlyIsSuppressed(t *testing.T) {
	const port = "2203"
	bus := startFileBus(t, port, "dlopen_monitor")
	canary := canaryBinDir() + "/dlopen_canary"

	libm := signalHostLibm(t)
	before := suppressedCount(t, port, "dlopen_monitor", suppress.RootOnlyDirectory)
	if err := RunCanaryBinary(canary, libm); err != nil {
		t.Fatalf("dlopen_canary %s: %v", libm, err)
	}
	waitSuppressed(t, port, "dlopen_monitor", suppress.RootOnlyDirectory, before, 15*time.Second)
	noEvent(t, bus, "dlopen of "+libm, 2*time.Second, dlopenOf(libm))

	// A directory owned by nobody, outside /tmp and /home: ranked by owner.
	dir := fmt.Sprintf("/var/lib/hookmon-e2e-dlopen-%d", os.Getpid())
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(dir, "libfake_hook.so")
	if out, err := exec.Command("cp", canaryBinDir()+"/libfake_hook.so", lib).CombinedOutput(); err != nil {
		t.Fatalf("cp: %v\n%s", err, out)
	}
	if err := RunCanaryBinary(canary, lib); err != nil {
		t.Fatalf("dlopen_canary %s: %v", lib, err)
	}
	if _, err := bus.WaitForEvent(dlopenOf(lib), 15*time.Second); err != nil {
		t.Errorf("dlopen of %s (directory owned by nobody) not reported: %v", lib, err)
	}
}

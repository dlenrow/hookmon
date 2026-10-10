//go:build linux && e2e

package e2e

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/agent/sensors"
	"github.com/dlenrow/hookmon/pkg/event"
)

// execInjLib is the library the canaries preload, and its LibraryHash.
func execInjLib(t *testing.T) (path, hash string) {
	t.Helper()
	path = canaryBinDir() + "/libfake_hook.so"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return path, fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}

// execInjFillers returns n short variables with distinct names.
func execInjFillers(n int) []string {
	env := make([]string, n)
	for i := range env {
		env[i] = fmt.Sprintf("EXECINJ_FILL_%05d=x", i)
	}
	return env
}

// execInjRun runs /bin/true directly (the tests run as root; sudo would
// rewrite the environment) with exactly env, and returns its PID.
func execInjRun(t *testing.T, env []string) uint32 {
	t.Helper()
	cmd := exec.Command("/bin/true")
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run /bin/true: %v", err)
	}
	return uint32(cmd.Process.Pid)
}

func execInjStartBus(t *testing.T) *BusProcess {
	t.Helper()
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	t.Cleanup(func() { bus.Stop() })
	return bus
}

// TestExecInj_PreloadAt100th: LD_PRELOAD as the 100th environment variable
// is detected. Before step 4 the sensor scanned only the first 64.
func TestExecInj_PreloadAt100th(t *testing.T) {
	bus := execInjStartBus(t)
	lib, hash := execInjLib(t)

	env := append(execInjFillers(99), "LD_PRELOAD="+lib)
	pid := execInjRun(t, env)

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventExecInjection && e.PID == pid &&
			e.ExecInjectionDetail != nil && e.ExecInjectionDetail.EnvVar == "LD_PRELOAD"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("LD_PRELOAD as variable 100 not detected: %v", err)
	}
	d := evt.ExecInjectionDetail
	t.Logf("PASS: EXEC_INJECTION pid=%d lib=%s hash=%s target=%s", evt.PID, d.LibraryPath, d.LibraryHash, d.TargetBinary)
	if d.LibraryPath != lib {
		t.Errorf("library_path %q, want %q", d.LibraryPath, lib)
	}
	if d.LibraryHash != hash {
		t.Errorf("library_hash %q, want %q", d.LibraryHash, hash)
	}
	if d.TargetBinary != "/bin/true" {
		t.Errorf("target_binary %q, want /bin/true", d.TargetBinary)
	}
	if d.ScanTruncated {
		t.Error("scan_truncated set on a 100-variable environment")
	}
}

// TestExecInj_Execveat: an execveat(fd, "", AT_EMPTY_PATH) with LD_PRELOAD
// is detected. The sensor used to hook sys_enter_execve only.
func TestExecInj_Execveat(t *testing.T) {
	bus := execInjStartBus(t)
	lib, hash := execInjLib(t)

	// The canary replaces itself with /bin/true, so the exec keeps its PID.
	cmd := exec.Command(canaryBinDir()+"/execveat_canary", lib, "/bin/true")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("execveat_canary: %v", err)
	}
	pid := uint32(cmd.Process.Pid)

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventExecInjection && e.PID == pid &&
			e.ExecInjectionDetail != nil && e.ExecInjectionDetail.EnvVar == "LD_PRELOAD"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("execveat with LD_PRELOAD not detected: %v", err)
	}
	d := evt.ExecInjectionDetail
	t.Logf("PASS: EXEC_INJECTION via execveat pid=%d lib=%s hash=%s target=%s", evt.PID, d.LibraryPath, d.LibraryHash, d.TargetBinary)
	if d.LibraryPath != lib {
		t.Errorf("library_path %q, want %q", d.LibraryPath, lib)
	}
	if d.LibraryHash != hash {
		t.Errorf("library_hash %q, want %q", d.LibraryHash, hash)
	}
	if !strings.HasPrefix(d.TargetBinary, "/dev/fd/") {
		t.Errorf("target_binary %q, want the /dev/fd/N name the kernel gives an AT_EMPTY_PATH exec", d.TargetBinary)
	}
}

// TestExecInj_ScanTruncated: a process with more environment variables than
// the sensor scans yields an event with scan_truncated set, even though the
// LD_PRELOAD past the limit is not seen.
func TestExecInj_ScanTruncated(t *testing.T) {
	bus := execInjStartBus(t)
	lib, _ := execInjLib(t)

	n := sensors.ExecInjectionScanLimit + 10
	env := append(execInjFillers(n), "LD_PRELOAD="+lib)
	pid := execInjRun(t, env)

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventExecInjection && e.PID == pid &&
			e.ExecInjectionDetail != nil && e.ExecInjectionDetail.ScanTruncated
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("no scan_truncated event for %d variables (limit %d): %v", n+1, sensors.ExecInjectionScanLimit, err)
	}
	t.Logf("PASS: scan_truncated pid=%d target=%s severity=%s", evt.PID, evt.ExecInjectionDetail.TargetBinary, evt.Severity)
	if evt.ExecInjectionDetail.EnvVar != "" {
		t.Errorf("truncation event names variable %q", evt.ExecInjectionDetail.EnvVar)
	}
	if evt.Severity != event.SeverityAlert {
		t.Errorf("severity %s, want ALERT", evt.Severity)
	}
}

//go:build linux && e2e

package e2e

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/agent/sensors"
	"github.com/dlenrow/hookmon/pkg/event"
)

// TestSensor8_ElfRpath_OriginTmpCleanEnv: a binary with
// RUNPATH=$ORIGIN/../tmp, run with an empty environment, produces an
// ELF_RPATH event. No LD_* variable is set, so no other sensor reports the
// exec: the event comes from elf_rpath's own sched_process_exec hook. The
// binary exits at once, so the bus reads its exec record after the process
// is gone.
func TestSensor8_ElfRpath_OriginTmpCleanEnv(t *testing.T) {
	// Lay out <dir>/bin/<binary> next to a world-writable <dir>/tmp, the
	// library directory its RUNPATH names: an app whose scratch directory
	// any local user can drop a libc.so.6 into.
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	tmpDir := filepath.Join(dir, "tmp")
	for _, d := range []string{binDir, tmpDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(tmpDir, 0o1777); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "test_rpath_origin_tmp")
	copyExecutable(t, canaryBinDir()+"/test_rpath_origin_tmp", bin)

	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	cmd := exec.Command(bin)
	cmd.Env = []string{}
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run %s: %v", bin, err)
	}
	pid := uint32(cmd.Process.Pid)

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventElfRpath && e.ElfRpathDetail != nil && e.PID == pid
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("no ELF_RPATH event for pid %d (%s): %v", pid, bin, err)
	}
	d := evt.ElfRpathDetail
	t.Logf("PASS: ELF_RPATH pid=%d exe=%s runpath=%s risk=%s severity=%s",
		evt.PID, evt.ExePath, d.RunpathRaw, d.HighestRisk, evt.Severity)

	if want, _ := filepath.EvalSymlinks(bin); evt.ExePath != want {
		t.Errorf("ExePath = %q, want %q", evt.ExePath, want)
	}
	if !d.HasRunpath || d.HasRpath || d.RunpathRaw != "$ORIGIN/../tmp" {
		t.Errorf("has_runpath=%v has_rpath=%v runpath=%q, want RUNPATH $ORIGIN/../tmp only",
			d.HasRunpath, d.HasRpath, d.RunpathRaw)
	}
	if !d.UsesOrigin {
		t.Error("uses_origin = false")
	}
	// World-writable is HIGH; under /tmp (where t.TempDir() usually is) the
	// resolved directory is CRITICAL.
	if d.HighestRisk != event.RpathRiskHigh && d.HighestRisk != event.RpathRiskCritical {
		t.Errorf("highest risk = %s, want HIGH or CRITICAL", d.HighestRisk)
	}
	if want := sensors.RpathSeverity(d.HighestRisk); evt.Severity != want {
		t.Errorf("severity = %s, want %s for risk %s", evt.Severity, want, d.HighestRisk)
	}
}

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("canary missing (run make build-canaries): %v", err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

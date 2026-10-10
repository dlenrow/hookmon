//go:build linux && e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// TestRpathW_EmitOncePerBinaryVersion: elf_rpath reports a binary once per
// version, not on every exec. Three execs of a binary with RPATH /tmp/evil
// produce one ELF_RPATH event, for the first exec; after the binary's mtime
// changes, the next exec produces one more.
func TestRpathW_EmitOncePerBinaryVersion(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "test_rpath")
	copyExecutable(t, canaryBinDir()+"/test_rpath", bin)
	exePath, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}

	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	run := func() uint32 {
		t.Helper()
		cmd := exec.Command(bin)
		cmd.Env = []string{}
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("run %s: %v", bin, err)
		}
		return uint32(cmd.Process.Pid)
	}
	matches := func(e *event.HookEvent) bool {
		return e.EventType == event.EventElfRpath && e.ElfRpathDetail != nil && e.ExePath == exePath
	}

	var pids []uint32
	for i := 0; i < 3; i++ {
		pids = append(pids, run())
	}
	first, err := bus.WaitForEvent(matches, 15*time.Second)
	if err != nil {
		t.Fatalf("no ELF_RPATH event for %s: %v", exePath, err)
	}
	if first.PID != pids[0] {
		t.Errorf("event pid = %d, want the first exec's pid %d (execs: %v)", first.PID, pids[0], pids)
	}
	if extra, err := bus.WaitForEvent(matches, 5*time.Second); err == nil {
		t.Fatalf("second ELF_RPATH event for the same binary version: pid %d (execs: %v)", extra.PID, pids)
	}

	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(bin, later, later); err != nil {
		t.Fatal(err)
	}
	pid := run()
	next, err := bus.WaitForEvent(matches, 15*time.Second)
	if err != nil {
		t.Fatalf("no ELF_RPATH event after the binary changed: %v", err)
	}
	if next.PID != pid {
		t.Errorf("event pid = %d, want %d", next.PID, pid)
	}
	t.Logf("PASS: one event per version: pids %d then %d, risk %s, hash %s",
		first.PID, next.PID, next.ElfRpathDetail.HighestRisk, next.ExeHash)
}

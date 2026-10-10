//go:build linux

package sensors

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dlenrow/hookmon/pkg/event"
)

func TestPcacheExecEntry(t *testing.T) {
	raw := &rpathExecEvent{PID: 10, PPID: 9, UID: 1000, GID: 1001}
	copy(raw.Comm[:], "cp")
	copy(raw.Filename[:], "/usr/bin/cp")
	e := execEntry(raw)
	if e.PID != 10 || e.PPID != 9 || e.UID != 1000 || e.GID != 1001 || e.Comm != "cp" || e.Exe != "/usr/bin/cp" {
		t.Errorf("execEntry = %+v", e)
	}

	// A filename that fills the buffer may be truncated, so it is dropped;
	// the rest of the record is kept.
	copy(raw.Filename[:], "/"+strings.Repeat("a", len(raw.Filename)))
	if e := execEntry(raw); e.Exe != "" || e.UID != 1000 || e.Comm != "cp" {
		t.Errorf("execEntry with a full filename buffer = %+v", e)
	}
}

// The real elf_rpath sensor feeds the cache that a real linker_config
// sensor reads. The file sensor is given an empty proc root, so every
// writer looks as if it had already exited when its event was read: the
// identity can come only from the exec cache. Each cp must be reported with
// its own UID, comm and parent, every time.
func TestPcacheShortLivedWriterFromExecRecords(t *testing.T) {
	requireRoot(t)
	rp := NewElfRpathSensor()
	if err := rp.Start(); err != nil {
		t.Fatalf("start elf_rpath: %v", err)
	}
	t.Cleanup(func() { rp.Stop() })
	go func() { // keep its event channel from filling
		for range rp.Events() {
		}
	}()

	etc := tempDir(t)
	src := filepath.Join(tempDir(t), "src")
	writeFile(t, src, " \n")
	preload := filepath.Join(etc, "ld.so.preload")
	s := newLinkerConfigSensor(etc, tempDir(t))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Stop() })
	isPreload := func(e *event.HookEvent) bool {
		return e.LinkerConfigDetail != nil && e.LinkerConfigDetail.FilePath == preload
	}

	const rounds = 20
	for i := 0; i < rounds; i++ {
		os.Remove(preload)
		cmd := exec.Command("cp", src, preload)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cp: %v\n%s", err, out)
		}
		cpPid := uint32(cmd.ProcessState.Pid())
		ev := waitHookEvent(t, s.Events(), "cp to ld.so.preload", func(e *event.HookEvent) bool {
			return isPreload(e) && e.PID == cpPid
		})
		if ev.UID != 0 || ev.GID != 0 || ev.Comm != "cp" || ev.PPID != uint32(os.Getpid()) {
			t.Errorf("round %d: cp reported as uid=%d gid=%d comm=%q ppid=%d; want 0, 0, cp, %d",
				i, ev.UID, ev.GID, ev.Comm, ev.PPID, os.Getpid())
		}
		if ev.Severity != event.SeverityCritical {
			t.Errorf("round %d: severity %s", i, ev.Severity)
		}
	}

	// The test process itself exec'd before elf_rpath started, so it is
	// not in the cache: its write is reported as unknown, never as 0.
	writeFile(t, preload, "")
	ev := waitHookEvent(t, s.Events(), "write by the test process", func(e *event.HookEvent) bool {
		return isPreload(e) && e.PID == uint32(os.Getpid())
	})
	if ev.UID != unknownID || ev.GID != unknownID {
		t.Errorf("writer that never exec'd while the cache was fed: uid=%d gid=%d, want unknown %d",
			ev.UID, ev.GID, unknownID)
	}
}

//go:build linux

package sensors

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// noSuchPID is above any pid_max, so /proc/<noSuchPID> never exists: the
// process has already exited, as short-lived ones have by the time Go reads
// their exec record.
const noSuchPID = 5000000

// execRecord builds the record the BPF program would send for an exec of
// path, as passed in filename.
func execRecord(t *testing.T, path, filename string, pid, ppid uint32) *rpathExecEvent {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	raw := &rpathExecEvent{
		PID: pid, PPID: ppid,
		Dev: st.Dev, Ino: st.Ino,
		MtimeSec: int64(st.Mtim.Sec), MtimeNsec: uint32(st.Mtim.Nsec),
		Mode: st.Mode,
	}
	copy(raw.Filename[:], filename)
	return raw
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestOpenExecutedAbsoluteAfterExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	writeExecutable(t, path)
	f, got := openExecuted(execRecord(t, path, path, noSuchPID, noSuchPID))
	if f == nil {
		t.Fatal("absolute filename of an exited process was not resolved")
	}
	f.Close()
	if want := realPath(path); got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

// A path that names a different file than the one the kernel loaded is
// never analyzed in its place.
func TestOpenExecutedRejectsReplacedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	writeExecutable(t, path)
	raw := execRecord(t, path, path, noSuchPID, noSuchPID)

	// Rewritten in place: same inode, new mtime.
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if f, _ := openExecuted(raw); f != nil {
		f.Close()
		t.Error("file with a different mtime was accepted")
	}

	// Replaced: new inode at the same path.
	raw = execRecord(t, path, path, noSuchPID, noSuchPID)
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, path)
	if f, _ := openExecuted(raw); f != nil {
		f.Close()
		t.Error("replacement file with a different inode was accepted")
	}
}

// A FIFO swapped in at the path must not block the sensor.
func TestOpenExecutedFIFODoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	writeExecutable(t, path)
	raw := execRecord(t, path, path, noSuchPID, noSuchPID)
	os.Remove(path)
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() {
		f, _ := openExecuted(raw)
		if f != nil {
			f.Close()
		}
		done <- f != nil
	}()
	select {
	case accepted := <-done:
		if accepted {
			t.Error("FIFO was accepted as the executed file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("openExecuted blocked on a FIFO")
	}
}

// A relative filename is resolved against the parent's cwd once the process
// itself is gone; a shell running ./tool shares its cwd with the child.
func TestOpenExecutedRelativeViaParentCwd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	writeExecutable(t, path)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)

	// This test process plays the parent.
	f, got := openExecuted(execRecord(t, path, "./tool", noSuchPID, uint32(os.Getpid())))
	if f == nil {
		t.Fatal("relative filename was not resolved against the parent's cwd")
	}
	f.Close()
	if want := realPath(path); got != want {
		t.Errorf("path = %q, want %q", got, want)
	}

	// Without a live process or parent in that directory it stays unresolved.
	if f, _ := openExecuted(execRecord(t, path, "./tool", noSuchPID, noSuchPID)); f != nil {
		f.Close()
		t.Error("relative filename resolved with neither process nor parent alive")
	}
}

// /dev/fd/N (execveat with a dirfd, fexecve) would name the bus's own fd.
func TestOpenExecutedSkipsDevFd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	writeExecutable(t, path)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// The bus's fd for this very file must still not be used.
	name := "/dev/fd/" + strconv.Itoa(int(f.Fd()))
	if g, _ := openExecuted(execRecord(t, path, name, noSuchPID, noSuchPID)); g != nil {
		g.Close()
		t.Errorf("%s was resolved through the bus's own fd table", name)
	}
}

// /proc/<pid>/exe is used while the process is alive, whatever the filename.
func TestOpenExecutedProcExe(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, got := openExecuted(execRecord(t, exe, "relative/name/that/does/not/exist", uint32(os.Getpid()), noSuchPID))
	if f == nil {
		t.Fatal("/proc/<pid>/exe of a live process was not used")
	}
	f.Close()
	if want := realPath(exe); got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

// A binary without RPATH is analyzed once and cached as a negative result;
// a binary that cannot be found is not cached, so a later exec can retry.
func TestHandleExecCachesNegativeResults(t *testing.T) {
	s := NewElfRpathSensor()
	path := filepath.Join(t.TempDir(), "tool")
	writeExecutable(t, path) // not ELF: analyzed as "no RPATH"

	raw := execRecord(t, path, path, noSuchPID, noSuchPID)
	if evt := s.handleExec(raw); evt != nil {
		t.Fatalf("event for a binary without RPATH: %+v", evt)
	}
	if s.cache.Len() != 1 {
		t.Fatalf("cache len = %d after first exec, want 1", s.cache.Len())
	}
	key := FileID{Dev: raw.Dev, Ino: raw.Ino, MtimeNs: raw.MtimeSec*int64(time.Second) + int64(raw.MtimeNsec), Mode: raw.Mode}
	if res, ok := s.cache.Get(key); !ok || res.Detail != nil {
		t.Fatalf("cache entry = %+v, %v; want a negative hit", res, ok)
	}

	// Once cached, the file is not needed again.
	os.Remove(path)
	if evt := s.handleExec(raw); evt != nil {
		t.Fatalf("event from cached negative result: %+v", evt)
	}

	// Unresolvable: different inode, no file. Nothing is cached.
	gone := *raw
	gone.Ino++
	if evt := s.handleExec(&gone); evt != nil {
		t.Fatalf("event for an unresolvable exec: %+v", evt)
	}
	if s.cache.Len() != 1 {
		t.Errorf("cache len = %d, want 1: unresolved execs must not be cached", s.cache.Len())
	}
}

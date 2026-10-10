//go:build linux

package sensors

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func dlopenWSHA(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(b))
}

func TestDlopenWLibraryHashPaths(t *testing.T) {
	h := newDlopenHashes("/proc")
	pid := uint32(os.Getpid())
	dir := t.TempDir()
	lib := filepath.Join(dir, "libx.so")
	if err := os.WriteFile(lib, []byte("not really a library"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := dlopenWSHA(t, lib)

	if got := h.library(pid, lib); got != want {
		t.Errorf("absolute path: got %q, want %q", got, want)
	}

	// An absolute symlink resolves against the process's root, here /.
	link := filepath.Join(dir, "liblink.so")
	if err := os.Symlink(lib, link); err != nil {
		t.Fatal(err)
	}
	if got := h.library(pid, link); got != want {
		t.Errorf("symlink: got %q, want %q", got, want)
	}

	if got := h.library(pid, filepath.Join(dir, "missing.so")); got != "" {
		t.Errorf("missing file: got %q, want empty", got)
	}
	if got := h.library(pid, dir); got != "" {
		t.Errorf("directory: got %q, want empty", got)
	}

	// A FIFO at the path must neither block the sensor nor be hashed.
	fifo := filepath.Join(dir, "fifo.so")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() { done <- h.library(pid, fifo) }()
	select {
	case got := <-done:
		if got != "" {
			t.Errorf("fifo: got %q, want empty", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hashing a FIFO blocked")
	}

	// A bare name not mapped by the process is not guessed.
	if got := h.library(pid, "libx.so"); got != "" {
		t.Errorf("unmapped bare name: got %q, want empty", got)
	}
}

func TestDlopenWHashCacheFollowsChanges(t *testing.T) {
	h := newDlopenHashes("/proc")
	pid := uint32(os.Getpid())
	lib := filepath.Join(t.TempDir(), "libx.so")
	if err := os.WriteFile(lib, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	first := h.library(pid, lib)
	if first != dlopenWSHA(t, lib) || h.library(pid, lib) != first {
		t.Fatalf("hash %q, want %q twice", first, dlopenWSHA(t, lib))
	}
	if err := os.WriteFile(lib, []byte("two, longer"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := h.library(pid, lib); got != dlopenWSHA(t, lib) {
		t.Errorf("after rewrite: got %q, want %q", got, dlopenWSHA(t, lib))
	}
}

func TestDlopenWExeHash(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	h := newDlopenHashes("/proc")
	if got, want := h.exe(uint32(os.Getpid())), dlopenWSHA(t, exe); got != want {
		t.Errorf("exe hash %q, want %q", got, want)
	}
	if got := h.exe(0); got != "" {
		t.Errorf("pid 0: got %q, want empty", got)
	}
}

// A bare name is hashed through /proc/<pid>/map_files, which needs
// CAP_SYS_ADMIN.
func TestDlopenWLibraryHashBareNameMapped(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to open /proc/<pid>/map_files")
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	cmd := exec.Command(sleep, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	pid := uint32(cmd.Process.Pid)

	// Wait for the dynamic loader to map libc into the child.
	var libc string
	for i := 0; i < 100 && libc == ""; i++ {
		f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
		if err == nil {
			for _, m := range dlopenScanMaps(f) {
				if filepath.Base(m.Path) == "libc.so.6" {
					libc = m.Path
				}
			}
			f.Close()
		}
		if libc == "" {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if libc == "" {
		t.Skip("sleep does not map libc.so.6 (static or not glibc)")
	}
	h := newDlopenHashes("/proc")
	if got, want := h.library(pid, "libc.so.6"), dlopenWSHA(t, libc); got != want {
		t.Errorf("bare libc.so.6: got %q, want %q (%s)", got, want, libc)
	}
}

// The sensor attaches to the host's libc at startup and its attachment
// check passes. Needs root and the compiled BPF object.
func TestDlopenWSensorAttachesHostLibc(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}
	if len(dlopenMonitorBPF) == 0 {
		t.Skip("dlopen_monitor.o is a placeholder; build it with make bpf")
	}
	s := NewDlopenMonitorSensor()
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Stop()
	if err := s.CheckAttached(); err != nil {
		t.Fatalf("CheckAttached: %v", err)
	}
	s.libcs.mu.Lock()
	n := len(s.libcs.attached)
	s.libcs.mu.Unlock()
	if n == 0 {
		t.Fatal("no libc attached")
	}
	t.Logf("%d libc(s) attached", n)
}

// Any process can map a file named libc.so.6. One that is not an ELF object
// exporting dlopen is skipped, not counted as a libc the sensor failed to
// cover; neither is one whose processes have all exited.
func TestDlopenWAttachSkipsFakeAndVanishedLibc(t *testing.T) {
	s := NewDlopenMonitorSensor()
	fake := filepath.Join(t.TempDir(), "libc.so.6")
	if err := os.WriteFile(fake, []byte("\x7fELF but not really"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.attachLibc(&dlopenCandidate{Desc: fake, Opens: []string{fake}}); err != errDlopenNoSymbol {
		t.Errorf("fake libc: err = %v, want errDlopenNoSymbol", err)
	}
	gone := []string{"/proc/999999999/map_files/7f00-7f10", filepath.Join(t.TempDir(), "nope")}
	if _, err := s.attachLibc(&dlopenCandidate{Desc: "gone", Opens: gone}); err != errDlopenGone {
		t.Errorf("vanished libc: err = %v, want errDlopenGone", err)
	}
}

func TestDlopenWExportsDlopenRealLibc(t *testing.T) {
	for _, p := range dlopenHostLibcs[:3] {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()
		if !dlopenExportsDlopen(f) {
			t.Errorf("%s: dlopen not found", p)
		}
		return
	}
	t.Skip("no host libc.so.6 at the usual paths")
}

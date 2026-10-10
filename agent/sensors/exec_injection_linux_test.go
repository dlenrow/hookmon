//go:build linux

package sensors

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

func TestExecInjInjectedLibrary(t *testing.T) {
	cases := []struct {
		envVar, value, want string
	}{
		{"LD_PRELOAD", "/usr/lib/libfoo.so", "/usr/lib/libfoo.so"},
		{"LD_PRELOAD", "  /usr/lib/libfoo.so: ", "/usr/lib/libfoo.so"},
		{"LD_PRELOAD", "/a.so /b.so", ""},
		{"LD_PRELOAD", "/a.so:/b.so", ""},
		{"LD_PRELOAD", "libfoo.so", ""},
		{"LD_PRELOAD", "./libfoo.so", ""},
		{"LD_PRELOAD", "", ""},
		{"LD_AUDIT", "/usr/lib/libaudit.so", "/usr/lib/libaudit.so"},
		{"LD_AUDIT", "/a.so:/b.so", ""},
		// LD_AUDIT splits at colons only.
		{"LD_AUDIT", "/dir with space/a.so", "/dir with space/a.so"},
		{"LD_LIBRARY_PATH", "/usr/lib", ""},
		{"LD_DEBUG", "all", ""},
	}
	for _, c := range cases {
		if got := injectedLibrary(c.envVar, c.value); got != c.want {
			t.Errorf("injectedLibrary(%q, %q) = %q, want %q", c.envVar, c.value, got, c.want)
		}
	}
}

// execInjRaw builds a BPF record for toEvent.
func execInjRaw(pid, ppid, flags, mntNs uint32, envVar, value, filename string) *execInjectionEvent {
	raw := &execInjectionEvent{EventType: 3, PID: pid, PPID: ppid, Flags: flags, MntNs: mntNs}
	copy(raw.Comm[:], "true")
	copy(raw.Filename[:], filename)
	copy(raw.EnvVarName[:], envVar)
	copy(raw.EnvValue[:], value)
	return raw
}

func execInjSelfMntNs(t *testing.T) uint32 {
	t.Helper()
	ns := nsInode("/proc/self/ns/mnt")
	if ns == 0 {
		t.Fatal("cannot read /proc/self/ns/mnt")
	}
	return uint32(ns)
}

func execInjWriteLib(t *testing.T, dir, name, content string) (path, sum string) {
	t.Helper()
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(content)))
}

func TestExecInjToEvent(t *testing.T) {
	s := NewExecInjectionSensor()
	mntNs := execInjSelfMntNs(t)
	lib, sum := execInjWriteLib(t, t.TempDir(), "libinj.so", "not really a library")
	self := uint32(os.Getpid())

	evt := s.toEvent(execInjRaw(self, 1, 0, mntNs, "LD_PRELOAD", lib, "/bin/true"))
	d := evt.ExecInjectionDetail
	if evt.EventType != event.EventExecInjection || evt.Severity != event.SeverityAlert || evt.PID != self {
		t.Errorf("event %+v", evt)
	}
	if d.EnvVar != "LD_PRELOAD" || d.LibraryPath != lib || d.LibraryHash != sum ||
		d.TargetBinary != "/bin/true" || d.SetBy != "env" || d.ScanTruncated || d.ValueTruncated {
		t.Errorf("detail %+v, want LD_PRELOAD %s %s", *d, lib, sum)
	}

	// A value cut short names the wrong file: no hash.
	d = s.toEvent(execInjRaw(self, 1, envValueTruncated, mntNs, "LD_PRELOAD", lib, "/bin/true")).ExecInjectionDetail
	if !d.ValueTruncated || d.LibraryHash != "" || d.LibraryPath != lib {
		t.Errorf("value-truncated detail %+v", *d)
	}

	// The truncation event names no variable.
	d = s.toEvent(execInjRaw(self, 1, envScanTruncated, mntNs, "", "", "/dev/fd/3")).ExecInjectionDetail
	if !d.ScanTruncated || d.EnvVar != "" || d.LibraryPath != "" || d.LibraryHash != "" || d.TargetBinary != "/dev/fd/3" {
		t.Errorf("truncation detail %+v", *d)
	}

	// LD_LIBRARY_PATH names directories: no hash.
	d = s.toEvent(execInjRaw(self, 1, 0, mntNs, "LD_LIBRARY_PATH", filepath.Dir(lib), "/bin/true")).ExecInjectionDetail
	if d.LibraryHash != "" {
		t.Errorf("LD_LIBRARY_PATH got hash %q", d.LibraryHash)
	}
}

func TestExecInjLibraryHashResolution(t *testing.T) {
	h := newLibraryHasher()
	mntNs := execInjSelfMntNs(t)
	lib, sum := execInjWriteLib(t, t.TempDir(), "libinj.so", "library one")
	self := uint32(os.Getpid())
	gone := uint32(1 << 30) // above any pid_max: never a live process

	cases := []struct {
		name string
		raw  *execInjectionEvent
		want string
	}{
		{"process alive", execInjRaw(self, 1, 0, mntNs, "", "", ""), sum},
		{"process gone, parent shares its root", execInjRaw(gone, self, envParentRoot, mntNs, "", "", ""), sum},
		{"process gone, root not shared", execInjRaw(gone, self, 0, mntNs, "", "", ""), ""},
		{"other mount namespace", execInjRaw(self, self, envParentRoot, mntNs+1, "", "", ""), ""},
		{"namespace unknown", execInjRaw(self, self, envParentRoot, 0, "", "", ""), ""},
	}
	for _, c := range cases {
		if got := h.hash(c.raw, "LD_PRELOAD", lib); got != c.want {
			t.Errorf("%s: hash = %q, want %q", c.name, got, c.want)
		}
	}

	// A new version of the file is hashed again, not served from the cache.
	raw := execInjRaw(self, 1, 0, mntNs, "", "", "")
	time.Sleep(10 * time.Millisecond)
	_, sum2 := execInjWriteLib(t, filepath.Dir(lib), "libinj.so", "library two")
	if got := h.hash(raw, "LD_PRELOAD", lib); got != sum2 {
		t.Errorf("after rewrite: hash = %q, want %q", got, sum2)
	}
}

func TestExecInjOpenRegularInRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "lib", "real.so"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	// An absolute symlink resolves inside root, as it does for a process
	// whose root this is.
	if err := os.Symlink("/lib/real.so", filepath.Join(root, "lib", "link.so")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "lib", "fifo.so"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := openRegularInRoot(root, "/lib/link.so")
	if f == nil {
		t.Fatal("symlink inside root not opened")
	}
	buf := make([]byte, 16)
	n, _ := f.Read(buf)
	f.Close()
	if string(buf[:n]) != "inside" {
		t.Errorf("read %q through the symlink, want the file inside root", buf[:n])
	}

	for _, p := range []string{"/lib/fifo.so", "/lib", "/lib/missing.so", "/../../../../etc/passwd"} {
		if f := openRegularInRoot(root, p); f != nil {
			f.Close()
			t.Errorf("openRegularInRoot(%q) opened a file", p)
		}
	}
	// /proc magic links would name the bus's own files.
	if f := openRegularInRoot("/", "/proc/self/exe"); f != nil {
		f.Close()
		t.Error("magic link /proc/self/exe was followed")
	}
}

// execInjStart starts the sensor, with the bounded-loop program if bounded.
func execInjStart(t *testing.T, bounded bool) *ExecInjectionSensor {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("loading the BPF program needs root")
	}
	s := NewExecInjectionSensor()
	s.bounded = bounded
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { s.Stop() })
	want := ExecInjectionScanLimit
	if bounded {
		want = ExecInjectionScanLimitBounded
	}
	if s.scanLimit != want {
		t.Fatalf("scan limit %d, want %d (bpf_loop missing on this kernel?)", s.scanLimit, want)
	}
	return s
}

// execInjRun runs /bin/true with exactly env and returns its pid. os/exec
// would drop duplicate keys and empty strings, so this uses ForkExec.
func execInjRun(t *testing.T, env []string) uint32 {
	t.Helper()
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	fd := devNull.Fd()
	pid, err := syscall.ForkExec("/bin/true", []string{"/bin/true"},
		&syscall.ProcAttr{Env: env, Files: []uintptr{fd, fd, fd}})
	if err != nil {
		t.Fatalf("run /bin/true: %v", err)
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("wait for /bin/true: %v", err)
	}
	return uint32(pid)
}

// execInjFillers returns n short variables.
func execInjFillers(n int) []string {
	env := make([]string, n)
	for i := range env {
		env[i] = fmt.Sprintf("EXECINJ_FILL_%05d=x", i)
	}
	return env
}

// execInjCollect returns the sensor's events for pid, waiting until no more
// arrive for half a second.
func execInjCollect(s *ExecInjectionSensor, pid uint32) []*event.HookEvent {
	var got []*event.HookEvent
	timeout := time.After(5 * time.Second)
	for {
		select {
		case evt := <-s.Events():
			if evt.PID == pid {
				got = append(got, evt)
			}
		case <-time.After(500 * time.Millisecond):
			return got
		case <-timeout:
			return got
		}
	}
}

// TestExecInjScanBoundary checks each program's limit exactly: a variable
// in the last place scanned is reported, and one more variable turns into a
// truncation event. It also checks the variable sizes where a read ends.
func TestExecInjScanBoundary(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		name := "bpf_loop"
		if bounded {
			name = "bounded"
		}
		t.Run(name, func(t *testing.T) {
			s := execInjStart(t, bounded)
			limit := s.scanLimit
			const lib = "/nonexistent/execinj.so"

			// LD_PRELOAD is the last variable scanned.
			pid := execInjRun(t, append(execInjFillers(limit-1), "LD_PRELOAD="+lib))
			got := execInjCollect(s, pid)
			if len(got) != 1 || got[0].ExecInjectionDetail.EnvVar != "LD_PRELOAD" ||
				got[0].ExecInjectionDetail.LibraryPath != lib || got[0].ExecInjectionDetail.ScanTruncated {
				t.Errorf("LD_PRELOAD at %d of %d: got %s", limit, limit, execInjDescribe(got))
			}

			// One variable more than the limit: LD_PRELOAD is past it.
			pid = execInjRun(t, append(execInjFillers(limit), "LD_PRELOAD="+lib))
			got = execInjCollect(s, pid)
			if len(got) != 1 || !got[0].ExecInjectionDetail.ScanTruncated || got[0].ExecInjectionDetail.EnvVar != "" {
				t.Errorf("LD_PRELOAD at %d of limit %d: got %s, want one truncation event", limit+1, limit, execInjDescribe(got))
			}

			// Variables of 254, 255 and 256 bytes: one read, one read that
			// fills the buffer, and two reads. The scan must stay aligned on
			// variable starts after each. A value too long to capture is
			// flagged.
			long := strings.Repeat("v", 300)
			env := []string{
				"A=" + strings.Repeat("a", 252),
				"B=" + strings.Repeat("b", 253),
				"C=" + strings.Repeat("c", 254),
				"",
				"LD_AUDIT=" + lib,
				"X=LD_PRELOAD=/not/a/variable.so",
				"LD_DEBUG=" + long,
			}
			pid = execInjRun(t, env)
			got = execInjCollect(s, pid)
			if len(got) != 2 {
				t.Fatalf("long variables: got %s, want LD_AUDIT and LD_DEBUG", execInjDescribe(got))
			}
			for _, e := range got {
				d := e.ExecInjectionDetail
				switch d.EnvVar {
				case "LD_AUDIT":
					if d.LibraryPath != lib || d.ValueTruncated {
						t.Errorf("LD_AUDIT detail %+v", *d)
					}
				case "LD_DEBUG":
					if !d.ValueTruncated || !strings.HasPrefix(long, d.LibraryPath) || len(d.LibraryPath) != 255 {
						t.Errorf("LD_DEBUG detail: value_truncated=%v len=%d", d.ValueTruncated, len(d.LibraryPath))
					}
				default:
					t.Errorf("unexpected event %+v", *d)
				}
			}

			// More matches than the sensor reports per exec stop the scan.
			env = nil
			for i := 0; i < 17; i++ {
				env = append(env, "LD_LIBRARY_PATH=/x")
			}
			pid = execInjRun(t, env)
			got = execInjCollect(s, pid)
			truncated := 0
			for _, e := range got {
				if e.ExecInjectionDetail.ScanTruncated {
					truncated++
				}
			}
			if len(got) != 17 || truncated != 1 {
				t.Errorf("17 matches: got %d events, %d truncation, want 16 and 1", len(got), truncated)
			}
		})
	}
}

func execInjDescribe(evts []*event.HookEvent) string {
	var parts []string
	for _, e := range evts {
		d := e.ExecInjectionDetail
		parts = append(parts, fmt.Sprintf("{var=%q truncated=%v}", d.EnvVar, d.ScanTruncated))
	}
	return fmt.Sprintf("%d events %v", len(evts), parts)
}

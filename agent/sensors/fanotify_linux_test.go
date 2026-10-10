//go:build linux

package sensors

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// These tests use real fanotify groups on temporary directories. They need
// root: FAN_UNLIMITED_QUEUE needs CAP_SYS_ADMIN and open_by_handle_at needs
// CAP_DAC_READ_SEARCH. Run with: sudo go test ./agent/sensors/

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (fanotify with FAN_UNLIMITED_QUEUE, open_by_handle_at)")
	}
}

func tempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sha(content string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(content)))
}

// waitDirEvent reads ch until an event matches or the timeout passes.
func waitDirEvent(t *testing.T, ch <-chan dirEvent, what string, match func(dirEvent) bool) dirEvent {
	t.Helper()
	var seen []string
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-ch:
			if match(ev) {
				return ev
			}
			seen = append(seen, fmt.Sprintf("%s mask=%#x", ev.path(), ev.Mask))
		case <-deadline:
			t.Fatalf("no event for %s; saw %v", what, seen)
		}
	}
}

// waitHookEvent reads a sensor's channel until an event matches.
func waitHookEvent(t *testing.T, ch <-chan *event.HookEvent, what string, match func(*event.HookEvent) bool) *event.HookEvent {
	t.Helper()
	var seen []string
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-ch:
			if match(ev) {
				return ev
			}
			seen = append(seen, describeFileEvent(ev))
		case <-deadline:
			t.Fatalf("no event for %s; saw %v", what, seen)
			return nil
		}
	}
}

func describeFileEvent(ev *event.HookEvent) string {
	switch {
	case ev.LinkerConfigDetail != nil:
		return ev.LinkerConfigDetail.FilePath + ":" + ev.LinkerConfigDetail.Operation
	case ev.LibIntegrityDetail != nil:
		return ev.LibIntegrityDetail.LibraryPath + ":" + ev.LibIntegrityDetail.Operation
	}
	return string(ev.EventType)
}

func TestFanWatcherResolvesPaths(t *testing.T) {
	requireRoot(t)
	dir := tempDir(t)

	w, err := newFanWatcher(func(string) bool { return true }, newProcReader("/proc"))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := w.addTree(dir, nil); n != 1 || err != nil {
		t.Fatalf("addTree = %d, %v", n, err)
	}
	done := make(chan struct{})
	ch := make(chan dirEvent, 256)
	exited := make(chan struct{})
	go func() {
		w.run(done, ch)
		close(exited)
	}()
	t.Cleanup(func() {
		close(done)
		w.close()
		<-exited
	})

	is := func(d, name string, bit uint64) func(dirEvent) bool {
		return func(ev dirEvent) bool { return ev.Dir == d && ev.Name == name && ev.Mask&bit != 0 }
	}

	writeFile(t, filepath.Join(dir, "a.so"), "a")
	ev := waitDirEvent(t, ch, "create a.so", is(dir, "a.so", fanCreate))
	if ev.Pid != uint32(os.Getpid()) || !ev.Proc.Known || ev.Proc.UID != 0 || ev.Proc.PkgMgr != "" {
		t.Errorf("writer details: pid=%d (want %d) proc=%+v", ev.Pid, os.Getpid(), ev.Proc)
	}
	if ev.Mask&fanCloseWrite == 0 { // the kernel may merge it into the create
		waitDirEvent(t, ch, "close_write a.so", is(dir, "a.so", fanCloseWrite))
	}

	writeFile(t, filepath.Join(dir, ".tmp"), "b")
	if err := os.Rename(filepath.Join(dir, ".tmp"), filepath.Join(dir, "b.so")); err != nil {
		t.Fatal(err)
	}
	waitDirEvent(t, ch, "rename to b.so", is(dir, "b.so", fanMovedTo))

	if err := os.Remove(filepath.Join(dir, "a.so")); err != nil {
		t.Fatal(err)
	}
	waitDirEvent(t, ch, "delete a.so", is(dir, "a.so", fanDelete))

	// A new subdirectory is marked when its creation is seen; a file written
	// into it is reported by the mark or by the scan that follows it.
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(sub, "c.so"), "c")
	waitDirEvent(t, ch, "c.so in new subdirectory", is(sub, "c.so", fanCreate))

	// After a watched directory is renamed, events carry its new path.
	sub2 := filepath.Join(dir, "sub2")
	if err := os.Rename(sub, sub2); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // let the rename's own event be read first
	writeFile(t, filepath.Join(sub2, "d.so"), "d")
	waitDirEvent(t, ch, "d.so under renamed directory", is(sub2, "d.so", fanCreate))
}

func TestStartFailsWithoutMarks(t *testing.T) {
	requireRoot(t)
	missing := filepath.Join(tempDir(t), "missing")

	li := newLibIntegritySensor([]string{missing, missing + "2"}, filepath.Join(missing, "ld.so.cache"), "/proc")
	if err := li.Start(); err == nil {
		li.Stop()
		t.Error("lib_integrity started with no directory marked")
	}
	lc := newLinkerConfigSensor(missing, "/proc")
	if err := lc.Start(); err == nil {
		lc.Stop()
		t.Error("linker_config started with no directory marked")
	}
}

func TestLinkerConfigSensorTempEtc(t *testing.T) {
	requireRoot(t)
	etc := tempDir(t)
	confD := filepath.Join(etc, "ld.so.conf.d")
	if err := os.Mkdir(confD, 0o755); err != nil {
		t.Fatal(err)
	}
	preload := filepath.Join(etc, "ld.so.preload")
	writeFile(t, preload, "")
	writeFile(t, filepath.Join(etc, "ld.so.conf"), "include /etc/ld.so.conf.d/*.conf\n")

	s := newLinkerConfigSensor(etc, "/proc")
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Stop() })
	ch := s.Events()
	is := func(path, op string) func(*event.HookEvent) bool {
		return func(e *event.HookEvent) bool {
			d := e.LinkerConfigDetail
			return d != nil && d.FilePath == path && d.Operation == op
		}
	}

	// An unrelated file in /etc is not reported.
	writeFile(t, filepath.Join(etc, "hosts"), "127.0.0.1 localhost\n")

	// sed -i: write a temporary file and rename it over the original.
	writeFile(t, filepath.Join(etc, "sedAbC123"), " \n")
	if err := os.Rename(filepath.Join(etc, "sedAbC123"), preload); err != nil {
		t.Fatal(err)
	}
	ev := waitHookEvent(t, ch, "sed -i of ld.so.preload", is(preload, "rename"))
	d := ev.LinkerConfigDetail
	if d.OldHash != sha("") || d.NewHash != sha(" \n") {
		t.Errorf("hashes: old=%s (want baseline %s) new=%s (want %s)", d.OldHash, sha(""), d.NewHash, sha(" \n"))
	}
	if ev.Severity != event.SeverityCritical || ev.UID != 0 || ev.PID != uint32(os.Getpid()) {
		t.Errorf("severity=%s uid=%d pid=%d", ev.Severity, ev.UID, ev.PID)
	}

	if err := os.Remove(preload); err != nil {
		t.Fatal(err)
	}
	ev = waitHookEvent(t, ch, "rm of ld.so.preload", is(preload, "delete"))
	if ev.LinkerConfigDetail.OldHash != sha(" \n") || ev.LinkerConfigDetail.NewHash != "" {
		t.Errorf("delete hashes: %+v", ev.LinkerConfigDetail)
	}

	// ldconfig: write ld.so.cache~ and rename it to ld.so.cache.
	cache := filepath.Join(etc, "ld.so.cache")
	writeFile(t, cache+"~", "cache")
	if err := os.Rename(cache+"~", cache); err != nil {
		t.Fatal(err)
	}
	waitHookEvent(t, ch, "ld.so.cache replaced", is(cache, "rename"))

	writeFile(t, filepath.Join(confD, "x.conf"), "/opt/x\n")
	waitHookEvent(t, ch, "ld.so.conf.d/x.conf created", is(filepath.Join(confD, "x.conf"), "create"))

	// Replacing ld.so.conf.d itself: the new directory is marked and its
	// contents reported.
	if err := os.RemoveAll(confD); err != nil {
		t.Fatal(err)
	}
	waitHookEvent(t, ch, "ld.so.conf.d removed", is(confD, "delete"))
	if err := os.Mkdir(confD, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(confD, "y.conf"), "/opt/y\n")
	waitHookEvent(t, ch, "y.conf in recreated ld.so.conf.d", is(filepath.Join(confD, "y.conf"), "create"))
	// Written well after the scan, so only the new mark can report it.
	time.Sleep(300 * time.Millisecond)
	writeFile(t, filepath.Join(confD, "z.conf"), "/opt/z\n")
	waitHookEvent(t, ch, "z.conf in recreated ld.so.conf.d", is(filepath.Join(confD, "z.conf"), "create"))

	// Nothing above should have reported /etc/hosts or sed's temp file.
	time.Sleep(200 * time.Millisecond)
	for {
		select {
		case ev := <-ch:
			p := ev.LinkerConfigDetail.FilePath
			if strings.HasSuffix(p, "/hosts") || strings.Contains(p, "sedAbC123") {
				t.Errorf("unrelated file reported: %s", describeFileEvent(ev))
			}
			continue
		default:
		}
		break
	}
}

func TestLibIntegritySensorTempTree(t *testing.T) {
	requireRoot(t)
	tmp := tempDir(t)
	root := filepath.Join(tmp, "lib")
	arch := filepath.Join(root, "x86_64-linux-gnu")
	if err := os.MkdirAll(arch, 0o755); err != nil {
		t.Fatal(err)
	}
	pre := filepath.Join(arch, "libpre.so.1")
	writeFile(t, pre, "pre")
	cachePath := filepath.Join(tmp, "ld.so.cache")
	if err := os.WriteFile(cachePath, buildNewLdCache(binary.LittleEndian, 2,
		[]ldCacheEntry{{Key: "libpre.so.1", Value: pre}}), 0o644); err != nil {
		t.Fatal(err)
	}

	s := newLibIntegritySensor([]string{root, filepath.Join(tmp, "missing")}, cachePath, "/proc")
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Stop() })
	for i := 0; s.baseline.len() < 1 && i < 100; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	ch := s.Events()
	is := func(path, op string) func(*event.HookEvent) bool {
		return func(e *event.HookEvent) bool {
			d := e.LibIntegrityDetail
			return d != nil && d.LibraryPath == path && d.Operation == op
		}
	}

	// Overwrite in place (cp onto an existing library).
	writeFile(t, pre, "trojan")
	ev := waitHookEvent(t, ch, "overwrite of libpre.so.1", is(pre, "write"))
	d := ev.LibIntegrityDetail
	if d.OldHash != sha("pre") || d.NewHash != sha("trojan") || !d.InLdCache {
		t.Errorf("detail = %+v; want OldHash %s from the baseline, InLdCache true", d, sha("pre"))
	}
	if ev.Severity != event.SeverityAlert || ev.UID != 0 {
		t.Errorf("severity=%s uid=%d", ev.Severity, ev.UID)
	}

	// A non-library file is ignored; a new library is not in the cache.
	writeFile(t, filepath.Join(arch, "README"), "x")
	lnew := filepath.Join(arch, "libnew.so")
	writeFile(t, lnew, "new")
	ev = waitHookEvent(t, ch, "create of libnew.so", is(lnew, "create"))
	if ev.LibIntegrityDetail.InLdCache {
		t.Error("libnew.so reported as in ld.so.cache")
	}

	// ln -sf to a library: the hash is the target's content.
	link := filepath.Join(arch, "libpre.so")
	if err := os.Symlink("libpre.so.1", link); err != nil {
		t.Fatal(err)
	}
	ev = waitHookEvent(t, ch, "symlink libpre.so", is(link, "create"))
	if ev.LibIntegrityDetail.NewHash != sha("trojan") {
		t.Errorf("symlink NewHash = %s, want the target's %s", ev.LibIntegrityDetail.NewHash, sha("trojan"))
	}

	// A library dropped into a new subdirectory.
	sub := filepath.Join(root, "evil")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(sub, "libz.so.1"), "z")
	waitHookEvent(t, ch, "library in new subdirectory", func(e *event.HookEvent) bool {
		d := e.LibIntegrityDetail
		return d != nil && d.LibraryPath == filepath.Join(sub, "libz.so.1") && d.Operation == "create"
	})
}

//go:build linux

package sensors

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/dlenrow/hookmon/agent/suppress"
	"github.com/dlenrow/hookmon/pkg/event"
)

// Source filters: what each sensor drops because it cannot be a stealth
// hook, and what it still reports.

// TestFileSensorsDropPackageManagerWrites: a write with a package manager in
// the writer's ancestry is counted, not reported, and the baseline still
// moves, so the next reported change has the package's version as its old
// hash. Any other writer is reported.
func TestFileSensorsDropPackageManagerWrites(t *testing.T) {
	t.Run("linker_config", func(t *testing.T) {
		etc := t.TempDir()
		preload := filepath.Join(etc, "ld.so.preload")
		s := newLinkerConfigSensor(etc, "/proc")
		before := suppress.Get("linker_config", suppress.PackageManager)

		writeFile(t, preload, "pkg\n")
		s.handleEvent(dirEvent{Mask: fanCloseWrite, Pid: 1, Dir: etc, Name: "ld.so.preload",
			Proc: procInfo{Known: true, PkgMgr: "dpkg"}})
		if n := suppress.Get("linker_config", suppress.PackageManager); n != before+1 {
			t.Errorf("suppressed count %d, want %d", n, before+1)
		}
		select {
		case ev := <-s.eventCh:
			t.Fatalf("package-manager write reported: %+v", ev.LinkerConfigDetail)
		default:
		}

		pkgHash := hashFile(preload)
		writeFile(t, preload, "/tmp/evil.so\n")
		s.handleEvent(dirEvent{Mask: fanCloseWrite, Pid: 2, Dir: etc, Name: "ld.so.preload",
			Proc: procInfo{Known: true}})
		ev := <-s.eventCh
		if ev.Severity != event.SeverityCritical || ev.LinkerConfigDetail.OldHash != pkgHash {
			t.Errorf("got severity %s old hash %s, want CRITICAL and %s", ev.Severity, ev.LinkerConfigDetail.OldHash, pkgHash)
		}
	})

	t.Run("lib_integrity", func(t *testing.T) {
		root := t.TempDir()
		lib := filepath.Join(root, "libx.so.1")
		s := newLibIntegritySensor([]string{root}, filepath.Join(root, "ld.so.cache"), "/proc")
		s.realRoots = []string{root}
		before := suppress.Get("lib_integrity", suppress.PackageManager)

		writeFile(t, lib, "v1")
		s.handleEvent(dirEvent{Mask: fanCreate, Pid: 1, Dir: root, Name: "libx.so.1",
			Proc: procInfo{Known: true, PkgMgr: "rpm"}})
		if n := suppress.Get("lib_integrity", suppress.PackageManager); n != before+1 {
			t.Errorf("suppressed count %d, want %d", n, before+1)
		}
		select {
		case ev := <-s.eventCh:
			t.Fatalf("package-manager write reported: %+v", ev.LibIntegrityDetail)
		default:
		}

		pkgHash := hashFile(lib)
		writeFile(t, lib, "trojan")
		s.handleEvent(dirEvent{Mask: fanCloseWrite, Pid: 2, Dir: root, Name: "libx.so.1",
			Proc: procInfo{Known: true}})
		ev := <-s.eventCh
		if ev.Severity != event.SeverityAlert || ev.LibIntegrityDetail.OldHash != pkgHash {
			t.Errorf("got severity %s old hash %s, want ALERT and %s", ev.Severity, ev.LibIntegrityDetail.OldHash, pkgHash)
		}
	})
}

func TestSplitSearchPath(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"/a", []string{"/a"}},
		{"/a:/b", []string{"/a", "/b"}},
		{"/a;/b", []string{"/a", "/b"}},
		{"/opt/containerd/lib:", []string{"/opt/containerd/lib", ""}},
		{"/a::/b", []string{"/a", "", "/b"}},
		{":", []string{"", ""}},
	} {
		got := splitSearchPath(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("splitSearchPath(%q) = %q, want %q", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitSearchPath(%q) = %q, want %q", tc.in, got, tc.want)
				break
			}
		}
	}
}

// TestSearchPathRisk ranks LD_LIBRARY_PATH values against the host's own
// directories, which root owns on any Linux system.
func TestSearchPathRisk(t *testing.T) {
	for _, tc := range []struct {
		value, binaryDir string
		want             event.RpathRisk
	}{
		{"", "", event.RpathRiskNone},                              // no search path at all
		{"/usr/lib", "", event.RpathRiskNone},                      // standard
		{"/usr/lib:/usr/share", "", event.RpathRiskLow},            // root-only, non-standard
		{"/usr/lib;/usr/share", "", event.RpathRiskLow},            // semicolon separator
		{"/opt/containerd/lib:", "", event.RpathRiskHigh},          // containerd's: an empty entry
		{"/usr/lib::/usr/share", "", event.RpathRiskHigh},          // empty entry in the middle
		{"lib", "", event.RpathRiskCritical},                       // relative
		{"/usr/lib:/tmp/x", "", event.RpathRiskCritical},           // under /tmp
		{"/home/someone/lib", "", event.RpathRiskCritical},         // under /home
		{"/nonexistent-hookmon-test-dir", "", event.RpathRiskHigh}, // could be created
		{"$ORIGIN/../lib", "", event.RpathRiskMedium},              // binary unknown
		{"$ORIGIN/../share", "/usr/bin", event.RpathRiskLow},       // resolves to /usr/share
		{"$ORIGIN", "/tmp/build", event.RpathRiskCritical},         // resolves into /tmp
	} {
		got, why := searchPathRisk(hostFS{}, tc.value, tc.binaryDir)
		if got != tc.want {
			t.Errorf("searchPathRisk(%q, %q) = %s (%s), want %s", tc.value, tc.binaryDir, got, why, tc.want)
		}
	}
}

// TestReportExecInjection: only an LD_LIBRARY_PATH that names nothing a
// non-root user can change is dropped.
func TestReportExecInjection(t *testing.T) {
	self := uint32(os.Getpid())
	mntNs := execInjSelfMntNs(t)
	for _, tc := range []struct {
		name          string
		flags, mntNs  uint32
		envVar, value string
		want          bool
	}{
		{"safe search path", 0, mntNs, "LD_LIBRARY_PATH", "/usr/lib:/usr/share", false},
		{"containerd's empty entry", 0, mntNs, "LD_LIBRARY_PATH", "/opt/containerd/lib:", true},
		{"search path in /tmp", 0, mntNs, "LD_LIBRARY_PATH", "/tmp/hookmon", true},
		{"LD_PRELOAD of a system library", 0, mntNs, "LD_PRELOAD", "/usr/lib/x86_64-linux-gnu/libc.so.6", true},
		{"LD_AUDIT", 0, mntNs, "LD_AUDIT", "/usr/lib/libaudit.so", true},
		{"LD_DEBUG", 0, mntNs, "LD_DEBUG", "all", true},
		{"scan truncated", envScanTruncated, mntNs, "", "", true},
		{"namespace unknown", 0, 0, "LD_LIBRARY_PATH", "/usr/lib", true},
		{"value cut short, process gone", envValueTruncated, mntNs, "LD_LIBRARY_PATH", "/usr/lib", true},
	} {
		pid := self
		if tc.flags&envValueTruncated != 0 {
			pid = 1 << 30 // no such process
		}
		raw := execInjRaw(pid, 1, tc.flags, tc.mntNs, tc.envVar, tc.value, "/bin/true")
		if got := reportExecInjection(raw); got != tc.want {
			t.Errorf("%s: reportExecInjection = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestRootFSResolvesInsideRoot: paths, absolute symlinks and ".." resolve
// inside the root, as the process whose root it is resolves them.
func TestRootFSResolvesInsideRoot(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "b/c", "lib")
	mustSymlink(t, "/b", filepath.Join(root, "a"))              // absolute: inside root
	mustSymlink(t, "../b/c", filepath.Join(root, "lib", "rel")) // relative
	mustSymlink(t, "/loop", filepath.Join(root, "loop"))

	fs, err := openRootFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.close()

	for in, want := range map[string]string{
		"/a/c":       "/b/c",
		"/lib/rel":   "/b/c",
		"/b/c/../c":  "/b/c",
		"/../../a/c": "/b/c", // ".." stops at the root
		"/b":         "/b",
		"/":          "/",
	} {
		if got, err := fs.realPath(in); err != nil || got != want {
			t.Errorf("realPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := fs.realPath("/loop/x"); !errors.Is(err, unix.ELOOP) {
		t.Errorf("realPath through a symlink loop: %v, want ELOOP", err)
	}
	if _, err := fs.realPath("/missing/x"); err == nil {
		t.Error("realPath of a missing path succeeded")
	}
	if _, _, mode, ok := fs.stat("/a/c"); !ok || !mode.IsDir() {
		t.Errorf("stat(/a/c) = %v, %v; want a directory", mode, ok)
	}
	if _, _, _, ok := fs.stat("/missing"); ok {
		t.Error("stat(/missing) succeeded")
	}
}

func mkdirs(t *testing.T, root string, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// hostLibc returns the path of the host's glibc, or skips.
func hostLibc(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/aarch64-linux-gnu/libc.so.6", "/usr/lib64/libc.so.6"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no glibc at a known path")
	return ""
}

// TestDlopenLibraryRiskHost judges dlopens against the host's own files
// through a process root that is "/".
func TestDlopenLibraryRiskHost(t *testing.T) {
	libc := hostLibc(t)
	procRoot := t.TempDir()
	mkdirs(t, procRoot, "1")
	mustSymlink(t, "/", filepath.Join(procRoot, "1", "root"))
	writeFile(t, filepath.Join(procRoot, "1", "maps"), "")
	h := newDlopenHashes(procRoot)

	for _, tc := range []struct {
		path   string
		ok     bool
		below  bool // below MEDIUM: dropped
		reason string
	}{
		{libc, true, true, "system library, root-only directory"},
		{"libc.so.6", true, true, "bare name listed in ld.so.cache"},
		{"/tmp/hookmon-evil.so", true, false, "under /tmp"},
		{"/nonexistent-hookmon-dir/x.so", true, false, "directory could be created"},
		{"libhookmon-nope.so.9", false, false, "bare name neither mapped nor cached"},
		{"./x.so", false, false, "relative"},
		{"/proc/self/fd/3", false, false, "descriptor loader"},
		{"", false, false, "unread path"},
	} {
		risk, why, ok := h.libraryRisk(1, tc.path)
		if ok != tc.ok || (ok && RiskBelow(risk, event.RpathRiskMedium) != tc.below) {
			t.Errorf("%s: libraryRisk(%q) = %s (%s), ok=%v; want ok=%v, dropped=%v", tc.reason, tc.path, risk, why, ok, tc.ok, tc.below)
		}
	}
}

// TestDlopenLibraryRiskContainer judges dlopens inside a fake container
// root: the container's files decide, not the host's at the same path. The
// root-only cases need the files to be root's, so they need root.
func TestDlopenLibraryRiskContainer(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root: the fake container's files must be owned by root")
	}
	procRoot := t.TempDir()
	ctr := filepath.Join(procRoot, "ctr")
	mkdirs(t, ctr, "usr/lib/x86_64-linux-gnu", "opt/app", "tmp", "etc")
	mkdirs(t, procRoot, "7")
	mustSymlink(t, ctr, filepath.Join(procRoot, "7", "root"))
	// /lib -> usr/lib, as on a merged-/usr image.
	mustSymlink(t, "usr/lib", filepath.Join(ctr, "lib"))

	sys := filepath.Join(ctr, "usr/lib/x86_64-linux-gnu/libz.so.1")
	writeFile(t, sys, "z")
	writeFile(t, filepath.Join(ctr, "tmp/evil.so"), "e")
	app := filepath.Join(ctr, "opt/app/libapp.so")
	writeFile(t, app, "a")
	if err := os.Chown(filepath.Join(ctr, "opt/app"), 1000, 1000); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(ctr, "usr/lib/x86_64-linux-gnu/libloose.so")
	writeFile(t, loose, "l")
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}
	// An absolute symlink resolves inside the container, to its own libz.
	mustSymlink(t, "/usr/lib/x86_64-linux-gnu/libz.so.1", filepath.Join(ctr, "opt/libz-link.so"))
	writeFile(t, filepath.Join(procRoot, "7", "maps"),
		"7f0000000000-7f0000001000 r-xp 00000000 08:02 4242 /usr/lib/x86_64-linux-gnu/libz.so.1\n")
	h := newDlopenHashes(procRoot)

	for _, tc := range []struct {
		path  string
		below bool
	}{
		{"/usr/lib/x86_64-linux-gnu/libz.so.1", true},
		{"/lib/x86_64-linux-gnu/libz.so.1", true}, // through the /lib symlink
		{"libz.so.1", true},                       // bare name, mapped
		{"/opt/libz-link.so", true},               // symlink resolved inside the container
		{"/tmp/evil.so", false},
		{"/opt/app/libapp.so", false},                    // directory owned by uid 1000
		{"/usr/lib/x86_64-linux-gnu/libloose.so", false}, // world-writable file
	} {
		risk, why, ok := h.libraryRisk(7, tc.path)
		if !ok || RiskBelow(risk, event.RpathRiskMedium) != tc.below {
			t.Errorf("libraryRisk(%q) = %s (%s), ok=%v; want dropped=%v", tc.path, risk, why, ok, tc.below)
		}
	}
}

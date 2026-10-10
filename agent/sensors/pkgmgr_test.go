package sensors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeProc writes a minimal /proc/<pid> entry under root: status, an exe
// symlink (dangling is fine) and cmdline.
func fakeProc(t *testing.T, root string, pid, ppid, uid uint32, name, exe string, argv ...string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t%d\nPid:\t%d\nPPid:\t%d\n"+
		"Uid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\n", name, pid, pid, ppid, uid, uid, uid, uid, uid, uid, uid, uid)
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	cmd := strings.Join(argv, "\x00") + "\x00"
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmd), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPkgManagerName(t *testing.T) {
	tests := []struct {
		exe  string
		argv []string
		want string
	}{
		{"/usr/bin/dpkg", []string{"dpkg", "--unpack"}, "dpkg"},
		{"/usr/bin/dpkg (deleted)", nil, "dpkg"},
		{"/usr/bin/apt-get", nil, "apt-get"},
		{"/usr/bin/apt", nil, "apt"},
		{"/usr/bin/rpm", nil, "rpm"},
		{"/bin/rpm", nil, "rpm"},
		{"/usr/bin/python3.11", []string{"/usr/bin/python3", "/usr/bin/dnf", "install", "x"}, "dnf"},
		{"/usr/bin/python3", []string{"/usr/bin/python3", "-s", "/usr/bin/yum", "update"}, "yum"},
		{"/usr/libexec/platform-python3.6", []string{"/usr/libexec/platform-python", "/usr/bin/dnf-3"}, "dnf"},
		// A copy outside the system directories, or a look-alike name, is not trusted.
		{"/tmp/dpkg", []string{"dpkg"}, ""},
		{"/home/u/bin/apt-get", nil, ""},
		{"/usr/bin/python3", []string{"python3", "/home/u/dnf"}, ""},
		{"/usr/bin/python3", []string{"python3", "script.py", "/usr/bin/dnf"}, ""},
		{"/usr/bin/sed", []string{"sed", "-i", "dpkg"}, ""},
		{"/usr/bin/python3", []string{"python3"}, ""},
		{"/usr/bin/python3", nil, ""},
		{"", nil, ""},
	}
	for _, tt := range tests {
		if got := pkgManagerName(tt.exe, tt.argv); got != tt.want {
			t.Errorf("pkgManagerName(%q, %q) = %q, want %q", tt.exe, tt.argv, got, tt.want)
		}
	}
}

func TestProcReaderAncestry(t *testing.T) {
	root := t.TempDir()
	// apt-get -> dpkg -> sh (maintainer script) -> ldconfig
	fakeProc(t, root, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd", "/sbin/init")
	fakeProc(t, root, 100, 1, 0, "apt-get", "/usr/bin/apt-get", "apt-get", "install")
	fakeProc(t, root, 200, 100, 0, "dpkg", "/usr/bin/dpkg", "/usr/bin/dpkg", "--unpack")
	fakeProc(t, root, 300, 200, 0, "sh", "/usr/bin/dash", "/bin/sh", "/var/lib/dpkg/info/libc-bin.postinst")
	fakeProc(t, root, 400, 300, 0, "ldconfig", "/usr/sbin/ldconfig", "/sbin/ldconfig")
	// A shell user editing a file, and a process naming itself dpkg.
	fakeProc(t, root, 500, 501, 1000, "sed", "/usr/bin/sed", "sed", "-i", "s/a/b/", "/etc/ld.so.conf")
	fakeProc(t, root, 501, 1, 1000, "bash", "/usr/bin/bash", "-bash")
	fakeProc(t, root, 600, 1, 0, "dpkg", "/tmp/.x/dpkg", "dpkg")
	// Orphan: its parent exited, so it was reparented to init.
	fakeProc(t, root, 700, 1, 0, "ldconfig", "/usr/sbin/ldconfig", "ldconfig")

	r := newProcReader(root)

	info := r.lookup(400)
	if !info.Known || info.PkgMgr != "dpkg" || info.UID != 0 || info.PPID != 300 || info.Comm != "ldconfig" {
		t.Errorf("ldconfig under dpkg: %+v", info)
	}
	if info := r.lookup(200); info.PkgMgr != "dpkg" {
		t.Errorf("dpkg itself: %+v", info)
	}
	if info := r.lookup(100); info.PkgMgr != "apt-get" {
		t.Errorf("apt-get itself: %+v", info)
	}
	info = r.lookup(500)
	if !info.Known || info.PkgMgr != "" || info.UID != 1000 || info.GID != 1000 {
		t.Errorf("sed from a login shell: %+v", info)
	}
	if info := r.lookup(600); info.PkgMgr != "" {
		t.Errorf("binary named dpkg outside /usr/bin counted as a package manager: %+v", info)
	}
	if info := r.lookup(700); info.PkgMgr != "" {
		t.Errorf("orphan: %+v", info)
	}
}

func TestProcReaderWriterExited(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd")
	fakeProc(t, root, 200, 1, 0, "dpkg", "/usr/bin/dpkg", "dpkg")
	fakeProc(t, root, 400, 200, 0, "ldconfig", "/usr/sbin/ldconfig", "ldconfig")

	now := time.Unix(1000, 0)
	r := newProcReader(root)
	r.now = func() time.Time { return now }

	// First event (ldconfig creating ld.so.cache~) while it is alive.
	if info := r.lookup(400); info.PkgMgr != "dpkg" {
		t.Fatalf("live lookup: %+v", info)
	}
	// ldconfig renames the cache into place and exits before the next read.
	if err := os.RemoveAll(filepath.Join(root, "400")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(procMemoTTL / 2)
	if info := r.lookup(400); !info.Known || info.PkgMgr != "dpkg" || info.UID != 0 {
		t.Errorf("exited writer within the memo TTL: %+v", info)
	}

	// Past the TTL nothing is assumed: no package manager, and no UID 0.
	now = now.Add(procMemoTTL)
	info := r.lookup(400)
	if info.Known || info.PkgMgr != "" {
		t.Errorf("exited writer past the memo TTL: %+v", info)
	}
	if uid, gid := info.ids(); uid != unknownID || gid != unknownID {
		t.Errorf("ids of unknown process = %d, %d; want %d", uid, gid, unknownID)
	}

	// A PID never seen alive.
	if uid, _ := r.lookup(999).ids(); uid == 0 {
		t.Error("unseen PID reported as UID 0")
	}
	if uid, _ := r.lookup(0).ids(); uid != unknownID {
		t.Error("PID 0 not reported as unknown")
	}
}

func TestReadProcStatusMalformed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "42")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{
		"Name:\tx\nPPid:\t1\n",                    // no Uid
		"Name:\tx\nUid:\t\nGid:\t0\n",             // empty Uid
		"Name:\tx\nUid:\tabc\t0\t0\t0\nGid:\t0\n", // unparsable Uid
	} {
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
		if st, err := readProcStatus(root, 42); err == nil {
			t.Errorf("status %q parsed as %+v; want an error, not UID 0", status, st)
		}
	}
}

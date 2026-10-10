//go:build linux && e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/agent/observability"
	"github.com/dlenrow/hookmon/agent/registry"
	"github.com/dlenrow/hookmon/pkg/event"
)

// Fix plan step 4, linker_config and lib_integrity: each way of replacing a
// file (cp, sed -i, mv, ln -sf, rm) produces an event, and a package
// manager's writes are INFO.
//
// SAFETY: these tests change /etc/ld.so.preload and /usr/lib on the host.
// /etc/ld.so.preload, which every process on the host reads, only ever holds
// whitespace (see whitespaceFile), and its exact prior state is restored in
// t.Cleanup, including on failure. In /usr/lib only
// /usr/lib/hookmon-canary-<pid>.* files are created, and they are removed.
// The only real library touched is the one reinstalled by apt-get.

const preloadPath = "/etc/ld.so.preload"

func fileSHA(content string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(content)))
}

// whitespaceFile writes a file whose content is only whitespace, so that
// it is safe as /etc/ld.so.preload, or as a symlink target of it.
func whitespaceFile(t *testing.T, path, content string) {
	t.Helper()
	if strings.TrimSpace(content) != "" {
		t.Fatalf("refusing to write non-whitespace content %q to a file that may become %s", content, preloadPath)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// preloadState is /etc/ld.so.preload as found before the test.
type preloadState struct {
	exists   bool
	symlink  string
	content  []byte
	mode     os.FileMode
	uid, gid int
}

// savePreload records /etc/ld.so.preload and registers its restore. It
// skips the test if the file has real content: replacing that, even for a
// moment, would change what every process on the host loads.
func savePreload(t *testing.T) {
	t.Helper()
	var st preloadState
	fi, err := os.Lstat(preloadPath)
	switch {
	case os.IsNotExist(err):
	case err != nil:
		t.Fatalf("lstat %s: %v", preloadPath, err)
	default:
		st.exists, st.mode = true, fi.Mode()
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
			st.uid, st.gid = int(sys.Uid), int(sys.Gid)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			st.symlink, err = os.Readlink(preloadPath)
		} else {
			st.content, err = os.ReadFile(preloadPath)
		}
		if err != nil {
			t.Fatalf("read %s: %v", preloadPath, err)
		}
		if st.symlink != "" || strings.TrimSpace(string(st.content)) != "" {
			t.Skipf("%s is in use on this host (symlink %q, %d bytes); not touching it", preloadPath, st.symlink, len(st.content))
		}
	}
	t.Cleanup(func() {
		if err := os.Remove(preloadPath); err != nil && !os.IsNotExist(err) {
			t.Errorf("restore %s: %v", preloadPath, err)
		}
		if st.exists {
			if err := os.WriteFile(preloadPath, st.content, st.mode.Perm()); err != nil {
				t.Errorf("restore %s: %v", preloadPath, err)
			}
			os.Chmod(preloadPath, st.mode.Perm())
			os.Chown(preloadPath, st.uid, st.gid)
		}
		_, err := os.Lstat(preloadPath)
		if os.IsNotExist(err) == st.exists {
			t.Errorf("%s not restored: existed before=%v, lstat now: %v", preloadPath, st.exists, err)
		}
	})
}

// startFileBus starts a bus on its own status port and waits until the
// named sensors have started (their marks are in place).
func startFileBus(t *testing.T, port string, names ...string) *BusProcess {
	t.Helper()
	bus, err := StartBusArgs(busBin(), "--status-port", port)
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	t.Cleanup(func() { bus.Stop() })
	waitStatus(t, port, 60*time.Second, func(st *observability.StatusResponse) bool {
		m := sensorMap(st)
		for _, n := range names {
			if m[n].Status != registry.StatusAlive {
				return false
			}
		}
		return true
	})
	return bus
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// fileOpStep is one command against a watched file and the event it must
// produce. newContent is the file's content afterwards ("" after rm).
type fileOpStep struct {
	name       string
	do         func()
	ops        []string
	oldContent *string // checked when set
	newContent string
	deleted    bool
}

func checkSteps(t *testing.T, bus *BusProcess, path string, detail func(*event.HookEvent) (path, op, oldHash, newHash string, ok bool),
	wantSeverity event.Severity, steps []fileOpStep) []*event.HookEvent {
	t.Helper()
	var got []*event.HookEvent
	for _, st := range steps {
		st.do()
		evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
			p, op, oldH, newH, ok := detail(e)
			if !ok || p != path {
				return false
			}
			opOK := false
			for _, o := range st.ops {
				opOK = opOK || o == op
			}
			if !opOK {
				return false
			}
			if st.deleted {
				return newH == "" && (st.oldContent == nil || oldH == fileSHA(*st.oldContent))
			}
			return newH == fileSHA(st.newContent)
		}, 15*time.Second)
		if err != nil {
			t.Errorf("%s: no event for %s with op %v: %v", st.name, path, st.ops, err)
			continue
		}
		_, op, oldH, newH, _ := detail(evt)
		t.Logf("%s: op=%s old=%.20s new=%.20s severity=%s uid=%d pid=%d comm=%s",
			st.name, op, oldH, newH, evt.Severity, evt.UID, evt.PID, evt.Comm)
		if st.oldContent != nil && oldH != fileSHA(*st.oldContent) {
			t.Errorf("%s: OldHash = %q, want %q", st.name, oldH, fileSHA(*st.oldContent))
		}
		if evt.Severity != wantSeverity {
			t.Errorf("%s: severity %s, want %s", st.name, evt.Severity, wantSeverity)
		}
		if evt.UID != 0 {
			t.Errorf("%s: UID %d, want 0 (the test runs as root)", st.name, evt.UID)
		}
		got = append(got, evt)
	}
	return got
}

func linkerDetail(e *event.HookEvent) (string, string, string, string, bool) {
	if e.EventType != event.EventLinkerConfig || e.LinkerConfigDetail == nil {
		return "", "", "", "", false
	}
	d := e.LinkerConfigDetail
	return d.FilePath, d.Operation, d.OldHash, d.NewHash, true
}

func libDetail(e *event.HookEvent) (string, string, string, string, bool) {
	if e.EventType != event.EventLibIntegrity || e.LibIntegrityDetail == nil {
		return "", "", "", "", false
	}
	d := e.LibIntegrityDetail
	return d.LibraryPath, d.Operation, d.OldHash, d.NewHash, true
}

func strp(s string) *string { return &s }

// TestLinkerConfig_PreloadOperations: cp, sed -i, mv, ln -sf and rm against
// /etc/ld.so.preload each produce a CRITICAL LINKER_CONFIG event with the
// right hashes. The file exists (empty) when the bus starts, so the first
// event's OldHash comes from the startup baseline.
func TestLinkerConfig_PreloadOperations(t *testing.T) {
	src := t.TempDir() // removed after the restore below runs
	savePreload(t)
	mvSrc := fmt.Sprintf("/etc/.hookmon-e2e-%d", os.Getpid()) // same filesystem, so mv is a rename
	t.Cleanup(func() { os.Remove(mvSrc) })

	whitespaceFile(t, preloadPath, "")
	whitespaceFile(t, filepath.Join(src, "cp"), " \n")
	whitespaceFile(t, filepath.Join(src, "ln"), " \n \n")

	bus := startFileBus(t, "2185", "linker_config")

	steps := []fileOpStep{
		{name: "cp", ops: []string{"write", "create"}, oldContent: strp(""), newContent: " \n",
			do: func() { run(t, "cp", filepath.Join(src, "cp"), preloadPath) }},
		{name: "sed -i", ops: []string{"rename"}, oldContent: strp(" \n"), newContent: "\t\n",
			do: func() { run(t, "sed", "-i", `s/ /\t/`, preloadPath) }},
		{name: "mv", ops: []string{"rename"}, oldContent: strp("\t\n"), newContent: "\n\n",
			do: func() {
				whitespaceFile(t, mvSrc, "\n\n")
				run(t, "mv", mvSrc, preloadPath)
			}},
		// ln -sf replaces the file with a symlink to a whitespace-only file;
		// the hash is of the target's content.
		{name: "ln -sf", ops: []string{"rename", "create"}, newContent: " \n \n",
			do: func() { run(t, "ln", "-sf", filepath.Join(src, "ln"), preloadPath) }},
		{name: "rm", ops: []string{"delete"}, oldContent: strp(" \n \n"), deleted: true,
			do: func() { run(t, "rm", preloadPath) }},
	}
	checkSteps(t, bus, preloadPath, linkerDetail, event.SeverityCritical, steps)
}

// TestLibIntegrity_SoOperations: the same five operations against a canary
// .so in /usr/lib each produce an ALERT LIB_INTEGRITY event.
func TestLibIntegrity_SoOperations(t *testing.T) {
	pid := os.Getpid()
	canary := fmt.Sprintf("/usr/lib/hookmon-canary-%d.so", pid)
	mvSrc := fmt.Sprintf("/usr/lib/hookmon-canary-%d.tmp", pid) // same filesystem, so mv is a rename
	t.Cleanup(func() {
		os.Remove(canary)
		os.Remove(mvSrc)
	})
	src := t.TempDir()
	c1 := "hookmon canary one\n"
	if err := os.WriteFile(filepath.Join(src, "c1"), []byte(c1), 0o644); err != nil {
		t.Fatal(err)
	}
	c4 := "hookmon canary four\n"
	if err := os.WriteFile(filepath.Join(src, "c4"), []byte(c4), 0o644); err != nil {
		t.Fatal(err)
	}

	bus := startFileBus(t, "2186", "lib_integrity")

	c2 := strings.Replace(c1, "canary", "kanary", 1)
	c3 := "hookmon canary three\n"
	steps := []fileOpStep{
		{name: "cp", ops: []string{"create", "write"}, newContent: c1,
			do: func() { run(t, "cp", filepath.Join(src, "c1"), canary) }},
		{name: "sed -i", ops: []string{"rename"}, oldContent: &c1, newContent: c2,
			do: func() { run(t, "sed", "-i", "s/canary/kanary/", canary) }},
		{name: "mv", ops: []string{"rename"}, oldContent: &c2, newContent: c3,
			do: func() {
				if err := os.WriteFile(mvSrc, []byte(c3), 0o644); err != nil {
					t.Fatal(err)
				}
				run(t, "mv", mvSrc, canary)
			}},
		{name: "ln -sf", ops: []string{"rename", "create"}, newContent: c4,
			do: func() { run(t, "ln", "-sf", filepath.Join(src, "c4"), canary) }},
		{name: "rm", ops: []string{"delete"}, oldContent: &c4, deleted: true,
			do: func() { run(t, "rm", canary) }},
	}
	for _, evt := range checkSteps(t, bus, canary, libDetail, event.SeverityAlert, steps) {
		if evt.LibIntegrityDetail.InLdCache {
			t.Errorf("canary reported as in ld.so.cache: %+v", evt.LibIntegrityDetail)
		}
	}
}

// TestLibIntegrity_AptReinstallIsInfo: reinstalling one small library
// package with apt-get produces INFO events for its files, not ALERT,
// because dpkg is in the writer's ancestry.
func TestLibIntegrity_AptReinstallIsInfo(t *testing.T) {
	if _, err := exec.LookPath("apt-get"); err != nil {
		t.Skip("apt-get not available")
	}
	pkg := os.Getenv("HOOKMON_E2E_REINSTALL_PKG")
	if pkg == "" {
		pkg = "libmnl0"
	}
	out, err := exec.Command("dpkg", "-L", pkg).Output()
	if err != nil {
		t.Skipf("package %s not installed: %v", pkg, err)
	}
	// The package's regular shared-object files, by real path (the bus
	// reports /usr/lib/... where the package lists /lib/... on merged /usr).
	var libs []string
	for _, f := range strings.Split(string(out), "\n") {
		base := filepath.Base(f)
		if !strings.HasSuffix(base, ".so") && !strings.Contains(base, ".so.") {
			continue
		}
		if fi, err := os.Lstat(f); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if dir, err := filepath.EvalSymlinks(filepath.Dir(f)); err == nil {
			libs = append(libs, filepath.Join(dir, base))
		}
	}
	if len(libs) == 0 {
		t.Skipf("package %s has no shared objects", pkg)
	}

	// Remove only the .deb files this test downloads.
	before, _ := filepath.Glob("/var/cache/apt/archives/*.deb")
	t.Cleanup(func() {
		had := make(map[string]bool)
		for _, f := range before {
			had[f] = true
		}
		after, _ := filepath.Glob("/var/cache/apt/archives/*.deb")
		for _, f := range after {
			if !had[f] {
				os.Remove(f)
			}
		}
	})

	bus := startFileBus(t, "2187", "lib_integrity", "linker_config")

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "apt-get", "install", "--reinstall", "-y", "--no-install-recommends",
		"-o", "DPkg::Lock::Timeout=120", pkg)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	aptOut, err := cmd.CombinedOutput()
	if err != nil {
		s := string(aptOut)
		if strings.Contains(s, "Failed to fetch") || strings.Contains(s, "Unable to fetch") ||
			strings.Contains(s, "Temporary failure resolving") {
			t.Skipf("apt-get could not fetch %s; cannot test a package-manager write:\n%s", pkg, s)
		}
		t.Fatalf("apt-get install --reinstall %s: %v\n%s", pkg, err, s)
	}
	t.Logf("apt-get install --reinstall %s:\n%s", pkg, aptOut)

	isPkgLib := func(p string) bool {
		for _, l := range libs {
			if p == l || strings.HasPrefix(p, l+".dpkg-") {
				return true
			}
		}
		return false
	}
	// dpkg unpacks <lib>.dpkg-new and renames it over <lib>.
	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		p, op, _, _, ok := libDetail(e)
		return ok && op == "rename" && isPkgLib(p) && !strings.Contains(p, ".dpkg-")
	}, 30*time.Second)
	if err != nil {
		t.Fatalf("no LIB_INTEGRITY rename event for %v: %v", libs, err)
	}
	d := evt.LibIntegrityDetail
	t.Logf("reinstall: lib=%s op=%s severity=%s in_ld_cache=%v pid=%d ppid=%d comm=%s uid=%d",
		d.LibraryPath, d.Operation, evt.Severity, d.InLdCache, evt.PID, evt.PPID, evt.Comm, evt.UID)
	if evt.Severity != event.SeverityInfo {
		t.Errorf("package-manager write has severity %s, want INFO", evt.Severity)
	}
	if !d.InLdCache {
		t.Errorf("%s not reported as in ld.so.cache", d.LibraryPath)
	}

	// Every other event for the package's files must be INFO as well.
	bus.WaitForEvent(func(*event.HookEvent) bool { return false }, 3*time.Second)
	n := 0
	for _, e := range bus.unmatched {
		if p, op, _, _, ok := libDetail(e); ok && isPkgLib(p) {
			n++
			if e.Severity != event.SeverityInfo {
				t.Errorf("%s %s by pid %d (%s): severity %s, want INFO", op, p, e.PID, e.Comm, e.Severity)
			}
		}
		if p, op, _, _, ok := linkerDetail(e); ok {
			// ldconfig, run from dpkg's libc-bin trigger, rewrites the cache.
			// It may exit before the sensor reads its event; see procReader.
			t.Logf("linker_config: %s %s by pid %d (%s): severity %s", op, p, e.PID, e.Comm, e.Severity)
		}
	}
	t.Logf("%d further LIB_INTEGRITY events for %s, all checked for INFO", n, pkg)
}

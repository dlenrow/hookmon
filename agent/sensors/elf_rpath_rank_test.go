package sensors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dlenrow/hookmon/pkg/event"
)

// rpathWNoDangerousDirs empties dangerousDirs for one test, so a directory
// the test creates under /tmp is ranked by its owner and mode alone.
func rpathWNoDangerousDirs(t *testing.T) {
	t.Helper()
	saved := dangerousDirs
	dangerousDirs = nil
	t.Cleanup(func() { dangerousDirs = saved })
}

// rpathWMkdir creates dir with exactly perm, whatever the umask.
func rpathWMkdir(t *testing.T, dir string, perm os.FileMode) {
	t.Helper()
	if err := os.Mkdir(dir, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, perm); err != nil {
		t.Fatal(err)
	}
}

func rpathWClassify(t *testing.T, path, binaryDir string, isRpath, isSetuid bool, want event.RpathRisk) event.RpathEntry {
	t.Helper()
	entry := classifyEntry(path, binaryDir, isRpath, isSetuid)
	if entry.Risk != want {
		t.Errorf("classifyEntry(%q, dir %q, rpath=%v, setuid=%v) = %s, want %s (%s)",
			path, binaryDir, isRpath, isSetuid, entry.Risk, want, entry.Reason)
	}
	return entry
}

// The dangerous directories themselves, not only paths under them, are
// CRITICAL. Paths are cleaned first.
func TestRpathWDangerousDirExact(t *testing.T) {
	for _, p := range []string{
		"/tmp", "/tmp/", "/var/tmp", "/dev/shm", "/home",
		"//tmp/evil", "/usr/lib/../../tmp/x", "/home/./user/lib", "/var//tmp",
	} {
		rpathWClassify(t, p, "/usr/bin", false, false, event.RpathRiskCritical)
	}
	for _, p := range []string{"/tmpfoo", "/var/tmpx/lib", "/homework", "/dev/shmem"} {
		if got := dangerousPrefix(p); got != "" {
			t.Errorf("dangerousPrefix(%q) = %q; the match must be by whole path component", p, got)
		}
	}
}

// ${ORIGIN} is $ORIGIN, as glibc reads it; a longer name is not a token.
func TestRpathWBraceOrigin(t *testing.T) {
	rpathWClassify(t, "${ORIGIN}/../lib", "/usr/bin", false, false, event.RpathRiskLow)
	rpathWClassify(t, "${ORIGIN}/../lib", "/usr/bin", false, true, event.RpathRiskCritical)
	rpathWClassify(t, "${ORIGIN}/..", "/tmp/x", false, false, event.RpathRiskCritical)
	rpathWClassify(t, "${ORIGIN}", "/usr/bin", true, false, event.RpathRiskMedium) // LOW, bumped for DT_RPATH

	if _, origin := expandDST("${ORIGIN}/lib", "/opt/app/bin"); !origin {
		t.Error("${ORIGIN} not recognized as $ORIGIN")
	}
	for _, p := range []string{"$ORIGINAL/lib", "${ORIGIN/lib", "$ORIGIN_X"} {
		if got, origin := expandDST(p, "/opt/app/bin"); origin || got != p {
			t.Errorf("expandDST(%q) = %q, origin %v; want it unchanged, no origin", p, got, origin)
		}
		// Not a token, so a relative path, as ld.so would read it.
		rpathWClassify(t, p, "/usr/bin", false, false, event.RpathRiskCritical)
	}
}

// $LIB and $PLATFORM expand to this host's values before classification;
// they are not non-existent directories named "$LIB".
func TestRpathWLibPlatform(t *testing.T) {
	v := hostDST()
	for in, want := range map[string]string{
		"/opt/a/$LIB/b":        "/opt/a/" + v.lib + "/b",
		"/opt/a/${LIB}":        "/opt/a/" + v.lib,
		"/opt/a/$PLATFORM/lib": "/opt/a/" + v.platform + "/lib",
		"/opt/a/${PLATFORM}":   "/opt/a/" + v.platform,
		"/opt/$LIBX":           "/opt/$LIBX",
		"/opt/$FOO/lib":        "/opt/$FOO/lib",
		"$ORIGIN/../$LIB":      "/opt/app/bin/../" + v.lib,
	} {
		if got, _ := expandDST(in, "/opt/app/bin"); got != want {
			t.Errorf("expandDST(%q) = %q, want %q", in, got, want)
		}
	}

	// With fixed values that name an existing root-owned directory, the
	// entries rank like that directory, not as missing ones.
	saved := hostDST
	hostDST = func() dstValues { return dstValues{lib: "bin", platform: "bin"} }
	t.Cleanup(func() { hostDST = saved })
	if !rpathWRootOnly(t, "/usr/bin") {
		t.Skip("/usr/bin is not root-only-writable here")
	}
	for _, p := range []string{"/usr/$LIB", "/usr/${LIB}", "/usr/$PLATFORM", "/usr/${PLATFORM}"} {
		entry := rpathWClassify(t, p, "/usr/sbin", false, false, event.RpathRiskLow)
		if !entry.Exists {
			t.Errorf("%s: exists = false", p)
		}
	}
}

// $LIB names a directory that exists under /usr on this host.
func TestRpathWHostLibExists(t *testing.T) {
	if lib := hostDST().lib; !dirExists("/usr/" + lib) {
		t.Errorf("$LIB = %q, but /usr/%s does not exist", lib, lib)
	}
}

// rpathWRootOnly reports whether dir is root-owned and not group- or
// world-writable.
func rpathWRootOnly(t *testing.T, dir string) bool {
	t.Helper()
	uid, _, perm, ok := dirOwner(dir)
	return ok && uid == 0 && perm&0o022 == 0
}

// A non-standard directory is ranked by who can write to it: only root is
// LOW (no event), a non-root owner or a writing group is MEDIUM, everyone
// is HIGH.
func TestRpathWRankByWritability(t *testing.T) {
	// Root-owned, 0755: what distro binaries name (/usr/libexec/sudo,
	// /usr/lib/x86_64-linux-gnu/systemd).
	if rpathWRootOnly(t, "/usr/bin") {
		e := rpathWClassify(t, "/usr/bin", "/usr/sbin", false, false, event.RpathRiskLow)
		if !e.Exists {
			t.Error("/usr/bin: exists = false")
		}
		// DT_RPATH still bumps one level.
		rpathWClassify(t, "/usr/bin", "/usr/sbin", true, false, event.RpathRiskMedium)
	} else {
		t.Log("/usr/bin is not root-only-writable here; skipping that case")
	}

	rpathWNoDangerousDirs(t)
	base := t.TempDir()
	isRoot := os.Geteuid() == 0

	userDir := filepath.Join(base, "user")
	rpathWMkdir(t, userDir, 0o755)
	if isRoot {
		if err := os.Chown(userDir, 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	rpathWClassify(t, userDir, "/usr/bin", false, false, event.RpathRiskMedium)
	rpathWClassify(t, userDir, "/usr/bin", true, false, event.RpathRiskHigh)

	worldDir := filepath.Join(base, "world")
	rpathWMkdir(t, worldDir, 0o777)
	rpathWClassify(t, worldDir, "/usr/bin", false, false, event.RpathRiskHigh)

	if !isRoot {
		t.Log("not root: root-owned temp directory cases skipped")
		return
	}
	rootDir := filepath.Join(base, "root")
	rpathWMkdir(t, rootDir, 0o755)
	rpathWClassify(t, rootDir, "/usr/bin", false, false, event.RpathRiskLow)

	groupDir := filepath.Join(base, "group")
	rpathWMkdir(t, groupDir, 0o775)
	if err := os.Chown(groupDir, 0, 1); err != nil {
		t.Fatal(err)
	}
	rpathWClassify(t, groupDir, "/usr/bin", false, false, event.RpathRiskMedium)
}

// The whole binary ranks LOW, so no event, when its only non-standard
// RUNPATH directory is root-only-writable.
func TestRpathWAnalyzeRootOnlyRunpathIsLow(t *testing.T) {
	if !rpathWRootOnly(t, "/usr/bin") {
		t.Skip("/usr/bin is not root-only-writable here")
	}
	path := filepath.Join(t.TempDir(), "tool")
	rpathWWriteELF(t, path, "/usr/bin:/usr/lib")
	d, err := AnalyzeElfRpath(path)
	if err != nil || d == nil {
		t.Fatalf("AnalyzeElfRpath = %v, %v", d, err)
	}
	if d.HighestRisk != event.RpathRiskLow || !RiskBelow(d.HighestRisk, event.RpathRiskMedium) {
		t.Errorf("highest risk = %s, want LOW", d.HighestRisk)
	}
}

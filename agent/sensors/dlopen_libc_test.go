package sensors

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDlopenWParseMapsLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		ok   bool
		want dlopenMapping
	}{
		{
			name: "libc text segment",
			line: "7f2c3a428000-7f2c3a5bd000 r-xp 00028000 08:02 1835231                    /usr/lib/x86_64-linux-gnu/libc.so.6",
			ok:   true,
			want: dlopenMapping{Start: 0x7f2c3a428000, End: 0x7f2c3a5bd000,
				ID: dlopenLibcID{Major: 8, Minor: 2, Ino: 1835231}, Path: "/usr/lib/x86_64-linux-gnu/libc.so.6"},
		},
		{
			name: "deleted after an upgrade",
			line: "7f2c3a428000-7f2c3a5bd000 r-xp 00028000 fd:01 42 /lib/x86_64-linux-gnu/libc-2.31.so (deleted)",
			ok:   true,
			want: dlopenMapping{Start: 0x7f2c3a428000, End: 0x7f2c3a5bd000,
				ID: dlopenLibcID{Major: 0xfd, Minor: 1, Ino: 42}, Path: "/lib/x86_64-linux-gnu/libc-2.31.so", Deleted: true},
		},
		{
			name: "path with spaces, zero-padded low address",
			line: "00400000-00452000 r-xp 00000000 103:05 77 /opt/my app/lib dir/libc.so.6",
			ok:   true,
			want: dlopenMapping{Start: 0x400000, End: 0x452000,
				ID: dlopenLibcID{Major: 0x103, Minor: 5, Ino: 77}, Path: "/opt/my app/lib dir/libc.so.6"},
		},
		{name: "anonymous", line: "7ffd6e1d0000-7ffd6e1f1000 rw-p 00000000 00:00 0"},
		{name: "anonymous with trailing spaces", line: "7ffd6e1d0000-7ffd6e1f1000 rw-p 00000000 00:00 0      "},
		{name: "pseudo path", line: "7ffd6e1f8000-7ffd6e1fa000 r-xp 00000000 00:00 0                          [vdso]"},
		{name: "inode zero with a path", line: "7f00-7f10 r--p 00000000 00:00 0 /memfd:x"},
		{name: "bad address", line: "zz-7f10 r--p 00000000 08:02 5 /lib/libc.so.6"},
		{name: "end before start", line: "7f10-7f00 r--p 00000000 08:02 5 /lib/libc.so.6"},
		{name: "bad device", line: "7f00-7f10 r--p 00000000 0802 5 /lib/libc.so.6"},
		{name: "bad inode", line: "7f00-7f10 r--p 00000000 08:02 x /lib/libc.so.6"},
		{name: "empty", line: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := dlopenParseMapsLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (%+v)", ok, tt.ok, got)
			}
			if ok && got != tt.want {
				t.Errorf("got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestDlopenWIsGlibcObject(t *testing.T) {
	yes := []string{
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/lib/x86_64-linux-gnu/libc-2.31.so",
		"/lib/x86_64-linux-gnu/libdl.so.2",
		"/lib64/libdl-2.17.so",
	}
	no := []string{
		"/lib/ld-musl-x86_64.so.1",
		"/lib/libc.musl-x86_64.so.1",
		"/usr/lib/libc.so",
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
		"/usr/lib/x86_64-linux-gnu/libcap.so.2",
		"/usr/lib/x86_64-linux-gnu/libc-client.so",
		"/usr/lib/x86_64-linux-gnu/libc-.so",
		"/usr/lib/x86_64-linux-gnu/libdlm.so.3",
		"/lib64/ld-linux-x86-64.so.2",
		"/tmp/libc.so.6.evil",
	}
	for _, p := range yes {
		if !dlopenIsGlibcObject(p) {
			t.Errorf("%s: want glibc object", p)
		}
	}
	for _, p := range no {
		if dlopenIsGlibcObject(p) {
			t.Errorf("%s: want not a glibc object", p)
		}
	}
}

func TestDlopenWScanMapsOnePerFile(t *testing.T) {
	maps := strings.Join([]string{
		"55d0c8a00000-55d0c8a02000 r--p 00000000 08:02 100 /usr/bin/sleep",
		"7f0000000000-7f0000028000 r--p 00000000 08:02 200 /usr/lib/x86_64-linux-gnu/libc.so.6",
		"7f0000028000-7f00001bd000 r-xp 00028000 08:02 200 /usr/lib/x86_64-linux-gnu/libc.so.6",
		"7f00001bd000-7f0000215000 r--p 001bd000 08:02 200 /usr/lib/x86_64-linux-gnu/libc.so.6",
		"7f0000300000-7f0000301000 r--p 00000000 08:02 300 /usr/lib/x86_64-linux-gnu/libdl.so.2",
		"7f0000400000-7f0000401000 r--p 00000000 08:02 400 /usr/lib/x86_64-linux-gnu/libcap.so.2",
		"7f0000500000-7f0000521000 rw-p 00000000 00:00 0",
	}, "\n")
	got := dlopenScanMaps(strings.NewReader(maps))
	if len(got) != 2 {
		t.Fatalf("got %d mappings, want libc and libdl once each: %+v", len(got), got)
	}
	if got[0].ID.Ino != 200 || got[0].Start != 0x7f0000000000 || got[1].ID.Ino != 300 {
		t.Errorf("got %+v", got)
	}
}

func TestDlopenWExportsDlopenRejectsJunk(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":     nil,
		"text":      []byte("libc.so.6 is just a name"),
		"bad magic": []byte("\x7fELG\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		"truncated": []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00"),
	} {
		if dlopenExportsDlopen(strings.NewReader(string(b))) {
			t.Errorf("%s: reported as exporting dlopen", name)
		}
	}
	// The test binary is an ELF (on Linux) or Mach-O file that does not
	// define dlopen itself.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if dlopenExportsDlopen(f) {
		t.Error("test binary reported as exporting dlopen")
	}
}

// dlopenWProc builds a fake /proc for dlopenDiscover.
type dlopenWProc struct {
	t    *testing.T
	root string
}

func dlopenWNewProc(t *testing.T) *dlopenWProc {
	p := &dlopenWProc{t: t, root: t.TempDir()}
	p.process("self", "mnt:[4026531841]", "")
	return p
}

// process creates <root>/<pid>/maps and <root>/<pid>/ns/mnt. An empty ns
// leaves the ns link out, as for a process that exits mid-scan.
func (p *dlopenWProc) process(pid, ns string, maps ...string) {
	dir := filepath.Join(p.root, pid)
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
		p.t.Fatal(err)
	}
	if ns != "" {
		if err := os.Symlink(ns, filepath.Join(dir, "ns", "mnt")); err != nil {
			p.t.Fatal(err)
		}
	}
	if maps != nil {
		if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(strings.Join(maps, "\n")+"\n"), 0o644); err != nil {
			p.t.Fatal(err)
		}
	}
}

const (
	dlopenWHostNS      = "mnt:[4026531841]"
	dlopenWContainerNS = "mnt:[4026532500]"
	dlopenWHostLibc    = "7f0000028000-7f00001bd000 r-xp 00028000 08:02 200 /usr/lib/x86_64-linux-gnu/libc.so.6"
	// The container's libc: same path inside the container, another file.
	dlopenWCtrLibc = "7f1000028000-7f10001bd000 r-xp 00028000 08:02 9001 /usr/lib/x86_64-linux-gnu/libc.so.6"
)

func TestDlopenWDiscover(t *testing.T) {
	p := dlopenWNewProc(t)
	p.process("1", dlopenWHostNS, dlopenWHostLibc)
	p.process("2", "") // kernel thread: no maps file
	p.process("500", dlopenWContainerNS, dlopenWCtrLibc)
	// A second container from the same image maps the same underlying file.
	p.process("600", "mnt:[4026532600]",
		"7f2000028000-7f20001bd000 r-xp 00028000 08:02 9001 /usr/lib/x86_64-linux-gnu/libc.so.6")
	// Alpine: musl only, not covered.
	p.process("700", "mnt:[4026532700]", "7f3000000000-7f3000010000 r-xp 00000000 08:02 7777 /lib/ld-musl-x86_64.so.1")
	// Old glibc in a container: dlopen lives in libdl.
	p.process("800", "mnt:[4026532800]",
		"7f4000000000-7f4000010000 r-xp 00000000 08:02 8100 /lib/x86_64-linux-gnu/libc-2.28.so",
		"7f4000100000-7f4000101000 r-xp 00000000 08:02 8200 /lib/x86_64-linux-gnu/libdl-2.28.so")
	if err := os.MkdirAll(filepath.Join(p.root, "sys"), 0o755); err != nil {
		t.Fatal(err)
	}

	found, err := dlopenDiscover(p.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 4 {
		t.Fatalf("found %d libcs, want 4 (host, shared container, old libc, old libdl): %+v", len(found), found)
	}

	host := found[dlopenLibcID{Major: 8, Minor: 2, Ino: 200}]
	if host == nil || !host.HostNS {
		t.Fatalf("host libc = %+v, want found in the host namespace", host)
	}
	if want := filepath.Join(p.root, "1", "map_files", "7f0000028000-7f00001bd000"); len(host.Opens) != 1 || host.Opens[0] != want {
		t.Errorf("host Opens = %v, want [%s]", host.Opens, want)
	}

	ctr := found[dlopenLibcID{Major: 8, Minor: 2, Ino: 9001}]
	if ctr == nil || ctr.HostNS {
		t.Fatalf("container libc = %+v, want found outside the host namespace", ctr)
	}
	if len(ctr.Opens) != 2 || !strings.Contains(ctr.Opens[0], "/500/map_files/") || !strings.Contains(ctr.Opens[1], "/600/map_files/") {
		t.Errorf("container Opens = %v, want one per mapping process", ctr.Opens)
	}
	if !strings.Contains(ctr.Desc, "pid 500") {
		t.Errorf("Desc = %q, want it to name a process", ctr.Desc)
	}
	if found[dlopenLibcID{Major: 8, Minor: 2, Ino: 7777}] != nil {
		t.Error("musl was picked up")
	}
}

func TestDlopenWDiscoverCapsOpens(t *testing.T) {
	p := dlopenWNewProc(t)
	for _, pid := range []string{"10", "11", "12", "13", "14", "15"} {
		p.process(pid, dlopenWHostNS, dlopenWHostLibc)
	}
	found, err := dlopenDiscover(p.root)
	if err != nil {
		t.Fatal(err)
	}
	if c := found[dlopenLibcID{Major: 8, Minor: 2, Ino: 200}]; c == nil || len(c.Opens) != dlopenMaxOpens {
		t.Fatalf("got %+v, want %d Opens", c, dlopenMaxOpens)
	}
}

func TestDlopenWDiscoverMissingProc(t *testing.T) {
	if _, err := dlopenDiscover(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("want an error when /proc cannot be read")
	}
}

// dlopenWLink is a fake uprobe link that counts Close calls.
type dlopenWLink struct {
	id     dlopenLibcID
	closed int
}

func (l *dlopenWLink) Close() error { l.closed++; return nil }

// dlopenWAttacher records attaches and returns a per-ID outcome.
type dlopenWAttacher struct {
	links   []*dlopenWLink
	errs    map[uint64]error
	attachN map[uint64]int
}

func (a *dlopenWAttacher) attach(c *dlopenCandidate) (io.Closer, error) {
	a.attachN[c.ID.Ino]++
	if err := a.errs[c.ID.Ino]; err != nil {
		return nil, err
	}
	l := &dlopenWLink{id: c.ID}
	a.links = append(a.links, l)
	return l, nil
}

func dlopenWFound(inos ...uint64) map[dlopenLibcID]*dlopenCandidate {
	m := make(map[dlopenLibcID]*dlopenCandidate)
	for _, ino := range inos {
		id := dlopenLibcID{Major: 8, Minor: 2, Ino: ino}
		m[id] = &dlopenCandidate{ID: id, Desc: "libc"}
	}
	return m
}

func TestDlopenWReconcileLifecycle(t *testing.T) {
	fa := &dlopenWAttacher{errs: map[uint64]error{}, attachN: map[uint64]int{}}
	a := newDlopenAttachments(fa.attach)
	ok := func(io.Closer) error { return nil }

	if n := a.reconcile(dlopenWFound(1, 2)); n != 2 {
		t.Fatalf("attached %d, want 2", n)
	}
	if err := a.check(ok); err != nil {
		t.Fatalf("check: %v", err)
	}

	// Same libcs again: nothing new is attached.
	a.reconcile(dlopenWFound(1, 2))
	if fa.attachN[1] != 1 || fa.attachN[2] != 1 {
		t.Fatalf("attach counts %v, want each libc attached once", fa.attachN)
	}

	// Libc 2's container stopped and libc 3 appeared.
	if n := a.reconcile(dlopenWFound(1, 3)); n != 2 {
		t.Fatalf("attached %d, want 2", n)
	}
	for _, l := range fa.links {
		want := 0
		if l.id.Ino == 2 {
			want = 1
		}
		if l.closed != want {
			t.Errorf("libc %d closed %d times, want %d", l.id.Ino, l.closed, want)
		}
	}

	// Stop: every remaining link is closed once, none twice.
	a.closeAll()
	for _, l := range fa.links {
		if l.closed != 1 {
			t.Errorf("libc %d closed %d times after closeAll, want 1", l.id.Ino, l.closed)
		}
	}
	if err := a.check(ok); err == nil {
		t.Error("check passed with nothing attached")
	}
}

func TestDlopenWReconcileOutcomes(t *testing.T) {
	fa := &dlopenWAttacher{
		errs: map[uint64]error{
			2: errDlopenNoSymbol,
			3: errDlopenGone,
			4: errors.New("perf_event_open: permission denied"),
		},
		attachN: map[uint64]int{},
	}
	a := newDlopenAttachments(fa.attach)
	ok := func(io.Closer) error { return nil }

	if n := a.reconcile(dlopenWFound(1, 2, 3, 4)); n != 1 {
		t.Fatalf("attached %d, want 1", n)
	}
	// A libc without dlopen, or one whose processes exited, is not a gap.
	// One that exports dlopen and failed to attach is.
	err := a.check(ok)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("check = %v, want the attach failure", err)
	}
	if f := a.failures(); !strings.Contains(f, "08:02/4") || strings.Contains(f, "08:02/2") || strings.Contains(f, "08:02/3") {
		t.Errorf("failures = %q, want only libc 4", f)
	}

	// Retried on the next scan; success clears the failure.
	delete(fa.errs, 4)
	a.reconcile(dlopenWFound(1, 2, 3, 4))
	if fa.attachN[4] != 2 {
		t.Errorf("libc 4 attach attempts = %d, want 2", fa.attachN[4])
	}
	if err := a.check(ok); err != nil {
		t.Fatalf("check after retry: %v", err)
	}

	// A failed libc that disappears stops failing the check.
	fa.errs[5] = errors.New("boom")
	a.reconcile(dlopenWFound(1, 4, 5))
	if a.check(ok) == nil {
		t.Fatal("check passed with libc 5 unattached")
	}
	a.reconcile(dlopenWFound(1, 4))
	if err := a.check(ok); err != nil {
		t.Fatalf("check after libc 5 went away: %v", err)
	}
}

func TestDlopenWCheckReportsDetachedLink(t *testing.T) {
	fa := &dlopenWAttacher{errs: map[uint64]error{}, attachN: map[uint64]int{}}
	a := newDlopenAttachments(fa.attach)
	a.reconcile(dlopenWFound(1, 9001))
	err := a.check(func(c io.Closer) error {
		if c.(*dlopenWLink).id.Ino == 9001 {
			return errors.New("perf event has program 0 attached")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "08:02/9001") {
		t.Fatalf("check = %v, want the container libc's link named", err)
	}
}

// Past the attachment cap a libc is not attached but recorded as failed, so
// the attachment check fails instead of the bus taking unbounded links.
func TestDlopenWReconcileCap(t *testing.T) {
	saved := dlopenMaxAttachments
	dlopenMaxAttachments = 2
	t.Cleanup(func() { dlopenMaxAttachments = saved })

	fa := &dlopenWAttacher{errs: map[uint64]error{}, attachN: map[uint64]int{}}
	a := newDlopenAttachments(fa.attach)
	if n := a.reconcile(dlopenWFound(1, 2, 3)); n != 2 {
		t.Fatalf("attached %d, want 2 (the cap)", n)
	}
	if fa.attachN[3] != 0 {
		t.Error("libc past the cap was attached")
	}
	if err := a.check(func(io.Closer) error { return nil }); err == nil || !strings.Contains(err.Error(), "attachment limit") {
		t.Errorf("check = %v, want an attachment-limit failure", err)
	}
	// Once a libc goes away there is room again.
	if n := a.reconcile(dlopenWFound(1, 3)); n != 2 {
		t.Fatalf("attached %d after libc 2 left, want 2", n)
	}
	if err := a.check(func(io.Closer) error { return nil }); err != nil {
		t.Errorf("check after room freed: %v", err)
	}
}

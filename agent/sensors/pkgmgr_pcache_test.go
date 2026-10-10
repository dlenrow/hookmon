package sensors

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/agent/proccache"
)

// pcacheClock is one settable clock shared by a procReader and its cache, so
// the memo's read time and the cache's exec time compare correctly.
type pcacheClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *pcacheClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *pcacheClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// pcacheReader returns a procReader on a fake proc root with its own exec
// cache, fed (so lookups wait for records) and on a shared fake clock.
func pcacheReader(t *testing.T, root string, wait time.Duration) (*procReader, *proccache.Cache, *pcacheClock) {
	t.Helper()
	clk := &pcacheClock{t: time.Unix(5000, 0)}
	c := proccache.New(1024, time.Minute)
	c.SetClock(clk.now)
	c.AddFeeder()
	r := newProcReader(root)
	r.cache = c
	r.execWait = wait
	r.now = clk.now
	return r, c, clk
}

// pcacheFakeZombie writes /proc/<pid> as the kernel shows a zombie: status
// only, no exe link, empty cmdline.
func pcacheFakeZombie(t *testing.T, root string, pid, ppid, uid uint32, name string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Name:\t%s\nState:\tZ (zombie)\nTgid:\t%d\nPid:\t%d\nPPid:\t%d\n"+
		"Uid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\n", name, pid, pid, ppid, uid, uid, uid, uid, uid, uid, uid, uid)
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The writer is gone from /proc, but its exec record is cached: its real
// identity is reported, not unknownID and not 0.
func TestPcacheProcReaderFallsBackToCache(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd")
	fakeProc(t, root, 50, 1, 1000, "bash", "/usr/bin/bash", "-bash")
	r, c, _ := pcacheReader(t, root, time.Second)
	// cp (PID 400, now exited) was exec'd by the shell.
	c.Put(proccache.Entry{PID: 400, PPID: 50, UID: 1000, GID: 1001, Comm: "cp", Exe: "/usr/bin/cp"})

	info := r.lookup(400)
	if !info.Known || info.UID != 1000 || info.GID != 1001 || info.PPID != 50 || info.Comm != "cp" || info.PkgMgr != "" {
		t.Errorf("exited writer from the exec cache: %+v", info)
	}
	if uid, gid := info.ids(); uid != 1000 || gid != 1001 {
		t.Errorf("ids = %d, %d; want 1000, 1001", uid, gid)
	}
}

// The writer's exec record arrives after the file event: the lookup waits
// for it.
func TestPcacheProcReaderWaitsForLateRecord(t *testing.T) {
	root := t.TempDir()
	r, c, _ := pcacheReader(t, root, 5*time.Second)
	go func() {
		time.Sleep(50 * time.Millisecond)
		c.Put(proccache.Entry{PID: 401, PPID: 1, UID: 0, Comm: "sed", Exe: "/usr/bin/sed"})
	}()
	start := time.Now()
	info := r.lookup(401)
	if !info.Known || info.UID != 0 || info.Comm != "sed" {
		t.Errorf("late record: %+v", info)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("lookup took %v; it should return when the record arrives", d)
	}
}

// A writer neither in /proc nor in the cache stays unknown after the wait,
// and a second event from it does not wait again, but still finds a record
// that arrived late.
func TestPcacheProcReaderTimeout(t *testing.T) {
	root := t.TempDir()
	r, c, _ := pcacheReader(t, root, 100*time.Millisecond)

	start := time.Now()
	info := r.lookup(402)
	if d := time.Since(start); d < 100*time.Millisecond {
		t.Errorf("gave up after %v, before the wait bound", d)
	}
	if info.Known || info.PkgMgr != "" {
		t.Errorf("unknown writer: %+v", info)
	}
	if uid, gid := info.ids(); uid != unknownID || gid != unknownID {
		t.Errorf("ids = %d, %d; want unknownID, never 0", uid, gid)
	}

	r.execWait = time.Hour // a second wait would hang the test
	if info := r.lookup(402); info.Known {
		t.Errorf("second lookup: %+v", info)
	}
	c.Put(proccache.Entry{PID: 402, UID: 33, GID: 33, Comm: "late"})
	if info := r.lookup(402); !info.Known || info.UID != 33 {
		t.Errorf("record that arrived after the timeout: %+v", info)
	}
}

// With nothing feeding the cache (elf_rpath disabled), a lookup does not
// wait.
func TestPcacheProcReaderNoFeederNoWait(t *testing.T) {
	r := newProcReader(t.TempDir())
	r.cache = proccache.New(16, time.Minute)
	r.execWait = 5 * time.Second
	start := time.Now()
	if info := r.lookup(403); info.Known {
		t.Errorf("unknown writer: %+v", info)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("lookup without a feeder took %v", d)
	}
}

// /proc wins while the process is alive; the cache is only a fallback.
func TestPcacheProcReaderPrefersProc(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 404, 1, 1000, "vim", "/usr/bin/vim", "vim")
	r, c, _ := pcacheReader(t, root, time.Second)
	c.Put(proccache.Entry{PID: 404, PPID: 1, UID: 0, Comm: "stale"})
	if info := r.lookup(404); info.UID != 1000 || info.Comm != "vim" {
		t.Errorf("live process: %+v", info)
	}
}

// The memo from a /proc read is used for an exited PID, unless the PID
// exec'd again after that read.
func TestPcacheProcReaderMemoVersusReExec(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd")
	fakeProc(t, root, 405, 1, 0, "sh", "/usr/bin/dash", "sh")
	fakeProc(t, root, 406, 1, 0, "sh", "/usr/bin/dash", "sh")
	r, c, clk := pcacheReader(t, root, time.Second)

	// 405: exec'd before it was read, then exited.
	c.Put(proccache.Entry{PID: 405, PPID: 1, Comm: "sh", Exe: "/bin/sh"})
	clk.add(time.Millisecond)
	r.lookup(405)
	// 406: read as sh, then `exec dpkg`, which writes and exits.
	r.lookup(406)
	clk.add(time.Millisecond)
	c.Put(proccache.Entry{PID: 406, PPID: 1, Comm: "dpkg", Exe: "/usr/bin/dpkg"})
	for _, pid := range []string{"405", "406"} {
		if err := os.RemoveAll(filepath.Join(root, pid)); err != nil {
			t.Fatal(err)
		}
	}
	clk.add(time.Second)

	if info := r.lookup(405); !info.Known || info.Comm != "sh" || info.PkgMgr != "" {
		t.Errorf("memo of an exited PID: %+v", info)
	}
	if info := r.lookup(406); !info.Known || info.Comm != "dpkg" || info.PkgMgr != "dpkg" {
		t.Errorf("PID that exec'd again after the memo: %+v", info)
	}
}

// The package-manager walk passes through ancestors that have exited, using
// their exec records.
func TestPcacheAncestryThroughCachedAncestors(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd")
	fakeProc(t, root, 100, 1, 0, "apt-get", "/usr/bin/apt-get", "apt-get", "install")
	fakeProc(t, root, 200, 100, 0, "dpkg", "/usr/bin/dpkg", "/usr/bin/dpkg", "--configure")
	fakeProc(t, root, 60, 1, 0, "bash", "/usr/bin/bash", "-bash")
	r, c, _ := pcacheReader(t, root, time.Second)

	// dpkg (alive) -> sh (exited) -> ldconfig (exited): the trigger shell
	// and ldconfig are known only from the cache.
	c.Put(proccache.Entry{PID: 300, PPID: 200, Comm: "sh", Exe: "/bin/sh"})
	c.Put(proccache.Entry{PID: 301, PPID: 300, Comm: "ldconfig", Exe: "/sbin/ldconfig"})
	if info := r.lookup(301); !info.Known || info.PkgMgr != "dpkg" || info.UID != 0 || info.PPID != 300 {
		t.Errorf("ldconfig under an exited shell under dpkg: %+v", info)
	}

	// A whole chain that has exited: dpkg run from a login shell, then gone.
	c.Put(proccache.Entry{PID: 500, PPID: 60, Comm: "dpkg", Exe: "/usr/bin/dpkg"})
	c.Put(proccache.Entry{PID: 501, PPID: 500, Comm: "sh", Exe: "/bin/sh"})
	c.Put(proccache.Entry{PID: 502, PPID: 501, Comm: "cp", Exe: "/usr/bin/cp"})
	if info := r.lookup(502); info.PkgMgr != "dpkg" {
		t.Errorf("writer under an exited dpkg: %+v", info)
	}

	// A live writer whose parent exited between the two reads.
	fakeProc(t, root, 600, 550, 0, "mv", "/usr/bin/mv", "mv")
	c.Put(proccache.Entry{PID: 550, PPID: 200, Comm: "sh", Exe: "/bin/sh"})
	if info := r.lookup(600); info.PkgMgr != "dpkg" {
		t.Errorf("live writer, exited parent under dpkg: %+v", info)
	}

	// No package manager in a cached chain; a look-alike name outside the
	// system directories does not count either.
	c.Put(proccache.Entry{PID: 700, PPID: 60, Comm: "dpkg", Exe: "/tmp/.x/dpkg"})
	c.Put(proccache.Entry{PID: 701, PPID: 700, Comm: "sed", Exe: "/usr/bin/sed"})
	if info := r.lookup(701); !info.Known || info.PkgMgr != "" {
		t.Errorf("chain without a package manager: %+v", info)
	}

	// The walk stops at an ancestor found nowhere.
	c.Put(proccache.Entry{PID: 801, PPID: 800, Comm: "cp", Exe: "/usr/bin/cp"})
	if info := r.lookup(801); !info.Known || info.PkgMgr != "" {
		t.Errorf("chain with an unknown parent: %+v", info)
	}

	// A cycle of stale cached parents ends at maxAncestry.
	c.Put(proccache.Entry{PID: 901, PPID: 902, Exe: "/usr/bin/a"})
	c.Put(proccache.Entry{PID: 902, PPID: 901, Exe: "/usr/bin/b"})
	if info := r.lookup(901); info.PkgMgr != "" {
		t.Errorf("cycle: %+v", info)
	}
}

// A zombie keeps its /proc status but loses its exe link; the exec cache
// names its executable if the cached exec has the same parent.
func TestPcacheZombieUsesCachedExe(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, 0, "systemd", "/usr/lib/systemd/systemd")
	fakeProc(t, root, 60, 1, 0, "bash", "/usr/bin/bash", "-bash")
	pcacheFakeZombie(t, root, 210, 60, 0, "dpkg")
	pcacheFakeZombie(t, root, 211, 60, 0, "dpkg")
	r, c, _ := pcacheReader(t, root, time.Second)
	c.Put(proccache.Entry{PID: 210, PPID: 60, Comm: "dpkg", Exe: "/usr/bin/dpkg"})
	c.Put(proccache.Entry{PID: 211, PPID: 99, Comm: "dpkg", Exe: "/usr/bin/dpkg"}) // another process's exec

	if info := r.lookup(210); !info.Known || info.UID != 0 || info.PkgMgr != "dpkg" {
		t.Errorf("zombie dpkg: %+v", info)
	}
	if info := r.lookup(211); !info.Known || info.PkgMgr != "" {
		t.Errorf("zombie whose cached exec has another parent: %+v", info)
	}

	st, err := readProcStatus(root, 210)
	if err != nil || !st.zombie {
		t.Errorf("readProcStatus of a zombie: %+v, %v", st, err)
	}
	if st, err := readProcStatus(root, 60); err != nil || st.zombie {
		t.Errorf("readProcStatus of a live process: %+v, %v", st, err)
	}
}

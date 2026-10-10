package sensors

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dlenrow/hookmon/agent/proccache"
)

// unknownID is the UID and GID reported when the process that changed a file
// exited before the sensor could read /proc/<pid>/status and is not in the
// exec cache either. It is (uid_t)-1,
// which the kernel never assigns, so severity rules that treat UID 0 as root
// do not fire on it, and it cannot be mistaken for a real user.
const unknownID = ^uint32(0)

const (
	// procMemoTTL is how long a process's details are remembered after a
	// successful read, for use when a later event from the same PID arrives
	// after the process has exited.
	procMemoTTL = 10 * time.Second
	// procMemoMax bounds the memo; expired entries are dropped past it.
	procMemoMax = 4096
	// maxAncestry bounds the walk up the parent chain.
	maxAncestry = 64
	// execRecordWait bounds how long a lookup waits for the exec record of a
	// writer that is gone from /proc and not yet in the exec cache. The
	// kernel queues that record when the writer execs, before it can write
	// anything, so it is normally cached before the fanotify event is read.
	// It lags only while elf_rpath's reader works through records queued
	// ahead of it; each uncached binary there is opened and parsed, and a
	// risky one hashed, which can take tens of milliseconds for a large
	// binary. 200 ms leaves room for several of those. The watcher reads
	// events on one goroutine, so the bound is also how long one such event
	// can delay the events behind it; that is why it is not longer, and why
	// a PID that timed out is not waited for again within procMemoTTL.
	execRecordWait = 200 * time.Millisecond
)

// pkgManagerBins are the package-manager executables whose writes are
// expected. Matching uses /proc/<pid>/exe, not the comm name, which any
// process can set with prctl(PR_SET_NAME).
var pkgManagerBins = map[string]bool{
	"dpkg": true, "apt": true, "apt-get": true, "rpm": true, "dnf": true, "yum": true,
}

// pkgManagerScripts are package managers that run as Python scripts, so
// their exe is the interpreter and the script is on the command line.
var pkgManagerScripts = map[string]string{
	"dnf": "dnf", "dnf-3": "dnf", "yum": "yum",
}

// systemBinDirs are where a package manager's executable must live to count;
// a copy named dpkg elsewhere does not.
var systemBinDirs = map[string]bool{
	"/usr/bin": true, "/bin": true, "/usr/sbin": true, "/sbin": true,
}

// interpreterDirs additionally allow /usr/libexec, where RHEL 8 keeps
// platform-python.
var interpreterDirs = map[string]bool{
	"/usr/bin": true, "/bin": true, "/usr/libexec": true,
}

// pkgManagerName returns the package manager a process is, judged by its
// executable path and command line, or "".
func pkgManagerName(exe string, argv []string) string {
	exe = strings.TrimSuffix(exe, " (deleted)") // dpkg upgrading itself
	dir, base := filepath.Dir(exe), filepath.Base(exe)
	if systemBinDirs[dir] && pkgManagerBins[base] {
		return base
	}
	if len(argv) > 1 && interpreterDirs[dir] &&
		(strings.HasPrefix(base, "python") || strings.HasPrefix(base, "platform-python")) {
		for _, arg := range argv[1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if name, ok := pkgManagerScripts[filepath.Base(arg)]; ok && systemBinDirs[filepath.Dir(arg)] {
				return name
			}
			break
		}
	}
	return ""
}

// procInfo is what the sensor learned about the process behind a file event.
type procInfo struct {
	Known bool // read from /proc/<pid> (now or within procMemoTTL) or the exec cache
	UID   uint32
	GID   uint32
	PPID  uint32
	Comm  string
	// PkgMgr names the package manager found in the process or its
	// ancestors, or is "" if none was found or the process was gone.
	PkgMgr string
}

// ids returns the UID and GID to report: unknownID if the process was gone.
func (p procInfo) ids() (uid, gid uint32) {
	if !p.Known {
		return unknownID, unknownID
	}
	return p.UID, p.GID
}

type procMemo struct {
	info procInfo
	at   time.Time
}

// procReader reads a process's identity and package-manager ancestry from
// procfs, and falls back to the exec cache (proccache) for processes that
// have exited.
//
// The process that wrote a file may exit before the sensor reads its event
// (cp, sed -i and mv exit right after writing; ldconfig, run by a dpkg
// trigger, exits right after renaming its new ld.so.cache into place). When
// /proc/<pid> is gone the reader uses, in order:
//   - what it read for the same PID within the last procMemoTTL, unless the
//     exec cache shows the PID exec'd again after that read. The sensors look
//     up every event in a watched directory, including the temporary files
//     written next to watched ones (ld.so.cache~, sed's temp file, dpkg's
//     .dpkg-new), so the memo is often filled while the writer is alive;
//   - the exec cache, waiting up to execRecordWait for the writer's exec
//     record if it has not arrived yet.
//
// The ancestry walk uses the exec cache for each ancestor that is gone from
// /proc or is a zombie, so it still reaches a package manager whose
// maintainer-script shell has exited.
//
// If neither source has the process, the result is unknown: no
// package-manager downgrade, and unknownID instead of a UID. That remains
// the case for a writer that never exec'd while elf_rpath was running (a
// forked subshell, a daemon started before the bus) and has exited, and for
// every exited writer when elf_rpath is disabled, since nothing then fills
// the cache. The sensor never assumes a package manager it did not see.
type procReader struct {
	root     string
	ttl      time.Duration
	now      func() time.Time
	cache    *proccache.Cache
	execWait time.Duration

	mu     sync.Mutex
	memo   map[uint32]procMemo
	missed map[uint32]time.Time // PIDs whose wait for an exec record timed out
}

func newProcReader(root string) *procReader {
	return &procReader{
		root:     root,
		ttl:      procMemoTTL,
		now:      time.Now,
		cache:    proccache.Default,
		execWait: execRecordWait,
		memo:     make(map[uint32]procMemo),
		missed:   make(map[uint32]time.Time),
	}
}

// lookup returns what is known about pid now, or from the memo or the exec
// cache if the process has exited.
func (r *procReader) lookup(pid uint32) procInfo {
	if pid == 0 {
		return procInfo{}
	}
	now := r.now()
	if info, ok := r.read(pid); ok {
		r.mu.Lock()
		r.memo[pid] = procMemo{info: info, at: now}
		if len(r.memo) > procMemoMax {
			for p, m := range r.memo {
				if now.Sub(m.at) > r.ttl {
					delete(r.memo, p)
				}
			}
		}
		r.mu.Unlock()
		return info
	}
	r.mu.Lock()
	m, haveMemo := r.memo[pid]
	r.mu.Unlock()
	if haveMemo && now.Sub(m.at) <= r.ttl {
		if e, ok := r.cache.Get(pid); ok && e.ExecTime.After(m.at) {
			return r.fromExec(e) // exec'd again after the memo was read
		}
		return m.info
	}
	if e, ok := r.waitExec(pid, now); ok {
		return r.fromExec(e)
	}
	return procInfo{}
}

// waitExec returns pid's exec record, waiting for it unless an earlier wait
// for the same PID timed out within procMemoTTL; otherwise every event from
// one unknown writer would pay the wait again.
func (r *procReader) waitExec(pid uint32, now time.Time) (proccache.Entry, bool) {
	r.mu.Lock()
	at, missed := r.missed[pid]
	r.mu.Unlock()
	if missed && now.Sub(at) <= r.ttl {
		return r.cache.Get(pid)
	}
	e, ok := r.cache.Wait(pid, r.execWait)
	r.mu.Lock()
	defer r.mu.Unlock()
	if ok {
		delete(r.missed, pid)
		return e, true
	}
	r.missed[pid] = now
	if len(r.missed) > procMemoMax {
		for p, t := range r.missed {
			if now.Sub(t) > r.ttl {
				delete(r.missed, p)
			}
		}
	}
	return proccache.Entry{}, false
}

// fromExec describes an exited process from its exec record.
func (r *procReader) fromExec(e proccache.Entry) procInfo {
	return procInfo{
		Known:  true,
		UID:    e.UID,
		GID:    e.GID,
		PPID:   e.PPID,
		Comm:   e.Comm,
		PkgMgr: r.pkgManagerAncestor(e.Exe, nil, e.PPID),
	}
}

func (r *procReader) read(pid uint32) (procInfo, bool) {
	st, err := readProcStatus(r.root, pid)
	if err != nil {
		return procInfo{}, false
	}
	info := procInfo{Known: true, UID: st.uid, GID: st.gid, PPID: st.ppid, Comm: st.name}
	exe, argv := r.exeOf(pid, st)
	info.PkgMgr = r.pkgManagerAncestor(exe, argv, st.ppid)
	return info, true
}

// exeOf returns the executable and command line of a process whose /proc
// entry exists. A zombie (exited, not yet reaped) keeps its status but has
// no exe link or command line; its executable then comes from the exec
// cache, if the cached exec has the same parent.
func (r *procReader) exeOf(pid uint32, st procStatus) (string, []string) {
	if st.zombie {
		if e, ok := r.cache.Get(pid); ok && e.PPID == st.ppid {
			return e.Exe, nil
		}
		return "", nil
	}
	exe, _ := os.Readlink(filepath.Join(r.root, strconv.FormatUint(uint64(pid), 10), "exe"))
	return exe, readCmdline(r.root, pid)
}

// ancestor returns the executable, command line and parent of a process in
// a writer's ancestry: from /proc while its entry exists, else from the exec
// cache, whose parent is the one at exec time.
func (r *procReader) ancestor(pid uint32) (exe string, argv []string, ppid uint32, ok bool) {
	if st, err := readProcStatus(r.root, pid); err == nil {
		exe, argv = r.exeOf(pid, st)
		return exe, argv, st.ppid, true
	}
	if e, ok := r.cache.Get(pid); ok {
		return e.Exe, nil, e.PPID, true
	}
	return "", nil, 0, false
}

// pkgManagerAncestor checks a process (by its exe and argv), then walks up
// from its parent ppid, and returns the first package manager found. The
// walk stops before init (PID 1) and at the first process found neither in
// /proc nor in the exec cache. A live writer whose parent already exited has
// been reparented, so /proc no longer names its original parent and nothing
// above it is found.
func (r *procReader) pkgManagerAncestor(exe string, argv []string, ppid uint32) string {
	for depth := 0; depth < maxAncestry; depth++ {
		if name := pkgManagerName(exe, argv); name != "" {
			return name
		}
		if ppid <= 1 {
			return ""
		}
		var ok bool
		if exe, argv, ppid, ok = r.ancestor(ppid); !ok {
			return ""
		}
	}
	return ""
}

type procStatus struct {
	name           string
	ppid, uid, gid uint32
	zombie         bool // exited, not yet reaped
}

// readProcStatus parses Name, State, PPid and the real Uid and Gid from
// <root>/<pid>/status. The real IDs match what the eBPF sensors report
// (bpf_get_current_uid_gid).
func readProcStatus(root string, pid uint32) (procStatus, error) {
	data, err := os.ReadFile(filepath.Join(root, strconv.FormatUint(uint64(pid), 10), "status"))
	if err != nil {
		return procStatus{}, err
	}
	var st procStatus
	var haveUID, haveGID bool
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		val = strings.TrimLeft(val, " \t")
		switch key {
		case "Name":
			st.name = val
		case "State":
			st.zombie = strings.HasPrefix(val, "Z") || strings.HasPrefix(val, "X")
		case "PPid":
			st.ppid, _ = parseFirstUint(val)
		case "Uid":
			st.uid, haveUID = parseFirstUint(val)
		case "Gid":
			st.gid, haveGID = parseFirstUint(val)
		}
	}
	// A status without a readable Uid must not turn into UID 0.
	if !haveUID || !haveGID {
		return procStatus{}, fmt.Errorf("no valid Uid/Gid in status of pid %d", pid)
	}
	return st, nil
}

func parseFirstUint(s string) (uint32, bool) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(f[0], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

func readCmdline(root string, pid uint32) []string {
	data, err := os.ReadFile(filepath.Join(root, strconv.FormatUint(uint64(pid), 10), "cmdline"))
	if err != nil || len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
}

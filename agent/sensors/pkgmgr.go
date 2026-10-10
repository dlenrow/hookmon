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
)

// unknownID is the UID and GID reported when the process that changed a file
// exited before the sensor could read /proc/<pid>/status. It is (uid_t)-1,
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
	Known bool // /proc/<pid> was read, now or within procMemoTTL
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
// procfs.
//
// The process that wrote a file may exit before the sensor reads its event
// (ldconfig, run by a dpkg trigger, exits right after renaming its new
// ld.so.cache into place). When /proc/<pid> is gone the reader falls back to
// what it read for the same PID within the last procMemoTTL. The sensors
// look up every event in a watched directory, including the temporary files
// written next to watched ones (ld.so.cache~, sed's temp file, dpkg's
// .dpkg-new), so the memo is usually filled while the writer is alive.
// If there is no memo entry either, the result is unknown: no package-manager
// downgrade, and unknownID instead of a UID. The sensor never assumes a
// package manager it did not see.
type procReader struct {
	root string
	ttl  time.Duration
	now  func() time.Time

	mu   sync.Mutex
	memo map[uint32]procMemo
}

func newProcReader(root string) *procReader {
	return &procReader{root: root, ttl: procMemoTTL, now: time.Now, memo: make(map[uint32]procMemo)}
}

// lookup returns what is known about pid now, or from the memo if the
// process has exited.
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
	defer r.mu.Unlock()
	if m, ok := r.memo[pid]; ok && now.Sub(m.at) <= r.ttl {
		return m.info
	}
	return procInfo{}
}

func (r *procReader) read(pid uint32) (procInfo, bool) {
	st, err := readProcStatus(r.root, pid)
	if err != nil {
		return procInfo{}, false
	}
	info := procInfo{Known: true, UID: st.uid, GID: st.gid, PPID: st.ppid, Comm: st.name}
	info.PkgMgr = r.pkgManagerAncestor(pid, st.ppid)
	return info, true
}

// pkgManagerAncestor walks from pid up the parent chain and returns the first
// package manager found. The walk stops before init (PID 1) and at the first
// process that cannot be read; a writer whose parent already exited has been
// reparented, so its original ancestry is lost and nothing is found.
func (r *procReader) pkgManagerAncestor(pid, ppid uint32) string {
	cur, next := pid, ppid
	for depth := 0; depth < maxAncestry; depth++ {
		exe, _ := os.Readlink(filepath.Join(r.root, strconv.FormatUint(uint64(cur), 10), "exe"))
		if name := pkgManagerName(exe, readCmdline(r.root, cur)); name != "" {
			return name
		}
		if next <= 1 {
			return ""
		}
		cur = next
		st, err := readProcStatus(r.root, cur)
		if err != nil {
			return ""
		}
		next = st.ppid
	}
	return ""
}

type procStatus struct {
	name           string
	ppid, uid, gid uint32
}

// readProcStatus parses Name, PPid and the real Uid and Gid from
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

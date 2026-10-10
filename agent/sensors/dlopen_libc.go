package sensors

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// dlopen_monitor attaches its uprobe to every glibc object that exports
// dlopen and that some process has mapped: the host's libc and each
// container's own libc, found through /proc/<pid>/maps. This file holds the
// parts that do not need a kernel: parsing maps, grouping mappings by file,
// and keeping one attachment per file across rescans.

// dlopenLibcID identifies a mapped file by the device and inode that
// /proc/<pid>/maps prints. For a file on overlayfs (a container image),
// upstream kernels print the underlying file, the inode the kernel places a
// uprobe on, so containers that share an image layer share one ID. Ubuntu's
// overlayfs patches print the overlay's own device instead (the inode number
// is still the underlying one), so there each container has its own ID and
// its own link to the same file.
type dlopenLibcID struct {
	Major, Minor uint32
	Ino          uint64
}

func (id dlopenLibcID) String() string {
	return fmt.Sprintf("%02x:%02x/%d", id.Major, id.Minor, id.Ino)
}

// dlopenMapping is one file-backed line of /proc/<pid>/maps.
type dlopenMapping struct {
	Start, End uint64
	ID         dlopenLibcID
	// Path is the file's path as the kernel printed it, relative to the
	// root of the mapping process's mount namespace, without " (deleted)".
	Path    string
	Deleted bool
}

// dlopenParseMapsLine parses one line of /proc/<pid>/maps:
//
//	7f2c3a428000-7f2c3a5bd000 r-xp 00028000 08:02 1835231   /usr/lib/x86_64-linux-gnu/libc.so.6
//
// It reports false for anonymous and pseudo mappings ([heap], [vdso]) and
// for lines it cannot parse. The path is everything after the inode and may
// contain spaces.
func dlopenParseMapsLine(line string) (dlopenMapping, bool) {
	var f [5]string
	rest := line
	for i := range f {
		rest = strings.TrimLeft(rest, " \t")
		j := strings.IndexAny(rest, " \t")
		if j < 0 {
			// An anonymous mapping ends after the inode.
			return dlopenMapping{}, false
		}
		f[i], rest = rest[:j], rest[j:]
	}
	path := strings.TrimLeft(rest, " \t")
	if !strings.HasPrefix(path, "/") {
		return dlopenMapping{}, false
	}

	var m dlopenMapping
	start, end, ok := strings.Cut(f[0], "-")
	if !ok {
		return dlopenMapping{}, false
	}
	var err error
	if m.Start, err = strconv.ParseUint(start, 16, 64); err != nil {
		return dlopenMapping{}, false
	}
	if m.End, err = strconv.ParseUint(end, 16, 64); err != nil || m.End <= m.Start {
		return dlopenMapping{}, false
	}
	major, minor, ok := strings.Cut(f[3], ":")
	if !ok {
		return dlopenMapping{}, false
	}
	maj, err := strconv.ParseUint(major, 16, 32)
	if err != nil {
		return dlopenMapping{}, false
	}
	mnr, err := strconv.ParseUint(minor, 16, 32)
	if err != nil {
		return dlopenMapping{}, false
	}
	ino, err := strconv.ParseUint(f[4], 10, 64)
	if err != nil || ino == 0 {
		return dlopenMapping{}, false
	}
	m.ID = dlopenLibcID{Major: uint32(maj), Minor: uint32(mnr), Ino: ino}
	if p, ok := strings.CutSuffix(path, " (deleted)"); ok {
		path, m.Deleted = p, true
	}
	m.Path = path
	return m, true
}

// dlopenIsGlibcObject reports whether a mapped file's name is a glibc object
// that can export dlopen: libc.so.6 (glibc 2.34 and later moved dlopen into
// libc) or libdl.so.2 (earlier glibc), under either the soname or the
// versioned file name older distributions install (libc-2.31.so). musl's
// libc (ld-musl-*.so.1, libc.musl-*.so.1) is deliberately not matched.
func dlopenIsGlibcObject(path string) bool {
	base := filepath.Base(path)
	switch base {
	case "libc.so.6", "libdl.so.2":
		return true
	}
	for _, prefix := range []string{"libc-", "libdl-"} {
		if v, ok := strings.CutPrefix(base, prefix); ok {
			if v, ok = strings.CutSuffix(v, ".so"); ok && dlopenIsVersion(v) {
				return true
			}
		}
	}
	return false
}

// dlopenIsVersion reports whether s looks like "2.31": digits and dots,
// starting with a digit.
func dlopenIsVersion(s string) bool {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// dlopenScanMaps returns the glibc mappings in one maps file, one per file:
// a library is mapped as several segments that all name the same inode.
func dlopenScanMaps(r io.Reader) []dlopenMapping {
	var out []dlopenMapping
	seen := make(map[dlopenLibcID]bool)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		// Cheap filter first: most lines name other files.
		if !strings.Contains(line, "/libc") && !strings.Contains(line, "/libdl") {
			continue
		}
		m, ok := dlopenParseMapsLine(line)
		if !ok || !dlopenIsGlibcObject(m.Path) || seen[m.ID] {
			continue
		}
		seen[m.ID] = true
		out = append(out, m)
	}
	return out
}

// dlopenMaxOpens bounds how many processes are remembered per libc as places
// to open it from. Any one is enough; more only help when processes exit
// between the scan and the attach.
const dlopenMaxOpens = 4

// dlopenCandidate is one distinct glibc object found in the scan.
type dlopenCandidate struct {
	ID dlopenLibcID
	// Desc names the file for messages: its path and a process that maps it.
	Desc string
	// Opens are paths that open this exact file, tried in order:
	// /proc/<pid>/map_files/<start>-<end> for processes that map it, or a
	// plain path for a host seed. map_files names the mapped file itself, so
	// no path lookup inside the container is involved.
	Opens []string
	// HostNS is true if a process in the bus's own mount namespace maps it.
	HostNS bool
}

// dlopenDiscover reads <procRoot>/<pid>/maps for every process and returns
// one candidate per distinct glibc object. Processes that exit during the
// scan, and kernel threads, are skipped.
func dlopenDiscover(procRoot string) (map[dlopenLibcID]*dlopenCandidate, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	selfNS, _ := os.Readlink(filepath.Join(procRoot, "self", "ns", "mnt"))

	found := make(map[dlopenLibcID]*dlopenCandidate)
	for _, e := range entries {
		pid := e.Name()
		if _, err := strconv.ParseUint(pid, 10, 32); err != nil {
			continue
		}
		f, err := os.Open(filepath.Join(procRoot, pid, "maps"))
		if err != nil {
			continue
		}
		maps := dlopenScanMaps(f)
		f.Close()
		if len(maps) == 0 {
			continue
		}
		hostNS := false
		if selfNS != "" {
			ns, err := os.Readlink(filepath.Join(procRoot, pid, "ns", "mnt"))
			hostNS = err == nil && ns == selfNS
		}
		for _, m := range maps {
			c := found[m.ID]
			if c == nil {
				c = &dlopenCandidate{ID: m.ID, Desc: fmt.Sprintf("%s mapped by pid %s", m.Path, pid)}
				found[m.ID] = c
			}
			c.HostNS = c.HostNS || hostNS
			if len(c.Opens) < dlopenMaxOpens {
				c.Opens = append(c.Opens, filepath.Join(procRoot, pid, "map_files",
					fmt.Sprintf("%x-%x", m.Start, m.End)))
			}
		}
	}
	return found, nil
}

// dlopenExportsDlopen reports whether r is an ELF object that defines the
// dynamic function symbol dlopen. A file that does not parse does not: no
// process can be calling dlopen through it. Any process can map a file named
// libc.so.6, so a malformed one must not count as a libc the sensor failed
// to cover.
func dlopenExportsDlopen(r io.ReaderAt) (ok bool) {
	defer func() {
		// debug/elf can panic on malformed input.
		if recover() != nil {
			ok = false
		}
	}()
	f, err := elf.NewFile(r)
	if err != nil {
		return false
	}
	syms, err := f.DynamicSymbols()
	if err != nil {
		return false
	}
	for _, s := range syms {
		if s.Name == "dlopen" && s.Section != elf.SHN_UNDEF && s.Value != 0 &&
			elf.ST_TYPE(s.Info) == elf.STT_FUNC {
			return true
		}
	}
	return false
}

// Attach outcomes that are not failures of the sensor.
var (
	// errDlopenNoSymbol: the object does not export dlopen (libc.so.6 of
	// glibc before 2.34, where dlopen lives in libdl.so.2, or a file that is
	// only named like a libc).
	errDlopenNoSymbol = errors.New("does not export dlopen")
	// errDlopenGone: every process that mapped the object exited before it
	// could be opened.
	errDlopenGone = errors.New("no longer mapped")
)

// dlopenAttachment is one libc the program is attached to.
type dlopenAttachment struct {
	desc string
	link io.Closer
}

// dlopenAttachments keeps one uprobe link per distinct libc. reconcile runs
// at startup and on every rescan; check runs from the health loop.
type dlopenAttachments struct {
	mu       sync.Mutex
	attached map[dlopenLibcID]*dlopenAttachment
	// failed holds libcs that are mapped and export dlopen but could not be
	// attached. They are retried on every rescan and fail the health check
	// until then, because dlopen calls through them are not seen.
	failed map[dlopenLibcID]string
	attach func(*dlopenCandidate) (io.Closer, error)
}

// dlopenMaxAttachments caps how many distinct libcs get a uprobe link. Any
// user can map private copies of libc, and each copy would cost the bus a
// link and a program run per dlopen. Past the cap a libc is recorded as
// failed, so the attachment check reports the sensor unhealthy rather than
// the bus growing without bound.
var dlopenMaxAttachments = 256

func newDlopenAttachments(attach func(*dlopenCandidate) (io.Closer, error)) *dlopenAttachments {
	return &dlopenAttachments{
		attached: make(map[dlopenLibcID]*dlopenAttachment),
		failed:   make(map[dlopenLibcID]string),
		attach:   attach,
	}
}

// reconcile attaches to every found libc not yet attached and closes the
// link of every attached libc that is no longer found, so a libc whose
// processes have all exited (a stopped container, a replaced host libc) is
// detached and its inode released. It returns how many links are attached.
func (a *dlopenAttachments) reconcile(found map[dlopenLibcID]*dlopenCandidate) int {
	a.mu.Lock()
	defer a.mu.Unlock()

	for id, att := range a.attached {
		if found[id] == nil {
			att.link.Close()
			delete(a.attached, id)
		}
	}
	for id := range a.failed {
		if found[id] == nil {
			delete(a.failed, id)
		}
	}
	for _, id := range dlopenSortedIDs(found) {
		if a.attached[id] != nil {
			continue
		}
		if len(a.attached) >= dlopenMaxAttachments {
			a.failed[id] = fmt.Sprintf("attachment limit (%d libcs) reached", dlopenMaxAttachments)
			continue
		}
		c := found[id]
		l, err := a.attach(c)
		switch {
		case err == nil:
			a.attached[id] = &dlopenAttachment{desc: c.Desc, link: l}
			delete(a.failed, id)
		case errors.Is(err, errDlopenNoSymbol), errors.Is(err, errDlopenGone):
			delete(a.failed, id)
		default:
			a.failed[id] = err.Error()
		}
	}
	return len(a.attached)
}

// check runs fn on every attached link, then reports libcs that could not be
// attached. It fails if nothing is attached.
func (a *dlopenAttachments) check(fn func(io.Closer) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.attached) == 0 {
		return errors.New("no libc attached")
	}
	for _, id := range dlopenSortedIDs(a.attached) {
		att := a.attached[id]
		if err := fn(att.link); err != nil {
			return fmt.Errorf("libc %s (%s): %w", id, att.desc, err)
		}
	}
	if ids := dlopenSortedIDs(a.failed); len(ids) > 0 {
		return fmt.Errorf("libc %s not attached: %s", ids[0], a.failed[ids[0]])
	}
	return nil
}

// failures describes the libcs that could not be attached, as "" or as
// ": <id>: <reason>; ...".
func (a *dlopenAttachments) failures() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var parts []string
	for _, id := range dlopenSortedIDs(a.failed) {
		parts = append(parts, fmt.Sprintf("%s: %s", id, a.failed[id]))
	}
	if len(parts) == 0 {
		return ""
	}
	return ": " + strings.Join(parts, "; ")
}

// closeAll detaches every libc.
func (a *dlopenAttachments) closeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, att := range a.attached {
		att.link.Close()
		delete(a.attached, id)
	}
}

// dlopenSortedIDs returns m's keys in a fixed order, so messages and attach
// order do not depend on map iteration.
func dlopenSortedIDs[V any](m map[dlopenLibcID]V) []dlopenLibcID {
	ids := make([]dlopenLibcID, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := ids[i], ids[j]
		if a.Major != b.Major {
			return a.Major < b.Major
		}
		if a.Minor != b.Minor {
			return a.Minor < b.Minor
		}
		return a.Ino < b.Ino
	})
	return ids
}

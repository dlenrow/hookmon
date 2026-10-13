//go:build linux

package sensors

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/dlenrow/hookmon/pkg/event"
)

// A dlopen is reported only if the library could be a stealth hook: a file
// someone other than root can change, by writing the file, its directory or
// a directory above it. A library only root can change is dropped; replacing
// one in a watched library directory is lib_integrity's to report. Anything
// the sensor cannot judge is reported.

// libraryRisk ranks the library dlopen(path) loads in process pid, as that
// process sees the filesystem (a container's own root). ok is false when it
// cannot tell:
//   - a relative path, which resolves against a working directory, or a
//     path under /proc or /dev/fd (a memfd or descriptor loader);
//   - a bare name that the process has not mapped and that its
//     ld.so.cache does not list;
//   - a mapped file that has been deleted;
//   - a process that has exited.
//
// A bare name is judged by the file the process has mapped under that name,
// or else by every file its ld.so.cache lists for it. An LD_LIBRARY_PATH or
// RUNPATH that would find it elsewhere is reported by exec_injection or
// elf_rpath.
func (h *dlopenHashes) libraryRisk(pid uint32, path string) (risk event.RpathRisk, why string, ok bool) {
	switch {
	case path == "":
		return "", "", false
	case strings.Contains(path, "/") && !filepath.IsAbs(path):
		return "", "", false
	case strings.HasPrefix(path, "/proc/"), strings.HasPrefix(path, "/dev/fd/"):
		return "", "", false
	}
	proc := fmt.Sprintf("%s/%d", h.procRoot, pid)
	fs, err := openRootFS(proc + "/root")
	if err != nil {
		return "", "", false
	}
	defer fs.close()

	files := []string{path}
	if !strings.Contains(path, "/") {
		m, found := dlopenMappedByName(proc, path)
		switch {
		case found && m.Deleted:
			return "", "", false
		case found:
			files = []string{m.Path}
		default:
			if files = h.ldCache.lookup(fs, path); len(files) == 0 {
				return "", "", false
			}
		}
	}

	risk, why = event.RpathRiskNone, ""
	for _, f := range files {
		if real, err := fs.realPath(f); err == nil {
			f = real
		}
		r, w := libraryFileRisk(fs, f)
		if why == "" || riskLevel(r) > riskLevel(risk) {
			risk, why = r, w
		}
	}
	return risk, why, true
}

// dlopenMappedByName returns the file-backed mapping in proc's maps whose
// base name is name.
func dlopenMappedByName(proc, name string) (dlopenMapping, bool) {
	maps, err := os.Open(proc + "/maps")
	if err != nil {
		return dlopenMapping{}, false
	}
	defer maps.Close()
	sc := bufio.NewScanner(maps)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		if m, ok := dlopenParseMapsLine(sc.Text()); ok && filepath.Base(m.Path) == name {
			return m, true
		}
	}
	return dlopenMapping{}, false
}

// processLdCaches reads the ld.so.cache in a process's root, and keeps the
// last few parsed, keyed by the file's identity.
type processLdCaches struct {
	mu      sync.Mutex
	entries map[ldCacheFileID]map[string][]string
}

type ldCacheFileID struct {
	dev, ino uint64
	size     int64
	mtime    unix.Timespec
}

const processLdCacheMax = 8

// lookup returns the paths the process's /etc/ld.so.cache lists for name,
// or nil.
func (c *processLdCaches) lookup(fs rootFS, name string) []string {
	fd, err := fs.inRoot("/etc/ld.so.cache", 0)
	if err != nil {
		return nil
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil
	}
	id := ldCacheFileID{dev: st.Dev, ino: st.Ino, size: st.Size, mtime: st.Mtim}

	c.mu.Lock()
	byName, ok := c.entries[id]
	c.mu.Unlock()
	if !ok {
		// Reopening through /proc/self/fd reads exactly the file checked.
		data, err := os.ReadFile("/proc/self/fd/" + strconv.Itoa(fd))
		if err != nil {
			return nil
		}
		parsed, err := parseLdCache(data)
		if err != nil {
			return nil
		}
		byName = make(map[string][]string, len(parsed))
		for _, e := range parsed {
			if e.Key != "" && e.Value != "" {
				byName[e.Key] = append(byName[e.Key], e.Value)
			}
		}
		c.mu.Lock()
		if c.entries == nil || len(c.entries) >= processLdCacheMax {
			c.entries = make(map[ldCacheFileID]map[string][]string)
		}
		c.entries[id] = byName
		c.mu.Unlock()
	}
	return byName[name]
}

//go:build linux

package sensors

import (
	"bufio"
	"container/list"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// dlopenHashCacheSize bounds the file-hash cache. Hashes are reused while a
// file's device, inode, mtime and size are unchanged.
const dlopenHashCacheSize = 1024

type dlopenFileKey struct {
	Dev, Ino uint64
	MtimeNs  int64
	Size     int64
}

type dlopenHashEntry struct {
	key  dlopenFileKey
	hash string
}

// dlopenHashes hashes the executables and libraries named in dlopen events,
// as "sha256:<hex>", through the calling process's own view of the
// filesystem, so a container's files are hashed, not the host's files at
// the same path.
type dlopenHashes struct {
	procRoot string
	mu       sync.Mutex
	order    *list.List // front is most recently used; values are *dlopenHashEntry
	entries  map[dlopenFileKey]*list.Element
}

func newDlopenHashes(procRoot string) *dlopenHashes {
	return &dlopenHashes{
		procRoot: procRoot,
		order:    list.New(),
		entries:  make(map[dlopenFileKey]*list.Element, dlopenHashCacheSize),
	}
}

// exe returns the hash of the binary pid is running, or "" if the process
// has exited. /proc/<pid>/exe opens the loaded file itself, wherever it is.
func (h *dlopenHashes) exe(pid uint32) string {
	f, err := os.OpenFile(fmt.Sprintf("%s/%d/exe", h.procRoot, pid), os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	return h.hashFile(f)
}

// library returns the hash of the file that dlopen(path) in process pid
// names, or "" if it cannot be found:
//   - A path with a slash is resolved inside the process's root directory,
//     with symlinks kept inside that root; a relative one starts at the
//     process's working directory.
//   - A bare name is searched for by ld.so (LD_LIBRARY_PATH, RUNPATH,
//     ld.so.cache), which the bus does not repeat. It is hashed only if the
//     process already has a file of exactly that name mapped when the event
//     is read.
func (h *dlopenHashes) library(pid uint32, path string) string {
	f, err := h.openLibrary(pid, path)
	if err != nil {
		return ""
	}
	defer f.Close()
	return h.hashFile(f)
}

func (h *dlopenHashes) openLibrary(pid uint32, path string) (*os.File, error) {
	proc := fmt.Sprintf("%s/%d", h.procRoot, pid)
	if path == "" {
		return nil, errors.New("empty path")
	}
	if !strings.Contains(path, "/") {
		return dlopenOpenMappedByName(proc, path)
	}
	if !filepath.IsAbs(path) {
		// The kernel prints the cwd relative to the root of the process's
		// mount namespace, which for a container is its own root.
		cwd, err := os.Readlink(proc + "/cwd")
		if err != nil {
			return nil, err
		}
		if !filepath.IsAbs(cwd) || strings.HasSuffix(cwd, " (deleted)") {
			return nil, fmt.Errorf("working directory %q cannot be resolved", cwd)
		}
		path = filepath.Join(cwd, path)
	}
	root, err := unix.Open(proc+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	// RESOLVE_IN_ROOT treats the process's root as / for absolute symlinks
	// and "..", as the process itself saw the path. O_NONBLOCK keeps a FIFO
	// planted at the path from blocking the sensor.
	fd, err := unix.Openat2(root, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// dlopenOpenMappedByName opens the file the process has mapped whose base
// name is name, through /proc/<pid>/map_files.
func dlopenOpenMappedByName(proc, name string) (*os.File, error) {
	maps, err := os.Open(proc + "/maps")
	if err != nil {
		return nil, err
	}
	defer maps.Close()
	sc := bufio.NewScanner(maps)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		m, ok := dlopenParseMapsLine(sc.Text())
		if !ok || filepath.Base(m.Path) != name {
			continue
		}
		return os.OpenFile(fmt.Sprintf("%s/map_files/%x-%x", proc, m.Start, m.End), os.O_RDONLY|unix.O_NONBLOCK, 0)
	}
	return nil, fmt.Errorf("%s not mapped", name)
}

// hashFile returns "sha256:<hex>" of the regular file f, or "".
func (h *dlopenHashes) hashFile(f *os.File) string {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return ""
	}
	key := dlopenFileKey{Dev: st.Dev, Ino: st.Ino, MtimeNs: st.Mtim.Nano(), Size: st.Size}

	h.mu.Lock()
	if el, ok := h.entries[key]; ok {
		h.order.MoveToFront(el)
		hash := el.Value.(*dlopenHashEntry).hash
		h.mu.Unlock()
		return hash
	}
	h.mu.Unlock()

	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return ""
	}
	hash := fmt.Sprintf("sha256:%x", sum.Sum(nil))

	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.entries[key]; !ok {
		if h.order.Len() >= dlopenHashCacheSize {
			oldest := h.order.Back()
			h.order.Remove(oldest)
			delete(h.entries, oldest.Value.(*dlopenHashEntry).key)
		}
		h.entries[key] = h.order.PushFront(&dlopenHashEntry{key: key, hash: hash})
	}
	return hash
}

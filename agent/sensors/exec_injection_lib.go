//go:build linux

package sensors

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// maxLibraryHashSize bounds the file the sensor hashes for one event. A
// value can name any file, and hashing runs on the ring buffer's reader.
// Larger files get no hash.
const maxLibraryHashSize = 64 << 20

// libraryHashCacheSize bounds the hash cache. When it fills, it is cleared.
const libraryHashCacheSize = 1024

// libraryFileID identifies one version of a file. ctime is in the key
// because a writer can restore mtime but not ctime.
type libraryFileID struct {
	dev, ino     uint64
	size         int64
	mtime, ctime unix.Timespec
}

// libraryHasher computes LibraryHash: "sha256:<hex>" of the library an
// LD_PRELOAD or LD_AUDIT value names, read as the new process sees it.
//
// The hash is of the file as it is when the bus reads it, after the exec.
// Someone who can write the file can change it between ld.so loading it and
// the bus hashing it, so a hash is only as good as the protection of the
// file's directory. An allowlist entry should pin the path as well.
type libraryHasher struct {
	cache map[libraryFileID]string
}

func newLibraryHasher() *libraryHasher {
	return &libraryHasher{cache: make(map[libraryFileID]string)}
}

// hash returns LibraryHash for one event, or "" when the value does not name
// exactly one library by absolute path, or the file cannot be found in the
// process's mount namespace and root, is not a regular file, or is larger
// than maxLibraryHashSize.
func (h *libraryHasher) hash(raw *execInjectionEvent, envVar, value string) string {
	path := injectedLibrary(envVar, value)
	if path == "" {
		return ""
	}
	f := openAsProcess(raw, path)
	if f == nil {
		return ""
	}
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil || st.Size > maxLibraryHashSize {
		return ""
	}
	id := libraryFileID{dev: st.Dev, ino: st.Ino, size: st.Size, mtime: st.Mtim, ctime: st.Ctim}
	if sum, ok := h.cache[id]; ok {
		return sum
	}

	sha := sha256.New()
	n, err := io.Copy(sha, io.LimitReader(f, maxLibraryHashSize+1))
	if err != nil || n > maxLibraryHashSize {
		return ""
	}
	sum := fmt.Sprintf("sha256:%x", sha.Sum(nil))
	if len(h.cache) >= libraryHashCacheSize {
		clear(h.cache)
	}
	h.cache[id] = sum
	return sum
}

// injectedLibrary returns the library an LD_PRELOAD or LD_AUDIT value names,
// or "" if it names none, more than one, or one by a path that is not
// absolute. ld.so splits LD_PRELOAD at spaces and colons, LD_AUDIT at colons.
// LD_LIBRARY_PATH names directories and LD_DEBUG no file, so neither has a
// library. A name without a slash is searched for by ld.so, and a relative
// path is resolved against a working directory the bus may no longer see.
func injectedLibrary(envVar, value string) string {
	var seps string
	switch envVar {
	case "LD_PRELOAD":
		seps = " :"
	case "LD_AUDIT":
		seps = ":"
	default:
		return ""
	}
	fields := strings.FieldsFunc(value, func(r rune) bool { return strings.ContainsRune(seps, r) })
	if len(fields) != 1 || !filepath.IsAbs(fields[0]) {
		return ""
	}
	return fields[0]
}

// openAsProcess opens path as the process that exec'd resolves it: under the
// root directory of that process, or of its parent if the kernel reported
// the two share it, and only while that process is in the mount namespace
// the exec happened in. A short-lived process is often gone by now; its
// parent usually is not. It returns nil if neither can be used.
func openAsProcess(raw *execInjectionEvent, path string) *os.File {
	pids := []uint32{raw.PID}
	if raw.Flags&envParentRoot != 0 {
		pids = append(pids, raw.PPID)
	}
	for _, pid := range pids {
		proc := "/proc/" + strconv.FormatUint(uint64(pid), 10)
		if raw.MntNs == 0 || nsInode(proc+"/ns/mnt") != uint64(raw.MntNs) {
			continue
		}
		if f := openRegularInRoot(proc+"/root", path); f != nil {
			return f
		}
	}
	return nil
}

// nsInode returns the inode of a /proc/<pid>/ns/* link's namespace, or 0.
func nsInode(link string) uint64 {
	var st unix.Stat_t
	if err := unix.Stat(link, &st); err != nil {
		return 0
	}
	return st.Ino
}

// openRegularInRoot opens path for reading with root as "/": absolute
// symlinks resolve inside root, as they do for the process, and /proc magic
// links, which would name the bus's own files, are refused. Only a regular
// file is opened for reading; it is first opened O_PATH, so a device or
// FIFO is never opened.
func openRegularInRoot(root, path string) *os.File {
	rootFd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	defer unix.Close(rootFd)

	pathFd, err := unix.Openat2(rootFd, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil
	}
	defer unix.Close(pathFd)

	var st unix.Stat_t
	if err := unix.Fstat(pathFd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil
	}
	// Reopening through /proc/self/fd opens exactly the file checked above.
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pathFd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	return os.NewFile(uintptr(fd), path)
}

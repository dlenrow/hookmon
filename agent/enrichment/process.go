//go:build linux

package enrichment

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Enricher fills in process context on events from /proc and hashes the
// executable, caching hashes by file version. It is safe for concurrent use.
type Enricher struct {
	hashes *HashCache
	selfNS nsID // the bus's own mount namespace
}

// nsID identifies a namespace by the device and inode of its /proc link.
type nsID struct{ dev, ino uint64 }

// NewEnricher returns an Enricher with an empty hash cache.
func NewEnricher() *Enricher {
	e := &Enricher{hashes: NewHashCache(hashCacheCap)}
	e.selfNS, _ = mountNS("/proc/self")
	return e
}

// Enrich fills in cmdline, exe path, exe hash, cgroup and container ID for
// the event's PID. An ExePath or ExeHash the sensor already set is kept: a
// sensor that knows which binary was loaded (elf_rpath) names it, and
// /proc/<pid>/exe may already name a later exec.
//
// ExePath is the path as the process sees it, which is what
// /proc/<pid>/exe reads as. For a process in another mount namespace (a
// container) that path is resolved under /proc/<pid>/root, so the hash is
// of the container's file, not of whatever the host has at the same path.
// No hash is reported if the process is gone, because the namespace the
// path belongs to can no longer be known.
func (e *Enricher) Enrich(evt *event.HookEvent) {
	procDir := "/proc/" + strconv.FormatUint(uint64(evt.PID), 10)

	// Pin the process's root and namespace before reading its exe link,
	// so the path, the namespace and the file opened all belong together
	// even if the process exits midway.
	root, rootErr := os.OpenFile(procDir+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	var ns nsID
	var nsErr error
	if rootErr == nil {
		defer root.Close()
		ns, nsErr = mountNS(procDir)
	}

	if data, err := os.ReadFile(procDir + "/cmdline"); err == nil {
		evt.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
	}

	if evt.ExePath == "" {
		if exe, err := os.Readlink(procDir + "/exe"); err == nil {
			evt.ExePath = exe
		}
	}

	if data, err := os.ReadFile(procDir + "/cgroup"); err == nil {
		evt.CgroupPath, evt.ContainerID = parseProcCgroup(string(data))
	}

	if evt.ExePath == "" || evt.ExeHash != "" || rootErr != nil || nsErr != nil {
		return
	}
	f, err := openExe(root, ns != e.selfNS, procDir, evt.ExePath)
	if err != nil {
		return
	}
	defer f.Close()
	evt.ExeHash = e.hashes.Hash(f)
}

// mountNS returns the mount namespace of the process at procDir.
func mountNS(procDir string) (nsID, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(procDir+"/ns/mnt", &st); err != nil {
		return nsID{}, err
	}
	return nsID{dev: uint64(st.Dev), ino: uint64(st.Ino)}, nil
}

// openExe opens path, an executable path as a process sees it. In the bus's
// own mount namespace that is a host path, even for a chrooted process,
// because /proc/<pid>/exe reads relative to the reader's root. In another
// mount namespace it is relative to that namespace's root, which for a
// container is the process root, so it is resolved under root
// (/proc/<pid>/root).
func openExe(root *os.File, otherNS bool, procDir, path string) (*os.File, error) {
	flags := os.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC
	var f *os.File
	var err error
	if otherNS {
		f, err = openInRoot(root, procDir+"/root", path, flags)
	} else {
		f, err = os.OpenFile(path, flags, 0)
	}
	if err != nil {
		return nil, err
	}
	// O_NONBLOCK keeps a FIFO swapped in at the path from blocking; only a
	// regular file is hashed.
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("not a regular file")
	}
	return f, nil
}

// openInRoot opens path as if root were "/": "..", absolute symlinks and
// magic links cannot leave it, so a symlink planted inside a container
// cannot point the bus at a host file. Kernels before 5.6 have no openat2;
// there the path is opened through rootPath (/proc/<pid>/root), which
// follows the process root for the path itself but not for absolute
// symlinks inside it.
func openInRoot(root *os.File, rootPath, path string, flags int) (*os.File, error) {
	how := unix.OpenHow{
		Flags:   uint64(flags),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(int(root.Fd()), path, &how)
	if err == nil {
		return os.NewFile(uintptr(fd), path), nil
	}
	if !errors.Is(err, unix.ENOSYS) {
		return nil, err
	}
	return os.OpenFile(rootPath+"/"+strings.TrimPrefix(path, "/"), flags, 0)
}

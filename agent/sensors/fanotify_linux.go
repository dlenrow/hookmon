//go:build linux

package sensors

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// fanWatcher reports changes to the entries of a set of directories: create,
// delete, rename into (FAN_MOVED_TO) and close after writing. linker_config
// and lib_integrity share it.
//
// Directory-entry events need a group created with FAN_REPORT_DFID_NAME
// (Linux 5.9+), which reports each event as the directory's file handle plus
// the entry name, and the kernel refuses them on mount marks. That leaves a
// filesystem mark (FAN_MARK_FILESYSTEM) or one inode mark per directory. The
// watcher uses one mark per directory:
//
//   - A filesystem mark on / delivers every create, delete, rename and
//     close-after-write on the root filesystem: logs, builds, container
//     layers. The sensor would resolve a handle for each one to discard
//     nearly all of them, and the unrelated traffic shares the queue with the
//     few events that matter. With inode marks the kernel delivers only
//     events in the watched directories.
//   - The cost is one mark per directory: about 5,000 under /usr/lib on
//     Ubuntu 22.10, well below fs.fanotify.max_user_marks. Marks are not
//     recursive, so a directory created (or moved in) under a watched one is
//     marked when its event arrives and then scanned, and every file already
//     in it is reported as created. Nothing written into it is missed.
//
// Paths are resolved from the directory handle with open_by_handle_at and
// /proc/self/fd, so a watched directory that was renamed reports its current
// path. If the directory no longer exists, the path recorded when it was
// marked is used.
type fanWatcher struct {
	fd     int
	file   *os.File // fd, registered with the runtime poller so Close unblocks Read
	mask   uint64
	follow func(dir string) bool // marks new subdirectories it returns true for
	procs  *procReader

	mu       sync.Mutex
	dirs     map[string]string // handle key -> path when marked
	mountFds map[[8]byte]int   // fsid -> O_PATH fd used as open_by_handle_at's mount_fd

	reads readErrors // read failures, reported through healthErr
}

// healthErr reports whether reads from the fanotify fd keep failing, so the
// sensor's heartbeat stops while it is not seeing events.
func (w *fanWatcher) healthErr() error { return w.reads.err() }

// dirEvent is one change to a directory entry, with the process that made it.
type dirEvent struct {
	Mask uint64
	Pid  uint32
	Dir  string
	Name string
	Proc procInfo
}

func (e dirEvent) path() string { return filepath.Join(e.Dir, e.Name) }

// newFanWatcher creates the fanotify group. follow, if not nil, decides which
// newly created subdirectories of watched directories get marked too.
//
// FAN_UNLIMITED_QUEUE (root only) means the kernel never drops events with
// FAN_Q_OVERFLOW; the per-directory marks keep the volume to what happens in
// the watched directories.
func newFanWatcher(follow func(string) bool, procs *procReader) (*fanWatcher, error) {
	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_UNLIMITED_QUEUE|unix.FAN_REPORT_DFID_NAME,
		unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init with FAN_REPORT_DFID_NAME (needs Linux 5.9+ and CAP_SYS_ADMIN): %w", err)
	}
	mask := uint64(unix.FAN_CREATE | unix.FAN_DELETE | unix.FAN_MOVED_TO | unix.FAN_CLOSE_WRITE | unix.FAN_EVENT_ON_CHILD)
	if follow != nil {
		mask |= unix.FAN_ONDIR
	}
	return &fanWatcher{
		fd:       fd,
		file:     os.NewFile(uintptr(fd), "fanotify"),
		mask:     mask,
		follow:   follow,
		procs:    procs,
		dirs:     make(map[string]string),
		mountFds: make(map[[8]byte]int),
		reads:    readErrors{source: "fanotify"},
	}, nil
}

// addDir marks one directory. Marking an inode that is already marked only
// updates the mask, so a directory replaced at the same path is marked anew.
func (w *fanWatcher) addDir(path string) error {
	err := unix.FanotifyMark(w.fd, unix.FAN_MARK_ADD|unix.FAN_MARK_ONLYDIR|unix.FAN_MARK_DONT_FOLLOW,
		w.mask, unix.AT_FDCWD, path)
	if err != nil {
		return fmt.Errorf("fanotify_mark %s: %w", path, err)
	}

	var fsid [8]byte
	var st unix.Statfs_t
	h, _, herr := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	serr := unix.Statfs(path, &st)
	if serr == nil {
		binary.NativeEndian.PutUint32(fsid[0:4], uint32(st.Fsid.Val[0]))
		binary.NativeEndian.PutUint32(fsid[4:8], uint32(st.Fsid.Val[1]))
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if herr == nil && serr == nil {
		w.dirs[handleKey(fsid, h.Type(), h.Bytes())] = path
		if _, ok := w.mountFds[fsid]; !ok {
			if mfd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
				w.mountFds[fsid] = mfd
			}
		}
	}
	return nil
}

// addTree marks root and every directory below it, calling onFile for each
// non-directory entry. Each directory is marked before it is read, so a file
// created during the walk is either seen by the walk or reported by fanotify.
// It returns the number of directories marked and the first mark error.
func (w *fanWatcher) addTree(root string, onFile func(string)) (int, error) {
	n := 0
	var firstErr error
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if firstErr == nil && p == root {
				firstErr = err
			}
			return nil
		}
		if d.IsDir() {
			if err := w.addDir(p); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return fs.SkipDir
			}
			n++
			return nil
		}
		if onFile != nil {
			onFile(p)
		}
		return nil
	})
	return n, firstErr
}

// forget drops the recorded path of a deleted directory.
func (w *fanWatcher) forget(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, p := range w.dirs {
		if p == path {
			delete(w.dirs, k)
		}
	}
}

func handleKey(fsid [8]byte, htype int32, handle []byte) string {
	var t [4]byte
	binary.NativeEndian.PutUint32(t[:], uint32(htype))
	return string(fsid[:]) + string(t[:]) + string(handle)
}

// resolveDir returns the current path of the directory an event names.
func (w *fanWatcher) resolveDir(r fanRecord) string {
	w.mu.Lock()
	mfd, haveMount := w.mountFds[r.Fsid]
	recorded := w.dirs[handleKey(r.Fsid, r.HandleType, r.Handle)]
	w.mu.Unlock()
	if haveMount {
		fd, err := unix.OpenByHandleAt(mfd, unix.NewFileHandle(r.HandleType, r.Handle), unix.O_PATH|unix.O_CLOEXEC)
		if err == nil {
			p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
			unix.Close(fd)
			if err == nil && !strings.HasSuffix(p, " (deleted)") {
				return p
			}
		}
	}
	return recorded
}

// run reads events until done is closed or the watcher is closed, and sends
// each one on out. The writer's process details are read here, before
// anything slower, because the writer may be about to exit.
func (w *fanWatcher) run(done <-chan struct{}, out chan<- dirEvent) {
	buf := make([]byte, 64*1024)
	for {
		n, err := w.file.Read(buf)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			// The runtime poller absorbs EAGAIN; anything else here is
			// unexpected. Back off, and count it against the sensor's health.
			if !w.reads.handle(err, done) {
				return
			}
			continue
		}
		w.reads.ok()
		recs, _ := parseFanotifyEvents(buf[:n])
		for _, r := range recs {
			if !r.HasDir {
				continue // FAN_Q_OVERFLOW cannot happen with an unlimited queue
			}
			proc := w.procs.lookup(uint32(r.Pid))
			ev := dirEvent{Mask: r.Mask, Pid: uint32(r.Pid), Dir: w.resolveDir(r), Name: r.Name, Proc: proc}
			if ev.Dir == "" || ev.Name == "" {
				continue
			}
			if !send(done, out, ev) {
				return
			}
			if ev.Mask&fanOnDir != 0 && ev.Mask&fanDelete != 0 {
				// Events are read in order, so those for entries of the
				// deleted directory have already used its recorded path.
				w.forget(ev.path())
			}
			if ev.Mask&fanOnDir != 0 && ev.Mask&(fanCreate|fanMovedTo) != 0 && w.follow != nil && w.follow(ev.path()) {
				w.addTree(ev.path(), func(p string) {
					send(done, out, dirEvent{Mask: fanCreate, Pid: ev.Pid, Dir: filepath.Dir(p), Name: filepath.Base(p), Proc: proc})
				})
			}
		}
	}
}

func send(done <-chan struct{}, out chan<- dirEvent, ev dirEvent) bool {
	select {
	case out <- ev:
		return true
	case <-done:
		return false
	}
}

func (w *fanWatcher) close() {
	w.file.Close()
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, fd := range w.mountFds {
		unix.Close(fd)
	}
	w.mountFds = map[[8]byte]int{}
}

// fileExists reports whether the directory entry exists (a dangling symlink
// counts).
func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// procIDs fills the process fields of an event from what the watcher read.
// A process that was gone gets unknownID, never 0.
func procIDs(p procInfo) (uid, gid, ppid uint32, comm string) {
	uid, gid = p.ids()
	return uid, gid, p.PPID, p.Comm
}

//go:build linux

package sensors

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/dlenrow/hookmon/agent/suppress"
	"github.com/dlenrow/hookmon/pkg/event"
)

// watchedLibDirs are the standard shared library directories to monitor,
// including everything below them.
var watchedLibDirs = []string{
	"/usr/lib",
	"/usr/lib64",
	"/lib",
	"/lib64",
}

// LibIntegritySensor reports every write, create, delete and rename of a
// shared object (*.so, *.so.*) under the standard library directories. It
// marks each directory in those trees with fanotify; see fanWatcher.
//
// At start it records a baseline hash of every shared object, which becomes
// the OldHash of the first change to that file. The baseline is hashed in the
// background (gigabytes on a desktop install), so a file changed before its
// turn has no OldHash. InLdCache says whether the dynamic linker finds the
// library through /etc/ld.so.cache.
//
// A change is ALERT. A change with a package manager in the writer's
// process ancestry is not reported, only counted as suppressed; see
// procReader for what happens when the writer exited.
type LibIntegritySensor struct {
	roots       []string
	ldCachePath string
	procRoot    string

	realRoots []string // roots with symlinks resolved, set by Start
	eventCh   chan *event.HookEvent
	done      chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
	watcher   *fanWatcher
	baseline  *fileBaseline
	ldcache   *ldCacheIndex
}

func NewLibIntegritySensor() *LibIntegritySensor {
	return newLibIntegritySensor(watchedLibDirs, "/etc/ld.so.cache", "/proc")
}

func newLibIntegritySensor(roots []string, ldCachePath, procRoot string) *LibIntegritySensor {
	return &LibIntegritySensor{
		roots:       roots,
		ldCachePath: ldCachePath,
		procRoot:    procRoot,
		eventCh:     make(chan *event.HookEvent, 256),
		done:        make(chan struct{}),
		baseline:    newFileBaseline(),
		ldcache:     newLdCacheIndex(ldCachePath),
	}
}

func (s *LibIntegritySensor) Name() string                    { return "lib_integrity" }
func (s *LibIntegritySensor) Type() SensorType                { return SensorTypeFanotify }
func (s *LibIntegritySensor) Events() <-chan *event.HookEvent { return s.eventCh }

// Healthy reports why the sensor is not seeing events, or nil.
func (s *LibIntegritySensor) Healthy() error {
	if s.watcher == nil {
		return nil
	}
	return s.watcher.healthErr()
}

func isSharedObjectName(name string) bool {
	return strings.HasSuffix(name, ".so") || strings.Contains(name, ".so.")
}

func (s *LibIntegritySensor) underRoot(path string) bool {
	for _, r := range s.realRoots {
		if path == r || strings.HasPrefix(path, r+"/") {
			return true
		}
	}
	return false
}

// Start marks every directory under the library roots, starts the baseline
// hash and starts reading events. It fails if no directory could be marked.
func (s *LibIntegritySensor) Start() error {
	w, err := newFanWatcher(s.underRoot, newProcReader(s.procRoot))
	if err != nil {
		return err
	}
	var libs []string
	marked := 0
	var errs []error
	for _, root := range s.roots {
		real, err := filepath.EvalSymlinks(root)
		if err != nil {
			if !os.IsNotExist(err) {
				errs = append(errs, err)
			}
			continue
		}
		if s.underRoot(real) { // /lib -> usr/lib on merged-/usr systems
			continue
		}
		s.realRoots = append(s.realRoots, real)
		n, err := w.addTree(real, func(p string) {
			if isSharedObjectName(filepath.Base(p)) {
				libs = append(libs, p)
			}
		})
		marked += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	if marked == 0 {
		w.close()
		return fmt.Errorf("no fanotify mark succeeded under %v: %v", s.roots, errs)
	}
	s.watcher = w
	s.ldcache.contains("") // parse ld.so.cache now rather than on the first event

	ch := make(chan dirEvent, 1024)
	s.wg.Add(3)
	go func() {
		defer s.wg.Done()
		s.hashBaseline(libs)
	}()
	go func() {
		defer s.wg.Done()
		w.run(s.done, ch)
	}()
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-s.done:
				return
			case ev := <-ch:
				s.handleEvent(ev)
			}
		}
	}()
	return nil
}

// hashBaseline records the startup hash of each library found when marking.
// Marks are placed first, so a library changed meanwhile is still reported;
// setIfAbsent keeps the hash an event recorded over the startup one.
//
// On the Ubuntu 22.10 test host this reads 2.3 GB, about 9 s of one core, so
// it runs at the lowest CPU priority. The goroutine is locked to its thread
// and never unlocks, so the thread exits with it and the priority does not
// pass to other goroutines.
func (s *LibIntegritySensor) hashBaseline(libs []string) {
	runtime.LockOSThread()
	unix.Setpriority(unix.PRIO_PROCESS, unix.Gettid(), 19)

	byTarget := make(map[string]string) // a symlink and its target are read once
	for _, p := range libs {
		select {
		case <-s.done:
			return
		default:
		}
		target, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		h, ok := byTarget[target]
		if !ok {
			h = hashFile(target)
			byTarget[target] = h
		}
		s.baseline.setIfAbsent(p, h)
	}
}

func (s *LibIntegritySensor) Stop() error {
	s.stopOnce.Do(func() {
		close(s.done)
		if s.watcher != nil {
			s.watcher.close()
		}
		s.wg.Wait()
	})
	return nil
}

func (s *LibIntegritySensor) handleEvent(ev dirEvent) {
	// Directories are followed by the watcher; only files are reported.
	if ev.Mask&fanOnDir != 0 || !isSharedObjectName(ev.Name) {
		return
	}
	path := ev.path()
	if !s.underRoot(path) { // a watched directory moved out of the tree
		return
	}
	newHash := hashFile(path)
	op := fileOp(ev.Mask, fileExists(path))
	if op == "delete" {
		newHash = ""
	}
	// The baseline moves on either way, so the next reported change carries
	// the package's version as its old hash.
	oldHash := s.baseline.swap(path, newHash)
	if ev.Proc.PkgMgr != "" {
		suppress.Add(s.Name(), suppress.PackageManager)
		return
	}
	uid, gid, ppid, comm := procIDs(ev.Proc)

	hookEvt := &event.HookEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		EventType: event.EventLibIntegrity,
		Severity:  event.SeverityAlert,
		PID:       ev.Pid,
		PPID:      ppid,
		UID:       uid,
		GID:       gid,
		Comm:      comm,
		LibIntegrityDetail: &event.LibIntegrityDetail{
			LibraryPath: path,
			Operation:   op,
			OldHash:     oldHash,
			NewHash:     newHash,
			InLdCache:   s.ldcache.contains(path),
		},
	}

	select {
	case s.eventCh <- hookEvt:
	case <-s.done:
	}
}

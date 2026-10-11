//go:build linux

package sensors

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/dlenrow/hookmon/pkg/event"
)

// linkerConfigFiles are the files in /etc that the dynamic linker
// (ld.so.preload, ld.so.cache) and ldconfig (ld.so.conf) read.
var linkerConfigFiles = []string{"ld.so.preload", "ld.so.conf", "ld.so.cache"}

// linkerConfigDir is the drop-in directory ld.so.conf includes.
const linkerConfigDir = "ld.so.conf.d"

// LinkerConfigSensor reports every change to /etc/ld.so.preload,
// /etc/ld.so.conf, /etc/ld.so.cache and the entries of /etc/ld.so.conf.d:
// writes, creates, deletes and renames over them (sed -i, mv, ln -sf). It
// marks /etc and /etc/ld.so.conf.d with fanotify; see fanWatcher.
//
// A change is CRITICAL, or INFO when a package manager is in the writer's
// process ancestry (see procReader for what happens when the writer exited).
type LinkerConfigSensor struct {
	etcDir   string
	procRoot string

	eventCh  chan *event.HookEvent
	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	watcher  *fanWatcher
	baseline *fileBaseline
}

func NewLinkerConfigSensor() *LinkerConfigSensor {
	return newLinkerConfigSensor("/etc", "/proc")
}

func newLinkerConfigSensor(etcDir, procRoot string) *LinkerConfigSensor {
	return &LinkerConfigSensor{
		etcDir:   etcDir,
		procRoot: procRoot,
		eventCh:  make(chan *event.HookEvent, 256),
		done:     make(chan struct{}),
		baseline: newFileBaseline(),
	}
}

func (s *LinkerConfigSensor) Name() string                    { return "linker_config" }
func (s *LinkerConfigSensor) Type() SensorType                { return SensorTypeFanotify }
func (s *LinkerConfigSensor) Events() <-chan *event.HookEvent { return s.eventCh }

// Healthy reports why the sensor is not seeing events, or nil.
func (s *LinkerConfigSensor) Healthy() error {
	if s.watcher == nil {
		return nil
	}
	return s.watcher.healthErr()
}

func (s *LinkerConfigSensor) confDir() string { return filepath.Join(s.etcDir, linkerConfigDir) }

// isLinkerConfigPath reports whether path is one of the linker files, an
// entry of ld.so.conf.d, or ld.so.conf.d itself.
func (s *LinkerConfigSensor) isLinkerConfigPath(path string) bool {
	dir, name := filepath.Dir(path), filepath.Base(path)
	switch dir {
	case s.confDir():
		return true
	case s.etcDir:
		return name == linkerConfigDir || slices.Contains(linkerConfigFiles, name)
	}
	return false
}

// Start marks /etc and /etc/ld.so.conf.d, records the baseline hash of every
// watched file, and starts reading events. It fails if neither directory
// could be marked.
func (s *LinkerConfigSensor) Start() error {
	w, err := newFanWatcher(func(dir string) bool { return dir == s.confDir() }, newProcReader(s.procRoot))
	if err != nil {
		return err
	}
	marked := 0
	var errs []error
	for _, dir := range []string{s.etcDir, s.confDir()} {
		if err := w.addDir(dir); err != nil {
			errs = append(errs, err)
			continue
		}
		marked++
	}
	if marked == 0 {
		w.close()
		return fmt.Errorf("no fanotify mark succeeded: %v", errs)
	}
	s.watcher = w

	// Baseline after marking, so a change made in between is still reported.
	for _, name := range linkerConfigFiles {
		p := filepath.Join(s.etcDir, name)
		s.baseline.setIfAbsent(p, hashFile(p))
	}
	if entries, err := os.ReadDir(s.confDir()); err == nil {
		for _, e := range entries {
			p := filepath.Join(s.confDir(), e.Name())
			s.baseline.setIfAbsent(p, hashFile(p))
		}
	}

	ch := make(chan dirEvent, 1024)
	s.wg.Add(2)
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

func (s *LinkerConfigSensor) Stop() error {
	s.stopOnce.Do(func() {
		close(s.done)
		if s.watcher != nil {
			s.watcher.close()
		}
		s.wg.Wait()
	})
	return nil
}

func (s *LinkerConfigSensor) handleEvent(ev dirEvent) {
	path := ev.path()
	if !s.isLinkerConfigPath(path) {
		return
	}
	newHash := hashFile(path)
	op := fileOp(ev.Mask, fileExists(path))
	if op == "delete" {
		newHash = ""
	}
	oldHash := s.baseline.swap(path, newHash)

	severity := event.SeverityCritical
	if ev.Proc.PkgMgr != "" {
		severity = event.SeverityInfo
	}
	uid, gid, ppid, comm := procIDs(ev.Proc)

	hookEvt := &event.HookEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		EventType: event.EventLinkerConfig,
		Severity:  severity,
		PID:       ev.Pid,
		PPID:      ppid,
		UID:       uid,
		GID:       gid,
		Comm:      comm,
		LinkerConfigDetail: &event.LinkerConfigDetail{
			FilePath:  path,
			Operation: op,
			OldHash:   oldHash,
			NewHash:   newHash,
		},
	}

	select {
	case s.eventCh <- hookEvt:
	case <-s.done:
	}
}

// hashFile returns "sha256:<hex>" of a regular file's content (following
// symlinks), the format enrichment uses, or "" if it is not a readable
// regular file. The open is non-blocking so a FIFO planted under a watched
// name cannot stall the sensor.
func hashFile(path string) string {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

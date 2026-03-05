//go:build linux

package sensors

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/dlenrow/hookmon/pkg/event"
)

// watchedLibDirs are the standard shared library directories to monitor.
var watchedLibDirs = []string{
	"/usr/lib",
	"/usr/lib64",
	"/lib",
	"/lib64",
}

// LibIntegritySensor monitors standard library directories for modifications
// to shared object files using fanotify. Changes to .so files on disk may
// indicate an attacker replacing a legitimate library with a trojaned version.
type LibIntegritySensor struct {
	eventCh chan *event.HookEvent
	fd      int
	done    chan struct{}
}

func NewLibIntegritySensor() *LibIntegritySensor {
	return &LibIntegritySensor{
		eventCh: make(chan *event.HookEvent, 256),
		fd:      -1,
		done:    make(chan struct{}),
	}
}

func (s *LibIntegritySensor) Name() string       { return "lib_integrity" }
func (s *LibIntegritySensor) Type() SensorType   { return SensorTypeFanotify }
func (s *LibIntegritySensor) Events() <-chan *event.HookEvent { return s.eventCh }

func (s *LibIntegritySensor) Start() error {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("fanotify_init: %w", err)
	}
	s.fd = fd

	// Use FAN_MARK_MOUNT to catch writes to files within library directories.
	// FAN_CLOSE_WRITE is the only event mask that delivers fd-based events
	// without FAN_REPORT_FID; filtering to .so files happens in handleEvent.
	marked := make(map[string]bool)
	for _, dir := range watchedLibDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		// Avoid double-marking the same mount point
		if marked[dir] {
			continue
		}
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT,
			uint64(unix.FAN_CLOSE_WRITE), unix.AT_FDCWD, dir); err != nil {
			continue
		}
		marked[dir] = true
	}

	go s.readLoop()
	return nil
}

func (s *LibIntegritySensor) Stop() error {
	close(s.done)
	if s.fd >= 0 {
		unix.Close(s.fd)
	}
	return nil
}

func (s *LibIntegritySensor) readLoop() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-s.done:
			return
		default:
		}

		n, err := unix.Read(s.fd, buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		offset := 0
		for offset < n {
			meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			if meta.Event_len < uint32(unsafe.Sizeof(unix.FanotifyEventMetadata{})) {
				break
			}

			if meta.Fd >= 0 {
				s.handleEvent(meta)
				unix.Close(int(meta.Fd))
			}

			offset += int(meta.Event_len)
		}
	}
}

func (s *LibIntegritySensor) handleEvent(meta *unix.FanotifyEventMetadata) {
	fdPath := fmt.Sprintf("/proc/self/fd/%d", meta.Fd)
	filePath, err := os.Readlink(fdPath)
	if err != nil {
		return
	}

	// Only care about shared object files in watched library directories
	if !strings.HasSuffix(filePath, ".so") && !strings.Contains(filePath, ".so.") {
		return
	}
	inWatchedDir := false
	for _, dir := range watchedLibDirs {
		if strings.HasPrefix(filePath, dir+"/") {
			inWatchedDir = true
			break
		}
	}
	if !inWatchedDir {
		return
	}

	op := "write"
	if meta.Mask&unix.FAN_CREATE != 0 {
		op = "create"
	} else if meta.Mask&unix.FAN_DELETE != 0 {
		op = "delete"
	} else if meta.Mask&unix.FAN_MOVED_TO != 0 {
		op = "rename"
	}

	newHash := hashFile(filePath)

	hookEvt := &event.HookEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		EventType: event.EventLibIntegrity,
		Severity:  event.SeverityAlert,
		PID:       uint32(meta.Pid),
		LibIntegrityDetail: &event.LibIntegrityDetail{
			LibraryPath: filePath,
			Operation:   op,
			NewHash:     newHash,
		},
	}

	select {
	case s.eventCh <- hookEvt:
	default:
	}
}

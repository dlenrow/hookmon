//go:build linux

package sensors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/dlenrow/hookmon/pkg/event"
)

// watchedLinkerPaths are the linker config files and directories to monitor.
var watchedLinkerPaths = []string{
	"/etc/ld.so.preload",
	"/etc/ld.so.conf",
	"/etc/ld.so.conf.d",
}

// LinkerConfigSensor monitors linker configuration files for modifications
// using fanotify. Changes to /etc/ld.so.preload, /etc/ld.so.conf, and
// /etc/ld.so.conf.d/ are strong indicators of persistence or injection.
type LinkerConfigSensor struct {
	eventCh chan *event.HookEvent
	fd      int
	done    chan struct{}
}

func NewLinkerConfigSensor() *LinkerConfigSensor {
	return &LinkerConfigSensor{
		eventCh: make(chan *event.HookEvent, 256),
		fd:      -1,
		done:    make(chan struct{}),
	}
}

func (s *LinkerConfigSensor) Name() string       { return "linker_config" }
func (s *LinkerConfigSensor) Type() SensorType   { return SensorTypeFanotify }
func (s *LinkerConfigSensor) Events() <-chan *event.HookEvent { return s.eventCh }

func (s *LinkerConfigSensor) Start() error {
	// FAN_CLASS_NOTIF is unprivileged notification. FAN_CLOSE_WRITE detects
	// file modifications after the writer closes the fd.
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("fanotify_init: %w", err)
	}
	s.fd = fd

	for _, path := range watchedLinkerPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue // skip paths that don't exist yet
		}
		flags := uint(unix.FAN_CLOSE_WRITE | unix.FAN_CREATE | unix.FAN_DELETE | unix.FAN_MOVED_TO)
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, flags, unix.AT_FDCWD, path); err != nil {
			// Non-fatal: some paths may not be markable
			continue
		}
	}

	go s.readLoop()
	return nil
}

func (s *LinkerConfigSensor) Stop() error {
	close(s.done)
	if s.fd >= 0 {
		unix.Close(s.fd)
	}
	return nil
}

func (s *LinkerConfigSensor) readLoop() {
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

func (s *LinkerConfigSensor) handleEvent(meta *unix.FanotifyEventMetadata) {
	// Resolve fd to path
	fdPath := fmt.Sprintf("/proc/self/fd/%d", meta.Fd)
	filePath, err := os.Readlink(fdPath)
	if err != nil {
		filePath = "unknown"
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
		EventType: event.EventLinkerConfig,
		Severity:  event.SeverityCritical,
		PID:       uint32(meta.Pid),
		LinkerConfigDetail: &event.LinkerConfigDetail{
			FilePath:  filePath,
			Operation: op,
			NewHash:   newHash,
		},
	}

	select {
	case s.eventCh <- hookEvt:
	default:
	}
}

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

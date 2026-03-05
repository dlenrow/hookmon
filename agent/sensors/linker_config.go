//go:build linux

package sensors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
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
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("fanotify_init: %w", err)
	}
	s.fd = fd

	eventMask := uint64(unix.FAN_CLOSE_WRITE)
	// Use FAN_MARK_MOUNT on /etc to catch writes to any file under /etc,
	// then filter in handleEvent to only emit events for linker config paths.
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, eventMask, unix.AT_FDCWD, "/etc"); err != nil {
		return fmt.Errorf("fanotify_mark /etc: %w", err)
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

func isLinkerConfigPath(path string) bool {
	for _, watched := range watchedLinkerPaths {
		if path == watched || strings.HasPrefix(path, watched+"/") {
			return true
		}
	}
	return false
}

func (s *LinkerConfigSensor) handleEvent(meta *unix.FanotifyEventMetadata) {
	// Resolve fd to path
	fdPath := fmt.Sprintf("/proc/self/fd/%d", meta.Fd)
	filePath, err := os.Readlink(fdPath)
	if err != nil {
		filePath = "unknown"
	}

	// Filter: only emit events for linker config paths
	if !isLinkerConfigPath(filePath) {
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

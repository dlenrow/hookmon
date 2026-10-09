//go:build linux

package sensors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"

	"github.com/dlenrow/hookmon/pkg/event"
)

// rpathExecEvent mirrors struct exec_event in elf_rpath.c.
type rpathExecEvent struct {
	PID       uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	Dev       uint64
	Ino       uint64
	MtimeSec  int64
	MtimeNsec uint32
	Mode      uint32
	Comm      [16]byte
	Filename  [256]byte
}

// ElfRpathSensor analyzes the RPATH/RUNPATH of the binary loaded by every
// successful exec (execve and execveat). A sched_process_exec tracepoint
// program reports the filename passed to exec and the kernel's identity of
// the loaded binary; Go analyzes each binary version once, through an LRU
// cache keyed by that identity, and emits an ELF_RPATH event for every exec
// of a binary whose highest risk is MEDIUM or above.
type ElfRpathSensor struct {
	eventCh chan *event.HookEvent
	tp      link.Link
	reader  *ringbuf.Reader
	coll    *ebpf.Collection
	prog    *ebpf.Program
	done    chan struct{}
	cache   *RpathCache
}

func NewElfRpathSensor() *ElfRpathSensor {
	return &ElfRpathSensor{
		eventCh: make(chan *event.HookEvent, 256),
		done:    make(chan struct{}),
		cache:   NewRpathCache(rpathCacheCap),
	}
}

func (s *ElfRpathSensor) Name() string     { return "elf_rpath" }
func (s *ElfRpathSensor) Type() SensorType { return SensorTypeBPF }

func (s *ElfRpathSensor) Start() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elfRpathBPF))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	s.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	s.prog = s.coll.Programs["rpath_on_exec"]
	if s.prog == nil {
		return errors.New("BPF program 'rpath_on_exec' not found")
	}

	s.tp, err = link.Tracepoint("sched", "sched_process_exec", s.prog, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}

	eventsMap := s.coll.Maps["events"]
	if eventsMap == nil {
		return errors.New("BPF map 'events' not found")
	}

	s.reader, err = ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("create ringbuf reader: %w", err)
	}

	go s.readLoop()
	return nil
}

func (s *ElfRpathSensor) Stop() error {
	close(s.done)
	if s.reader != nil {
		s.reader.Close()
	}
	if s.tp != nil {
		s.tp.Close()
	}
	if s.coll != nil {
		s.coll.Close()
	}
	return nil
}

func (s *ElfRpathSensor) Events() <-chan *event.HookEvent { return s.eventCh }

// HeartbeatNs implements BPFHealth.
func (s *ElfRpathSensor) HeartbeatNs() (uint64, error) {
	return readHeartbeat(s.coll, "hookmon_heartbeat_elf_rpath")
}

// CheckAttached implements BPFHealth.
func (s *ElfRpathSensor) CheckAttached() error { return checkAttached(s.prog, s.tp) }

func (s *ElfRpathSensor) readLoop() {
	var record ringbuf.Record
	for {
		if err := s.reader.ReadInto(&record); err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		var raw rpathExecEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		hookEvt := s.handleExec(&raw)
		if hookEvt == nil {
			continue
		}
		select {
		case s.eventCh <- hookEvt:
		default:
		}
	}
}

// handleExec returns the ELF_RPATH event for one exec, or nil if the loaded
// binary's highest risk is below MEDIUM or the binary could not be read.
func (s *ElfRpathSensor) handleExec(raw *rpathExecEvent) *event.HookEvent {
	if raw.Ino == 0 {
		return nil // the kernel reported no executable file
	}
	key := FileID{
		Dev:     raw.Dev,
		Ino:     raw.Ino,
		MtimeNs: raw.MtimeSec*int64(time.Second) + int64(raw.MtimeNsec),
		Mode:    raw.Mode,
	}

	result, cached := s.cache.Get(key)
	if !cached {
		f, path := openExecuted(raw)
		if f == nil {
			// Not cached, so a later exec of the same binary can try again.
			return nil
		}
		result = RpathResult{Detail: safeAnalyze(f, path, raw.Mode&(syscall.S_ISUID|syscall.S_ISGID) != 0), Path: path}
		f.Close()
		s.cache.Put(key, result)
	}

	if result.Detail == nil || RiskBelow(result.Detail.HighestRisk, event.RpathRiskMedium) {
		return nil
	}

	path := result.Path
	if cached {
		// Name the binary as it was executed this time, if it can still be
		// found; it may have been renamed since it was analyzed.
		if f, p := openExecuted(raw); f != nil {
			f.Close()
			path = p
		}
	}

	detail := *result.Detail
	return &event.HookEvent{
		ID:             uuid.New().String(),
		Timestamp:      time.Now(),
		EventType:      event.EventElfRpath,
		Severity:       RpathSeverity(detail.HighestRisk),
		PID:            raw.PID,
		PPID:           raw.PPID,
		UID:            raw.UID,
		GID:            raw.GID,
		Comm:           nullTermStr(raw.Comm[:]),
		ExePath:        path,
		ElfRpathDetail: &detail,
	}
}

// safeAnalyze runs the analyzer on an untrusted binary. A panic in the ELF
// parser on a malformed file must not take the sensor down.
func safeAnalyze(f *os.File, path string, setuid bool) (detail *event.ElfRpathDetail) {
	defer func() {
		if recover() != nil {
			detail = nil
		}
	}()
	return analyzeElfRpath(f, path, setuid)
}

// openExecuted opens the binary the kernel loaded for this exec and returns
// it with its path, or nil if it cannot be found. Each candidate is accepted
// only if its inode and mtime match what the kernel reported, so a path that
// now names a different file is never analyzed in place of the real one.
//
// Candidates, in order:
//  1. /proc/<pid>/exe: exactly the loaded file, whatever the filename looked
//     like (relative, execveat with a dirfd, fexecve, a script whose
//     interpreter was loaded, a container path), but only while the process
//     is alive and has not exec'd again.
//  2. An absolute filename, as passed to exec. Works after the process
//     exits; this is the common case for short-lived processes.
//  3. A relative filename, joined to the cwd of the process and then of its
//     parent (a shell running ./tool shares its cwd with the child).
//
// What remains unresolved: a process that has already exited and whose
// filename was relative to a directory neither it nor its parent is in, was
// passed as a dirfd-relative /dev/fd/N path (execveat, fexecve, memfd), was
// a script (the filename names the script, the kernel loaded the
// interpreter), or names a file in another mount namespace (containers).
// Those execs are skipped and not cached, so a later exec of the same binary
// is analyzed. The filename is also skipped if it fills the 256-byte buffer
// and may be truncated.
func openExecuted(raw *rpathExecEvent) (*os.File, string) {
	pid := strconv.FormatUint(uint64(raw.PID), 10)
	ppid := strconv.FormatUint(uint64(raw.PPID), 10)

	if f := openVerified("/proc/"+pid+"/exe", raw); f != nil {
		if p, err := os.Readlink("/proc/" + pid + "/exe"); err == nil {
			return f, p
		}
		f.Close()
	}

	filename := nullTermStr(raw.Filename[:])
	if filename == "" || len(filename) >= len(raw.Filename)-1 {
		return nil, ""
	}

	if filepath.IsAbs(filename) {
		// /dev/fd/N and /proc/self/... would name the bus's own files.
		if strings.HasPrefix(filename, "/dev/fd/") || strings.HasPrefix(filename, "/proc/self/") ||
			strings.HasPrefix(filename, "/proc/thread-self/") {
			return nil, ""
		}
		if f := openVerified(filename, raw); f != nil {
			return f, realPath(filename)
		}
		return nil, ""
	}

	for _, p := range []string{pid, ppid} {
		cwdLink := "/proc/" + p + "/cwd"
		if f := openVerified(filepath.Join(cwdLink, filename), raw); f != nil {
			if cwd, err := os.Readlink(cwdLink); err == nil {
				return f, realPath(filepath.Join(cwd, filename))
			}
			f.Close()
		}
	}
	return nil, ""
}

// openVerified opens path and returns it if it is the file the kernel
// loaded: a regular file with the same inode and mtime. The device is not
// compared: the kernel reports the superblock's device, which differs from
// st_dev on btrfs subvolumes and some overlayfs setups.
//
// The path may have been replaced since the exec. Checking it before the
// open keeps the bus from opening a device, and O_NONBLOCK keeps a FIFO
// swapped in after the check from blocking the sensor. The check after the
// open is the one that counts.
func openVerified(path string, raw *rpathExecEvent) *os.File {
	if fi, err := os.Stat(path); err != nil || !sameFile(fi, raw) {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	if fi, err := f.Stat(); err != nil || !sameFile(fi, raw) {
		f.Close()
		return nil
	}
	return f
}

// sameFile reports whether fi is a regular file with the inode and mtime
// the kernel reported for the loaded binary.
func sameFile(fi os.FileInfo, raw *rpathExecEvent) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && fi.Mode().IsRegular() &&
		st.Ino == raw.Ino &&
		int64(st.Mtim.Sec) == raw.MtimeSec && int64(st.Mtim.Nsec) == int64(raw.MtimeNsec)
}

// realPath resolves symlinks, as ld.so does when it computes $ORIGIN for the
// main program (from /proc/self/exe).
func realPath(path string) string {
	if p, err := filepath.EvalSymlinks(path); err == nil {
		return p
	}
	return path
}

// elfRpathBPF is provided via go:embed in embed.go

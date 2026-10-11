//go:build linux

package sensors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
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

	"github.com/dlenrow/hookmon/agent/enrichment"
	"github.com/dlenrow/hookmon/agent/proccache"
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
// cache keyed by that identity, and emits one ELF_RPATH event per binary
// version whose highest risk is MEDIUM or above, on its first exec.
//
// Every exec record also goes into the process cache (proccache.Default),
// which the file sensors read when a writer has exited before they could
// read /proc.
type ElfRpathSensor struct {
	eventCh  chan *event.HookEvent
	tp       link.Link
	reader   *ringbuf.Reader
	coll     *ebpf.Collection
	prog     *ebpf.Program
	done     chan struct{}
	readErrs readErrors // ring buffer read errors; see CheckAttached
	cache    *RpathCache
	procs    *proccache.Cache
	feeding  bool
}

func NewElfRpathSensor() *ElfRpathSensor {
	return &ElfRpathSensor{
		eventCh: make(chan *event.HookEvent, 256),
		done:    make(chan struct{}),
		cache:   NewRpathCache(rpathCacheCap),
		procs:   proccache.Default,
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

	s.procs.AddFeeder()
	s.feeding = true
	go s.readLoop()
	return nil
}

func (s *ElfRpathSensor) Stop() error {
	close(s.done)
	if s.feeding {
		s.procs.RemoveFeeder()
	}
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
func (s *ElfRpathSensor) CheckAttached() error {
	if err := s.readErrs.err(); err != nil {
		return err
	}
	return checkAttached(s.prog, s.tp)
}

func (s *ElfRpathSensor) readLoop() {
	var record ringbuf.Record
	for {
		if err := s.reader.ReadInto(&record); err != nil {
			// Closed: stop. Anything else: back off, and let
			// CheckAttached report it while it lasts.
			if !s.readErrs.handle(err, s.done) {
				return
			}
			continue
		}
		s.readErrs.ok()

		var raw rpathExecEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		// Before the analysis, which may open and hash the binary, so a file
		// sensor waiting for this process is not kept waiting.
		s.procs.Put(execEntry(&raw))

		hookEvt := s.handleExec(&raw)
		if hookEvt == nil {
			continue
		}
		select {
		case s.eventCh <- hookEvt:
		default:
			// Dropped: let the next exec of this binary report it.
			s.cache.unclaimEmit(execFileID(&raw))
		}
	}
}

// execEntry is the process cache's record of one exec. It is made for every
// exec, including those whose binary the RPATH analysis skips. A filename
// that fills the buffer may be truncated, so it is left out.
func execEntry(raw *rpathExecEvent) proccache.Entry {
	exe := nullTermStr(raw.Filename[:])
	if len(exe) >= len(raw.Filename)-1 {
		exe = ""
	}
	return proccache.Entry{
		PID:  raw.PID,
		PPID: raw.PPID,
		UID:  raw.UID,
		GID:  raw.GID,
		Comm: nullTermStr(raw.Comm[:]),
		Exe:  exe,
	}
}

// execFileID is the identity of the binary the kernel loaded for an exec.
func execFileID(raw *rpathExecEvent) FileID {
	return FileID{
		Dev:     raw.Dev,
		Ino:     raw.Ino,
		MtimeNs: raw.MtimeSec*int64(time.Second) + int64(raw.MtimeNsec),
		Mode:    raw.Mode,
	}
}

// handleExec returns the ELF_RPATH event for one exec, or nil if the loaded
// binary's highest risk is below MEDIUM, the binary could not be read, or
// this version of the binary was already reported. Each binary version is
// reported once, on its first exec, not on every exec.
func (s *ElfRpathSensor) handleExec(raw *rpathExecEvent) *event.HookEvent {
	if raw.Ino == 0 {
		return nil // the kernel reported no executable file
	}
	key := execFileID(raw)

	var f *os.File
	result, cached := s.cache.Get(key)
	if !cached {
		var path string
		f, path = openExecuted(raw)
		if f == nil {
			// Not cached, so a later exec of the same binary can try again.
			return nil
		}
		defer f.Close()
		result = RpathResult{Detail: safeAnalyze(f, path, raw.Mode&(syscall.S_ISUID|syscall.S_ISGID) != 0), Path: path}
		s.cache.Put(key, result)
	}

	if result.Detail == nil || RiskBelow(result.Detail.HighestRisk, event.RpathRiskMedium) {
		return nil
	}
	if !s.cache.claimEmit(key) {
		return nil
	}

	path := result.Path
	if f == nil {
		// Analyzed on an earlier exec whose event was not delivered. Name
		// the binary as it was executed this time, if it can still be
		// found; it may have been renamed since it was analyzed.
		if g, p := openExecuted(raw); g != nil {
			defer g.Close()
			f, path = g, p
		}
	}

	// Hash the file the kernel loaded, already verified by inode and mtime,
	// so the hash matches ExePath even for a process in a container or one
	// that has exited.
	var hash string
	if f != nil {
		hash = enrichment.SHA256Reader(io.NewSectionReader(f, 0, math.MaxInt64))
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
		ExeHash:        hash,
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

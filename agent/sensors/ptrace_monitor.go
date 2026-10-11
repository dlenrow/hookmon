//go:build linux

package sensors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"

	"github.com/dlenrow/hookmon/pkg/event"
)

// ptraceRequestNames maps ptrace request numbers to human-readable names.
var ptraceRequestNames = map[uint32]string{
	4:      "PTRACE_POKETEXT",
	5:      "PTRACE_POKEDATA",
	6:      "PTRACE_POKEUSER",
	13:     "PTRACE_SETREGS",
	16:     "PTRACE_ATTACH",
	0x4205: "PTRACE_SETREGSET",
	0x4206: "PTRACE_SEIZE",
}

// ptraceMonitorEvent mirrors the C struct in ptrace_monitor.c.
type ptraceMonitorEvent struct {
	EventType     uint32
	PID           uint32
	UID           uint32
	GID           uint32
	PPID          uint32
	Comm          [16]byte
	PtraceRequest uint32
	TargetPID     uint32
	PidNSInum     uint32 // the caller's PID namespace
	Addr          uint64
}

// PtraceMonitorSensor monitors ptrace() syscalls for dangerous requests:
// attaching (PTRACE_ATTACH, PTRACE_SEIZE) and writing a tracee's memory or
// registers (PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_POKEUSER,
// PTRACE_SETREGS, PTRACE_SETREGSET).
type PtraceMonitorSensor struct {
	eventCh  chan *event.HookEvent
	tp       link.Link
	reader   *ringbuf.Reader
	coll     *ebpf.Collection
	prog     *ebpf.Program
	done     chan struct{}
	readErrs readErrors // ring buffer read errors; see CheckAttached
	selfNS   uint64     // the bus's PID namespace inode; 0 if unknown
}

func NewPtraceMonitorSensor() *PtraceMonitorSensor {
	return &PtraceMonitorSensor{
		eventCh: make(chan *event.HookEvent, 256),
		done:    make(chan struct{}),
	}
}

func (s *PtraceMonitorSensor) Name() string     { return "ptrace_monitor" }
func (s *PtraceMonitorSensor) Type() SensorType { return SensorTypeBPF }

func (s *PtraceMonitorSensor) Start() error {
	// Targets of callers in this namespace are looked up directly in /proc.
	if fi, err := os.Stat("/proc/self/ns/pid"); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			s.selfNS = st.Ino
		}
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ptraceMonitorBPF))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	s.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	s.prog = s.coll.Programs["trace_ptrace_enter"]
	if s.prog == nil {
		return errors.New("BPF program 'trace_ptrace_enter' not found")
	}

	s.tp, err = link.Tracepoint("syscalls", "sys_enter_ptrace", s.prog, nil)
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

func (s *PtraceMonitorSensor) Stop() error {
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

func (s *PtraceMonitorSensor) Events() <-chan *event.HookEvent { return s.eventCh }

// HeartbeatNs implements BPFHealth.
func (s *PtraceMonitorSensor) HeartbeatNs() (uint64, error) {
	return readHeartbeat(s.coll, "hookmon_heartbeat_ptrace_monitor")
}

// CheckAttached implements BPFHealth.
func (s *PtraceMonitorSensor) CheckAttached() error {
	if err := s.readErrs.err(); err != nil {
		return err
	}
	return checkAttached(s.prog, s.tp)
}

func (s *PtraceMonitorSensor) readLoop() {
	for {
		record, err := s.reader.Read()
		if err != nil {
			// Closed: stop. Anything else: back off, and let
			// CheckAttached report it while it lasts.
			if !s.readErrs.handle(err, s.done) {
				return
			}
			continue
		}
		s.readErrs.ok()

		var raw ptraceMonitorEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		reqName := ptraceRequestNames[raw.PtraceRequest]
		if reqName == "" {
			reqName = fmt.Sprintf("PTRACE_%d", raw.PtraceRequest)
		}

		hookEvt := &event.HookEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			EventType: event.EventPtraceInject,
			Severity:  event.SeverityAlert,
			PID:       raw.PID,
			PPID:      raw.PPID,
			UID:       raw.UID,
			GID:       raw.GID,
			Comm:      nullTermStr(raw.Comm[:]),
			PtraceDetail: &event.PtraceDetail{
				Request:     raw.PtraceRequest,
				RequestName: reqName,
				TargetPID:   raw.TargetPID,
				TargetComm:  ptraceTargetComm("/proc", s.selfNS, uint64(raw.PidNSInum), raw.TargetPID),
				Addr:        raw.Addr,
			},
		}

		select {
		case s.eventCh <- hookEvt:
		default:
		}
	}
}

// ptraceMonitorBPF is provided via go:embed in embed.go

//go:build linux

package sensors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"

	"github.com/dlenrow/hookmon/pkg/event"
)

// ExecInjectionScanLimit is how many reads the exec_injection sensor makes
// of each new process's environment on kernels with bpf_loop (5.17 and
// later): MAX_ENV_READS in exec_injection.c. A variable shorter than 256
// bytes takes one read, so in practice this is the number of variables
// scanned. When the environment goes on past it, the sensor sends an event
// with ScanTruncated set.
const ExecInjectionScanLimit = 8192

// ExecInjectionScanLimitBounded is the same limit on older kernels, where
// the verifier walks every iteration: MAX_ENV_READS_BOUNDED.
const ExecInjectionScanLimitBounded = 512

// Flags in execInjectionEvent.Flags (EXEC_INJ_* in exec_injection.c).
const (
	envScanTruncated  = 1 << 0
	envValueTruncated = 1 << 1
	envParentRoot     = 1 << 2
)

// execInjectionEvent mirrors struct hook_event in exec_injection.c.
type execInjectionEvent struct {
	EventType  uint32
	PID        uint32
	UID        uint32
	GID        uint32
	PPID       uint32
	Flags      uint32
	MntNs      uint32
	Comm       [16]byte
	Filename   [256]byte
	EnvValue   [256]byte
	EnvVarName [32]byte
}

// ExecInjectionSensor reports dangerous linker environment variables
// (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, LD_DEBUG) in every new process,
// whether it was started by execve or execveat. A sched_process_exec program
// scans the environment the kernel copied onto the new process's stack,
// before the process runs.
type ExecInjectionSensor struct {
	eventCh chan *event.HookEvent
	tp      link.Link
	reader  *ringbuf.Reader
	coll    *ebpf.Collection
	prog    *ebpf.Program
	done    chan struct{}
	libs    *libraryHasher

	// bounded loads the bounded-loop program even where bpf_loop exists.
	// Tests set it to cover the older-kernel path.
	bounded bool
	// scanLimit is the limit of the program that was loaded.
	scanLimit int
}

func NewExecInjectionSensor() *ExecInjectionSensor {
	return &ExecInjectionSensor{
		eventCh: make(chan *event.HookEvent, 256),
		done:    make(chan struct{}),
		libs:    newLibraryHasher(),
	}
}

func (s *ExecInjectionSensor) Name() string     { return "exec_injection" }
func (s *ExecInjectionSensor) Type() SensorType { return SensorTypeBPF }

func (s *ExecInjectionSensor) Start() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(execInjectionBPF))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	// The object has both programs; a kernel without bpf_loop rejects the
	// first, so load only the one this kernel can run.
	progName, limit := "exec_injection_loop", ExecInjectionScanLimit
	if s.bounded || features.HaveProgramHelper(ebpf.TracePoint, asm.FnLoop) != nil {
		progName, limit = "exec_injection_bounded", ExecInjectionScanLimitBounded
	}
	for name := range spec.Programs {
		if name != progName {
			delete(spec.Programs, name)
		}
	}
	s.scanLimit = limit

	s.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	s.prog = s.coll.Programs[progName]
	if s.prog == nil {
		return fmt.Errorf("BPF program %q not found", progName)
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

func (s *ExecInjectionSensor) Stop() error {
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

func (s *ExecInjectionSensor) Events() <-chan *event.HookEvent { return s.eventCh }

// HeartbeatNs implements BPFHealth.
func (s *ExecInjectionSensor) HeartbeatNs() (uint64, error) {
	return readHeartbeat(s.coll, "hookmon_heartbeat_exec_injection")
}

// CheckAttached implements BPFHealth.
func (s *ExecInjectionSensor) CheckAttached() error { return checkAttached(s.prog, s.tp) }

func (s *ExecInjectionSensor) readLoop() {
	for {
		record, err := s.reader.Read()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		var raw execInjectionEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		select {
		case s.eventCh <- s.toEvent(&raw):
		default:
		}
	}
}

// toEvent converts one BPF record. A record that names no variable is the
// truncation event.
func (s *ExecInjectionSensor) toEvent(raw *execInjectionEvent) *event.HookEvent {
	detail := &event.ExecInjectionDetail{
		TargetBinary:  nullTermStr(raw.Filename[:]),
		SetBy:         "env",
		EnvVar:        nullTermStr(raw.EnvVarName[:]),
		ScanTruncated: raw.Flags&envScanTruncated != 0,
	}
	if detail.EnvVar != "" {
		detail.LibraryPath = nullTermStr(raw.EnvValue[:])
		detail.ValueTruncated = raw.Flags&envValueTruncated != 0
		if !detail.ValueTruncated {
			detail.LibraryHash = s.libs.hash(raw, detail.EnvVar, detail.LibraryPath)
		}
	}

	return &event.HookEvent{
		ID:                  uuid.New().String(),
		Timestamp:           time.Now(),
		EventType:           event.EventExecInjection,
		Severity:            event.SeverityAlert,
		PID:                 raw.PID,
		PPID:                raw.PPID,
		UID:                 raw.UID,
		GID:                 raw.GID,
		Comm:                nullTermStr(raw.Comm[:]),
		ExecInjectionDetail: detail,
	}
}

// execInjectionBPF is provided via go:embed in embed.go

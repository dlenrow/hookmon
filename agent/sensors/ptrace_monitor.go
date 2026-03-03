//go:build linux

package sensors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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
	16:     "PTRACE_ATTACH",
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
	Addr          uint64
}

// PtraceMonitorSensor monitors ptrace() syscalls for dangerous requests
// (PTRACE_ATTACH, PTRACE_SEIZE, PTRACE_POKETEXT, PTRACE_POKEDATA).
type PtraceMonitorSensor struct {
	eventCh chan *event.HookEvent
	tp      link.Link
	reader  *ringbuf.Reader
	coll    *ebpf.Collection
	done    chan struct{}
}

func NewPtraceMonitorSensor() *PtraceMonitorSensor {
	return &PtraceMonitorSensor{
		eventCh: make(chan *event.HookEvent, 256),
		done:    make(chan struct{}),
	}
}

func (s *PtraceMonitorSensor) Name() string       { return "ptrace_monitor" }
func (s *PtraceMonitorSensor) Type() SensorType   { return SensorTypeBPF }

func (s *PtraceMonitorSensor) Start() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ptraceMonitorBPF))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	s.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	prog := s.coll.Programs["trace_ptrace_enter"]
	if prog == nil {
		return errors.New("BPF program 'trace_ptrace_enter' not found")
	}

	s.tp, err = link.Tracepoint("syscalls", "sys_enter_ptrace", prog, nil)
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

func (s *PtraceMonitorSensor) readLoop() {
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

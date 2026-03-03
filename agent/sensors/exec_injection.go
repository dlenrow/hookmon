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

// execInjectionEvent mirrors the C struct in exec_injection.c.
type execInjectionEvent struct {
	EventType  uint32
	PID        uint32
	UID        uint32
	GID        uint32
	PPID       uint32
	Comm       [16]byte
	Filename   [256]byte
	EnvValue   [256]byte
	EnvVarName [32]byte
}

// ExecInjectionSensor monitors execve() syscalls for dangerous linker env vars
// (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, LD_DEBUG).
type ExecInjectionSensor struct {
	eventCh chan *event.HookEvent
	tp      link.Link
	reader  *ringbuf.Reader
	coll    *ebpf.Collection
	done    chan struct{}
}

func NewExecInjectionSensor() *ExecInjectionSensor {
	return &ExecInjectionSensor{
		eventCh: make(chan *event.HookEvent, 256),
		done:    make(chan struct{}),
	}
}

func (s *ExecInjectionSensor) Name() string       { return "exec_injection" }
func (s *ExecInjectionSensor) Type() SensorType   { return SensorTypeBPF }

func (s *ExecInjectionSensor) Start() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(execInjectionBPF))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	s.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	prog := s.coll.Programs["trace_execve_enter"]
	if prog == nil {
		return errors.New("BPF program 'trace_execve_enter' not found")
	}

	s.tp, err = link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
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

		envVar := nullTermStr(raw.EnvVarName[:])
		hookEvt := &event.HookEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			EventType: event.EventExecInjection,
			Severity:  event.SeverityAlert,
			PID:       raw.PID,
			PPID:      raw.PPID,
			UID:       raw.UID,
			GID:       raw.GID,
			Comm:      nullTermStr(raw.Comm[:]),
			ExecInjectionDetail: &event.ExecInjectionDetail{
				LibraryPath:  nullTermStr(raw.EnvValue[:]),
				TargetBinary: nullTermStr(raw.Filename[:]),
				SetBy:        "env",
				EnvVar:       envVar,
			},
		}

		select {
		case s.eventCh <- hookEvt:
		default:
		}
	}
}

// execInjectionBPF is provided via go:embed in embed.go

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

// bpfSyscallEvent mirrors the C struct hook_event in bpf_syscall.c.
type bpfSyscallEvent struct {
	EventType  uint32
	PID        uint32
	UID        uint32
	GID        uint32
	PPID       uint32
	Comm       [16]byte
	BPFCmd     uint32
	ProgType   uint32
	ProgName   [16]byte
	AttachType uint32
	InsnCount  uint32
}

// BPFSyscallSensor monitors the bpf() syscall for program loading and attachment.
type BPFSyscallSensor struct {
	eventCh chan *event.HookEvent
	tp      link.Link
	reader  *ringbuf.Reader
	coll    *ebpf.Collection
	done    chan struct{}
}

// NewBPFSyscallSensor creates a new bpf() syscall monitor sensor.
func NewBPFSyscallSensor() *BPFSyscallSensor {
	return &BPFSyscallSensor{
		eventCh: make(chan *event.HookEvent, 256),
		done:    make(chan struct{}),
	}
}

func (s *BPFSyscallSensor) Name() string { return "bpf_syscall" }

func (s *BPFSyscallSensor) Start() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfSyscallBPF))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	s.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	prog := s.coll.Programs["trace_bpf_enter"]
	if prog == nil {
		return errors.New("BPF program 'trace_bpf_enter' not found in collection")
	}

	s.tp, err = link.AttachTracepoint(link.TracepointOptions{
		Group:   "syscalls",
		Name:    "sys_enter_bpf",
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}

	eventsMap := s.coll.Maps["events"]
	if eventsMap == nil {
		return errors.New("BPF map 'events' not found in collection")
	}

	s.reader, err = ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("create ringbuf reader: %w", err)
	}

	go s.readLoop()
	return nil
}

func (s *BPFSyscallSensor) Stop() error {
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

func (s *BPFSyscallSensor) Events() <-chan *event.HookEvent { return s.eventCh }

func (s *BPFSyscallSensor) readLoop() {
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

		var raw bpfSyscallEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		evtType := event.EventBPFLoad
		if raw.BPFCmd == 8 { // BPF_PROG_ATTACH
			evtType = event.EventBPFAttach
		}

		hookEvt := &event.HookEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			EventType: evtType,
			Severity:  event.SeverityWarn,
			PID:       raw.PID,
			PPID:      raw.PPID,
			UID:       raw.UID,
			GID:       raw.GID,
			Comm:      nullTermStr(raw.Comm[:]),
			BPFDetail: &event.BPFDetail{
				BPFCommand: raw.BPFCmd,
				ProgType:   raw.ProgType,
				ProgName:   nullTermStr(raw.ProgName[:]),
				AttachType: raw.AttachType,
				InsnCount:  raw.InsnCount,
			},
		}

		select {
		case s.eventCh <- hookEvt:
		default:
			// Drop event if channel full
		}
	}
}

// nullTermStr converts a null-terminated byte slice to a string.
func nullTermStr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		n = len(b)
	}
	return string(b[:n])
}

// bpfSyscallBPF is a placeholder for the compiled eBPF bytecode.
// In production, this is populated by bpf2go via go:generate.
// go:generate bpf2go -cc clang -target amd64 bpfSyscall bpf_syscall.c
var bpfSyscallBPF []byte

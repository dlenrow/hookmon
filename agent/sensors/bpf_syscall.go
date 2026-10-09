//go:build linux

package sensors

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"

	"github.com/dlenrow/hookmon/pkg/event"
)

// bpf() commands from include/uapi/linux/bpf.h that the sensor captures.
const (
	bpfCmdProgLoad          = 5
	bpfCmdProgAttach        = 8
	bpfCmdRawTracepointOpen = 17
	bpfCmdLinkCreate        = 28
)

// bpfSyscallEvent mirrors the C struct hook_event in bpf_syscall.c. Every
// field is naturally aligned, so binary.Read sees the C layout.
type bpfSyscallEvent struct {
	EventType    uint32
	PID          uint32
	UID          uint32
	GID          uint32
	PPID         uint32
	Comm         [16]byte
	BPFCmd       uint32
	ProgType     uint32
	ProgName     [16]byte
	AttachType   uint32
	InsnCount    uint32
	TargetFD     int32
	ProgID       uint32
	Tag          [8]byte
	AttachTarget [64]byte
}

// BPFSyscallSensor monitors the bpf() syscall for program loading and
// attachment, and periodically reports every loaded BPF program.
type BPFSyscallSensor struct {
	eventCh   chan *event.HookEvent
	enter     link.Link
	exit      link.Link
	reader    *ringbuf.Reader
	coll      *ebpf.Collection
	progEnter *ebpf.Program
	progExit  *ebpf.Program
	done      chan struct{}
	wg        sync.WaitGroup
}

// NewBPFSyscallSensor creates a new bpf() syscall monitor sensor.
func NewBPFSyscallSensor() *BPFSyscallSensor {
	return &BPFSyscallSensor{
		eventCh: make(chan *event.HookEvent, 256),
		done:    make(chan struct{}),
	}
}

func (s *BPFSyscallSensor) Name() string     { return "bpf_syscall" }
func (s *BPFSyscallSensor) Type() SensorType { return SensorTypeBPF }

func (s *BPFSyscallSensor) Start() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfSyscallBPF))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	s.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	s.progEnter = s.coll.Programs["trace_bpf_enter"]
	if s.progEnter == nil {
		return errors.New("BPF program 'trace_bpf_enter' not found in collection")
	}
	s.progExit = s.coll.Programs["trace_bpf_exit"]
	if s.progExit == nil {
		return errors.New("BPF program 'trace_bpf_exit' not found in collection")
	}

	eventsMap := s.coll.Maps["events"]
	if eventsMap == nil {
		return errors.New("BPF map 'events' not found in collection")
	}
	s.reader, err = ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("create ringbuf reader: %w", err)
	}

	// Attach the exit hook first, so that every call the enter hook records
	// has its exit seen.
	s.exit, err = link.Tracepoint("syscalls", "sys_exit_bpf", s.progExit, nil)
	if err != nil {
		return fmt.Errorf("attach sys_exit_bpf: %w", err)
	}
	s.enter, err = link.Tracepoint("syscalls", "sys_enter_bpf", s.progEnter, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter_bpf: %w", err)
	}

	s.wg.Add(2)
	go s.readLoop()
	go s.inventoryLoop()
	return nil
}

func (s *BPFSyscallSensor) Stop() error {
	close(s.done)
	if s.reader != nil {
		s.reader.Close()
	}
	s.wg.Wait()
	if s.enter != nil {
		s.enter.Close()
	}
	if s.exit != nil {
		s.exit.Close()
	}
	if s.coll != nil {
		s.coll.Close()
	}
	return nil
}

func (s *BPFSyscallSensor) Events() <-chan *event.HookEvent { return s.eventCh }

// HeartbeatNs implements BPFHealth. The enter hook records each call and the
// exit hook emits it, so the sensor works only if both run: this returns the
// older of the two heartbeats. Reading the first map is itself a bpf() call,
// which runs both hooks before the second map is read.
func (s *BPFSyscallSensor) HeartbeatNs() (uint64, error) {
	enter, err := readHeartbeat(s.coll, "hookmon_heartbeat_bpf_syscall")
	if err != nil {
		return 0, err
	}
	exit, err := readHeartbeat(s.coll, "hookmon_heartbeat_bpf_syscall_exit")
	if err != nil {
		return 0, err
	}
	return min(enter, exit), nil
}

// CheckAttached implements BPFHealth for both hooks.
func (s *BPFSyscallSensor) CheckAttached() error {
	if err := checkAttached(s.progEnter, s.enter); err != nil {
		return fmt.Errorf("sys_enter_bpf: %w", err)
	}
	if err := checkAttached(s.progExit, s.exit); err != nil {
		return fmt.Errorf("sys_exit_bpf: %w", err)
	}
	return nil
}

func (s *BPFSyscallSensor) readLoop() {
	defer s.wg.Done()
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

		select {
		case s.eventCh <- syscallEvent(&raw):
		default:
			// Drop event if channel full
		}
	}
}

// syscallEvent converts one ring buffer record to a BPF_LOAD or BPF_ATTACH
// event. The record carries the program's ID and tag as the kernel had them
// when the call returned (PROG_LOAD) or began (attach). If the program is
// still loaded, its load time and creator UID, and for attach events its
// name and type, are read from the kernel by ID.
func syscallEvent(raw *bpfSyscallEvent) *event.HookEvent {
	evtType := event.EventBPFAttach
	if raw.BPFCmd == bpfCmdProgLoad {
		evtType = event.EventBPFLoad
	}

	d := &event.BPFDetail{
		BPFCommand:   raw.BPFCmd,
		ProgType:     raw.ProgType,
		ProgName:     nullTermStr(raw.ProgName[:]),
		AttachType:   raw.AttachType,
		TargetFD:     raw.TargetFD,
		InsnCount:    raw.InsnCount,
		AttachTarget: nullTermStr(raw.AttachTarget[:]),
	}
	if raw.ProgID != 0 {
		d.ProgID = raw.ProgID
		d.ProgHash = hex.EncodeToString(raw.Tag[:])
		if k, err := programDetail(ebpf.ProgramID(raw.ProgID)); err == nil && k.ProgHash == d.ProgHash {
			d.LoadTime = k.LoadTime
			d.CreatedByUID = k.CreatedByUID
			if d.ProgName == "" {
				d.ProgName = k.ProgName
			}
			if raw.BPFCmd != bpfCmdProgLoad {
				d.ProgType = k.ProgType
			}
		}
	}

	return &event.HookEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		EventType: evtType,
		Severity:  event.SeverityWarn,
		PID:       raw.PID,
		PPID:      raw.PPID,
		UID:       raw.UID,
		GID:       raw.GID,
		Comm:      nullTermStr(raw.Comm[:]),
		BPFDetail: d,
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

// bpfSyscallBPF is provided via go:embed in embed.go

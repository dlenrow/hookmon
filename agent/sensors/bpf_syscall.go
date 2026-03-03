//go:build linux

package sensors

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"

	"github.com/dlenrow/hookmon/pkg/event"
)

// bpfSyscallEvent mirrors the C struct hook_event in bpf_syscall.c.
// The C struct uses __attribute__((packed)) to match Go's binary.Read layout.
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
	InsnsPtr   uint64
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

func (s *BPFSyscallSensor) Name() string       { return "bpf_syscall" }
func (s *BPFSyscallSensor) Type() SensorType   { return SensorTypeBPF }

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

	s.tp, err = link.Tracepoint("syscalls", "sys_enter_bpf", prog, nil)
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

		// Compute BPF bytecode hash if we have the instructions pointer
		progHash := ""
		if raw.BPFCmd == 5 { // BPF_PROG_LOAD
			if raw.InsnsPtr != 0 && raw.InsnCount > 0 {
				progHash = computeProgHash(raw.PID, raw.InsnsPtr, raw.InsnCount)
			}
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
				ProgHash:   progHash,
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

// computeProgHash reads BPF bytecode from /proc/<pid>/mem and computes its SHA256.
// Each BPF instruction is 8 bytes, so total size = insn_count * 8.
// This works because the tracepoint fires during the bpf() syscall while the
// process is still alive and the instructions buffer is still in its address space.
func computeProgHash(pid uint32, insnsPtr uint64, insnCount uint32) string {
	const bpfInsnSize = 8
	size := int64(insnCount) * bpfInsnSize
	if size <= 0 || size > 1<<20 { // sanity: cap at 1MB
		fmt.Fprintf(os.Stderr, "computeProgHash: bad size %d (insn_count=%d)\n", size, insnCount)
		return ""
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(memPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "computeProgHash: open %s: %v\n", memPath, err)
		return ""
	}
	defer f.Close()

	buf := make([]byte, size)
	n, err := f.ReadAt(buf, int64(insnsPtr))
	if err != nil {
		fmt.Fprintf(os.Stderr, "computeProgHash: readat offset=0x%x size=%d: %v (read %d bytes)\n",
			insnsPtr, size, err, n)
		return ""
	}

	h := sha256.New()
	h.Write(buf[:n])
	hash := fmt.Sprintf("sha256:%x", h.Sum(nil))
	fmt.Fprintf(os.Stderr, "computeProgHash: pid=%d insns=0x%x count=%d hash=%s\n",
		pid, insnsPtr, insnCount, hash)
	return hash
}

// bpfSyscallBPF is provided via go:embed in embed.go

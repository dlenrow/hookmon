//go:build linux

package sensors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"

	"github.com/dlenrow/hookmon/pkg/event"
)

// shmEvent mirrors the C struct in shm_monitor.c.
type shmEvent struct {
	EventType uint32
	PID       uint32
	UID       uint32
	GID       uint32
	PPID      uint32
	Comm      [16]byte
	SHMName   [128]byte
	Oflag     uint32
	Mode      uint32
}

// SHMMonitorSensor monitors /dev/shm openat() calls for bpftime-style patterns.
type SHMMonitorSensor struct {
	eventCh chan *event.HookEvent
	tp      link.Link
	reader  *ringbuf.Reader
	coll    *ebpf.Collection
	done    chan struct{}
}

func NewSHMMonitorSensor() *SHMMonitorSensor {
	return &SHMMonitorSensor{
		eventCh: make(chan *event.HookEvent, 256),
		done:    make(chan struct{}),
	}
}

func (s *SHMMonitorSensor) Name() string { return "shm_monitor" }

func (s *SHMMonitorSensor) Start() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(shmMonitorBPF))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	s.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	prog := s.coll.Programs["trace_shm_open"]
	if prog == nil {
		return errors.New("BPF program 'trace_shm_open' not found")
	}

	s.tp, err = link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)
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

func (s *SHMMonitorSensor) Stop() error {
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

func (s *SHMMonitorSensor) Events() <-chan *event.HookEvent { return s.eventCh }

func (s *SHMMonitorSensor) readLoop() {
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

		var raw shmEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		shmName := nullTermStr(raw.SHMName[:])
		pattern := classifySHMPattern(shmName)

		hookEvt := &event.HookEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			EventType: event.EventSHMCreate,
			Severity:  event.SeverityCritical,
			PID:       raw.PID,
			PPID:      raw.PPID,
			UID:       raw.UID,
			GID:       raw.GID,
			Comm:      nullTermStr(raw.Comm[:]),
			SHMDetail: &event.SHMDetail{
				SHMName: shmName,
				Pattern: pattern,
			},
		}

		select {
		case s.eventCh <- hookEvt:
		default:
		}
	}
}

// classifySHMPattern identifies if a shared memory segment name matches
// known bpftime patterns.
func classifySHMPattern(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "bpftime"):
		return "bpftime"
	case strings.Contains(lower, "bpf"):
		return "bpf_related"
	default:
		return "unknown"
	}
}

// shmMonitorBPF is provided via go:embed in embed.go

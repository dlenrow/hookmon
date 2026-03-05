//go:build linux

package sensors

import (
	"bytes"
	"debug/elf"
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

// dlopenEvent mirrors the C struct in dlopen_monitor.c.
type dlopenEvent struct {
	EventType   uint32
	PID         uint32
	UID         uint32
	GID         uint32
	PPID        uint32
	Comm        [16]byte
	LibraryPath [256]byte
	Flags       int32
}

// DlopenMonitorSensor monitors dlopen() for runtime library injection.
type DlopenMonitorSensor struct {
	eventCh chan *event.HookEvent
	uprobe  link.Link
	reader  *ringbuf.Reader
	coll    *ebpf.Collection
	done    chan struct{}
}

func NewDlopenMonitorSensor() *DlopenMonitorSensor {
	return &DlopenMonitorSensor{
		eventCh: make(chan *event.HookEvent, 256),
		done:    make(chan struct{}),
	}
}

func (s *DlopenMonitorSensor) Name() string       { return "dlopen_monitor" }
func (s *DlopenMonitorSensor) Type() SensorType   { return SensorTypeBPF }

func (s *DlopenMonitorSensor) Start() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(dlopenMonitorBPF))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	s.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	prog := s.coll.Programs["trace_dlopen"]
	if prog == nil {
		return errors.New("BPF program 'trace_dlopen' not found")
	}

	// Try libc first (glibc 2.34+ merged dlopen into libc), then libdl fallback
	var ex *link.Executable
	for _, path := range []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/lib/aarch64-linux-gnu/libc.so.6",
		"/lib/x86_64-linux-gnu/libdl.so.2",
		"/lib64/libdl.so.2",
	} {
		ex, err = link.OpenExecutable(path)
		if err == nil {
			break
		}
	}
	if ex == nil {
		return fmt.Errorf("open libdl/libc for uprobe: %w", err)
	}

	// Try standard symbol names. On glibc 2.34+, dlopen is a versioned symbol
	// (dlopen@@GLIBC_2.34) which some cilium/ebpf versions can't resolve.
	// If all names fail, resolve the address manually from the ELF.
	for _, sym := range []string{"dlopen", "__libc_dlopen_mode", "__dlopen"} {
		s.uprobe, err = ex.Uprobe(sym, prog, nil)
		if err == nil {
			break
		}
	}
	if s.uprobe == nil {
		// Last resort: find dlopen offset from ELF dynamic symbols directly
		addr, addrErr := findDynSymOffset("dlopen")
		if addrErr != nil {
			return fmt.Errorf("attach uprobe (all methods failed): %w", err)
		}
		s.uprobe, err = ex.Uprobe("", prog, &link.UprobeOptions{Address: addr})
		if err != nil {
			return fmt.Errorf("attach uprobe at offset 0x%x: %w", addr, err)
		}
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

func (s *DlopenMonitorSensor) Stop() error {
	close(s.done)
	if s.reader != nil {
		s.reader.Close()
	}
	if s.uprobe != nil {
		s.uprobe.Close()
	}
	if s.coll != nil {
		s.coll.Close()
	}
	return nil
}

func (s *DlopenMonitorSensor) Events() <-chan *event.HookEvent { return s.eventCh }

func (s *DlopenMonitorSensor) readLoop() {
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

		var raw dlopenEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		hookEvt := &event.HookEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			EventType: event.EventDlopen,
			Severity:  event.SeverityWarn,
			PID:       raw.PID,
			PPID:      raw.PPID,
			UID:       raw.UID,
			GID:       raw.GID,
			Comm:      nullTermStr(raw.Comm[:]),
			DlopenDetail: &event.DlopenDetail{
				LibraryPath: nullTermStr(raw.LibraryPath[:]),
				Flags:       int(raw.Flags),
			},
		}

		select {
		case s.eventCh <- hookEvt:
		default:
		}
	}
}

// findDynSymOffset scans standard libc paths for a dynamic symbol and
// returns its file offset. This handles versioned symbols like dlopen@@GLIBC_2.34
// that cilium/ebpf's Uprobe can't resolve by name.
func findDynSymOffset(name string) (uint64, error) {
	for _, path := range []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/lib/aarch64-linux-gnu/libc.so.6",
	} {
		f, err := elf.Open(path)
		if err != nil {
			continue
		}
		syms, err := f.DynamicSymbols()
		f.Close()
		if err != nil {
			continue
		}
		for _, sym := range syms {
			if sym.Name == name && sym.Value != 0 {
				return sym.Value, nil
			}
		}
	}
	return 0, fmt.Errorf("symbol %s not found in libc", name)
}

// dlopenMonitorBPF is provided via go:embed in embed.go

//go:build linux

package sensors

import (
	"bytes"
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
	EnvLen    uint32 // bytes of Env the BPF program copied
	EnvTotal  uint32 // size of the creator's whole environment
	Env       [4096]byte
}

// SHMMonitorSensor monitors /dev/shm segment creation through openat() and
// openat2() for bpftime-style patterns.
type SHMMonitorSensor struct {
	eventCh   chan *event.HookEvent
	tp        link.Link
	tpOpenat2 link.Link
	reader    *ringbuf.Reader
	coll      *ebpf.Collection
	prog      *ebpf.Program
	progOat2  *ebpf.Program
	done      chan struct{}
	readErrs  readErrors // ring buffer read errors; see CheckAttached
}

func NewSHMMonitorSensor() *SHMMonitorSensor {
	return &SHMMonitorSensor{
		eventCh: make(chan *event.HookEvent, 256),
		done:    make(chan struct{}),
	}
}

func (s *SHMMonitorSensor) Name() string     { return "shm_monitor" }
func (s *SHMMonitorSensor) Type() SensorType { return SensorTypeBPF }

func (s *SHMMonitorSensor) Start() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(shmMonitorBPF))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	s.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	s.prog = s.coll.Programs["trace_shm_open"]
	if s.prog == nil {
		return errors.New("BPF program 'trace_shm_open' not found")
	}
	s.progOat2 = s.coll.Programs["trace_shm_openat2"]
	if s.progOat2 == nil {
		return errors.New("BPF program 'trace_shm_openat2' not found")
	}

	s.tp, err = link.Tracepoint("syscalls", "sys_enter_openat", s.prog, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}

	// openat2 exists from kernel 5.6, and the ring buffer this sensor needs
	// from 5.8, so every kernel that can run the sensor has it.
	s.tpOpenat2, err = link.Tracepoint("syscalls", "sys_enter_openat2", s.progOat2, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter_openat2: %w", err)
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
	if s.tpOpenat2 != nil {
		s.tpOpenat2.Close()
	}
	if s.coll != nil {
		s.coll.Close()
	}
	return nil
}

func (s *SHMMonitorSensor) Events() <-chan *event.HookEvent { return s.eventCh }

// HeartbeatNs implements BPFHealth. The openat and openat2 hooks each have a
// heartbeat map and the bus probes both; this returns the older of the two,
// so a sensor that lost either hook stops advancing.
func (s *SHMMonitorSensor) HeartbeatNs() (uint64, error) {
	openat, err := readHeartbeat(s.coll, "hookmon_heartbeat_shm_monitor")
	if err != nil {
		return 0, err
	}
	openat2, err := readHeartbeat(s.coll, "hookmon_heartbeat_shm_monitor_openat2")
	if err != nil {
		return 0, err
	}
	return min(openat, openat2), nil
}

// CheckAttached implements BPFHealth for both hooks.
func (s *SHMMonitorSensor) CheckAttached() error {
	if err := s.readErrs.err(); err != nil {
		return err
	}
	if err := checkAttached(s.prog, s.tp); err != nil {
		return fmt.Errorf("sys_enter_openat: %w", err)
	}
	if err := checkAttached(s.progOat2, s.tpOpenat2); err != nil {
		return fmt.Errorf("sys_enter_openat2: %w", err)
	}
	return nil
}

func (s *SHMMonitorSensor) readLoop() {
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

		var raw shmEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		shmName := nullTermStr(raw.SHMName[:])
		pattern, severity := classifySHM(shmName, shmCreatorEnv(&raw))

		hookEvt := &event.HookEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			EventType: event.EventSHMCreate,
			Severity:  severity,
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

// shmCreatorEnv returns the creating process's environment as NUL-terminated
// strings. The BPF program copies up to len(raw.Env) bytes while the creator
// runs. A longer environment is read from /proc/<pid>/environ, which works
// only while the creator is still alive; if it has exited, the partial copy
// is used.
func shmCreatorEnv(raw *shmEvent) []byte {
	n := min(int(raw.EnvLen), len(raw.Env))
	if n > 0 && raw.EnvLen >= raw.EnvTotal {
		return raw.Env[:n]
	}
	if env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", raw.PID)); err == nil {
		return env
	}
	return raw.Env[:n]
}

// shmMonitorBPF is provided via go:embed in embed.go

//go:build linux

package sensors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/dlenrow/hookmon/pkg/event"
)

// dlopenRescanInterval is how often the sensor looks for libcs to attach to
// and libcs to detach from. A container started after a scan is not covered
// until the next one.
const dlopenRescanInterval = 5 * time.Minute

// dlopenHostLibcs are the host's glibc objects at their usual paths. They are
// attached only when no process in the bus's own mount namespace maps a
// glibc, so that the dlopen probe helper, which runs on the host's libc,
// still has a hook to fire.
var dlopenHostLibcs = []string{
	"/lib/x86_64-linux-gnu/libc.so.6",
	"/lib64/libc.so.6",
	"/lib/aarch64-linux-gnu/libc.so.6",
	"/lib/x86_64-linux-gnu/libdl.so.2",
	"/lib64/libdl.so.2",
}

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
//
// One program is attached by uprobe to dlopen in every distinct glibc object
// (libc.so.6, or libdl.so.2 before glibc 2.34) that a process has mapped,
// found in /proc/<pid>/maps at startup and every dlopenRescanInterval and
// identified by the device and inode maps prints. A container with its own
// libc gets its own attachment. A libc no process maps any more is detached.
// Where maps prints the overlay's device (Ubuntu kernels), containers from
// one image each get a link to the same file, the program runs once per link
// for each dlopen, and the (exe hash, library path) dedupe drops the repeats
// when the executable can be hashed.
//
// Health with several attachments: all links share one program and one
// heartbeat map. Every cycle the bus runs hookmon-dlopen-probe, which calls
// dlopen through the host's libc, so a moving heartbeat shows the program
// still runs from the host libc's uprobe. CheckAttached then asks the kernel,
// for every link, whether the program is still attached to its perf event,
// and fails if any is not, or if a mapped libc could not be attached. The
// host helper cannot fire a container's libc, so for those the attachment
// query is the only check.
//
// Not covered: musl (Alpine) and statically linked binaries, which have no
// glibc dlopen to hook; dlmopen; and loaders that map code without dlopen.
type DlopenMonitorSensor struct {
	eventCh chan *event.HookEvent
	reader  *ringbuf.Reader
	coll    *ebpf.Collection
	prog    *ebpf.Program
	libcs   *dlopenAttachments
	dedupe  *dlopenDedupe
	hashes  *dlopenHashes
	done    chan struct{}
	wg      sync.WaitGroup
}

func NewDlopenMonitorSensor() *DlopenMonitorSensor {
	return &DlopenMonitorSensor{
		eventCh: make(chan *event.HookEvent, 256),
		dedupe:  newDlopenDedupe(dlopenDedupeWindow, dlopenDedupeSize),
		hashes:  newDlopenHashes("/proc"),
		done:    make(chan struct{}),
	}
}

func (s *DlopenMonitorSensor) Name() string     { return "dlopen_monitor" }
func (s *DlopenMonitorSensor) Type() SensorType { return SensorTypeBPF }

func (s *DlopenMonitorSensor) Start() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(dlopenMonitorBPF))
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	s.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	s.prog = s.coll.Programs["trace_dlopen"]
	if s.prog == nil {
		return errors.New("BPF program 'trace_dlopen' not found")
	}

	eventsMap := s.coll.Maps["events"]
	if eventsMap == nil {
		return errors.New("BPF map 'events' not found")
	}

	s.reader, err = ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("create ringbuf reader: %w", err)
	}

	s.libcs = newDlopenAttachments(s.attachLibc)
	found, err := dlopenFindLibcs()
	if err != nil {
		return fmt.Errorf("find libcs: %w", err)
	}
	if s.libcs.reconcile(found) == 0 {
		return fmt.Errorf("no libc attached (%d glibc objects found)%s", len(found), s.libcs.failures())
	}

	s.wg.Add(1)
	go s.rescanLoop()
	go s.readLoop()
	return nil
}

// dlopenFindLibcs returns every glibc object to attach to.
func dlopenFindLibcs() (map[dlopenLibcID]*dlopenCandidate, error) {
	found, err := dlopenDiscover("/proc")
	if err != nil {
		return nil, err
	}
	for _, c := range found {
		if c.HostNS {
			return found, nil
		}
	}
	for _, p := range dlopenHostLibcs {
		var st unix.Stat_t
		if unix.Stat(p, &st) != nil {
			continue
		}
		id := dlopenLibcID{Major: unix.Major(st.Dev), Minor: unix.Minor(st.Dev), Ino: st.Ino}
		if found[id] == nil {
			found[id] = &dlopenCandidate{ID: id, Desc: p, Opens: []string{p}, HostNS: true}
		}
	}
	return found, nil
}

// attachLibc attaches trace_dlopen to dlopen in one libc.
func (s *DlopenMonitorSensor) attachLibc(c *dlopenCandidate) (io.Closer, error) {
	var f *os.File
	for _, p := range c.Opens {
		var err error
		if f, err = os.Open(p); err == nil {
			break
		}
	}
	if f == nil {
		return nil, errDlopenGone
	}
	defer f.Close()
	if !dlopenExportsDlopen(f) {
		return nil, errDlopenNoSymbol
	}

	// Attach through the open descriptor: the kernel places the uprobe on
	// exactly the file opened above, even if every process that mapped it
	// exits in the meantime. On overlayfs it resolves to the underlying
	// inode, the one the processes execute.
	path := fmt.Sprintf("/proc/self/fd/%d", f.Fd())
	ex, err := link.OpenExecutable(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", c.Desc, err)
	}
	l, err := ex.Uprobe("dlopen", s.prog, nil)
	if err != nil {
		return nil, fmt.Errorf("uprobe dlopen in %s: %w", c.Desc, err)
	}
	return l, nil
}

// rescanLoop attaches to new libcs and detaches from vanished ones every
// dlopenRescanInterval, until Stop. A failed scan keeps what is attached.
func (s *DlopenMonitorSensor) rescanLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(dlopenRescanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}
		if found, err := dlopenFindLibcs(); err == nil {
			s.libcs.reconcile(found)
		}
	}
}

func (s *DlopenMonitorSensor) Stop() error {
	close(s.done)
	s.wg.Wait()
	if s.reader != nil {
		s.reader.Close()
	}
	if s.libcs != nil {
		s.libcs.closeAll()
	}
	if s.coll != nil {
		s.coll.Close()
	}
	return nil
}

func (s *DlopenMonitorSensor) Events() <-chan *event.HookEvent { return s.eventCh }

// HeartbeatNs implements BPFHealth.
func (s *DlopenMonitorSensor) HeartbeatNs() (uint64, error) {
	return readHeartbeat(s.coll, "hookmon_heartbeat_dlopen_monitor")
}

// CheckAttached implements BPFHealth for every libc the program is attached
// to; see DlopenMonitorSensor.
func (s *DlopenMonitorSensor) CheckAttached() error {
	if s.libcs == nil {
		return errors.New("sensor not started")
	}
	return s.libcs.check(func(c io.Closer) error {
		l, ok := c.(link.Link)
		if !ok {
			return fmt.Errorf("attachment %T is not a link", c)
		}
		return checkAttached(s.prog, l)
	})
}

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

		libPath := nullTermStr(raw.LibraryPath[:])
		exeHash := s.hashes.exe(raw.PID)
		if !s.dedupe.report(exeHash, libPath) {
			continue
		}
		var libHash string
		// A path that fills the buffer may be cut short and name another file.
		if len(libPath) < len(raw.LibraryPath)-1 {
			libHash = s.hashes.library(raw.PID, libPath)
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
			ExeHash:   exeHash,
			DlopenDetail: &event.DlopenDetail{
				LibraryPath: libPath,
				LibraryHash: libHash,
				Flags:       int(raw.Flags),
			},
		}

		select {
		case s.eventCh <- hookEvt:
		default:
		}
	}
}

// dlopenMonitorBPF is provided via go:embed in embed.go

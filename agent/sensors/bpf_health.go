//go:build linux

package sensors

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// readHeartbeat returns key 0 of the named heartbeat array map.
func readHeartbeat(coll *ebpf.Collection, mapName string) (uint64, error) {
	if coll == nil {
		return 0, errors.New("sensor not started")
	}
	m := coll.Maps[mapName]
	if m == nil {
		return 0, fmt.Errorf("BPF map %q not found", mapName)
	}
	var key uint32
	var val uint64
	if err := m.Lookup(&key, &val); err != nil {
		return 0, fmt.Errorf("lookup %s: %w", mapName, err)
	}
	return val, nil
}

// checkAttached verifies that prog still exists, that link l still points at
// it, and that the kernel still reports prog attached to l's perf event.
// The bus holds fds for both objects, so Program.Info and Link.Info succeed
// while the bus is alive; the perf event query is the part that reflects the
// hook itself.
func checkAttached(prog *ebpf.Program, l link.Link) error {
	if prog == nil || l == nil {
		return errors.New("sensor not started")
	}
	pi, err := prog.Info()
	if err != nil {
		return fmt.Errorf("program info: %w", err)
	}
	progID, ok := pi.ID()
	if !ok {
		return errors.New("kernel did not report a program ID")
	}

	// perf_event links exist from kernel 5.15. Older kernels attach through
	// an ioctl and have no link object to query.
	li, err := l.Info()
	switch {
	case errors.Is(err, link.ErrNotSupported):
	case err != nil:
		return fmt.Errorf("link info: %w", err)
	case li.Program != progID:
		return fmt.Errorf("link %d points at program %d, want %d", li.ID, li.Program, progID)
	}

	pe, ok := l.(link.PerfEvent)
	if !ok {
		return fmt.Errorf("link %T has no perf event", l)
	}
	f, err := pe.PerfEvent()
	if err != nil {
		return fmt.Errorf("perf event: %w", err)
	}
	defer f.Close()

	attached, err := perfEventProgID(int(f.Fd()))
	if err != nil {
		return err
	}
	if ebpf.ProgramID(attached) != progID {
		return fmt.Errorf("perf event has program %d attached, want %d", attached, progID)
	}
	return nil
}

// bpfTaskFDQuery is BPF_TASK_FD_QUERY from include/uapi/linux/bpf.h.
const bpfTaskFDQuery = 20

// taskFDQueryAttr mirrors the task_fd_query member of union bpf_attr.
type taskFDQueryAttr struct {
	PID         uint32
	FD          uint32
	Flags       uint32
	BufLen      uint32
	Buf         uint64
	ProgID      uint32
	FDType      uint32
	ProbeOffset uint64
	ProbeAddr   uint64
}

// perfEventProgID asks the kernel which BPF program is attached to the perf
// event behind fd in this process, the same query `bpftool perf` uses.
func perfEventProgID(fd int) (uint32, error) {
	attr := taskFDQueryAttr{PID: uint32(os.Getpid()), FD: uint32(fd)}
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfTaskFDQuery,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno == unix.ENOENT {
		return 0, errors.New("no BPF program attached to perf event")
	}
	if errno != 0 {
		return 0, fmt.Errorf("BPF_TASK_FD_QUERY: %w", errno)
	}
	return attr.ProgID, nil
}

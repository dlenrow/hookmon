//go:build linux

package sensors

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/dlenrow/hookmon/pkg/event"
)

// inventoryLoop lists every loaded BPF program at startup and then every
// inventoryInterval, until Stop.
func (s *BPFSyscallSensor) inventoryLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(inventoryInterval)
	defer ticker.Stop()
	for {
		for _, evt := range inventoryEvents(uuid.New().String(), time.Now(), listPrograms()) {
			if !s.emitInventory(evt) {
				return
			}
		}
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}
	}
}

// emitInventory delivers one inventory event without crowding out live
// events: the ring buffer reader drops events when the channel is full, so a
// scan waits while the channel is more than half full. It returns false once
// the sensor is stopping.
func (s *BPFSyscallSensor) emitInventory(evt *event.HookEvent) bool {
	for len(s.eventCh) > cap(s.eventCh)/2 {
		select {
		case <-s.done:
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
	select {
	case s.eventCh <- evt:
		return true
	case <-s.done:
		return false
	}
}

// listPrograms returns the kernel's view of every loaded BPF program, in ID
// order. A program unloaded between listing and reading is skipped.
func listPrograms() []*event.BPFDetail {
	var progs []*event.BPFDetail
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			// ENOENT ends the list.
			return progs
		}
		id = next
		if d, err := programDetail(id); err == nil {
			progs = append(progs, d)
		}
	}
}

// programDetail reads the kernel's record of program id: type, name, tag,
// creator UID and load time.
func programDetail(id ebpf.ProgramID) (*event.BPFDetail, error) {
	prog, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return nil, err
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return nil, err
	}
	d := &event.BPFDetail{
		ProgID:   uint32(id),
		ProgType: uint32(info.Type),
		ProgName: info.Name,
		ProgHash: info.Tag,
	}
	if uid, ok := info.CreatedByUID(); ok {
		d.CreatedByUID = &uid
	}
	if t, err := progLoadTime(prog.FD()); err == nil {
		d.LoadTime = &t
	}
	return d, nil
}

// bpfObjGetInfoByFD is BPF_OBJ_GET_INFO_BY_FD from include/uapi/linux/bpf.h.
const bpfObjGetInfoByFD = 15

// progInfoHead is struct bpf_prog_info from include/uapi/linux/bpf.h up to
// and including nr_map_ids. The kernel fills only info_len bytes, so a
// prefix of the struct is a valid request. cilium/ebpf v0.16 does not expose
// load_time, so the sensor reads it with this call.
type progInfoHead struct {
	Type            uint32
	ID              uint32
	Tag             [8]byte
	JitedProgLen    uint32
	XlatedProgLen   uint32
	JitedProgInsns  uint64
	XlatedProgInsns uint64
	LoadTime        uint64 // CLOCK_BOOTTIME ns
	CreatedByUID    uint32
	NrMapIDs        uint32
}

// objInfoAttr is the info member of union bpf_attr. Info is an
// unsafe.Pointer, not a uint64, so the runtime keeps the buffer alive and
// updates the pointer if the stack moves. That matches the kernel's 64-bit
// field only on 64-bit targets, which is all the bus is built for; the
// array below fails to compile elsewhere. The struct must have no trailing
// padding: the kernel rejects the call unless every byte after info is zero.
type objInfoAttr struct {
	FD      uint32
	InfoLen uint32
	Info    unsafe.Pointer
}

var _ [unsafe.Sizeof(uintptr(0)) - 8]byte

// progLoadTime returns when the program behind fd was loaded.
func progLoadTime(fd int) (time.Time, error) {
	var info progInfoHead
	attr := objInfoAttr{FD: uint32(fd), InfoLen: uint32(unsafe.Sizeof(info)), Info: unsafe.Pointer(&info)}
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfObjGetInfoByFD,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return time.Time{}, fmt.Errorf("BPF_OBJ_GET_INFO_BY_FD: %w", errno)
	}
	if info.LoadTime == 0 {
		return time.Time{}, errors.New("kernel reported no load time")
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Time{}, fmt.Errorf("read CLOCK_BOOTTIME: %w", err)
	}
	return wallFromBoot(time.Now().Round(0), uint64(ts.Nano()), info.LoadTime), nil
}

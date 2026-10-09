package sensors

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"

	"github.com/dlenrow/hookmon/pkg/event"
)

// inventoryInterval is how often the bpf_syscall sensor lists every loaded
// BPF program. It also lists them once at startup, which is what catches
// programs loaded before the bus started.
const inventoryInterval = 5 * time.Minute

// inventoryEvents builds the events of one inventory scan: one BPF_INVENTORY
// event per program, in the order given, then the host summary. The events
// have no process context. PID is 0, so the bus's filter for its own
// activity never drops them.
func inventoryEvents(scanID string, now time.Time, progs []*event.BPFDetail) []*event.HookEvent {
	evts := make([]*event.HookEvent, 0, len(progs)+1)
	byType := make(map[string]uint32)
	for _, p := range progs {
		byType[ebpf.ProgramType(p.ProgType).String()]++
		evts = append(evts, &event.HookEvent{
			ID:        uuid.New().String(),
			Timestamp: now,
			EventType: event.EventBPFInventory,
			Severity:  event.SeverityInfo,
			BPFDetail: p,
			BPFInventoryDetail: &event.BPFInventoryDetail{
				ScanID: scanID,
			},
		})
	}
	evts = append(evts, &event.HookEvent{
		ID:        uuid.New().String(),
		Timestamp: now,
		EventType: event.EventBPFInventory,
		Severity:  event.SeverityInfo,
		BPFInventoryDetail: &event.BPFInventoryDetail{
			ScanID:    scanID,
			Summary:   true,
			ProgCount: uint32(len(progs)),
			ByType:    byType,
		},
	})
	return evts
}

// wallFromBoot converts a CLOCK_BOOTTIME reading, such as a program's
// load_time, to wall-clock time, given the current wall and boot times.
func wallFromBoot(nowWall time.Time, nowBootNs, thenBootNs uint64) time.Time {
	return nowWall.Add(-time.Duration(int64(nowBootNs - thenBootNs)))
}

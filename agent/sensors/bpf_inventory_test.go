package sensors

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/dlenrow/hookmon/pkg/event"
)

func TestInventoryEvents(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	uid := uint32(0)
	progs := []*event.BPFDetail{
		{ProgID: 7, ProgType: uint32(ebpf.TracePoint), ProgName: "hello_count", ProgHash: "a04f5eef06a7f555", CreatedByUID: &uid},
		{ProgID: 9, ProgType: uint32(ebpf.TracePoint), ProgName: "net_count", ProgHash: "1122334455667788"},
		{ProgID: 12, ProgType: uint32(ebpf.CGroupSKB), ProgName: "sd_fw_egress", ProgHash: "8877665544332211"},
	}

	evts := inventoryEvents("scan-1", now, progs)
	if len(evts) != len(progs)+1 {
		t.Fatalf("got %d events, want %d (one per program plus a summary)", len(evts), len(progs)+1)
	}

	ids := make(map[string]bool)
	for i, e := range evts {
		if e.EventType != event.EventBPFInventory {
			t.Errorf("event %d: type %s, want BPF_INVENTORY", i, e.EventType)
		}
		if e.Severity != event.SeverityInfo {
			t.Errorf("event %d: severity %s, want INFO", i, e.Severity)
		}
		if e.PID != 0 || e.PPID != 0 {
			t.Errorf("event %d: pid=%d ppid=%d; inventory events must carry no process", i, e.PID, e.PPID)
		}
		if !e.Timestamp.Equal(now) {
			t.Errorf("event %d: timestamp %v, want %v", i, e.Timestamp, now)
		}
		if e.BPFInventoryDetail == nil || e.BPFInventoryDetail.ScanID != "scan-1" {
			t.Fatalf("event %d: inventory detail %+v, want scan_id scan-1", i, e.BPFInventoryDetail)
		}
		if e.ID == "" || ids[e.ID] {
			t.Errorf("event %d: ID %q empty or repeated", i, e.ID)
		}
		ids[e.ID] = true
	}

	for i, p := range progs {
		e := evts[i]
		if e.BPFInventoryDetail.Summary {
			t.Errorf("event %d: per-program event marked as summary", i)
		}
		if e.BPFDetail != p {
			t.Errorf("event %d: BPFDetail %+v, want %+v", i, e.BPFDetail, p)
		}
	}

	sum := evts[len(evts)-1]
	if !sum.BPFInventoryDetail.Summary {
		t.Fatal("last event is not the summary")
	}
	if sum.BPFDetail != nil {
		t.Errorf("summary carries a BPFDetail: %+v", sum.BPFDetail)
	}
	if sum.BPFInventoryDetail.ProgCount != 3 {
		t.Errorf("summary prog_count %d, want 3", sum.BPFInventoryDetail.ProgCount)
	}
	wantByType := map[string]uint32{ebpf.TracePoint.String(): 2, ebpf.CGroupSKB.String(): 1}
	if len(sum.BPFInventoryDetail.ByType) != len(wantByType) {
		t.Errorf("summary by_type %v, want %v", sum.BPFInventoryDetail.ByType, wantByType)
	}
	for k, v := range wantByType {
		if sum.BPFInventoryDetail.ByType[k] != v {
			t.Errorf("summary by_type[%s] = %d, want %d", k, sum.BPFInventoryDetail.ByType[k], v)
		}
	}
}

func TestInventoryEvents_NoPrograms(t *testing.T) {
	evts := inventoryEvents("scan-empty", time.Now(), nil)
	if len(evts) != 1 {
		t.Fatalf("got %d events, want only the summary", len(evts))
	}
	d := evts[0].BPFInventoryDetail
	if d == nil || !d.Summary || d.ProgCount != 0 {
		t.Errorf("summary %+v, want summary with prog_count 0", d)
	}
}

func TestWallFromBoot(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	const nowBoot = 3_600_000_000_000 // one hour after boot
	got := wallFromBoot(now, nowBoot, nowBoot-90_000_000_000)
	if want := now.Add(-90 * time.Second); !got.Equal(want) {
		t.Errorf("wallFromBoot = %v, want %v", got, want)
	}
}

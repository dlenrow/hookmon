//go:build linux && e2e

package e2e

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// BPF program commands as the sensor reports them in BPFDetail.BPFCommand.
const (
	bpfCmdProgLoad          = 5
	bpfCmdRawTracepointOpen = 17
	bpfCmdLinkCreate        = 28
)

var tagRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

// canaryProg is one program bpf_tag_canary loaded, as the kernel reported
// it to the canary.
type canaryProg struct {
	ID  uint32
	Tag string
}

// startTagCanary runs bpf_tag_canary with args and returns the programs it
// reports. The canary keeps them loaded until it exits or is killed; the
// returned stop func kills it and also runs at cleanup.
func startTagCanary(t *testing.T, want int, args ...string) (progs []canaryProg, stop func()) {
	t.Helper()
	cmd := exec.Command(canaryBinDir()+"/bpf_tag_canary", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("canary stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bpf_tag_canary: %v", err)
	}
	stop = func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}
	t.Cleanup(stop)

	lines := make(chan canaryProg)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			var p canaryProg
			if _, err := fmt.Sscanf(sc.Text(), "loaded id=%d tag=%s", &p.ID, &p.Tag); err == nil {
				lines <- p
			}
		}
		close(lines)
	}()
	deadline := time.After(15 * time.Second)
	for len(progs) < want {
		select {
		case p, ok := <-lines:
			if !ok {
				t.Fatalf("bpf_tag_canary exited after reporting %d of %d programs", len(progs), want)
			}
			progs = append(progs, p)
		case <-deadline:
			t.Fatalf("bpf_tag_canary reported %d of %d programs in 15s", len(progs), want)
		}
	}
	return progs, stop
}

// waitForProgEvent waits for an event of type et for program id.
func waitForProgEvent(t *testing.T, bus *BusProcess, et event.EventType, cmd uint32, id uint32) *event.HookEvent {
	t.Helper()
	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == et && e.BPFDetail != nil && e.BPFDetail.ProgID == id &&
			(cmd == 0 || e.BPFDetail.BPFCommand == cmd)
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("no %s (cmd %d) event for program id %d: %v", et, cmd, id, err)
	}
	return evt
}

// checkKernelView checks that a BPF event carries the kernel's record of the
// program the canary loaded.
func checkKernelView(t *testing.T, evt *event.HookEvent, p canaryProg, name string) {
	t.Helper()
	d := evt.BPFDetail
	if d.ProgHash != p.Tag {
		t.Errorf("prog id %d: prog_hash %q, want kernel tag %q", p.ID, d.ProgHash, p.Tag)
	}
	if !tagRE.MatchString(d.ProgHash) {
		t.Errorf("prog id %d: prog_hash %q is not a 16-hex-digit tag", p.ID, d.ProgHash)
	}
	if d.ProgName != name {
		t.Errorf("prog id %d: prog_name %q, want %q", p.ID, d.ProgName, name)
	}
	if d.LoadTime == nil || time.Since(*d.LoadTime) > 10*time.Minute || time.Until(*d.LoadTime) > time.Minute {
		t.Errorf("prog id %d: load_time %v, want the time of the load", p.ID, d.LoadTime)
	}
	if d.CreatedByUID == nil || *d.CreatedByUID != 0 {
		t.Errorf("prog id %d: created_by_uid %v, want 0 (canary runs as root)", p.ID, d.CreatedByUID)
	}
}

// TestSensor1_BPFSyscall_SameProgramSameTag loads hello_count twice in one
// process. The second load's instructions carry different map fds, which
// changed the old buffer hash; the kernel tag must not change.
func TestSensor1_BPFSyscall_SameProgramSameTag(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	progs, stop := startTagCanary(t, 2, "-copies", "2", "-hold", "30s",
		canaryDir()+"/hello_bpf.o", "hello_count")
	e1 := waitForProgEvent(t, bus, event.EventBPFLoad, bpfCmdProgLoad, progs[0].ID)
	e2 := waitForProgEvent(t, bus, event.EventBPFLoad, bpfCmdProgLoad, progs[1].ID)
	stop()

	if progs[0].ID == progs[1].ID {
		t.Fatalf("canary loaded one program, not two: id %d", progs[0].ID)
	}
	checkKernelView(t, e1, progs[0], "hello_count")
	checkKernelView(t, e2, progs[1], "hello_count")
	if e1.BPFDetail.ProgHash != e2.BPFDetail.ProgHash {
		t.Errorf("same program, different prog_hash: %s vs %s", e1.BPFDetail.ProgHash, e2.BPFDetail.ProgHash)
	}
	t.Logf("PASS: ids %d and %d, tag %s for both", progs[0].ID, progs[1].ID, e1.BPFDetail.ProgHash)
}

// TestSensor1_BPFSyscall_ModifiedProgramNewTag loads hello_count and a copy
// with one changed instruction (same name, same map). The tags must differ.
func TestSensor1_BPFSyscall_ModifiedProgramNewTag(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	orig, stopOrig := startTagCanary(t, 1, "-hold", "30s", canaryDir()+"/hello_bpf.o", "hello_count")
	mod, stopMod := startTagCanary(t, 1, "-hold", "30s", canaryDir()+"/hello_bpf_mod.o", "hello_count")
	eOrig := waitForProgEvent(t, bus, event.EventBPFLoad, bpfCmdProgLoad, orig[0].ID)
	eMod := waitForProgEvent(t, bus, event.EventBPFLoad, bpfCmdProgLoad, mod[0].ID)
	stopOrig()
	stopMod()

	checkKernelView(t, eOrig, orig[0], "hello_count")
	checkKernelView(t, eMod, mod[0], "hello_count")
	if eOrig.BPFDetail.ProgHash == eMod.BPFDetail.ProgHash {
		t.Errorf("modified program kept prog_hash %s", eOrig.BPFDetail.ProgHash)
	}
	t.Logf("PASS: original tag %s, modified tag %s", eOrig.BPFDetail.ProgHash, eMod.BPFDetail.ProgHash)
}

// TestSensor1_BPFInventory_PreexistingProgram loads hello_count, then starts
// the bus. The program must appear in the bus's first inventory, which runs
// at startup, followed by that scan's host summary.
func TestSensor1_BPFInventory_PreexistingProgram(t *testing.T) {
	progs, stop := startTagCanary(t, 1, "-hold", "60s", canaryDir()+"/hello_bpf.o", "hello_count")
	busStart := time.Now()

	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	evt := waitForProgEvent(t, bus, event.EventBPFInventory, 0, progs[0].ID)
	stop()

	checkKernelView(t, evt, progs[0], "hello_count")
	if !evt.BPFDetail.LoadTime.Before(busStart) {
		t.Errorf("load_time %v is not before the bus started (%v)", evt.BPFDetail.LoadTime, busStart)
	}
	if evt.Severity != event.SeverityInfo {
		t.Errorf("severity %s, want INFO", evt.Severity)
	}
	if evt.PID != 0 || evt.PPID != 0 {
		t.Errorf("inventory event has process context pid=%d ppid=%d", evt.PID, evt.PPID)
	}
	inv := evt.BPFInventoryDetail
	if inv == nil || inv.ScanID == "" || inv.Summary {
		t.Fatalf("inventory detail %+v, want a per-program entry with a scan_id", inv)
	}

	sum, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventBPFInventory && e.BPFInventoryDetail != nil &&
			e.BPFInventoryDetail.Summary && e.BPFInventoryDetail.ScanID == inv.ScanID
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("no host summary for scan %s: %v", inv.ScanID, err)
	}
	if sum.BPFInventoryDetail.ProgCount < 1 || sum.BPFInventoryDetail.ByType["TracePoint"] < 1 {
		t.Errorf("summary %+v does not count the canary's tracepoint program", sum.BPFInventoryDetail)
	}
	t.Logf("PASS: pre-existing prog id %d tag %s in scan %s; summary: %d programs %v",
		progs[0].ID, evt.BPFDetail.ProgHash, inv.ScanID, sum.BPFInventoryDetail.ProgCount, sum.BPFInventoryDetail.ByType)
}

// TestSensor1_BPFSyscall_LinkCreateAttach runs load_canary, which attaches
// hello_count to a tracepoint. On kernels 5.15 and newer cilium/ebpf does
// that with BPF_LINK_CREATE (attach type BPF_PERF_EVENT).
func TestSensor1_BPFSyscall_LinkCreateAttach(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	go func() {
		time.Sleep(1 * time.Second)
		LoadCanary(canaryBinDir()+"/load_canary",
			canaryDir()+"/hello_bpf.o",
			"syscalls", "sys_enter_getpid", "hello_count")
	}()

	load, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventBPFLoad && e.BPFDetail != nil &&
			e.BPFDetail.ProgName == "hello_count" && e.BPFDetail.ProgID != 0
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect BPF_LOAD for hello_count: %v", err)
	}
	attach := waitForProgEvent(t, bus, event.EventBPFAttach, bpfCmdLinkCreate, load.BPFDetail.ProgID)

	d := attach.BPFDetail
	if d.ProgHash != load.BPFDetail.ProgHash {
		t.Errorf("attach prog_hash %s, load prog_hash %s", d.ProgHash, load.BPFDetail.ProgHash)
	}
	if d.ProgName != "hello_count" {
		t.Errorf("attach prog_name %q, want hello_count (read from the kernel by ID)", d.ProgName)
	}
	if attach.PID != load.PID {
		t.Errorf("attach pid %d, load pid %d", attach.PID, load.PID)
	}
	t.Logf("PASS: BPF_LINK_CREATE of prog id %d (tag %s) attach_type=%d target_fd=%d pid=%d",
		d.ProgID, d.ProgHash, d.AttachType, d.TargetFD, attach.PID)
}

// TestSensor1_BPFSyscall_RawTracepointAttach attaches a raw tracepoint
// program, which goes through BPF_RAW_TRACEPOINT_OPEN.
func TestSensor1_BPFSyscall_RawTracepointAttach(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	progs, stop := startTagCanary(t, 1, "-hold", "30s", "-raw-tp", "sys_enter",
		canaryDir()+"/raw_tp_canary.o", "raw_tp_count")
	attach := waitForProgEvent(t, bus, event.EventBPFAttach, bpfCmdRawTracepointOpen, progs[0].ID)
	stop()

	checkKernelView(t, attach, progs[0], "raw_tp_count")
	if attach.BPFDetail.AttachTarget != "sys_enter" {
		t.Errorf("attach_target %q, want sys_enter", attach.BPFDetail.AttachTarget)
	}
	t.Logf("PASS: BPF_RAW_TRACEPOINT_OPEN %s of prog id %d tag %s",
		attach.BPFDetail.AttachTarget, progs[0].ID, attach.BPFDetail.ProgHash)
}

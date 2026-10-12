//go:build linux && e2e

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/agent/suppress"
	"github.com/dlenrow/hookmon/pkg/event"
)

// Fix plan step 4, shm_monitor and ptrace_monitor: SHM severity follows the
// pattern (a segment with no BPF pattern is not reported at all), bpftime's
// real segment name and its rename variable are matched, segments made
// with openat2 are seen, and ptrace register and USER-area
// writes are reported with the target's comm.

// ptrace requests (include/uapi/linux/ptrace.h).
const (
	shmPtrPokeUser  = 6
	shmPtrSetRegs   = 13
	shmPtrAttach    = 16
	shmPtrSetRegSet = 0x4205
)

// shmPtrUnique returns a name no earlier run used, short enough for a comm.
func shmPtrUnique(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano()%1_000_000_000)
}

// shmPtrStartBus starts a bus and gives its sensors time to attach.
func shmPtrStartBus(t *testing.T) *BusProcess {
	t.Helper()
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	t.Cleanup(func() { bus.Stop() })
	time.Sleep(1 * time.Second)
	return bus
}

// shmPtrRun runs a canary to completion with env as its whole environment
// and returns its PID and standard output.
func shmPtrRun(t *testing.T, env []string, bin string, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	os.Stderr.Write(out.Bytes())
	if err != nil {
		t.Fatalf("%s %v: %v", bin, args, err)
	}
	return cmd.Process.Pid, out.String()
}

var shmPtrBaseEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}

// shmPtrWaitSHM waits for the SHM_CREATE event of segment name from pid.
func shmPtrWaitSHM(t *testing.T, bus *BusProcess, name string, pid int) *event.HookEvent {
	t.Helper()
	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventSHMCreate && e.SHMDetail != nil &&
			e.SHMDetail.SHMName == name && e.PID == uint32(pid)
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("no SHM_CREATE for /dev/shm/%s from pid %d: %v", name, pid, err)
	}
	t.Logf("SHM_CREATE name=%s pattern=%s severity=%s pid=%d comm=%s",
		evt.SHMDetail.SHMName, evt.SHMDetail.Pattern, evt.Severity, evt.PID, evt.Comm)
	return evt
}

func shmPtrCheckSHM(t *testing.T, evt *event.HookEvent, pattern string, severity event.Severity) {
	t.Helper()
	if evt.SHMDetail.Pattern != pattern || evt.Severity != severity {
		t.Errorf("/dev/shm/%s: got pattern %s, severity %s; want %s, %s",
			evt.SHMDetail.SHMName, evt.SHMDetail.Pattern, evt.Severity, pattern, severity)
	}
}

// TestSensor3_SHMMonitor_BpftimeDefaultName: bpftime's own segment name,
// bpftime_maps_shm (runtime/src/handler/handler_manager.hpp:51 upstream),
// is CRITICAL.
func TestSensor3_SHMMonitor_BpftimeDefaultName(t *testing.T) {
	const name = "bpftime_maps_shm"
	if _, err := os.Stat("/dev/shm/" + name); err == nil {
		t.Skipf("/dev/shm/%s exists; a bpftime runtime may be running on this host", name)
	}
	bus := shmPtrStartBus(t)
	pid, _ := shmPtrRun(t, shmPtrBaseEnv, canaryBinDir()+"/shm_canary", "/"+name)
	shmPtrCheckSHM(t, shmPtrWaitSHM(t, bus, name, pid), "bpftime", event.SeverityCritical)
}

// TestSensor3_SHMMonitor_EnvRenamedIsBpftime: bpftime takes its segment name
// from BPFTIME_GLOBAL_SHM_NAME (handler_manager.hpp:60-66 upstream). A
// segment whose name has nothing to do with bpf, created by a process whose
// environment names it that way, is bpftime's and CRITICAL. The canary reads
// the variable the way bpftime does.
func TestSensor3_SHMMonitor_EnvRenamedIsBpftime(t *testing.T) {
	name := shmPtrUnique("hm_cache_")
	bus := shmPtrStartBus(t)
	env := append([]string{"BPFTIME_GLOBAL_SHM_NAME=" + name}, shmPtrBaseEnv...)
	pid, _ := shmPtrRun(t, env, canaryBinDir()+"/shm_canary")
	shmPtrCheckSHM(t, shmPtrWaitSHM(t, bus, name, pid), "bpftime", event.SeverityCritical)
}

// TestSensor3_SHMMonitor_BpfRelatedIsAlert: "bpf" in the name without
// "bpftime" is ALERT.
func TestSensor3_SHMMonitor_BpfRelatedIsAlert(t *testing.T) {
	name := shmPtrUnique("hm_bpf_")
	bus := shmPtrStartBus(t)
	pid, _ := shmPtrRun(t, shmPtrBaseEnv, canaryBinDir()+"/shm_canary", "/"+name)
	shmPtrCheckSHM(t, shmPtrWaitSHM(t, bus, name, pid), "bpf_related", event.SeverityAlert)
}

// TestSensor3_SHMMonitor_GenericIsSuppressed: a segment whose name says
// nothing about BPF is not reported (browsers make them constantly for
// their own IPC); the bus counts it as suppressed.
func TestSensor3_SHMMonitor_GenericIsSuppressed(t *testing.T) {
	const port = "2204"
	name := shmPtrUnique("hm_generic_")
	bus := startFileBus(t, port, "shm_monitor")
	before := suppressedCount(t, port, "shm_monitor", suppress.NoBPFPattern)
	pid, _ := shmPtrRun(t, shmPtrBaseEnv, canaryBinDir()+"/shm_canary", "/"+name)
	waitSuppressed(t, port, "shm_monitor", suppress.NoBPFPattern, before, 15*time.Second)
	noEvent(t, bus, "/dev/shm/"+name, 2*time.Second, func(e *event.HookEvent) bool {
		return e.EventType == event.EventSHMCreate && e.SHMDetail != nil &&
			e.SHMDetail.SHMName == name && e.PID == uint32(pid)
	})
}

// TestSensor3_SHMMonitor_Openat2: a segment created with openat2(), which
// the openat() hook does not see, is detected.
func TestSensor3_SHMMonitor_Openat2(t *testing.T) {
	name := shmPtrUnique("bpftime_oat2_")
	bus := shmPtrStartBus(t)
	pid, _ := shmPtrRun(t, shmPtrBaseEnv, canaryBinDir()+"/shm_openat2_canary", name)
	shmPtrCheckSHM(t, shmPtrWaitSHM(t, bus, name, pid), "bpftime", event.SeverityCritical)
}

// shmPtrCanaryValue returns the number on the canary's "<key>=<n>" line.
func shmPtrCanaryValue(t *testing.T, out, key string) uint64 {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + key + `=(\d+)$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("canary printed no %s line:\n%s", key, out)
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// shmPtrRegRequests are the requests ptrace_regs_canary makes.
func shmPtrRegRequests() []uint32 {
	reqs := []uint32{shmPtrSetRegSet, shmPtrPokeUser}
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "386" {
		reqs = append(reqs, shmPtrSetRegs)
	}
	return reqs
}

// shmPtrWaitPtrace waits for one event per request from the caller that
// match, checks the target's PID and comm, and returns the events by request.
func shmPtrWaitPtrace(t *testing.T, bus *BusProcess, caller func(*event.HookEvent) bool,
	reqs []uint32, targetPID uint32, targetComm string) map[uint32]*event.HookEvent {
	t.Helper()
	got := make(map[uint32]*event.HookEvent)
	for _, req := range reqs {
		evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
			return e.EventType == event.EventPtraceInject && e.PtraceDetail != nil &&
				e.PtraceDetail.Request == req && caller(e)
		}, 15*time.Second)
		if err != nil {
			t.Errorf("no PTRACE_INJECT for request %#x: %v", req, err)
			continue
		}
		got[req] = evt
		d := evt.PtraceDetail
		t.Logf("PTRACE_INJECT %s(%#x) pid=%d comm=%s target_pid=%d target_comm=%q addr=%#x severity=%s",
			d.RequestName, d.Request, evt.PID, evt.Comm, d.TargetPID, d.TargetComm, d.Addr, evt.Severity)
		if d.TargetPID != targetPID {
			t.Errorf("%s: target_pid %d, want %d", d.RequestName, d.TargetPID, targetPID)
		}
		if d.TargetComm != targetComm {
			t.Errorf("%s: target_comm %q, want %q", d.RequestName, d.TargetComm, targetComm)
		}
		if evt.Severity != event.SeverityAlert {
			t.Errorf("%s: severity %s, want ALERT", d.RequestName, evt.Severity)
		}
	}
	return got
}

// TestSensor6_PtraceMonitor_RegisterWrites: SETREGS (x86), SETREGSET and
// POKEUSER on a traced child are each reported, with the child's comm. On
// x86_64, POKEUSER's address (the USER-area offset) is checked too.
func TestSensor6_PtraceMonitor_RegisterWrites(t *testing.T) {
	target := shmPtrUnique("hmpt")
	bus := shmPtrStartBus(t)
	pid, out := shmPtrRun(t, shmPtrBaseEnv, canaryBinDir()+"/ptrace_regs_canary", target)
	child := uint32(shmPtrCanaryValue(t, out, "target_pid"))
	got := shmPtrWaitPtrace(t, bus, func(e *event.HookEvent) bool { return e.PID == uint32(pid) },
		shmPtrRegRequests(), child, target)
	if runtime.GOARCH == "amd64" {
		want := shmPtrCanaryValue(t, out, "pokeuser_addr")
		if evt := got[shmPtrPokeUser]; evt != nil && evt.PtraceDetail.Addr != want {
			t.Errorf("PTRACE_POKEUSER addr %#x, want %#x", evt.PtraceDetail.Addr, want)
		}
	}
}

// TestSensor6_PtraceMonitor_AttachTargetComm: PTRACE_ATTACH, where the
// target is not yet a tracee, also carries the target's comm. The existing
// canary's child keeps the parent's name.
func TestSensor6_PtraceMonitor_AttachTargetComm(t *testing.T) {
	bus := shmPtrStartBus(t)
	pid, _ := shmPtrRun(t, shmPtrBaseEnv, canaryBinDir()+"/ptrace_canary")
	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventPtraceInject && e.PtraceDetail != nil &&
			e.PtraceDetail.Request == shmPtrAttach && e.PID == uint32(pid)
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("no PTRACE_ATTACH from pid %d: %v", pid, err)
	}
	d := evt.PtraceDetail
	t.Logf("PTRACE_ATTACH target_pid=%d target_comm=%q", d.TargetPID, d.TargetComm)
	if d.TargetComm != "ptrace_canary" {
		t.Errorf("target_comm %q, want %q", d.TargetComm, "ptrace_canary")
	}
}

// TestSensor6_PtraceMonitor_TargetCommInPidNamespace: a caller in its own
// PID namespace names its target by a PID that means something else on the
// host (the child is PID 2 inside, which on the host is kthreadd). The comm
// must be the target's, not that of the host's process with the same number.
func TestSensor6_PtraceMonitor_TargetCommInPidNamespace(t *testing.T) {
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare not found")
	}
	target := shmPtrUnique("hmns")
	bus := shmPtrStartBus(t)
	// unshare --fork runs the canary as its child, PID 1 in the new namespace.
	unsharePID, out := shmPtrRun(t, shmPtrBaseEnv, unshare, "--pid", "--fork", "--mount-proc",
		canaryBinDir()+"/ptrace_regs_canary", target)
	child := uint32(shmPtrCanaryValue(t, out, "target_pid"))
	if hostComm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", child)); err == nil {
		t.Logf("host PID %d is %q", child, bytes.TrimSpace(hostComm))
	}
	shmPtrWaitPtrace(t, bus, func(e *event.HookEvent) bool { return e.PPID == uint32(unsharePID) },
		shmPtrRegRequests(), child, target)
}

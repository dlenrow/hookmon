//go:build linux

package e2e

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// These tests require:
// - Root privileges (sudo)
// - hookmon-bus binary at HOOKMON_BUS_BIN (default: /tmp/hookmon-bus)
// - Canary binaries built by test/canary/Makefile
// - Run: sudo go test -tags e2e -count=1 -timeout 300s ./test/e2e/...

func busBin() string {
	if v := os.Getenv("HOOKMON_BUS_BIN"); v != "" {
		return v
	}
	// Fallback to legacy env var
	if v := os.Getenv("HOOKMON_AGENT_BIN"); v != "" {
		return v
	}
	return "/tmp/hookmon-bus"
}

func canaryBinDir() string {
	if v := os.Getenv("HOOKMON_CANARY_BIN"); v != "" {
		return v
	}
	return "/tmp/canary/bin"
}

func canaryDir() string {
	if v := os.Getenv("HOOKMON_CANARY_DIR"); v != "" {
		return v
	}
	return "/tmp/canary"
}

// ---------------------------------------------------------------------------
// Sensor 1: bpf_syscall — detect BPF program loading
// ---------------------------------------------------------------------------

func TestSensor1_BPFSyscall_DetectLoad(t *testing.T) {
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

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventBPFLoad &&
			e.BPFDetail != nil &&
			e.BPFDetail.ProgName == "hello_count"
	}, 15*time.Second)

	if err != nil {
		t.Fatalf("did not detect BPF_LOAD for hello_count: %v", err)
	}

	t.Logf("PASS: BPF_LOAD detected — prog=%s type=%d pid=%d insn=%d",
		evt.BPFDetail.ProgName, evt.BPFDetail.ProgType, evt.PID, evt.BPFDetail.InsnCount)

	if evt.BPFDetail.ProgHash == "" {
		t.Error("expected non-empty prog_hash")
	}
	if evt.Severity != event.SeverityWarn {
		t.Errorf("expected severity WARN (no allowlist match), got %s", evt.Severity)
	}
}

func TestSensor1_BPFSyscall_DifferentHashPerProgram(t *testing.T) {
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
		time.Sleep(1 * time.Second)
		LoadCanary(canaryBinDir()+"/load_canary",
			canaryDir()+"/net_monitor.o",
			"syscalls", "sys_enter_connect", "net_count")
	}()

	evt1, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "hello_count"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect hello_count: %v", err)
	}

	evt2, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "net_count"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect net_count: %v", err)
	}

	if evt1.BPFDetail.ProgHash == evt2.BPFDetail.ProgHash {
		t.Error("different BPF programs must have different prog_hash values")
	}
	t.Logf("PASS: hello_count hash=%s, net_count hash=%s", evt1.BPFDetail.ProgHash, evt2.BPFDetail.ProgHash)
}

func TestSensor1_BPFSyscall_VersionChangeNewHash(t *testing.T) {
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
		time.Sleep(1 * time.Second)
		LoadCanary(canaryBinDir()+"/load_canary",
			canaryDir()+"/hello_bpf_v2.o",
			"syscalls", "sys_enter_getpid", "hello_count_v2")
	}()

	evt1, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "hello_count"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect hello_count v1: %v", err)
	}

	evt2, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "hello_count_v2"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect hello_count_v2: %v", err)
	}

	if evt1.BPFDetail.ProgHash == evt2.BPFDetail.ProgHash {
		t.Error("v1 and v2 must have different prog_hash (different bytecode)")
	}
	t.Logf("PASS: v1 hash=%s, v2 hash=%s", evt1.BPFDetail.ProgHash, evt2.BPFDetail.ProgHash)
}

// ---------------------------------------------------------------------------
// Sensor 2: exec_injection — detect LD_PRELOAD in execve()
// ---------------------------------------------------------------------------

func TestSensor2_ExecInjection_LDPreload(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	libPath := canaryBinDir() + "/libfake_hook.so"

	go func() {
		time.Sleep(1 * time.Second)
		RunShellCanary(canaryDir()+"/exec_injection_canary.sh", libPath, "/bin/true")
	}()

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventExecInjection &&
			e.ExecInjectionDetail != nil &&
			strings.Contains(e.ExecInjectionDetail.LibraryPath, "fake_hook")
	}, 15*time.Second)

	if err != nil {
		t.Fatalf("did not detect EXEC_INJECTION with LD_PRELOAD: %v", err)
	}

	t.Logf("PASS: EXEC_INJECTION detected — lib=%s target=%s env=%s pid=%d",
		evt.ExecInjectionDetail.LibraryPath,
		evt.ExecInjectionDetail.TargetBinary,
		evt.ExecInjectionDetail.EnvVar,
		evt.PID)

	if evt.ExecInjectionDetail.EnvVar != "LD_PRELOAD" {
		t.Errorf("expected EnvVar=LD_PRELOAD, got %s", evt.ExecInjectionDetail.EnvVar)
	}
}

// ---------------------------------------------------------------------------
// Sensor 3: shm_monitor — detect bpftime-pattern shared memory
// ---------------------------------------------------------------------------

func TestSensor3_SHMMonitor_BpftimePattern(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	go func() {
		time.Sleep(1 * time.Second)
		RunCanaryBinary(canaryBinDir()+"/shm_canary", "/bpftime_canary_test")
	}()

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventSHMCreate &&
			e.SHMDetail != nil &&
			e.SHMDetail.Pattern == "bpftime"
	}, 15*time.Second)

	if err != nil {
		t.Fatalf("did not detect SHM_CREATE with bpftime pattern: %v", err)
	}

	t.Logf("PASS: SHM_CREATE detected — name=%s pattern=%s severity=%s pid=%d",
		evt.SHMDetail.SHMName, evt.SHMDetail.Pattern, evt.Severity, evt.PID)

	if evt.Severity != event.SeverityCritical {
		t.Errorf("expected severity CRITICAL for bpftime SHM, got %s", evt.Severity)
	}
}

// ---------------------------------------------------------------------------
// Sensor 4: dlopen_monitor — detect runtime dlopen() of non-standard library
// ---------------------------------------------------------------------------

func TestSensor4_DlopenMonitor_LoadLibrary(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	libPath := canaryBinDir() + "/libfake_hook.so"

	go func() {
		time.Sleep(1 * time.Second)
		RunCanaryBinary(canaryBinDir()+"/dlopen_canary", libPath)
	}()

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventDlopen &&
			e.DlopenDetail != nil &&
			strings.Contains(e.DlopenDetail.LibraryPath, "fake_hook")
	}, 15*time.Second)

	if err != nil {
		t.Fatalf("did not detect DLOPEN of fake_hook: %v", err)
	}

	t.Logf("PASS: DLOPEN detected — lib=%s flags=%d pid=%d",
		evt.DlopenDetail.LibraryPath, evt.DlopenDetail.Flags, evt.PID)
}

// ---------------------------------------------------------------------------
// Sensor 5: linker_config — detect writes to ld.so config files
// ---------------------------------------------------------------------------

func TestSensor5_LinkerConfig_WriteConfD(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	go func() {
		time.Sleep(1 * time.Second)
		RunShellCanary(canaryDir()+"/linker_config_canary.sh")
	}()

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventLinkerConfig &&
			e.LinkerConfigDetail != nil &&
			strings.Contains(e.LinkerConfigDetail.FilePath, "hookmon-canary-test")
	}, 15*time.Second)

	if err != nil {
		t.Fatalf("did not detect LINKER_CONFIG write: %v", err)
	}

	t.Logf("PASS: LINKER_CONFIG detected — file=%s op=%s severity=%s pid=%d",
		evt.LinkerConfigDetail.FilePath, evt.LinkerConfigDetail.Operation, evt.Severity, evt.PID)

	if evt.Severity != event.SeverityCritical {
		t.Errorf("expected severity CRITICAL for linker config change, got %s", evt.Severity)
	}
}

// ---------------------------------------------------------------------------
// Sensor 6: ptrace_monitor — detect ptrace attach/inject
// ---------------------------------------------------------------------------

func TestSensor6_PtraceMonitor_Attach(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	go func() {
		time.Sleep(1 * time.Second)
		RunCanaryBinary(canaryBinDir()+"/ptrace_canary")
	}()

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventPtraceInject &&
			e.PtraceDetail != nil
	}, 15*time.Second)

	if err != nil {
		t.Fatalf("did not detect PTRACE_INJECT: %v", err)
	}

	t.Logf("PASS: PTRACE_INJECT detected — request=%s(%d) target_pid=%d pid=%d",
		evt.PtraceDetail.RequestName, evt.PtraceDetail.Request,
		evt.PtraceDetail.TargetPID, evt.PID)

	// Should be PTRACE_ATTACH (16) or PTRACE_SEIZE (16902)
	if evt.PtraceDetail.Request != 16 && evt.PtraceDetail.Request != 16902 {
		t.Errorf("expected PTRACE_ATTACH(16) or PTRACE_SEIZE(16902), got %d", evt.PtraceDetail.Request)
	}
}

// ---------------------------------------------------------------------------
// Sensor 7: lib_integrity — detect shared library modification on disk
// ---------------------------------------------------------------------------

func TestSensor7_LibIntegrity_WriteToUsrLib(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	libPath := canaryBinDir() + "/libfake_hook.so"

	go func() {
		time.Sleep(1 * time.Second)
		RunShellCanary(canaryDir()+"/lib_integrity_canary.sh", libPath)
	}()

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventLibIntegrity &&
			e.LibIntegrityDetail != nil &&
			strings.Contains(e.LibIntegrityDetail.LibraryPath, "hookmon_canary_test")
	}, 15*time.Second)

	if err != nil {
		t.Fatalf("did not detect LIB_INTEGRITY write: %v", err)
	}

	t.Logf("PASS: LIB_INTEGRITY detected — lib=%s op=%s severity=%s pid=%d",
		evt.LibIntegrityDetail.LibraryPath, evt.LibIntegrityDetail.Operation,
		evt.Severity, evt.PID)
}

// ---------------------------------------------------------------------------
// Sensor 8: elf_rpath — detect suspicious RPATH/RUNPATH in ELF binaries
// ---------------------------------------------------------------------------

func TestSensor8_ElfRpath_SuspiciousPath(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	rpathBinary := canaryBinDir() + "/test_rpath"

	go func() {
		time.Sleep(1 * time.Second)
		// Execute the binary — the elf_rpath audit sensor runs on every execve
		RunCanaryBinary(rpathBinary)
	}()

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventElfRpath &&
			e.ElfRpathDetail != nil
	}, 15*time.Second)

	if err != nil {
		t.Fatalf("did not detect ELF_RPATH event: %v", err)
	}

	t.Logf("PASS: ELF_RPATH detected — rpath=%s risk=%s setuid=%v pid=%d",
		evt.ElfRpathDetail.RpathRaw, evt.ElfRpathDetail.HighestRisk,
		evt.ElfRpathDetail.IsSetuid, evt.PID)

	// /tmp/evil should be CRITICAL risk
	if evt.ElfRpathDetail.HighestRisk != "CRITICAL" {
		t.Errorf("expected CRITICAL risk for /tmp/evil RPATH, got %s", string(evt.ElfRpathDetail.HighestRisk))
	}

	// Should contain the /tmp/evil path
	if !strings.Contains(evt.ElfRpathDetail.RpathRaw, "/tmp/evil") {
		t.Errorf("expected RPATH to contain /tmp/evil, got %s", evt.ElfRpathDetail.RpathRaw)
	}
}

// ---------------------------------------------------------------------------
// Combined attack: bpftime simulation (SHM + EXEC_INJECTION)
// ---------------------------------------------------------------------------

func TestCombined_BpftimeAttackChain(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	simBin := canaryBinDir() + "/bpftime_sim"
	libPath := canaryBinDir() + "/libfake_hook.so"

	go func() {
		time.Sleep(1 * time.Second)
		RunBpftimeSim(simBin, libPath, "/bin/true")
	}()

	// Phase 1: SHM_CREATE with bpftime pattern
	shmEvt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventSHMCreate &&
			e.SHMDetail != nil &&
			e.SHMDetail.Pattern == "bpftime"
	}, 30*time.Second)

	if err != nil {
		t.Fatalf("did not detect SHM_CREATE: %v", err)
	}

	t.Logf("Phase 1: SHM_CREATE — name=%s pattern=%s severity=%s",
		shmEvt.SHMDetail.SHMName, shmEvt.SHMDetail.Pattern, shmEvt.Severity)

	// Phase 2: EXEC_INJECTION with LD_PRELOAD
	injEvt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventExecInjection &&
			e.ExecInjectionDetail != nil &&
			strings.Contains(e.ExecInjectionDetail.LibraryPath, "fake_hook")
	}, 30*time.Second)

	if err != nil {
		t.Fatalf("did not detect EXEC_INJECTION: %v", err)
	}

	t.Logf("Phase 2: EXEC_INJECTION — lib=%s env=%s severity=%s",
		injEvt.ExecInjectionDetail.LibraryPath,
		injEvt.ExecInjectionDetail.EnvVar,
		injEvt.Severity)

	t.Logf("PASS: Full bpftime attack chain detected (SHM_CREATE + EXEC_INJECTION)")
}

// ---------------------------------------------------------------------------
// Policy evaluation tests
// ---------------------------------------------------------------------------

func TestPolicy_AllowByProgHash(t *testing.T) {
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

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "hello_count"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect hello_count: %v", err)
	}

	// Allowlist by exact prog_hash
	allowlist := []*event.AllowlistEntry{
		{
			ID:          "test-allow-prog-hash",
			Description: "Allow hello_count by prog_hash",
			EventTypes:  []event.EventType{event.EventBPFLoad},
			ProgHash:    evt.BPFDetail.ProgHash,
			Action:      event.ActionAllow,
			Enabled:     true,
		},
	}

	result := EvaluateAgainstAllowlist(evt, allowlist)
	if result.Action != event.ActionAllow {
		t.Errorf("expected ALLOW, got %s: %s", result.Action, result.Reason)
	}
	t.Logf("PASS: prog_hash allowlist matched — hash=%s", evt.BPFDetail.ProgHash)
}

func TestPolicy_DenyByProgHash(t *testing.T) {
	bus, err := StartBus(busBin())
	if err != nil {
		t.Fatalf("start bus: %v", err)
	}
	defer bus.Stop()

	go func() {
		time.Sleep(1 * time.Second)
		LoadCanary(canaryBinDir()+"/load_canary",
			canaryDir()+"/net_monitor.o",
			"syscalls", "sys_enter_connect", "net_count")
	}()

	evt, err := bus.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "net_count"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect net_count: %v", err)
	}

	denyList := []*event.AllowlistEntry{
		{
			ID:          "test-deny-prog-hash",
			Description: "Deny net_count by prog_hash",
			EventTypes:  []event.EventType{event.EventBPFLoad},
			ProgHash:    evt.BPFDetail.ProgHash,
			Action:      event.ActionDeny,
			Enabled:     true,
		},
	}

	result := EvaluateAgainstAllowlist(evt, denyList)
	if result.Action != event.ActionDeny {
		t.Errorf("expected DENY, got %s", result.Action)
	}
	t.Logf("PASS: prog_hash deny matched — hash=%s", evt.BPFDetail.ProgHash)
}

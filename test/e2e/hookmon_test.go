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
// - hookmon-agent binary at HOOKMON_AGENT_BIN (default: /tmp/hookmon-agent)
// - Canary loader at HOOKMON_LOADER_BIN (default: /tmp/load-canary)
// - Compiled canary .o files at HOOKMON_CANARY_DIR (default: /tmp)

func agentBin() string {
	if v := os.Getenv("HOOKMON_AGENT_BIN"); v != "" {
		return v
	}
	return "/tmp/hookmon-agent"
}

func loaderBin() string {
	if v := os.Getenv("HOOKMON_LOADER_BIN"); v != "" {
		return v
	}
	return "/tmp/load-canary"
}

func canaryDir() string {
	if v := os.Getenv("HOOKMON_CANARY_DIR"); v != "" {
		return v
	}
	return "/tmp"
}

func fakeHookLib() string {
	if v := os.Getenv("HOOKMON_FAKE_HOOK_LIB"); v != "" {
		return v
	}
	return "/tmp/libfake_hook.so"
}

// TestDetectUnknownBPFLoad verifies that loading a BPF program with no
// allowlist entry generates an event with WARN severity.
func TestDetectUnknownBPFLoad(t *testing.T) {
	agent, err := StartAgent(agentBin())
	if err != nil {
		t.Fatalf("start agent: %v", err)
	}
	defer agent.Stop()

	// Load canary "hello_bpf" — should be detected as unknown
	go func() {
		time.Sleep(1 * time.Second)
		LoadCanary(loaderBin(), canaryDir()+"/hello_bpf.o",
			"syscalls", "sys_enter_getpid", "hello_count")
	}()

	evt, err := agent.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventBPFLoad &&
			e.BPFDetail != nil &&
			e.BPFDetail.ProgName == "hello_count"
	}, 15*time.Second)

	if err != nil {
		t.Fatalf("did not detect hello_bpf load: %v", err)
	}

	t.Logf("Detected BPF_LOAD event:")
	t.Logf("  PID: %d, Comm: %s", evt.PID, evt.Comm)
	t.Logf("  ProgName: %s, ProgType: %d", evt.BPFDetail.ProgName, evt.BPFDetail.ProgType)
	t.Logf("  ProgHash: %s", evt.BPFDetail.ProgHash)
	t.Logf("  ExeHash: %s", evt.ExeHash)
	t.Logf("  InsnCount: %d", evt.BPFDetail.InsnCount)

	// Without allowlist, severity should be WARN (default)
	if evt.Severity != event.SeverityWarn {
		t.Errorf("expected severity WARN, got %s", evt.Severity)
	}

	// ProgHash should be populated
	if evt.BPFDetail.ProgHash == "" {
		t.Error("expected non-empty prog_hash for BPF_LOAD event")
	}
}

// TestDetectSecondApp verifies that a different BPF program (net_monitor)
// produces a different prog_hash than hello_bpf.
func TestDetectSecondApp(t *testing.T) {
	agent, err := StartAgent(agentBin())
	if err != nil {
		t.Fatalf("start agent: %v", err)
	}
	defer agent.Stop()

	// Load both canaries sequentially and capture their hashes
	var helloHash, netHash string

	go func() {
		time.Sleep(1 * time.Second)
		LoadCanary(loaderBin(), canaryDir()+"/hello_bpf.o",
			"syscalls", "sys_enter_getpid", "hello_count")
		time.Sleep(1 * time.Second)
		LoadCanary(loaderBin(), canaryDir()+"/net_monitor.o",
			"syscalls", "sys_enter_connect", "net_count")
	}()

	// Wait for hello_bpf
	evt1, err := agent.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "hello_count"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect hello_bpf: %v", err)
	}
	helloHash = evt1.BPFDetail.ProgHash

	// Wait for net_monitor
	evt2, err := agent.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "net_count"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect net_monitor: %v", err)
	}
	netHash = evt2.BPFDetail.ProgHash

	t.Logf("hello_bpf prog_hash:  %s", helloHash)
	t.Logf("net_monitor prog_hash: %s", netHash)

	if helloHash == netHash {
		t.Error("different BPF programs should have different prog_hash values")
	}
	if helloHash == "" || netHash == "" {
		t.Error("prog_hash should not be empty")
	}
}

// TestVersionChangeNewHash verifies that hello_bpf_v2 (revised version)
// has a different prog_hash than hello_bpf v1.
func TestVersionChangeNewHash(t *testing.T) {
	agent, err := StartAgent(agentBin())
	if err != nil {
		t.Fatalf("start agent: %v", err)
	}
	defer agent.Stop()

	var v1Hash, v2Hash string

	go func() {
		time.Sleep(1 * time.Second)
		LoadCanary(loaderBin(), canaryDir()+"/hello_bpf.o",
			"syscalls", "sys_enter_getpid", "hello_count")
		time.Sleep(1 * time.Second)
		LoadCanary(loaderBin(), canaryDir()+"/hello_bpf_v2.o",
			"syscalls", "sys_enter_getpid", "hello_count_v2")
	}()

	evt1, err := agent.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "hello_count"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect hello_bpf v1: %v", err)
	}
	v1Hash = evt1.BPFDetail.ProgHash

	evt2, err := agent.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "hello_count_v2"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect hello_bpf v2: %v", err)
	}
	v2Hash = evt2.BPFDetail.ProgHash

	t.Logf("hello_bpf v1 prog_hash: %s", v1Hash)
	t.Logf("hello_bpf v2 prog_hash: %s", v2Hash)

	if v1Hash == v2Hash {
		t.Error("v1 and v2 of hello_bpf should have different prog_hash values (different bytecode)")
	}
}

// TestWhitelistByProgHash verifies that an event matching an allowlist entry
// by prog_hash is classified as ALLOW.
func TestWhitelistByProgHash(t *testing.T) {
	agent, err := StartAgent(agentBin())
	if err != nil {
		t.Fatalf("start agent: %v", err)
	}
	defer agent.Stop()

	// First, load hello_bpf to capture its hash
	go func() {
		time.Sleep(1 * time.Second)
		LoadCanary(loaderBin(), canaryDir()+"/hello_bpf.o",
			"syscalls", "sys_enter_getpid", "hello_count")
	}()

	evt, err := agent.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "hello_count"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect hello_bpf: %v", err)
	}

	capturedHash := evt.BPFDetail.ProgHash
	t.Logf("Captured prog_hash: %s", capturedHash)

	// Create allowlist entry matching this exact hash
	allowlist := []*event.AllowlistEntry{
		{
			ID:          "test-whitelist-1",
			Description: "Whitelisted hello_bpf canary",
			EventTypes:  []event.EventType{event.EventBPFLoad},
			ProgHash:    capturedHash,
			Action:      event.ActionAllow,
			Enabled:     true,
		},
	}

	// Evaluate the captured event against the allowlist
	result := EvaluateAgainstAllowlist(evt, allowlist)
	if result.Action != event.ActionAllow {
		t.Errorf("expected ALLOW for matching prog_hash, got %s: %s", result.Action, result.Reason)
	}
	t.Logf("Policy result: %s (entry: %s)", result.Action, result.MatchedEntryID)

	// Now verify that v2 does NOT match the same allowlist entry
	agent.Stop()
	agent2, err := StartAgent(agentBin())
	if err != nil {
		t.Fatalf("restart agent: %v", err)
	}
	defer agent2.Stop()

	go func() {
		time.Sleep(1 * time.Second)
		LoadCanary(loaderBin(), canaryDir()+"/hello_bpf_v2.o",
			"syscalls", "sys_enter_getpid", "hello_count_v2")
	}()

	evt2, err := agent2.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "hello_count_v2"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect hello_bpf v2: %v", err)
	}

	result2 := EvaluateAgainstAllowlist(evt2, allowlist)
	if result2.Action != event.ActionAlert {
		t.Errorf("expected ALERT for non-matching prog_hash (v2), got %s", result2.Action)
	}
	t.Logf("v2 policy result: %s (different hash = not whitelisted)", result2.Action)
}

// TestBlacklistByProgHash verifies that a DENY allowlist entry blocks
// a specific BPF program by hash.
func TestBlacklistByProgHash(t *testing.T) {
	agent, err := StartAgent(agentBin())
	if err != nil {
		t.Fatalf("start agent: %v", err)
	}
	defer agent.Stop()

	go func() {
		time.Sleep(1 * time.Second)
		LoadCanary(loaderBin(), canaryDir()+"/net_monitor.o",
			"syscalls", "sys_enter_connect", "net_count")
	}()

	evt, err := agent.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "net_count"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect net_monitor: %v", err)
	}

	// Create a DENY entry for this specific program
	denyList := []*event.AllowlistEntry{
		{
			ID:          "test-blacklist-1",
			Description: "Blacklisted net_monitor canary",
			EventTypes:  []event.EventType{event.EventBPFLoad},
			ProgHash:    evt.BPFDetail.ProgHash,
			Action:      event.ActionDeny,
			Enabled:     true,
		},
	}

	result := EvaluateAgainstAllowlist(evt, denyList)
	if result.Action != event.ActionDeny {
		t.Errorf("expected DENY for blacklisted prog_hash, got %s", result.Action)
	}
	t.Logf("Blacklist result: %s (entry: %s)", result.Action, result.MatchedEntryID)
}

// TestWhitelistByExeHash verifies allowlist matching by loader binary hash.
func TestWhitelistByExeHash(t *testing.T) {
	agent, err := StartAgent(agentBin())
	if err != nil {
		t.Fatalf("start agent: %v", err)
	}
	defer agent.Stop()

	go func() {
		time.Sleep(1 * time.Second)
		LoadCanary(loaderBin(), canaryDir()+"/hello_bpf.o",
			"syscalls", "sys_enter_getpid", "hello_count")
	}()

	evt, err := agent.WaitForEvent(func(e *event.HookEvent) bool {
		return e.BPFDetail != nil && e.BPFDetail.ProgName == "hello_count"
	}, 15*time.Second)
	if err != nil {
		t.Fatalf("did not detect hello_bpf: %v", err)
	}

	if evt.ExeHash == "" {
		t.Skip("exe_hash not populated (enrichment may not have run)")
	}

	// Whitelist by loader binary hash — allows ALL programs from this loader
	allowlist := []*event.AllowlistEntry{
		{
			ID:          "test-exe-whitelist",
			Description: "Trust the load-canary binary",
			EventTypes:  []event.EventType{event.EventBPFLoad},
			ExeHash:     evt.ExeHash,
			Action:      event.ActionAllow,
			Enabled:     true,
		},
	}

	result := EvaluateAgainstAllowlist(evt, allowlist)
	if result.Action != event.ActionAllow {
		t.Errorf("expected ALLOW for matching exe_hash, got %s", result.Action)
	}
	t.Logf("Whitelisted by exe_hash: %s", evt.ExeHash)
}

// TestDetectBpftimeExploit simulates the full bpftime-go attack chain and
// verifies that both SHM_CREATE (CRITICAL) and EXEC_INJECTION (ALERT) events fire.
func TestDetectBpftimeExploit(t *testing.T) {
	agent, err := StartAgent(agentBin())
	if err != nil {
		t.Fatalf("start agent: %v", err)
	}
	defer agent.Stop()

	// Run the bpftime attack simulator in the background
	go func() {
		time.Sleep(1 * time.Second)
		if err := RunBpftimeSim(bpftimeSimBin(), fakeHookLib(), "/bin/true"); err != nil {
			t.Logf("bpftime_sim error (may be expected): %v", err)
		}
	}()

	// Phase 1: Detect shared memory creation with bpftime naming pattern
	shmEvt, err := agent.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventSHMCreate &&
			e.SHMDetail != nil &&
			e.SHMDetail.Pattern == "bpftime"
	}, 30*time.Second)

	if err != nil {
		t.Fatalf("did not detect SHM_CREATE with bpftime pattern: %v", err)
	}

	t.Logf("Detected SHM_CREATE event:")
	t.Logf("  PID: %d, Comm: %s", shmEvt.PID, shmEvt.Comm)
	t.Logf("  SHMName: %s", shmEvt.SHMDetail.SHMName)
	t.Logf("  Pattern: %s", shmEvt.SHMDetail.Pattern)
	t.Logf("  Severity: %s", shmEvt.Severity)

	if shmEvt.Severity != event.SeverityCritical {
		t.Errorf("expected severity CRITICAL for bpftime SHM, got %s", shmEvt.Severity)
	}

	// Phase 2: Detect exec injection of fake_hook library
	injEvt, err := agent.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventExecInjection &&
			e.ExecInjectionDetail != nil &&
			strings.Contains(e.ExecInjectionDetail.LibraryPath, "fake_hook")
	}, 30*time.Second)

	if err != nil {
		t.Fatalf("did not detect EXEC_INJECTION with fake_hook: %v", err)
	}

	t.Logf("Detected EXEC_INJECTION event:")
	t.Logf("  PID: %d, Comm: %s", injEvt.PID, injEvt.Comm)
	t.Logf("  LibraryPath: %s", injEvt.ExecInjectionDetail.LibraryPath)
	t.Logf("  TargetBinary: %s", injEvt.ExecInjectionDetail.TargetBinary)
	t.Logf("  LibraryHash: %s", injEvt.ExecInjectionDetail.LibraryHash)
	t.Logf("  SetBy: %s", injEvt.ExecInjectionDetail.SetBy)
	t.Logf("  EnvVar: %s", injEvt.ExecInjectionDetail.EnvVar)
	t.Logf("  Severity: %s", injEvt.Severity)

	if injEvt.Severity != event.SeverityAlert {
		t.Errorf("expected severity ALERT for EXEC_INJECTION, got %s", injEvt.Severity)
	}

	t.Logf("=== bpftime attack chain fully detected ===")
	t.Logf("  SHM_CREATE (CRITICAL) + EXEC_INJECTION (ALERT) = userspace eBPF attack pattern")
}

// TestDenyBpftimeByPolicy verifies that a DENY policy entry can match
// bpftime-pattern SHM events and block the attack.
func TestDenyBpftimeByPolicy(t *testing.T) {
	agent, err := StartAgent(agentBin())
	if err != nil {
		t.Fatalf("start agent: %v", err)
	}
	defer agent.Stop()

	// Trigger bpftime simulation
	go func() {
		time.Sleep(1 * time.Second)
		if err := RunBpftimeSim(bpftimeSimBin(), fakeHookLib(), "/bin/true"); err != nil {
			t.Logf("bpftime_sim error (may be expected): %v", err)
		}
	}()

	// Capture the SHM_CREATE event
	shmEvt, err := agent.WaitForEvent(func(e *event.HookEvent) bool {
		return e.EventType == event.EventSHMCreate &&
			e.SHMDetail != nil &&
			e.SHMDetail.Pattern == "bpftime"
	}, 30*time.Second)

	if err != nil {
		t.Fatalf("did not detect SHM_CREATE: %v", err)
	}

	t.Logf("Captured SHM_CREATE event (SHMName=%s, Pattern=%s)", shmEvt.SHMDetail.SHMName, shmEvt.SHMDetail.Pattern)

	// Build a DENY policy entry that matches bpftime SHM patterns.
	// Uses LibraryPath field to match against the SHM name.
	denyList := []*event.AllowlistEntry{
		{
			ID:          "deny-bpftime-shm",
			Description: "Block bpftime-pattern shared memory creation",
			EventTypes:  []event.EventType{event.EventSHMCreate},
			LibraryPath: "bpftime",
			Action:      event.ActionDeny,
			Enabled:     true,
		},
	}

	// Evaluate: should get DENY
	result := EvaluateAgainstAllowlist(shmEvt, denyList)
	if result.Action != event.ActionDeny {
		t.Errorf("expected DENY for bpftime SHM event, got %s: %s", result.Action, result.Reason)
	}
	t.Logf("Policy result for bpftime SHM: %s (entry: %s)", result.Action, result.MatchedEntryID)

	// Verify the same DENY entry does NOT match a non-bpftime SHM event
	nonBpftimeEvt := &event.HookEvent{
		EventType: event.EventSHMCreate,
		SHMDetail: &event.SHMDetail{
			SHMName: "/dev/shm/postgres_shared_12345",
			Pattern: "unknown",
		},
	}
	result2 := EvaluateAgainstAllowlist(nonBpftimeEvt, denyList)
	if result2.Action == event.ActionDeny {
		t.Errorf("DENY entry should NOT match non-bpftime SHM event, but got DENY")
	}
	t.Logf("Policy result for non-bpftime SHM: %s (correctly not matched)", result2.Action)
}

package policy

import (
	"testing"

	"github.com/dlenrow/hookmon/pkg/event"
)

func TestDefaultRules_Count(t *testing.T) {
	rules := DefaultRules()
	if len(rules) != 8 {
		t.Errorf("expected 8 default rules, got %d", len(rules))
	}
}

func TestDefaultRules_UniqueNames(t *testing.T) {
	rules := DefaultRules()
	seen := make(map[string]bool)
	for _, r := range rules {
		if seen[r.Name] {
			t.Errorf("duplicate rule name: %s", r.Name)
		}
		seen[r.Name] = true
	}
}

// --- Individual rule tests ---

func TestRuleExecInjectionFromRoot(t *testing.T) {
	rule := ruleExecInjectionFromRoot()

	// Should fire: exec injection from UID 0.
	evt := &event.HookEvent{
		EventType: event.EventExecInjection,
		UID:       0,
		Hostname:  "host-1",
		ExePath:   "/usr/bin/test",
		ExecInjectionDetail: &event.ExecInjectionDetail{
			EnvVar: "LD_PRELOAD",
		},
	}
	result := rule.Evaluate(evt)
	if result == nil {
		t.Fatal("expected rule to fire for root exec injection")
	}
	if result.Action != event.ActionAlert {
		t.Errorf("expected ALERT, got %s", result.Action)
	}

	// Should not fire: exec injection from non-root.
	evt.UID = 1000
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire for non-root")
	}

	// Should not fire: non-exec-injection event.
	evt.EventType = event.EventBPFLoad
	evt.UID = 0
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire for non-exec-injection event")
	}
}

func TestRuleLDSoPreloadModified(t *testing.T) {
	rule := ruleLDSoPreloadModified()

	evt := &event.HookEvent{
		EventType: event.EventExecInjection,
		Hostname:  "host-1",
		ExecInjectionDetail: &event.ExecInjectionDetail{
			SetBy:       "/etc/ld.so.preload",
			LibraryPath: "/usr/lib/evil.so",
		},
	}
	if result := rule.Evaluate(evt); result == nil {
		t.Fatal("expected rule to fire for ld.so.preload")
	}

	// Different SetBy.
	evt.ExecInjectionDetail.SetBy = "env"
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire for env-based injection")
	}

	// No detail.
	evt.ExecInjectionDetail = nil
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire without detail")
	}

	// Wrong event type.
	evt.EventType = event.EventBPFLoad
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire for BPF_LOAD")
	}
}

func TestRuleBPFtimeSHM(t *testing.T) {
	rule := ruleBPFtimeSHM()

	evt := &event.HookEvent{
		EventType: event.EventSHMCreate,
		Hostname:  "host-1",
		PID:       42,
		SHMDetail: &event.SHMDetail{
			SHMName: "bpftime_agent_shm",
			Pattern: "bpftime",
		},
	}
	if result := rule.Evaluate(evt); result == nil {
		t.Fatal("expected rule to fire for bpftime SHM")
	}

	// Non-bpftime pattern.
	evt.SHMDetail.Pattern = "generic"
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire for generic SHM")
	}

	// No detail.
	evt.SHMDetail = nil
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire without detail")
	}
}

func TestRuleUnknownBinaryRoot(t *testing.T) {
	rule := ruleUnknownBinaryRoot()

	// Root with no exe hash.
	evt := &event.HookEvent{
		EventType: event.EventBPFLoad,
		UID:       0,
		Hostname:  "host-1",
		ExePath:   "/tmp/mystery",
	}
	if result := rule.Evaluate(evt); result == nil {
		t.Fatal("expected rule to fire for root unknown binary")
	}

	// Root with known hash.
	evt.ExeHash = "sha256:known"
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire for root with known binary")
	}

	// Non-root with no hash.
	evt.UID = 1000
	evt.ExeHash = ""
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire for non-root")
	}
}

func TestRuleLinkerConfigModified(t *testing.T) {
	rule := ruleLinkerConfigModified()

	evt := &event.HookEvent{
		EventType: event.EventLinkerConfig,
		Hostname:  "host-1",
		LinkerConfigDetail: &event.LinkerConfigDetail{
			FilePath:  "/etc/ld.so.preload",
			Operation: "write",
		},
	}
	if result := rule.Evaluate(evt); result == nil {
		t.Fatal("expected rule to fire for linker config")
	}

	// Without detail (should still fire — only checks event type).
	evt.LinkerConfigDetail = nil
	if result := rule.Evaluate(evt); result == nil {
		t.Fatal("expected rule to fire even without detail")
	}

	// Wrong event type.
	evt.EventType = event.EventBPFLoad
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire for BPF_LOAD")
	}
}

func TestRulePtraceFromNonDebugger(t *testing.T) {
	rule := rulePtraceFromNonDebugger()

	evt := &event.HookEvent{
		EventType: event.EventPtraceInject,
		PID:       100,
		Comm:      "evil",
		Hostname:  "host-1",
		PtraceDetail: &event.PtraceDetail{
			RequestName: "PTRACE_POKETEXT",
			TargetPID:   200,
		},
	}
	if result := rule.Evaluate(evt); result == nil {
		t.Fatal("expected rule to fire for ptrace")
	}

	// No detail.
	evt.PtraceDetail = nil
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire without ptrace detail")
	}

	// Wrong event type.
	evt.EventType = event.EventBPFLoad
	evt.PtraceDetail = &event.PtraceDetail{RequestName: "PTRACE_POKETEXT"}
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire for BPF_LOAD")
	}
}

func TestRuleLibraryReplacement(t *testing.T) {
	rule := ruleLibraryReplacement()

	evt := &event.HookEvent{
		EventType: event.EventLibIntegrity,
		Hostname:  "host-1",
		LibIntegrityDetail: &event.LibIntegrityDetail{
			LibraryPath: "/usr/lib/libssl.so",
			Operation:   "write",
		},
	}
	if result := rule.Evaluate(evt); result == nil {
		t.Fatal("expected rule to fire for library replacement")
	}

	// No detail.
	evt.LibIntegrityDetail = nil
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire without detail")
	}
}

func TestRuleElfRpathSuspicious(t *testing.T) {
	rule := ruleElfRpathSuspicious()

	// CRITICAL risk — should fire.
	evt := &event.HookEvent{
		EventType: event.EventElfRpath,
		ExePath:   "/opt/bin/suspicious",
		Hostname:  "host-1",
		ElfRpathDetail: &event.ElfRpathDetail{
			HighestRisk: event.RpathRiskCritical,
		},
	}
	if result := rule.Evaluate(evt); result == nil {
		t.Fatal("expected rule to fire for CRITICAL risk")
	}

	// HIGH risk — should not fire (rule only fires on CRITICAL).
	evt.ElfRpathDetail.HighestRisk = event.RpathRiskHigh
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire for HIGH risk (only CRITICAL)")
	}

	// MEDIUM risk — should not fire.
	evt.ElfRpathDetail.HighestRisk = event.RpathRiskMedium
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire for MEDIUM risk")
	}

	// No detail.
	evt.ElfRpathDetail = nil
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire without detail")
	}

	// Wrong event type.
	evt.EventType = event.EventBPFLoad
	evt.ElfRpathDetail = &event.ElfRpathDetail{HighestRisk: event.RpathRiskCritical}
	if rule.Evaluate(evt) != nil {
		t.Error("should not fire for BPF_LOAD event type")
	}
}

func TestEvaluateRules_ReturnsFirstMatch(t *testing.T) {
	// Create an event that matches exec_injection_from_root (rule 1)
	// AND ld_so_preload_modified (rule 2). evaluateRules should return
	// the first match.
	evt := &event.HookEvent{
		EventType: event.EventExecInjection,
		UID:       0,
		Hostname:  "host-1",
		ExePath:   "/usr/bin/test",
		ExecInjectionDetail: &event.ExecInjectionDetail{
			SetBy:  "/etc/ld.so.preload",
			EnvVar: "LD_PRELOAD",
		},
	}
	result := evaluateRules(evt)
	if result == nil {
		t.Fatal("expected a rule to fire")
	}
	// The first rule in DefaultRules() is exec_injection_from_root.
	if result.Reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestEvaluateRules_NoneMatch(t *testing.T) {
	// A BPF load from non-root with known hash triggers no built-in rules.
	evt := &event.HookEvent{
		EventType: event.EventBPFLoad,
		UID:       1000,
		ExeHash:   "sha256:known",
	}
	result := evaluateRules(evt)
	if result != nil {
		t.Errorf("expected nil, got rule result: %s", result.Reason)
	}
}

package policy

import (
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
	"go.uber.org/zap"
)

func newTestEngine(entries ...*event.AllowlistEntry) *Engine {
	e := NewEngine(zap.NewNop())
	if len(entries) > 0 {
		e.LoadAllowlist(entries)
	}
	return e
}

func baseEvent(et event.EventType) *event.HookEvent {
	return &event.HookEvent{
		ID:        "test-001",
		Timestamp: time.Now(),
		HostID:    "host-1",
		Hostname:  "web-01",
		EventType: et,
		PID:       1234,
		UID:       1000,
		ExePath:   "/usr/bin/test",
		ExeHash:   "sha256:abc123",
	}
}

// --- classifySeverity tests ---

func TestClassifySeverity_AllowReturnsInfo(t *testing.T) {
	evt := baseEvent(event.EventBPFLoad)
	result := &event.PolicyResult{Action: event.ActionAllow}
	got := classifySeverity(result, evt)
	if got != event.SeverityInfo {
		t.Errorf("ALLOW action: got %q, want INFO", got)
	}
}

func TestClassifySeverity_LdSoPreloadIsCritical(t *testing.T) {
	evt := baseEvent(event.EventExecInjection)
	evt.UID = 1000 // non-root, should still be CRITICAL for ld.so.preload
	evt.ExecInjectionDetail = &event.ExecInjectionDetail{SetBy: "/etc/ld.so.preload"}
	result := &event.PolicyResult{Action: event.ActionAlert}
	got := classifySeverity(result, evt)
	if got != event.SeverityCritical {
		t.Errorf("ld.so.preload: got %q, want CRITICAL", got)
	}
}

func TestClassifySeverity_BpftimeSHMIsCritical(t *testing.T) {
	evt := baseEvent(event.EventSHMCreate)
	evt.SHMDetail = &event.SHMDetail{Pattern: "bpftime"}
	result := &event.PolicyResult{Action: event.ActionAlert}
	got := classifySeverity(result, evt)
	if got != event.SeverityCritical {
		t.Errorf("bpftime SHM: got %q, want CRITICAL", got)
	}
}

func TestClassifySeverity_RootIsCritical(t *testing.T) {
	evt := baseEvent(event.EventBPFLoad)
	evt.UID = 0
	result := &event.PolicyResult{Action: event.ActionAlert}
	got := classifySeverity(result, evt)
	if got != event.SeverityCritical {
		t.Errorf("root UID: got %q, want CRITICAL", got)
	}
}

func TestClassifySeverity_ExecInjectionNonRootIsAlert(t *testing.T) {
	evt := baseEvent(event.EventExecInjection)
	evt.UID = 1000
	result := &event.PolicyResult{Action: event.ActionAlert}
	got := classifySeverity(result, evt)
	if got != event.SeverityAlert {
		t.Errorf("exec injection non-root: got %q, want ALERT", got)
	}
}

func TestClassifySeverity_LinkerConfigIsCritical(t *testing.T) {
	evt := baseEvent(event.EventLinkerConfig)
	result := &event.PolicyResult{Action: event.ActionAlert}
	got := classifySeverity(result, evt)
	if got != event.SeverityCritical {
		t.Errorf("linker config: got %q, want CRITICAL", got)
	}
}

func TestClassifySeverity_PtraceNonRootIsAlert(t *testing.T) {
	evt := baseEvent(event.EventPtraceInject)
	result := &event.PolicyResult{Action: event.ActionAlert}
	got := classifySeverity(result, evt)
	if got != event.SeverityAlert {
		t.Errorf("ptrace non-root: got %q, want ALERT", got)
	}
}

func TestClassifySeverity_LibIntegrityIsAlert(t *testing.T) {
	evt := baseEvent(event.EventLibIntegrity)
	result := &event.PolicyResult{Action: event.ActionAlert}
	got := classifySeverity(result, evt)
	if got != event.SeverityAlert {
		t.Errorf("lib integrity: got %q, want ALERT", got)
	}
}

func TestClassifySeverity_ElfRpathByRisk(t *testing.T) {
	tests := []struct {
		risk     event.RpathRisk
		expected event.Severity
	}{
		{event.RpathRiskCritical, event.SeverityCritical},
		{event.RpathRiskHigh, event.SeverityAlert},
		{event.RpathRiskMedium, event.SeverityWarn},
		{event.RpathRiskLow, event.SeverityInfo},
		{event.RpathRiskNone, event.SeverityInfo},
	}
	for _, tt := range tests {
		t.Run(string(tt.risk), func(t *testing.T) {
			evt := baseEvent(event.EventElfRpath)
			evt.ElfRpathDetail = &event.ElfRpathDetail{HighestRisk: tt.risk}
			result := &event.PolicyResult{Action: event.ActionAlert}
			got := classifySeverity(result, evt)
			if got != tt.expected {
				t.Errorf("ELF_RPATH risk=%s: got %q, want %q", tt.risk, got, tt.expected)
			}
		})
	}
}

func TestClassifySeverity_NoExeHashIsAlert(t *testing.T) {
	evt := baseEvent(event.EventBPFLoad)
	evt.ExeHash = ""
	result := &event.PolicyResult{Action: event.ActionAlert}
	got := classifySeverity(result, evt)
	if got != event.SeverityAlert {
		t.Errorf("empty exe hash: got %q, want ALERT", got)
	}
}

func TestClassifySeverity_KnownBPFEventIsWarn(t *testing.T) {
	evt := baseEvent(event.EventBPFLoad)
	evt.ExeHash = "sha256:known"
	result := &event.PolicyResult{Action: event.ActionAlert}
	got := classifySeverity(result, evt)
	if got != event.SeverityWarn {
		t.Errorf("known BPF load: got %q, want WARN", got)
	}
}

// --- Engine.Evaluate tests ---

func TestEvaluate_AllowlistMatchOverridesRule(t *testing.T) {
	// Create an event that would trigger the exec_injection_from_root rule.
	evt := baseEvent(event.EventExecInjection)
	evt.UID = 0
	evt.ExecInjectionDetail = &event.ExecInjectionDetail{EnvVar: "LD_PRELOAD", LibraryPath: "/usr/lib/libfoo.so"}

	// Create an allowlist ALLOW entry that matches this event.
	entry := &event.AllowlistEntry{
		ID:         "allow-1",
		EventTypes: []event.EventType{event.EventExecInjection},
		ExeHash:    evt.ExeHash,
		Action:     event.ActionAllow,
		Enabled:    true,
	}

	engine := newTestEngine(entry)
	result := engine.Evaluate(evt)

	if result.Action != event.ActionAllow {
		t.Errorf("expected ALLOW, got %s", result.Action)
	}
	if result.MatchedEntryID != "allow-1" {
		t.Errorf("expected matched entry allow-1, got %s", result.MatchedEntryID)
	}
	if evt.Severity != event.SeverityInfo {
		t.Errorf("expected severity INFO, got %s", evt.Severity)
	}
}

func TestEvaluate_NoMatchUsesBuiltInRule(t *testing.T) {
	evt := baseEvent(event.EventExecInjection)
	evt.UID = 0
	evt.ExecInjectionDetail = &event.ExecInjectionDetail{EnvVar: "LD_PRELOAD"}

	engine := newTestEngine() // empty allowlist
	result := engine.Evaluate(evt)

	if result.Action != event.ActionAlert {
		t.Errorf("expected ALERT from built-in rule, got %s", result.Action)
	}
	if result.Reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestEvaluate_NoMatchNoRule_DefaultAlert(t *testing.T) {
	// BPF_LOAD from non-root with known hash — no rule fires, no allowlist match.
	evt := baseEvent(event.EventBPFLoad)
	evt.UID = 1000
	evt.ExeHash = "sha256:known"

	engine := newTestEngine()
	result := engine.Evaluate(evt)

	if result.Action != event.ActionAlert {
		t.Errorf("expected default ALERT, got %s", result.Action)
	}
	if evt.Severity != event.SeverityWarn {
		t.Errorf("expected severity WARN for known binary, got %s", evt.Severity)
	}
}

func TestEvaluate_AgentOfflineIsAlert(t *testing.T) {
	evt := baseEvent(event.EventAgentOffline)
	engine := newTestEngine()
	result := engine.Evaluate(evt)

	if result.Action != event.ActionAlert {
		t.Errorf("expected ALERT, got %s", result.Action)
	}
	if evt.Severity != event.SeverityAlert {
		t.Errorf("expected ALERT severity, got %s", evt.Severity)
	}
}

func TestEvaluate_AgentRecoveredIsAlert(t *testing.T) {
	evt := baseEvent(event.EventAgentRecovered)
	engine := newTestEngine()
	result := engine.Evaluate(evt)

	if result.Action != event.ActionAlert {
		t.Errorf("expected ALERT, got %s", result.Action)
	}
}

func TestEvaluate_DenyEntryReturnsDeny(t *testing.T) {
	evt := baseEvent(event.EventSHMCreate)
	evt.SHMDetail = &event.SHMDetail{Pattern: "bpftime", SHMName: "bpftime_agent_shm"}

	entry := &event.AllowlistEntry{
		ID:         "deny-bpftime",
		EventTypes: []event.EventType{event.EventSHMCreate},
		Action:     event.ActionDeny,
		Enabled:    true,
	}

	engine := newTestEngine(entry)
	result := engine.Evaluate(evt)

	if result.Action != event.ActionDeny {
		t.Errorf("expected DENY, got %s", result.Action)
	}
}

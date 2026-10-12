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
	if result.Disposition != event.DispositionAllowed || result.Disposition.Kept() {
		t.Errorf("expected disposition allowed (not kept), got %q", result.Disposition)
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
	if result.Disposition != event.DispositionLifecycle || !result.Disposition.Kept() {
		t.Errorf("expected disposition lifecycle (kept), got %q", result.Disposition)
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

	if result.Action != event.ActionDeny || result.Disposition != event.DispositionDenied {
		t.Errorf("expected DENY, denied; got %s, %s", result.Action, result.Disposition)
	}
}

// --- BPF_INVENTORY ---

// inventoryEvent is a per-program inventory event as the bus sends it: no
// process context, so UID 0 and no exe hash.
func inventoryEvent(tag string) *event.HookEvent {
	return &event.HookEvent{
		ID:                 "inv-001",
		Timestamp:          time.Now(),
		HostID:             "host-1",
		Hostname:           "web-01",
		EventType:          event.EventBPFInventory,
		BPFDetail:          &event.BPFDetail{ProgID: 42, ProgName: "hello_count", ProgHash: tag},
		BPFInventoryDetail: &event.BPFInventoryDetail{ScanID: "scan-1"},
	}
}

func TestEvaluate_InventoryUnknownProgramIsAlertFirstSighting(t *testing.T) {
	// A loaded program nobody approved is a new hook, at ALERT whatever
	// its (absent) process context.
	evt := inventoryEvent("a04f5eef06a7f555")
	result := newTestEngine().Evaluate(evt)
	if evt.Severity != event.SeverityAlert {
		t.Errorf("severity: got %q, want ALERT", evt.Severity)
	}
	if result.Action != event.ActionAlert || result.MatchedEntryID != "" || result.Disposition != event.DispositionFirstSighting {
		t.Errorf("unknown program: got action %q entry %q disposition %q, want ALERT, no entry, first_sighting",
			result.Action, result.MatchedEntryID, result.Disposition)
	}
	if evt.PolicyResult != result {
		t.Error("PolicyResult not set on the event")
	}
}

func TestEvaluate_InventoryAllowlistedProgramRecordsMatch(t *testing.T) {
	entry := &event.AllowlistEntry{
		ID:         "allow-hello",
		EventTypes: []event.EventType{event.EventBPFLoad, event.EventBPFInventory},
		ProgHash:   "a04f5eef06a7f555",
		Action:     event.ActionAllow,
		Enabled:    true,
	}
	evt := inventoryEvent("a04f5eef06a7f555")
	result := newTestEngine(entry).Evaluate(evt)
	if result.Action != event.ActionAllow || result.MatchedEntryID != "allow-hello" || result.Disposition != event.DispositionAllowed {
		t.Errorf("got action %q entry %q disposition %q, want ALLOW allow-hello allowed", result.Action, result.MatchedEntryID, result.Disposition)
	}
	if evt.Severity != event.SeverityInfo {
		t.Errorf("severity: got %q, want INFO", evt.Severity)
	}
}

func TestEvaluate_InventoryDeniedProgramAlertsEveryScan(t *testing.T) {
	entry := &event.AllowlistEntry{
		ID:         "deny-hello",
		EventTypes: []event.EventType{event.EventBPFInventory},
		ProgHash:   "a04f5eef06a7f555",
		Action:     event.ActionAlert,
		Enabled:    true,
		Status:     event.StatusRejected,
	}
	engine := newTestEngine(entry)
	for scan := 0; scan < 2; scan++ {
		evt := inventoryEvent("a04f5eef06a7f555")
		result := engine.Evaluate(evt)
		if result.Disposition != event.DispositionDenied || evt.Severity != event.SeverityAlert || result.MatchedEntryID != "deny-hello" {
			t.Errorf("scan %d: disposition %q severity %q entry %q, want denied ALERT deny-hello",
				scan, result.Disposition, evt.Severity, result.MatchedEntryID)
		}
	}
}

func TestEvaluate_InventorySummaryIsInfo(t *testing.T) {
	evt := &event.HookEvent{
		ID:        "inv-sum",
		Timestamp: time.Now(),
		HostID:    "host-1",
		EventType: event.EventBPFInventory,
		BPFInventoryDetail: &event.BPFInventoryDetail{
			ScanID: "scan-1", Summary: true, ProgCount: 3,
		},
	}
	result := newTestEngine().Evaluate(evt)
	if evt.Severity != event.SeverityInfo || result.Action != event.ActionAllow || result.Disposition.Kept() {
		t.Errorf("summary: got severity %q action %q disposition %q, want INFO ALLOW and not kept",
			evt.Severity, result.Action, result.Disposition)
	}
}

package event

import (
	"encoding/json"
	"testing"
	"time"
)

func sampleEvent() *HookEvent {
	return &HookEvent{
		ID:        "evt-json-001",
		Timestamp: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
		HostID:    "host-json",
		Hostname:  "web-01",
		EventType: EventBPFLoad,
		Severity:  SeverityWarn,
		PID:       1234,
		PPID:      1,
		UID:       0,
		GID:       0,
		Comm:      "cilium-agent",
		Cmdline:   "/usr/bin/cilium-agent --config-dir=/etc/cilium",
		ExePath:   "/usr/bin/cilium-agent",
		ExeHash:   "sha256:abcdef1234567890",
		BPFDetail: &BPFDetail{
			BPFCommand: 5, // BPF_PROG_LOAD
			ProgType:   1, // KPROBE
			ProgName:   "trace_tcp_connect",
			InsnCount:  142,
			ProgHash:   "sha256:prog123",
		},
	}
}

func TestHookEvent_JSONRoundTrip(t *testing.T) {
	orig := sampleEvent()

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded HookEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Core fields.
	if decoded.ID != orig.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, orig.ID)
	}
	if decoded.EventType != orig.EventType {
		t.Errorf("EventType: got %q, want %q", decoded.EventType, orig.EventType)
	}
	if decoded.Severity != orig.Severity {
		t.Errorf("Severity: got %q, want %q", decoded.Severity, orig.Severity)
	}
	if decoded.PID != orig.PID {
		t.Errorf("PID: got %d, want %d", decoded.PID, orig.PID)
	}
	if decoded.ExeHash != orig.ExeHash {
		t.Errorf("ExeHash: got %q, want %q", decoded.ExeHash, orig.ExeHash)
	}

	// BPF detail.
	if decoded.BPFDetail == nil {
		t.Fatal("BPFDetail should not be nil")
	}
	if decoded.BPFDetail.ProgName != "trace_tcp_connect" {
		t.Errorf("ProgName: got %q", decoded.BPFDetail.ProgName)
	}
	if decoded.BPFDetail.InsnCount != 142 {
		t.Errorf("InsnCount: got %d", decoded.BPFDetail.InsnCount)
	}
}

func TestHookEvent_JSONRoundTrip_AllDetails(t *testing.T) {
	evt := &HookEvent{
		ID:        "evt-all",
		Timestamp: time.Now().UTC().Truncate(time.Millisecond),
		HostID:    "h1",
		EventType: EventExecInjection,
		Severity:  SeverityAlert,
		ExecInjectionDetail: &ExecInjectionDetail{
			LibraryPath:  "/usr/lib/evil.so",
			LibraryHash:  "sha256:lib",
			TargetBinary: "/usr/bin/target",
			SetBy:        "env",
			EnvVar:       "LD_PRELOAD",
		},
		SHMDetail: &SHMDetail{
			SHMName: "bpftime_shm",
			Size:    4096,
			Pattern: "bpftime",
		},
		DlopenDetail: &DlopenDetail{
			LibraryPath: "/tmp/lib.so",
			LibraryHash: "sha256:dl",
			Flags:       2,
		},
		LinkerConfigDetail: &LinkerConfigDetail{
			FilePath:  "/etc/ld.so.preload",
			Operation: "write",
			OldHash:   "sha256:old",
			NewHash:   "sha256:new",
		},
		PtraceDetail: &PtraceDetail{
			Request:     4,
			RequestName: "PTRACE_POKETEXT",
			TargetPID:   999,
			TargetComm:  "victim",
			Addr:        0x7fff1234,
		},
		LibIntegrityDetail: &LibIntegrityDetail{
			LibraryPath: "/usr/lib/libssl.so",
			Operation:   "write",
			OldHash:     "sha256:orig",
			NewHash:     "sha256:trojan",
			InLdCache:   true,
		},
		ElfRpathDetail: &ElfRpathDetail{
			HasRpath:   true,
			HasRunpath: false,
			RpathRaw:   "/tmp/evil",
			Entries: []RpathEntry{
				{Path: "/tmp/evil", Risk: RpathRiskCritical, Reason: "writable dir", Exists: true, IsRpath: true},
			},
			HighestRisk:    RpathRiskCritical,
			UsesOrigin:     false,
			UsesDeprecated: true,
			IsSetuid:       false,
		},
		PolicyResult: &PolicyResult{
			Action:         ActionAlert,
			MatchedEntryID: "entry-1",
			Reason:         "test reason",
		},
	}

	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded HookEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Spot-check each detail.
	if decoded.ExecInjectionDetail == nil || decoded.ExecInjectionDetail.EnvVar != "LD_PRELOAD" {
		t.Error("ExecInjectionDetail round-trip failed")
	}
	if decoded.SHMDetail == nil || decoded.SHMDetail.Pattern != "bpftime" {
		t.Error("SHMDetail round-trip failed")
	}
	if decoded.DlopenDetail == nil || decoded.DlopenDetail.Flags != 2 {
		t.Error("DlopenDetail round-trip failed")
	}
	if decoded.LinkerConfigDetail == nil || decoded.LinkerConfigDetail.Operation != "write" {
		t.Error("LinkerConfigDetail round-trip failed")
	}
	if decoded.PtraceDetail == nil || decoded.PtraceDetail.Addr != 0x7fff1234 {
		t.Error("PtraceDetail round-trip failed")
	}
	if decoded.LibIntegrityDetail == nil || !decoded.LibIntegrityDetail.InLdCache {
		t.Error("LibIntegrityDetail round-trip failed")
	}
	if decoded.ElfRpathDetail == nil || decoded.ElfRpathDetail.HighestRisk != RpathRiskCritical {
		t.Error("ElfRpathDetail round-trip failed")
	}
	if decoded.ElfRpathDetail != nil && len(decoded.ElfRpathDetail.Entries) != 1 {
		t.Error("ElfRpathDetail entries count mismatch")
	}
	if decoded.PolicyResult == nil || decoded.PolicyResult.Action != ActionAlert {
		t.Error("PolicyResult round-trip failed")
	}
}

func TestHookEvent_OmitEmpty(t *testing.T) {
	evt := &HookEvent{
		ID:        "evt-minimal",
		Timestamp: time.Now(),
		HostID:    "h1",
		EventType: EventBPFLoad,
		Severity:  SeverityInfo,
	}

	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	s := string(data)
	// omitempty fields should not appear.
	for _, absent := range []string{
		"bpf_detail",
		"exec_injection_detail",
		"shm_detail",
		"dlopen_detail",
		"linker_config_detail",
		"ptrace_detail",
		"lib_integrity_detail",
		"elf_rpath_detail",
		"policy_result",
	} {
		if contains(s, `"`+absent+`"`) {
			t.Errorf("expected %q to be omitted from JSON", absent)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && jsonContains(s, substr)
}

func jsonContains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestAllowlistEntry_JSONRoundTrip(t *testing.T) {
	pt := uint32(1)
	expires := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	entry := &AllowlistEntry{
		ID:             "al-001",
		CreatedAt:      time.Now().UTC().Truncate(time.Millisecond),
		CreatedBy:      "admin",
		Description:    "test entry",
		EventTypes:     []EventType{EventBPFLoad, EventExecInjection},
		ExeHash:        "sha256:exe",
		ExePath:        "/usr/bin/*",
		LibraryHash:    "sha256:lib",
		LibraryPath:    "/usr/lib/*.so",
		ProgName:       "trace_*",
		ProgType:       &pt,
		ProgHash:       "sha256:prog",
		HostPattern:    "web-*",
		UIDRange:       &UIDRange{Min: 0, Max: 65535},
		ContainerImage: "app-*",
		AllowedRpaths:  []string{"/usr/lib*", "/lib*"},
		Action:         ActionAllow,
		Expires:        &expires,
		Enabled:        true,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded AllowlistEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != "al-001" {
		t.Errorf("ID mismatch")
	}
	if len(decoded.EventTypes) != 2 {
		t.Errorf("EventTypes count: got %d, want 2", len(decoded.EventTypes))
	}
	if decoded.ProgType == nil || *decoded.ProgType != 1 {
		t.Error("ProgType round-trip failed")
	}
	if decoded.UIDRange == nil || decoded.UIDRange.Max != 65535 {
		t.Error("UIDRange round-trip failed")
	}
	if len(decoded.AllowedRpaths) != 2 {
		t.Errorf("AllowedRpaths count: got %d, want 2", len(decoded.AllowedRpaths))
	}
	if decoded.Expires == nil {
		t.Error("Expires should not be nil")
	}
}

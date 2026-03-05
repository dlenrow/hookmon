package ingestion

import (
	"testing"
	"time"

	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	"github.com/dlenrow/hookmon/pkg/event"
)

func TestProtoToEvent_CoreFields(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	pe := &hookmonv1.HookEvent{
		ID:          "evt-proto-001",
		Timestamp:   ts,
		HostID:      "host-1",
		Hostname:    "web-01",
		EventType:   hookmonv1.EventType_EVENT_TYPE_BPF_LOAD,
		Severity:    hookmonv1.Severity_SEVERITY_WARN,
		PID:         1234,
		PPID:        1,
		UID:         0,
		GID:         0,
		Comm:        "cilium",
		Cmdline:     "/usr/bin/cilium",
		ExePath:     "/usr/bin/cilium",
		ExeHash:     "sha256:abc",
		CgroupPath:  "/sys/fs/cgroup/system.slice",
		ContainerID: "ctr-123",
		Namespace:   "default",
	}

	evt := protoToEvent(pe)

	if evt.ID != "evt-proto-001" {
		t.Errorf("ID: got %q", evt.ID)
	}
	if evt.EventType != event.EventBPFLoad {
		t.Errorf("EventType: got %q, want BPF_LOAD", evt.EventType)
	}
	if evt.Severity != event.SeverityWarn {
		t.Errorf("Severity: got %q, want WARN", evt.Severity)
	}
	if evt.PID != 1234 {
		t.Errorf("PID: got %d", evt.PID)
	}
	if evt.ExeHash != "sha256:abc" {
		t.Errorf("ExeHash: got %q", evt.ExeHash)
	}
	if evt.ContainerID != "ctr-123" {
		t.Errorf("ContainerID: got %q", evt.ContainerID)
	}
}

func TestProtoToEvent_Nil(t *testing.T) {
	if evt := protoToEvent(nil); evt != nil {
		t.Error("nil proto should produce nil event")
	}
}

func TestProtoToEvent_AllEventTypes(t *testing.T) {
	for protoType, expectedType := range protoEventTypeToEventType {
		pe := &hookmonv1.HookEvent{EventType: protoType}
		evt := protoToEvent(pe)
		if evt.EventType != expectedType {
			t.Errorf("proto %v: got %q, want %q", protoType, evt.EventType, expectedType)
		}
	}
}

func TestProtoToEvent_AllSeverities(t *testing.T) {
	tests := []struct {
		proto    hookmonv1.Severity
		expected event.Severity
	}{
		{hookmonv1.Severity_SEVERITY_INFO, event.SeverityInfo},
		{hookmonv1.Severity_SEVERITY_WARN, event.SeverityWarn},
		{hookmonv1.Severity_SEVERITY_ALERT, event.SeverityAlert},
		{hookmonv1.Severity_SEVERITY_CRITICAL, event.SeverityCritical},
		{hookmonv1.Severity_SEVERITY_UNSPECIFIED, event.SeverityInfo}, // default
	}
	for _, tt := range tests {
		pe := &hookmonv1.HookEvent{Severity: tt.proto}
		evt := protoToEvent(pe)
		if evt.Severity != tt.expected {
			t.Errorf("proto sev %v: got %q, want %q", tt.proto, evt.Severity, tt.expected)
		}
	}
}

func TestProtoToEvent_BPFDetail(t *testing.T) {
	pe := &hookmonv1.HookEvent{
		EventType: hookmonv1.EventType_EVENT_TYPE_BPF_LOAD,
		BPFDetail: &hookmonv1.BPFDetail{
			BPFCommand: 5,
			ProgType:   1,
			ProgName:   "trace_tcp",
			AttachType: 3,
			TargetFD:   7,
			InsnCount:  142,
			ProgHash:   "sha256:prog",
		},
	}
	evt := protoToEvent(pe)
	if evt.BPFDetail == nil {
		t.Fatal("BPFDetail nil")
	}
	if evt.BPFDetail.ProgName != "trace_tcp" {
		t.Errorf("ProgName: got %q", evt.BPFDetail.ProgName)
	}
	if evt.BPFDetail.InsnCount != 142 {
		t.Errorf("InsnCount: got %d", evt.BPFDetail.InsnCount)
	}
}

func TestProtoToEvent_ExecInjectionDetail(t *testing.T) {
	pe := &hookmonv1.HookEvent{
		EventType: hookmonv1.EventType_EVENT_TYPE_EXEC_INJECTION,
		ExecInjectionDetail: &hookmonv1.ExecInjectionDetail{
			LibraryPath:  "/usr/lib/evil.so",
			LibraryHash:  "sha256:lib",
			TargetBinary: "/usr/bin/target",
			SetBy:        "env",
			EnvVar:       "LD_PRELOAD",
		},
	}
	evt := protoToEvent(pe)
	if evt.ExecInjectionDetail == nil {
		t.Fatal("ExecInjectionDetail nil")
	}
	if evt.ExecInjectionDetail.EnvVar != "LD_PRELOAD" {
		t.Errorf("EnvVar: got %q", evt.ExecInjectionDetail.EnvVar)
	}
}

func TestProtoToEvent_ElfRpathDetail(t *testing.T) {
	pe := &hookmonv1.HookEvent{
		EventType: hookmonv1.EventType_EVENT_TYPE_ELF_RPATH,
		ElfRpathDetail: &hookmonv1.ElfRpathDetail{
			HasRpath:   true,
			HasRunpath: false,
			RpathRaw:   "/tmp/evil",
			RunpathRaw: "",
			Entries: []*hookmonv1.RpathEntry{
				{Path: "/tmp/evil", Risk: "CRITICAL", Reason: "writable", Exists: true, IsRpath: true},
			},
			HighestRisk:    "CRITICAL",
			UsesOrigin:     false,
			UsesDeprecated: true,
			IsSetuid:       false,
		},
	}
	evt := protoToEvent(pe)
	if evt.ElfRpathDetail == nil {
		t.Fatal("ElfRpathDetail nil")
	}
	if !evt.ElfRpathDetail.HasRpath {
		t.Error("HasRpath should be true")
	}
	if evt.ElfRpathDetail.HighestRisk != event.RpathRiskCritical {
		t.Errorf("HighestRisk: got %q", evt.ElfRpathDetail.HighestRisk)
	}
	if len(evt.ElfRpathDetail.Entries) != 1 {
		t.Fatalf("Entries count: got %d", len(evt.ElfRpathDetail.Entries))
	}
	if evt.ElfRpathDetail.Entries[0].Risk != event.RpathRiskCritical {
		t.Errorf("entry risk: got %q", evt.ElfRpathDetail.Entries[0].Risk)
	}
	if !evt.ElfRpathDetail.UsesDeprecated {
		t.Error("UsesDeprecated should be true")
	}
}

func TestProtoToEvent_NilDetails(t *testing.T) {
	pe := &hookmonv1.HookEvent{EventType: hookmonv1.EventType_EVENT_TYPE_BPF_LOAD}
	evt := protoToEvent(pe)

	if evt.BPFDetail != nil {
		t.Error("BPFDetail should be nil")
	}
	if evt.ExecInjectionDetail != nil {
		t.Error("ExecInjectionDetail should be nil")
	}
	if evt.SHMDetail != nil {
		t.Error("SHMDetail should be nil")
	}
	if evt.ElfRpathDetail != nil {
		t.Error("ElfRpathDetail should be nil")
	}
}

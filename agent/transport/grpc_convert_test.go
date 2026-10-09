package transport

import (
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

func sampleBPFEvent() *event.HookEvent {
	return &event.HookEvent{
		ID:          "evt-bpf",
		Timestamp:   time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
		HostID:      "host-1",
		Hostname:    "web-01",
		EventType:   event.EventBPFLoad,
		Severity:    event.SeverityWarn,
		PID:         1234,
		PPID:        1,
		UID:         0,
		GID:         0,
		Comm:        "cilium-agent",
		Cmdline:     "/usr/bin/cilium-agent",
		ExePath:     "/usr/bin/cilium-agent",
		ExeHash:     "sha256:abc",
		CgroupPath:  "/sys/fs/cgroup/system.slice",
		ContainerID: "abc123",
		Namespace:   "default",
		BPFDetail: &event.BPFDetail{
			BPFCommand: 5,
			ProgType:   1,
			ProgName:   "trace_tcp",
			AttachType: 3,
			TargetFD:   7,
			InsnCount:  142,
			ProgHash:   "sha256:prog",
		},
	}
}

func TestEventToProto_CoreFields(t *testing.T) {
	evt := sampleBPFEvent()
	pe := eventToProto(evt)

	if pe.Id != evt.ID {
		t.Errorf("ID: got %q, want %q", pe.Id, evt.ID)
	}
	if pe.HostId != evt.HostID {
		t.Errorf("HostID: got %q, want %q", pe.HostId, evt.HostID)
	}
	if pe.Hostname != evt.Hostname {
		t.Errorf("Hostname: got %q", pe.Hostname)
	}
	if pe.Pid != evt.PID {
		t.Errorf("PID: got %d", pe.Pid)
	}
	if pe.Ppid != evt.PPID {
		t.Errorf("PPID: got %d", pe.Ppid)
	}
	if pe.Uid != evt.UID {
		t.Errorf("UID: got %d", pe.Uid)
	}
	if pe.Comm != evt.Comm {
		t.Errorf("Comm: got %q", pe.Comm)
	}
	if pe.ExePath != evt.ExePath {
		t.Errorf("ExePath: got %q", pe.ExePath)
	}
	if pe.ExeHash != evt.ExeHash {
		t.Errorf("ExeHash: got %q", pe.ExeHash)
	}
	if pe.ContainerId != evt.ContainerID {
		t.Errorf("ContainerID: got %q", pe.ContainerId)
	}
}

func TestEventToProto_BPFDetail(t *testing.T) {
	evt := sampleBPFEvent()
	pe := eventToProto(evt)

	if pe.BpfDetail == nil {
		t.Fatal("BPFDetail should not be nil")
	}
	if pe.BpfDetail.BpfCmd != 5 {
		t.Errorf("BPFCommand: got %d", pe.BpfDetail.BpfCmd)
	}
	if pe.BpfDetail.ProgName != "trace_tcp" {
		t.Errorf("ProgName: got %q", pe.BpfDetail.ProgName)
	}
	if pe.BpfDetail.InsnCount != 142 {
		t.Errorf("InsnCount: got %d", pe.BpfDetail.InsnCount)
	}
	if pe.BpfDetail.ProgHash != "sha256:prog" {
		t.Errorf("ProgHash: got %q", pe.BpfDetail.ProgHash)
	}
}

func TestEventToProto_ExecInjectionDetail(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventExecInjection,
		ExecInjectionDetail: &event.ExecInjectionDetail{
			LibraryPath:  "/usr/lib/evil.so",
			LibraryHash:  "sha256:lib",
			TargetBinary: "/usr/bin/target",
			SetBy:        "env",
			EnvVar:       "LD_PRELOAD",
		},
	}
	pe := eventToProto(evt)
	if pe.ExecInjectionDetail == nil {
		t.Fatal("ExecInjectionDetail nil")
	}
	if pe.ExecInjectionDetail.LibraryPath != "/usr/lib/evil.so" {
		t.Errorf("LibraryPath: got %q", pe.ExecInjectionDetail.LibraryPath)
	}
	if pe.ExecInjectionDetail.EnvVar != "LD_PRELOAD" {
		t.Errorf("EnvVar: got %q", pe.ExecInjectionDetail.EnvVar)
	}
}

func TestEventToProto_SHMDetail(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventSHMCreate,
		SHMDetail: &event.SHMDetail{SHMName: "bpftime_shm", Size: 4096, Pattern: "bpftime"},
	}
	pe := eventToProto(evt)
	if pe.ShmDetail == nil {
		t.Fatal("SHMDetail nil")
	}
	if pe.ShmDetail.ShmName != "bpftime_shm" {
		t.Errorf("SHMName: got %q", pe.ShmDetail.ShmName)
	}
}

func TestEventToProto_DlopenDetail(t *testing.T) {
	evt := &event.HookEvent{
		EventType:    event.EventDlopen,
		DlopenDetail: &event.DlopenDetail{LibraryPath: "/tmp/lib.so", LibraryHash: "sha256:dl", Flags: 2},
	}
	pe := eventToProto(evt)
	if pe.DlopenDetail == nil {
		t.Fatal("DlopenDetail nil")
	}
	if pe.DlopenDetail.Flags != 2 {
		t.Errorf("Flags: got %d", pe.DlopenDetail.Flags)
	}
}

func TestEventToProto_LinkerConfigDetail(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventLinkerConfig,
		LinkerConfigDetail: &event.LinkerConfigDetail{
			FilePath: "/etc/ld.so.preload", Operation: "write",
			OldHash: "sha256:old", NewHash: "sha256:new",
		},
	}
	pe := eventToProto(evt)
	if pe.LinkerConfigDetail == nil {
		t.Fatal("LinkerConfigDetail nil")
	}
	if pe.LinkerConfigDetail.FilePath != "/etc/ld.so.preload" {
		t.Errorf("FilePath: got %q", pe.LinkerConfigDetail.FilePath)
	}
}

func TestEventToProto_PtraceDetail(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventPtraceInject,
		PtraceDetail: &event.PtraceDetail{
			Request: 4, RequestName: "PTRACE_POKETEXT",
			TargetPID: 999, TargetComm: "victim", Addr: 0x1234,
		},
	}
	pe := eventToProto(evt)
	if pe.PtraceDetail == nil {
		t.Fatal("PtraceDetail nil")
	}
	if pe.PtraceDetail.TargetPid != 999 {
		t.Errorf("TargetPID: got %d", pe.PtraceDetail.TargetPid)
	}
	if pe.PtraceDetail.Addr != 0x1234 {
		t.Errorf("Addr: got %x", pe.PtraceDetail.Addr)
	}
}

func TestEventToProto_LibIntegrityDetail(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventLibIntegrity,
		LibIntegrityDetail: &event.LibIntegrityDetail{
			LibraryPath: "/usr/lib/libssl.so", Operation: "write",
			OldHash: "sha256:orig", NewHash: "sha256:trojan", InLdCache: true,
		},
	}
	pe := eventToProto(evt)
	if pe.LibIntegrityDetail == nil {
		t.Fatal("LibIntegrityDetail nil")
	}
	if !pe.LibIntegrityDetail.InLdCache {
		t.Error("InLdCache should be true")
	}
}

func TestEventToProto_ElfRpathDetail(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventElfRpath,
		ElfRpathDetail: &event.ElfRpathDetail{
			HasRpath:   true,
			HasRunpath: false,
			RpathRaw:   "/tmp/evil",
			RunpathRaw: "",
			Entries: []event.RpathEntry{
				{Path: "/tmp/evil", Risk: event.RpathRiskCritical, Reason: "writable", Exists: true, IsRpath: true},
				{Path: "/usr/lib", Risk: event.RpathRiskNone, Reason: "standard", Exists: true, IsRpath: true},
			},
			HighestRisk:    event.RpathRiskCritical,
			UsesOrigin:     false,
			UsesDeprecated: true,
			IsSetuid:       false,
		},
	}
	pe := eventToProto(evt)
	if pe.ElfRpathDetail == nil {
		t.Fatal("ElfRpathDetail nil")
	}
	if !pe.ElfRpathDetail.HasRpath {
		t.Error("HasRpath should be true")
	}
	if len(pe.ElfRpathDetail.Entries) != 2 {
		t.Fatalf("Entries count: got %d, want 2", len(pe.ElfRpathDetail.Entries))
	}
	if pe.ElfRpathDetail.Entries[0].Risk != "CRITICAL" {
		t.Errorf("first entry risk: got %q", pe.ElfRpathDetail.Entries[0].Risk)
	}
	if pe.ElfRpathDetail.HighestRisk != "CRITICAL" {
		t.Errorf("HighestRisk: got %q", pe.ElfRpathDetail.HighestRisk)
	}
	if !pe.ElfRpathDetail.UsesDeprecated {
		t.Error("UsesDeprecated should be true")
	}
}

func TestEventToProto_NilDetails(t *testing.T) {
	evt := &event.HookEvent{EventType: event.EventBPFLoad}
	pe := eventToProto(evt)

	if pe.BpfDetail != nil {
		t.Error("BPFDetail should be nil")
	}
	if pe.ExecInjectionDetail != nil {
		t.Error("ExecInjectionDetail should be nil")
	}
	if pe.ElfRpathDetail != nil {
		t.Error("ElfRpathDetail should be nil")
	}
}

// --- eventTypeToProto ---

func TestEventTypeToProto_AllTypes(t *testing.T) {
	types := []event.EventType{
		event.EventBPFLoad,
		event.EventBPFAttach,
		event.EventExecInjection,
		event.EventSHMCreate,
		event.EventDlopen,
		event.EventLinkerConfig,
		event.EventPtraceInject,
		event.EventLibIntegrity,
		event.EventAgentOffline,
		event.EventAgentRecovered,
		event.EventElfRpath,
		event.EventBPFInventory,
	}
	for _, et := range types {
		proto := eventTypeToProto(et)
		if proto == 0 { // UNSPECIFIED
			t.Errorf("eventTypeToProto(%q) returned UNSPECIFIED", et)
		}
	}
}

func TestEventTypeToProto_Unknown(t *testing.T) {
	proto := eventTypeToProto(event.EventType("NONEXISTENT"))
	if proto != 0 {
		t.Errorf("unknown type should return UNSPECIFIED, got %d", proto)
	}
}

// --- severityToProto ---

func TestSeverityToProto_AllLevels(t *testing.T) {
	levels := []event.Severity{
		event.SeverityInfo,
		event.SeverityWarn,
		event.SeverityAlert,
		event.SeverityCritical,
	}
	for _, s := range levels {
		proto := severityToProto(s)
		if proto == 0 { // UNSPECIFIED
			t.Errorf("severityToProto(%q) returned UNSPECIFIED", s)
		}
	}
}

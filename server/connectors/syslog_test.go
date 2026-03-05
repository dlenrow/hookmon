package connectors

import (
	"strings"
	"testing"

	"github.com/dlenrow/hookmon/pkg/event"
)

// --- CEF escaping ---

func TestCefEscape(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"hello", "hello"},
		{`back\slash`, `back\\slash`},
		{"pipe|char", `pipe\|char`},
		{"eq=sign", `eq\=sign`},
		{"new\nline", `new\nline`},
		{"cr\rreturn", `cr\rreturn`},
		{`all\|=` + "\n\r", `all\\\|\=\n\r`},
	}
	for _, tt := range tests {
		got := cefEscape(tt.input)
		if got != tt.expected {
			t.Errorf("cefEscape(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// --- Severity mapping ---

func TestSeverityToNum(t *testing.T) {
	tests := []struct {
		sev      event.Severity
		expected int
	}{
		{event.SeverityInfo, 1},
		{event.SeverityWarn, 4},
		{event.SeverityAlert, 7},
		{event.SeverityCritical, 10},
		{event.Severity("UNKNOWN"), 0},
	}
	for _, tt := range tests {
		got := severityToNum(tt.sev)
		if got != tt.expected {
			t.Errorf("severityToNum(%q) = %d, want %d", tt.sev, got, tt.expected)
		}
	}
}

// --- Event descriptions ---

func TestEventDescription_AllTypes(t *testing.T) {
	types := []struct {
		et   event.EventType
		want string
	}{
		{event.EventBPFLoad, "BPF Program Loaded"},
		{event.EventBPFAttach, "BPF Program Attached"},
		{event.EventExecInjection, "Exec Injection Detected"},
		{event.EventSHMCreate, "Suspicious Shared Memory Created"},
		{event.EventDlopen, "Dynamic Library Loaded via dlopen"},
		{event.EventLinkerConfig, "Linker Configuration Modified"},
		{event.EventPtraceInject, "Ptrace Code Injection Detected"},
		{event.EventLibIntegrity, "Shared Library Modified on Disk"},
		{event.EventElfRpath, "Suspicious ELF RPATH/RUNPATH Detected"},
	}
	for _, tt := range types {
		got := eventDescription(tt.et)
		if got != tt.want {
			t.Errorf("eventDescription(%q) = %q, want %q", tt.et, got, tt.want)
		}
	}
}

func TestEventDescription_Unknown(t *testing.T) {
	got := eventDescription(event.EventType("INVENTED"))
	if got != "Unknown Hook Event" {
		t.Errorf("unknown type: got %q, want %q", got, "Unknown Hook Event")
	}
}

// --- CEF formatting ---

func TestFormatCEF_Header(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventBPFLoad,
		Severity:  event.SeverityAlert,
		Hostname:  "web-01",
		UID:       0,
		ExePath:   "/usr/bin/test",
	}
	cef := formatCEF(evt)

	// Check header prefix.
	if !strings.HasPrefix(cef, "CEF:0|HookMon|HookMon|1.0|BPF_LOAD|BPF Program Loaded|7|") {
		t.Errorf("CEF header mismatch: %s", cef)
	}
}

func TestFormatCEF_BPFExtensions(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventBPFLoad,
		Severity:  event.SeverityWarn,
		BPFDetail: &event.BPFDetail{
			ProgType:  1,
			ProgName:  "trace_tcp",
			InsnCount: 142,
		},
	}
	cef := formatCEF(evt)

	if !strings.Contains(cef, "cs1Label=ProgType") {
		t.Error("missing cs1Label=ProgType")
	}
	if !strings.Contains(cef, "cs1=1") {
		t.Error("missing cs1=1")
	}
	if !strings.Contains(cef, "cs2Label=ProgName") {
		t.Error("missing cs2Label=ProgName")
	}
	if !strings.Contains(cef, "cs2=trace_tcp") {
		t.Error("missing cs2=trace_tcp")
	}
	if !strings.Contains(cef, "cn1Label=InsnCount") {
		t.Error("missing cn1Label=InsnCount")
	}
	if !strings.Contains(cef, "cn1=142") {
		t.Error("missing cn1=142")
	}
}

func TestFormatCEF_ExecInjectionExtensions(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventExecInjection,
		Severity:  event.SeverityAlert,
		ExecInjectionDetail: &event.ExecInjectionDetail{
			LibraryPath: "/usr/lib/evil.so",
			SetBy:       "env",
		},
	}
	cef := formatCEF(evt)
	if !strings.Contains(cef, "cs1=/usr/lib/evil.so") {
		t.Error("missing library path in CEF")
	}
	if !strings.Contains(cef, "cs2=env") {
		t.Error("missing SetBy in CEF")
	}
}

func TestFormatCEF_ExeHash(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventBPFLoad,
		Severity:  event.SeverityInfo,
		ExeHash:   "sha256:abc123",
	}
	cef := formatCEF(evt)
	if !strings.Contains(cef, "cs3Label=ExeHash") {
		t.Error("missing cs3Label=ExeHash")
	}
	if !strings.Contains(cef, "cs3=sha256:abc123") {
		t.Error("missing exe hash value")
	}
}

func TestFormatCEF_PolicyResult(t *testing.T) {
	evt := &event.HookEvent{
		EventType:    event.EventBPFLoad,
		Severity:     event.SeverityInfo,
		PolicyResult: &event.PolicyResult{Action: event.ActionAllow},
	}
	cef := formatCEF(evt)
	if !strings.Contains(cef, "cs4Label=PolicyResult") {
		t.Error("missing cs4Label=PolicyResult")
	}
	if !strings.Contains(cef, "cs4=ALLOW") {
		t.Error("missing cs4=ALLOW")
	}
}

func TestFormatCEF_ElfRpathExtensions(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventElfRpath,
		Severity:  event.SeverityCritical,
		ElfRpathDetail: &event.ElfRpathDetail{
			HighestRisk: event.RpathRiskCritical,
			RpathRaw:    "/tmp/evil",
			RunpathRaw:  "$ORIGIN/../lib",
		},
	}
	cef := formatCEF(evt)
	if !strings.Contains(cef, "cs5Label=HighestRisk") {
		t.Error("missing cs5Label=HighestRisk")
	}
	if !strings.Contains(cef, "cs5=CRITICAL") {
		t.Error("missing cs5=CRITICAL")
	}
	if !strings.Contains(cef, "cs6Label=RpathRaw") {
		t.Error("missing cs6Label=RpathRaw")
	}
	if !strings.Contains(cef, "cs7Label=RunpathRaw") {
		t.Error("missing cs7Label=RunpathRaw")
	}
}

func TestFormatCEF_EscapingInValues(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventBPFLoad,
		Severity:  event.SeverityInfo,
		Hostname:  "host|with|pipes",
		ExePath:   "/path=with=equals",
	}
	cef := formatCEF(evt)
	if !strings.Contains(cef, `shost=host\|with\|pipes`) {
		t.Errorf("pipes should be escaped in hostname: %s", cef)
	}
	if !strings.Contains(cef, `sproc=/path\=with\=equals`) {
		t.Errorf("equals should be escaped in exe path: %s", cef)
	}
}

func TestFormatCEF_MinimalEvent(t *testing.T) {
	// Event with no optional fields — should not panic.
	evt := &event.HookEvent{
		EventType: event.EventBPFLoad,
		Severity:  event.SeverityInfo,
	}
	cef := formatCEF(evt)
	if !strings.HasPrefix(cef, "CEF:0|") {
		t.Errorf("minimal event should still produce valid CEF: %s", cef)
	}
}

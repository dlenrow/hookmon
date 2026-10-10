package connectors

import (
	"strings"
	"testing"

	"github.com/dlenrow/hookmon/pkg/event"
)

// --- CEF escaping ---
//
// CEF escapes differently in the header and in extensions. The header
// escapes backslash and pipe; extensions escape backslash and equals sign,
// and a pipe in an extension value is written as is. (This test used to
// expect one escaper for both, escaping pipes and equals signs everywhere,
// which put "\|" into extension values where a CEF parser reads it
// literally.)

func TestCefExtEscape(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"hello", "hello"},
		{`back\slash`, `back\\slash`},
		{"pipe|char", "pipe|char"},
		{"eq=sign", `eq\=sign`},
		{"new\nline", `new\nline`},
		{"cr\rreturn", `cr\rreturn`},
		{`all\|=` + "\n\r", `all\\|\=\n\r`},
	}
	for _, tt := range tests {
		got := cefExtEscape(tt.input)
		if got != tt.expected {
			t.Errorf("cefExtEscape(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestCefHeaderEscape(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"hello", "hello"},
		{`back\slash`, `back\\slash`},
		{"pipe|char", `pipe\|char`},
		{"eq=sign", "eq=sign"},
		{"new\nline", `new\nline`},
	}
	for _, tt := range tests {
		got := cefHeaderEscape(tt.input)
		if got != tt.expected {
			t.Errorf("cefHeaderEscape(%q) = %q, want %q", tt.input, got, tt.expected)
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
		{event.EventBPFInventory, "BPF Program Inventory"},
		{event.EventAgentOffline, "Sensor Bus Offline"},
		{event.EventAgentRecovered, "Sensor Bus Recovered"},
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

func TestFormatCEF_BPFInventory(t *testing.T) {
	prog := formatCEF(&event.HookEvent{
		EventType:          event.EventBPFInventory,
		Severity:           event.SeverityInfo,
		BPFDetail:          &event.BPFDetail{ProgType: 5, ProgName: "hello_count", ProgHash: "a04f5eef06a7f555", ProgID: 42},
		BPFInventoryDetail: &event.BPFInventoryDetail{ScanID: "scan-1"},
	})
	if !strings.HasPrefix(prog, "CEF:0|HookMon|HookMon|1.0|BPF_INVENTORY|BPF Program Inventory|1|") {
		t.Errorf("CEF header mismatch: %s", prog)
	}
	for _, want := range []string{"cs5Label=ProgTag", "cs5=a04f5eef06a7f555", "cn2Label=ProgID", "cn2=42", "cs6Label=ScanID", "cs6=scan-1"} {
		if !strings.Contains(prog, want) {
			t.Errorf("program event missing %q: %s", want, prog)
		}
	}
	if strings.Contains(prog, "cn3Label") {
		t.Errorf("program event carries the summary count: %s", prog)
	}

	sum := formatCEF(&event.HookEvent{
		EventType:          event.EventBPFInventory,
		Severity:           event.SeverityInfo,
		BPFInventoryDetail: &event.BPFInventoryDetail{ScanID: "scan-1", Summary: true, ProgCount: 3},
	})
	for _, want := range []string{"cs6=scan-1", "cn3Label=ProgCount", "cn3=3"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary missing %q: %s", want, sum)
		}
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

// TestFormatCEF_ElfRpathExtensions: the risk and both raw paths. This test
// used to expect RunpathRaw in cs7, which is not a CEF key (custom strings
// are cs1 to cs6), so a CEF parser dropped it. The raw paths are now in
// cs1 and cs2, which ELF_RPATH events do not otherwise use.
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
	for _, want := range []string{
		"cs5Label=HighestRisk", "cs5=CRITICAL",
		"cs1Label=RpathRaw", "cs1=/tmp/evil",
		"cs2Label=RunpathRaw", "cs2=$ORIGIN/../lib",
	} {
		if !strings.Contains(cef, want) {
			t.Errorf("missing %q: %s", want, cef)
		}
	}
	if strings.Contains(cef, "cs7") {
		t.Errorf("cs7 is not a CEF key: %s", cef)
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
	// Pipes are not escaped in extension values (see TestCefExtEscape).
	if !strings.Contains(cef, `shost=host|with|pipes`) {
		t.Errorf("pipes should be written as is in an extension value: %s", cef)
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

package connectors

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// siemCEFKeys are the CEF extension keys formatCEF may emit, from the CEF
// key dictionary. Custom strings are cs1-cs6 and custom numbers cn1-cn3;
// anything else (cs7, say) is not a CEF key and parsers drop it.
var siemCEFKeys = map[string]bool{
	"rt": true, "externalId": true, "deviceExternalId": true, "shost": true,
	"suid": true, "spid": true, "sproc": true, "dpid": true, "dproc": true,
	"reason": true, "fileHash": true, "oldFileHash": true, "fsize": true,
	"flexString1": true, "flexString1Label": true, "flexString2": true, "flexString2Label": true,
	"cs1": true, "cs2": true, "cs3": true, "cs4": true, "cs5": true, "cs6": true,
	"cs1Label": true, "cs2Label": true, "cs3Label": true, "cs4Label": true, "cs5Label": true, "cs6Label": true,
	"cn1": true, "cn2": true, "cn3": true, "cn1Label": true, "cn2Label": true, "cn3Label": true,
}

// siemExtKey finds the keys of a CEF extension: a word followed by an
// unescaped '='.
var siemExtKey = regexp.MustCompile(`(?:^| )([A-Za-z0-9]+)=`)

// siemParseCEF splits a CEF message into its seven header fields and its
// extension as key/value pairs, honouring the escapes.
func siemParseCEF(t *testing.T, msg string) ([]string, map[string]string) {
	t.Helper()
	var hdr []string
	var cur strings.Builder
	i := 0
	for ; i < len(msg) && len(hdr) < 7; i++ {
		c := msg[i]
		switch {
		case c == '\\' && i+1 < len(msg):
			i++
			cur.WriteByte(msg[i])
		case c == '|':
			hdr = append(hdr, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if len(hdr) != 7 {
		t.Fatalf("CEF header has %d fields: %s", len(hdr), msg)
	}
	ext := map[string]string{}
	rest := msg[i:]
	locs := siemExtKey.FindAllStringSubmatchIndex(rest, -1)
	for n, loc := range locs {
		// An escaped '=' ("\=") never matches: the key must end right
		// before the '='.
		key := rest[loc[2]:loc[3]]
		end := len(rest)
		if n+1 < len(locs) {
			end = locs[n+1][0]
		}
		val := rest[loc[1]:end]
		val = strings.NewReplacer(`\\`, `\`, `\=`, `=`, `\n`, "\n", `\r`, "\r").Replace(val)
		if _, dup := ext[key]; dup {
			t.Errorf("key %s appears twice: %s", key, msg)
		}
		ext[key] = val
	}
	for k := range ext {
		if !siemCEFKeys[k] {
			t.Errorf("%q is not a CEF extension key: %s", k, msg)
		}
	}
	for k := range ext {
		if strings.HasSuffix(k, "Label") {
			if _, ok := ext[strings.TrimSuffix(k, "Label")]; !ok {
				t.Errorf("label %s without its value: %s", k, msg)
			}
		}
	}
	return hdr, ext
}

// siemLabeled returns the value of the custom field labelled label.
func siemLabeled(ext map[string]string, label string) (string, bool) {
	for k, v := range ext {
		if strings.HasSuffix(k, "Label") && v == label {
			val, ok := ext[strings.TrimSuffix(k, "Label")]
			return val, ok
		}
	}
	return "", false
}

func siemProcEvent(et event.EventType) *event.HookEvent {
	return &event.HookEvent{
		ID:           "evt-1",
		Timestamp:    time.Date(2026, 10, 10, 12, 0, 0, 123456789, time.UTC),
		HostID:       "host-a",
		Hostname:     "web-01",
		EventType:    et,
		Severity:     event.SeverityAlert,
		PID:          4242,
		UID:          1000,
		ExePath:      "/usr/bin/loader",
		ExeHash:      "sha256:" + strings.Repeat("ab", 32),
		Cmdline:      "loader --flag=1",
		ContainerID:  "c0ffee",
		PolicyResult: &event.PolicyResult{Action: event.ActionAlert, Reason: "no allowlist match"},
	}
}

// TestFormatCEF_FieldsPerEventType checks the CEF fields of every event
// type, the common fields, and that every key is a real CEF key.
func TestFormatCEF_FieldsPerEventType(t *testing.T) {
	bpf := siemProcEvent(event.EventBPFLoad)
	bpf.BPFDetail = &event.BPFDetail{BPFCommand: 5, ProgType: 2, ProgName: "hello_count", InsnCount: 12, ProgHash: "a04f5eef06a7f555", ProgID: 77}

	attach := siemProcEvent(event.EventBPFAttach)
	attach.BPFDetail = &event.BPFDetail{BPFCommand: 17, ProgType: 17, ProgName: "rawtp", ProgID: 78, AttachTarget: "sys_enter"}

	inv := &event.HookEvent{ID: "inv", HostID: "host-a", Hostname: "web-01", EventType: event.EventBPFInventory, Severity: event.SeverityInfo,
		BPFDetail:          &event.BPFDetail{ProgType: 5, ProgName: "cilium", ProgHash: "00112233aabbccdd", ProgID: 9},
		BPFInventoryDetail: &event.BPFInventoryDetail{ScanID: "scan-9"}}

	exec := siemProcEvent(event.EventExecInjection)
	exec.ExecInjectionDetail = &event.ExecInjectionDetail{LibraryPath: "/tmp/evil.so", LibraryHash: "sha256:" + strings.Repeat("cd", 32),
		TargetBinary: "/usr/bin/ssh", SetBy: "env", EnvVar: "LD_PRELOAD", ValueTruncated: true}

	shm := siemProcEvent(event.EventSHMCreate)
	shm.SHMDetail = &event.SHMDetail{SHMName: "bpftime_maps", Size: 4096, Pattern: "bpftime"}

	dl := siemProcEvent(event.EventDlopen)
	dl.DlopenDetail = &event.DlopenDetail{LibraryPath: "/opt/x/libx.so", LibraryHash: "sha256:" + strings.Repeat("ef", 32), Flags: 2}

	lc := siemProcEvent(event.EventLinkerConfig)
	lc.LinkerConfigDetail = &event.LinkerConfigDetail{FilePath: "/etc/ld.so.preload", Operation: "write", OldHash: "sha256:old", NewHash: "sha256:new"}

	li := siemProcEvent(event.EventLibIntegrity)
	li.LibIntegrityDetail = &event.LibIntegrityDetail{LibraryPath: "/usr/lib/libz.so.1", Operation: "rename", OldHash: "sha256:o", NewHash: "sha256:n", InLdCache: true}

	pt := siemProcEvent(event.EventPtraceInject)
	pt.PtraceDetail = &event.PtraceDetail{Request: 4, RequestName: "PTRACE_POKETEXT", TargetPID: 99, TargetComm: "sshd", Addr: 0xffffffffff600000}

	rp := siemProcEvent(event.EventElfRpath)
	rp.ElfRpathDetail = &event.ElfRpathDetail{RpathRaw: "/tmp/lib", RunpathRaw: "$ORIGIN", HighestRisk: event.RpathRiskCritical, IsSetuid: true}

	off := &event.HookEvent{ID: "off-1", Timestamp: time.Now(), HostID: "host-a", Hostname: "web-01",
		EventType: event.EventAgentOffline, Severity: event.SeverityCritical,
		PolicyResult: &event.PolicyResult{Action: event.ActionAlert, Reason: "Agent heartbeat timeout"}}

	cases := []struct {
		name string
		evt  *event.HookEvent
		std  map[string]string // standard keys
		cust map[string]string // label -> value
	}{
		{"BPF_LOAD", bpf, nil, map[string]string{"ProgType": "2", "ProgName": "hello_count", "ProgTag": "a04f5eef06a7f555", "InsnCount": "12", "ProgID": "77", "BPFCommand": "5"}},
		{"BPF_ATTACH", attach, nil, map[string]string{"ProgName": "rawtp", "AttachTarget": "sys_enter", "ProgID": "78", "BPFCommand": "17"}},
		{"BPF_INVENTORY", inv, nil, map[string]string{"ProgType": "5", "ProgName": "cilium", "ProgTag": "00112233aabbccdd", "ProgID": "9", "ScanID": "scan-9"}},
		{"EXEC_INJECTION", exec, map[string]string{"fileHash": "sha256:" + strings.Repeat("cd", 32)},
			map[string]string{"LibraryPath": "/tmp/evil.so", "SetBy": "env", "EnvVar": "LD_PRELOAD", "TargetBinary": "/usr/bin/ssh", "ValueTruncated": "1"}},
		{"SHM_CREATE", shm, map[string]string{"fsize": "4096"}, map[string]string{"SHMName": "bpftime_maps", "Pattern": "bpftime"}},
		{"DLOPEN", dl, map[string]string{"fileHash": "sha256:" + strings.Repeat("ef", 32)}, map[string]string{"LibraryPath": "/opt/x/libx.so", "Flags": "2"}},
		{"LINKER_CONFIG", lc, map[string]string{"oldFileHash": "sha256:old", "fileHash": "sha256:new"}, map[string]string{"FilePath": "/etc/ld.so.preload", "Operation": "write"}},
		{"LIB_INTEGRITY", li, map[string]string{"oldFileHash": "sha256:o", "fileHash": "sha256:n"}, map[string]string{"LibraryPath": "/usr/lib/libz.so.1", "Operation": "rename", "InLdCache": "1"}},
		{"PTRACE_INJECT", pt, map[string]string{"dpid": "99", "dproc": "sshd"}, map[string]string{"Request": "PTRACE_POKETEXT", "TargetComm": "sshd", "Addr": "0xffffffffff600000", "RequestNum": "4"}},
		{"ELF_RPATH", rp, nil, map[string]string{"RpathRaw": "/tmp/lib", "RunpathRaw": "$ORIGIN", "HighestRisk": "CRITICAL", "Setuid": "1"}},
		{"AGENT_OFFLINE", off, map[string]string{"reason": "Agent heartbeat timeout"}, map[string]string{"PolicyResult": "ALERT"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := formatCEF(tc.evt)
			if strings.ContainsAny(msg, "\r\n") {
				t.Fatalf("message is not one line: %q", msg)
			}
			hdr, ext := siemParseCEF(t, msg)
			if hdr[0] != "CEF:0" || hdr[1] != "HookMon" || hdr[2] != "HookMon" || hdr[4] != tc.name {
				t.Errorf("header %q", hdr)
			}
			if hdr[5] == "Unknown Hook Event" {
				t.Errorf("no CEF name for %s", tc.name)
			}
			for k, want := range map[string]string{"externalId": tc.evt.ID, "deviceExternalId": "host-a", "shost": "web-01"} {
				if ext[k] != want {
					t.Errorf("%s = %q, want %q", k, ext[k], want)
				}
			}
			for k, want := range tc.std {
				if ext[k] != want {
					t.Errorf("%s = %q, want %q", k, ext[k], want)
				}
			}
			for label, want := range tc.cust {
				if got, ok := siemLabeled(ext, label); !ok || got != want {
					t.Errorf("custom %s = %q (present %v), want %q", label, got, ok, want)
				}
			}
			if tc.evt.PID != 0 {
				if ext["suid"] != "1000" || ext["spid"] != "4242" || ext["sproc"] != "/usr/bin/loader" {
					t.Errorf("process fields: suid=%q spid=%q sproc=%q", ext["suid"], ext["spid"], ext["sproc"])
				}
				if v, _ := siemLabeled(ext, "ExeHash"); v != tc.evt.ExeHash {
					t.Errorf("ExeHash = %q", v)
				}
				if v, _ := siemLabeled(ext, "Cmdline"); v != "loader --flag=1" {
					t.Errorf("Cmdline = %q", v)
				}
				if ext["rt"] != "1791633600123" { // 2026-10-10T12:00:00.123Z
					t.Errorf("rt = %q", ext["rt"])
				}
			}
		})
	}
}

// TestFormatCEF_NoProcessNoUID: events with no process (AGENT_OFFLINE,
// BPF_INVENTORY) carry no suid. The old formatter wrote suid=0 on every
// event, which reads as root.
func TestFormatCEF_NoProcessNoUID(t *testing.T) {
	for _, evt := range []*event.HookEvent{
		{EventType: event.EventAgentOffline, Severity: event.SeverityCritical, Hostname: "h"},
		{EventType: event.EventBPFInventory, Severity: event.SeverityInfo, BPFInventoryDetail: &event.BPFInventoryDetail{ScanID: "s", Summary: true, ProgCount: 3}},
	} {
		_, ext := siemParseCEF(t, formatCEF(evt))
		for _, k := range []string{"suid", "spid", "sproc"} {
			if _, ok := ext[k]; ok {
				t.Errorf("%s event carries %s", evt.EventType, k)
			}
		}
	}
}

// TestFormatCEF_HostileValues: separators and newlines inside values stay
// inside their field.
func TestFormatCEF_HostileValues(t *testing.T) {
	evt := siemProcEvent(event.EventDlopen)
	evt.Cmdline = "sh -c 'x=1 cs1=forged\nCEF:0|evil'"
	evt.DlopenDetail = &event.DlopenDetail{LibraryPath: `/tmp/a b=c\d|e.so`}
	msg := formatCEF(evt)
	if strings.ContainsAny(msg, "\r\n") {
		t.Fatalf("not one line: %q", msg)
	}
	_, ext := siemParseCEF(t, msg)
	if v, _ := siemLabeled(ext, "LibraryPath"); v != `/tmp/a b=c\d|e.so` {
		t.Errorf("LibraryPath = %q", v)
	}
	if v, _ := siemLabeled(ext, "Cmdline"); v != evt.Cmdline {
		t.Errorf("Cmdline = %q", v)
	}
}

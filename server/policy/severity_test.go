package policy

import (
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// TestSeverityTable checks one case for each row of the severity table in
// CLAUDE.md ("Severity Classification"), through Engine.Evaluate, with the
// severity the bus would have set on the event. Rows are in table order.
// Row 1, AGENT_OFFLINE from the watchdog (CRITICAL), does not go through
// the policy engine; TestWatchdog_OfflineOnce in server/ checks it.
func TestSeverityTable(t *testing.T) {
	root, user := uint32(0), uint32(1000)
	allowAll := &event.AllowlistEntry{
		ID: "allow-dlopen", EventTypes: []event.EventType{event.EventDlopen},
		Action: event.ActionAllow, Enabled: true,
	}
	ev := func(et event.EventType, uid uint32, busSev event.Severity, mod func(*event.HookEvent)) *event.HookEvent {
		e := &event.HookEvent{
			ID: "sev", Timestamp: time.Now(), HostID: "host-1", Hostname: "web-01",
			EventType: et, Severity: busSev, PID: 42, UID: uid,
			ExePath: "/usr/bin/x", ExeHash: "sha256:" + hex64("a"),
		}
		if mod != nil {
			mod(e)
		}
		return e
	}

	rows := []struct {
		row     string
		entries []*event.AllowlistEntry
		evt     *event.HookEvent
		want    event.Severity
	}{
		{"2 AGENT_OFFLINE arriving on an event stream",
			nil, ev(event.EventAgentOffline, root, "", nil), event.SeverityAlert},
		{"3 BPF_INVENTORY, program not on the allowlist (a new hook)",
			nil, ev(event.EventBPFInventory, root, event.SeverityInfo, func(e *event.HookEvent) {
				e.ExeHash = ""
				e.BPFDetail = &event.BPFDetail{ProgID: 7, ProgHash: "0123456789abcdef"}
				e.BPFInventoryDetail = &event.BPFInventoryDetail{ScanID: "s"}
			}), event.SeverityAlert},
		{"3 BPF_INVENTORY, program on the allowlist",
			[]*event.AllowlistEntry{{ID: "allow-prog", EventTypes: []event.EventType{event.EventBPFInventory},
				ProgHash: "0123456789abcdef", Action: event.ActionAllow, Enabled: true}},
			ev(event.EventBPFInventory, root, event.SeverityInfo, func(e *event.HookEvent) {
				e.ExeHash = ""
				e.BPFDetail = &event.BPFDetail{ProgID: 7, ProgHash: "0123456789abcdef"}
				e.BPFInventoryDetail = &event.BPFInventoryDetail{ScanID: "s"}
			}), event.SeverityInfo},
		{"4 matches an ALLOW entry (root, so it would be CRITICAL otherwise)",
			[]*event.AllowlistEntry{allowAll}, ev(event.EventDlopen, root, event.SeverityWarn, func(e *event.HookEvent) {
				e.DlopenDetail = &event.DlopenDetail{LibraryPath: "/usr/lib/libx.so"}
			}), event.SeverityInfo},
		{"5 bus rated it INFO: package-manager library write by root",
			nil, ev(event.EventLibIntegrity, root, event.SeverityInfo, func(e *event.HookEvent) {
				e.LibIntegrityDetail = &event.LibIntegrityDetail{LibraryPath: "/usr/lib/libmnl.so.0", Operation: "write"}
			}), event.SeverityInfo},
		{"5 bus rated it INFO: package-manager linker cache write by root",
			nil, ev(event.EventLinkerConfig, root, event.SeverityInfo, func(e *event.HookEvent) {
				e.LinkerConfigDetail = &event.LinkerConfigDetail{FilePath: "/etc/ld.so.cache", Operation: "write"}
			}), event.SeverityInfo},
		{"5 bus rated it INFO: ordinary /dev/shm segment from root",
			nil, ev(event.EventSHMCreate, root, event.SeverityInfo, func(e *event.HookEvent) {
				e.SHMDetail = &event.SHMDetail{SHMName: "/dev/shm/PostgreSQL.1", Pattern: "unknown"}
			}), event.SeverityInfo},
		{"6 bpftime-pattern shared memory (non-root)",
			nil, ev(event.EventSHMCreate, user, event.SeverityCritical, func(e *event.HookEvent) {
				e.SHMDetail = &event.SHMDetail{SHMName: "/dev/shm/bpftime_maps_shm", Pattern: "bpftime"}
			}), event.SeverityCritical},
		{"7 linker configuration modified (non-root)",
			nil, ev(event.EventLinkerConfig, user, event.SeverityCritical, func(e *event.HookEvent) {
				e.LinkerConfigDetail = &event.LinkerConfigDetail{FilePath: "/etc/ld.so.preload", Operation: "write"}
			}), event.SeverityCritical},
		{"8 ELF RPATH CRITICAL risk",
			nil, ev(event.EventElfRpath, user, event.SeverityCritical, func(e *event.HookEvent) {
				e.ElfRpathDetail = &event.ElfRpathDetail{HighestRisk: event.RpathRiskCritical}
			}), event.SeverityCritical},
		{"8 ELF RPATH HIGH risk, from root",
			nil, ev(event.EventElfRpath, root, event.SeverityAlert, func(e *event.HookEvent) {
				e.ElfRpathDetail = &event.ElfRpathDetail{HighestRisk: event.RpathRiskHigh}
			}), event.SeverityAlert},
		{"8 ELF RPATH MEDIUM risk, from root (was CRITICAL before step 7c)",
			nil, ev(event.EventElfRpath, root, event.SeverityWarn, func(e *event.HookEvent) {
				e.ElfRpathDetail = &event.ElfRpathDetail{HighestRisk: event.RpathRiskMedium}
			}), event.SeverityWarn},
		{"9 any other event from root: BPF load",
			nil, ev(event.EventBPFLoad, root, event.SeverityWarn, func(e *event.HookEvent) {
				e.BPFDetail = &event.BPFDetail{ProgHash: "0123456789abcdef"}
			}), event.SeverityCritical},
		{"10 exec injection (non-root)",
			nil, ev(event.EventExecInjection, user, event.SeverityAlert, func(e *event.HookEvent) {
				e.ExecInjectionDetail = &event.ExecInjectionDetail{EnvVar: "LD_PRELOAD", LibraryPath: "/tmp/x.so", SetBy: "env"}
			}), event.SeverityAlert},
		{"11 ptrace injection (non-root)",
			nil, ev(event.EventPtraceInject, user, event.SeverityAlert, func(e *event.HookEvent) {
				e.PtraceDetail = &event.PtraceDetail{Request: 16, RequestName: "PTRACE_ATTACH", TargetPID: 1}
			}), event.SeverityAlert},
		{"12 shared library modified on disk, not by a package manager (non-root)",
			nil, ev(event.EventLibIntegrity, user, event.SeverityAlert, func(e *event.HookEvent) {
				e.LibIntegrityDetail = &event.LibIntegrityDetail{LibraryPath: "/usr/lib/libx.so", Operation: "write"}
			}), event.SeverityAlert},
		{"13 shared memory with a BPF-related name (non-root)",
			nil, ev(event.EventSHMCreate, user, event.SeverityAlert, func(e *event.HookEvent) {
				e.SHMDetail = &event.SHMDetail{SHMName: "/dev/shm/my_bpf_maps", Pattern: "bpf_related"}
			}), event.SeverityAlert},
		{"14 the bus could not hash the binary (dlopen, non-root)",
			nil, ev(event.EventDlopen, user, event.SeverityWarn, func(e *event.HookEvent) {
				e.ExeHash = ""
				e.DlopenDetail = &event.DlopenDetail{LibraryPath: "/opt/x/libx.so"}
			}), event.SeverityAlert},
		{"15 BPF load not on the allowlist (non-root, hashed binary)",
			nil, ev(event.EventBPFLoad, user, event.SeverityWarn, func(e *event.HookEvent) {
				e.BPFDetail = &event.BPFDetail{ProgType: 8, ProgHash: "0123456789abcdef"}
			}), event.SeverityWarn},
	}
	for _, r := range rows {
		t.Run(r.row, func(t *testing.T) {
			newTestEngine(r.entries...).Evaluate(r.evt)
			if r.evt.Severity != r.want {
				t.Errorf("severity %s, want %s", r.evt.Severity, r.want)
			}
		})
	}
}

// TestSeverity_DenyAndRejectedClassifyAsUnmatched: an event matched by an
// ALERT or DENY entry (a rejected candidate, or one written by hand) gets
// the severity an unmatched event would, including the bus's INFO.
func TestSeverity_DenyAndRejectedClassifyAsUnmatched(t *testing.T) {
	for _, action := range []event.PolicyAction{event.ActionAlert, event.ActionDeny} {
		entry := &event.AllowlistEntry{ID: "e", Action: action, Enabled: true, Status: event.StatusRejected}
		evt := baseEvent(event.EventDlopen)
		evt.Severity = event.SeverityWarn
		newTestEngine(entry).Evaluate(evt)
		if evt.Severity != event.SeverityWarn || evt.PolicyResult.MatchedEntryID != "e" {
			t.Errorf("%s: severity %s entry %q, want WARN by e", action, evt.Severity, evt.PolicyResult.MatchedEntryID)
		}
		pkg := baseEvent(event.EventLibIntegrity)
		pkg.UID, pkg.Severity = 0, event.SeverityInfo
		newTestEngine(entry).Evaluate(pkg)
		if pkg.Severity != event.SeverityInfo {
			t.Errorf("%s: package-manager write got %s, want INFO", action, pkg.Severity)
		}
	}
}

// TestSeverity_EventWithoutBusSeverity: an event that arrives with no
// severity is rated as the bus would have rated it, then classified.
func TestSeverity_EventWithoutBusSeverity(t *testing.T) {
	cases := []struct {
		et   event.EventType
		mod  func(*event.HookEvent)
		want event.Severity
	}{
		{event.EventBPFLoad, nil, event.SeverityWarn},
		{event.EventDlopen, nil, event.SeverityWarn},
		{event.EventExecInjection, nil, event.SeverityAlert},
		{event.EventPtraceInject, nil, event.SeverityAlert},
		{event.EventLibIntegrity, nil, event.SeverityAlert},
		{event.EventLinkerConfig, nil, event.SeverityCritical},
		{event.EventSHMCreate, func(e *event.HookEvent) { e.SHMDetail = &event.SHMDetail{SHMName: "x", Pattern: "unknown"} }, event.SeverityInfo},
		{event.EventSHMCreate, func(e *event.HookEvent) { e.SHMDetail = &event.SHMDetail{SHMName: "bpf_x", Pattern: "bpf_related"} }, event.SeverityAlert},
		{event.EventElfRpath, func(e *event.HookEvent) {
			e.ElfRpathDetail = &event.ElfRpathDetail{HighestRisk: event.RpathRiskMedium}
		}, event.SeverityWarn},
	}
	for _, c := range cases {
		evt := baseEvent(c.et)
		if c.mod != nil {
			c.mod(evt)
		}
		newTestEngine().Evaluate(evt)
		if evt.Severity != c.want {
			t.Errorf("%s with no bus severity: got %s, want %s", c.et, evt.Severity, c.want)
		}
	}
}

func hex64(c string) string {
	s := ""
	for len(s) < 64 {
		s += c
	}
	return s[:64]
}

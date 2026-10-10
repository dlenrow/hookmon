package policy

import (
	"strings"

	"github.com/dlenrow/hookmon/pkg/event"
)

// classifySeverity is the server's severity for an event that is not a bus
// lifecycle event or a BPF_INVENTORY event (Evaluate handles those). It
// follows the table in CLAUDE.md ("Severity Classification"); the first
// row that applies wins.
//
// The bus rates every event when it sees it, with context the server does
// not have: whether a package manager wrote the file, what the /dev/shm
// segment is called and by whom, and who can write an RPATH directory. The
// server keeps that rating and adds what it knows: the allowlist, and two
// escalations (root, and a binary the bus could not hash). Neither
// escalation touches an event the bus rated INFO, or an ELF_RPATH event,
// whose severity is the RPATH risk of the binary.
//
// An event that matched an ALERT or DENY entry (written by hand, or a
// rejected candidate) is classified like an unmatched one.
func classifySeverity(result *event.PolicyResult, evt *event.HookEvent) event.Severity {
	// Matches an allowlist entry with ALLOW.
	if result.Action == event.ActionAllow {
		return event.SeverityInfo
	}

	sev := reportedSeverity(evt)
	switch {
	// The bus rated it INFO on purpose: a package manager wrote the library
	// or linker file, or a /dev/shm segment has no BPF pattern.
	case sev == event.SeverityInfo:
		return event.SeverityInfo

	// bpftime-pattern shared memory.
	case evt.EventType == event.EventSHMCreate && evt.SHMDetail != nil && evt.SHMDetail.Pattern == "bpftime":
		return event.SeverityCritical

	// Linker configuration changed (not by a package manager), or an
	// injection attributed to /etc/ld.so.preload.
	case evt.EventType == event.EventLinkerConfig,
		evt.EventType == event.EventExecInjection && evt.ExecInjectionDetail != nil &&
			evt.ExecInjectionDetail.SetBy == "/etc/ld.so.preload":
		return event.SeverityCritical

	// ELF RPATH: the risk of the binary's library search path, as the bus
	// ranked it by who can write each directory. The UID of the process
	// that ran it does not change it.
	case evt.EventType == event.EventElfRpath:
		return sev

	// Any other event from root.
	case evt.UID == 0:
		return event.SeverityCritical

	// The bus could not hash the binary: raise WARN (BPF load or attach,
	// dlopen) to ALERT.
	case evt.ExeHash == "" && sev == event.SeverityWarn:
		return event.SeverityAlert
	}

	// Otherwise the bus's rating: ALERT for exec injection, ptrace, a library
	// changed on disk and BPF-named shared memory; WARN for a BPF load or
	// attach and a dlopen.
	return sev
}

// reportedSeverity is the severity the bus set, or, for an event that came
// without one, what the bus would have set (defaultSeverity).
func reportedSeverity(evt *event.HookEvent) event.Severity {
	switch evt.Severity {
	case event.SeverityInfo, event.SeverityWarn, event.SeverityAlert, event.SeverityCritical:
		return evt.Severity
	}
	return defaultSeverity(evt)
}

// defaultSeverity is the bus's per-sensor rating, for events that arrive
// without one. It cannot know about package managers, so it never gives
// the INFO the bus gives their writes.
func defaultSeverity(evt *event.HookEvent) event.Severity {
	switch evt.EventType {
	case event.EventBPFInventory:
		return event.SeverityInfo
	case event.EventExecInjection, event.EventPtraceInject, event.EventLibIntegrity:
		return event.SeverityAlert
	case event.EventLinkerConfig:
		return event.SeverityCritical
	case event.EventSHMCreate:
		if d := evt.SHMDetail; d != nil {
			switch {
			case d.Pattern == "bpftime":
				return event.SeverityCritical
			case d.Pattern == "bpf_related" || strings.Contains(strings.ToLower(d.SHMName), "bpf"):
				return event.SeverityAlert
			}
		}
		return event.SeverityInfo
	case event.EventElfRpath:
		if d := evt.ElfRpathDetail; d != nil {
			switch d.HighestRisk {
			case event.RpathRiskCritical:
				return event.SeverityCritical
			case event.RpathRiskHigh:
				return event.SeverityAlert
			case event.RpathRiskMedium:
				return event.SeverityWarn
			}
			return event.SeverityInfo
		}
	}
	return event.SeverityWarn
}

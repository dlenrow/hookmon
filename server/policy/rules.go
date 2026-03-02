package policy

import (
	"fmt"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Rule is a built-in policy rule that is always evaluated, independent of the
// user-managed allowlist. Rules detect high-confidence threat patterns.
type Rule struct {
	// Name is a short human-readable identifier for the rule.
	Name string

	// Description explains what the rule detects.
	Description string

	// Evaluate checks the event and returns a PolicyResult if the rule fires,
	// or nil if the rule does not apply.
	Evaluate func(evt *event.HookEvent) *event.PolicyResult
}

// DefaultRules returns the set of built-in rules that are always evaluated.
func DefaultRules() []Rule {
	return []Rule{
		ruleLDPreloadFromRoot(),
		ruleLDSoPreloadModified(),
		ruleBPFtimeSHM(),
		ruleUnknownBinaryRoot(),
	}
}

// ruleLDPreloadFromRoot fires when an LD_PRELOAD event originates from UID 0.
// Root-initiated preload injection is suspicious because legitimate tools
// rarely need it and an attacker with root can persist a backdoor this way.
func ruleLDPreloadFromRoot() Rule {
	return Rule{
		Name:        "ld_preload_from_root",
		Description: "LD_PRELOAD set by root user (UID 0)",
		Evaluate: func(evt *event.HookEvent) *event.PolicyResult {
			if evt.EventType != event.EventLDPreload {
				return nil
			}
			if evt.UID != 0 {
				return nil
			}
			return &event.PolicyResult{
				Action: event.ActionAlert,
				Reason: fmt.Sprintf("rule:ld_preload_from_root — LD_PRELOAD from UID 0 on %s (exe=%s)",
					evt.Hostname, evt.ExePath),
			}
		},
	}
}

// ruleLDSoPreloadModified fires when LD_PRELOAD was set via /etc/ld.so.preload.
// Modification of this file is a high-confidence indicator of compromise because
// it affects every dynamically-linked process on the host.
func ruleLDSoPreloadModified() Rule {
	return Rule{
		Name:        "ld_so_preload_modified",
		Description: "/etc/ld.so.preload modification detected",
		Evaluate: func(evt *event.HookEvent) *event.PolicyResult {
			if evt.EventType != event.EventLDPreload {
				return nil
			}
			if evt.PreloadDetail == nil {
				return nil
			}
			if evt.PreloadDetail.SetBy != "/etc/ld.so.preload" {
				return nil
			}
			return &event.PolicyResult{
				Action: event.ActionAlert,
				Reason: fmt.Sprintf("rule:ld_so_preload_modified — /etc/ld.so.preload changed on %s (library=%s)",
					evt.Hostname, evt.PreloadDetail.LibraryPath),
			}
		},
	}
}

// ruleBPFtimeSHM fires when shared memory creation matches the bpftime pattern.
// This is the primary detection signal for userspace eBPF runtimes that bypass
// the kernel bpf() syscall entirely.
func ruleBPFtimeSHM() Rule {
	return Rule{
		Name:        "bpftime_shm_pattern",
		Description: "Shared memory segment matching bpftime userspace eBPF pattern",
		Evaluate: func(evt *event.HookEvent) *event.PolicyResult {
			if evt.EventType != event.EventSHMCreate {
				return nil
			}
			if evt.SHMDetail == nil {
				return nil
			}
			if evt.SHMDetail.Pattern != "bpftime" {
				return nil
			}
			return &event.PolicyResult{
				Action: event.ActionAlert,
				Reason: fmt.Sprintf("rule:bpftime_shm_pattern — bpftime-pattern SHM on %s (name=%s, pid=%d)",
					evt.Hostname, evt.SHMDetail.SHMName, evt.PID),
			}
		},
	}
}

// ruleUnknownBinaryRoot fires when an event from root (UID 0) has no known
// binary hash, meaning the executable has never been seen or whitelisted.
// Combined with root privileges this is a high-priority investigation target.
func ruleUnknownBinaryRoot() Rule {
	return Rule{
		Name:        "unknown_binary_root",
		Description: "Unknown binary hash from root user",
		Evaluate: func(evt *event.HookEvent) *event.PolicyResult {
			if evt.UID != 0 {
				return nil
			}
			if evt.ExeHash != "" {
				return nil
			}
			return &event.PolicyResult{
				Action: event.ActionAlert,
				Reason: fmt.Sprintf("rule:unknown_binary_root — event from root with no binary hash on %s (exe=%s, type=%s)",
					evt.Hostname, evt.ExePath, evt.EventType),
			}
		},
	}
}

// evaluateRules runs all default rules against the event and returns the
// result from the first rule that fires, or nil if no rule matches.
// Rules are evaluated in priority order (most specific / most critical first).
func evaluateRules(evt *event.HookEvent) *event.PolicyResult {
	for _, rule := range DefaultRules() {
		if result := rule.Evaluate(evt); result != nil {
			return result
		}
	}
	return nil
}

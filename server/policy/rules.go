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
		ruleExecInjectionFromRoot(),
		ruleLDSoPreloadModified(),
		ruleBPFtimeSHM(),
		ruleUnknownBinaryRoot(),
		ruleLinkerConfigModified(),
		rulePtraceFromNonDebugger(),
		ruleLibraryReplacement(),
		ruleElfRpathSuspicious(),
	}
}

// ruleExecInjectionFromRoot fires when an exec injection event originates from UID 0.
// Root-initiated injection is suspicious because legitimate tools
// rarely need it and an attacker with root can persist a backdoor this way.
func ruleExecInjectionFromRoot() Rule {
	return Rule{
		Name:        "exec_injection_from_root",
		Description: "Exec injection (LD_PRELOAD/LD_AUDIT/etc.) by root user (UID 0)",
		Evaluate: func(evt *event.HookEvent) *event.PolicyResult {
			if evt.EventType != event.EventExecInjection {
				return nil
			}
			if evt.UID != 0 {
				return nil
			}
			envVar := "unknown"
			if evt.ExecInjectionDetail != nil && evt.ExecInjectionDetail.EnvVar != "" {
				envVar = evt.ExecInjectionDetail.EnvVar
			}
			return &event.PolicyResult{
				Action: event.ActionAlert,
				Reason: fmt.Sprintf("rule:exec_injection_from_root — %s from UID 0 on %s (exe=%s)",
					envVar, evt.Hostname, evt.ExePath),
			}
		},
	}
}

// ruleLDSoPreloadModified fires when injection was set via /etc/ld.so.preload.
// Modification of this file is a high-confidence indicator of compromise because
// it affects every dynamically-linked process on the host.
func ruleLDSoPreloadModified() Rule {
	return Rule{
		Name:        "ld_so_preload_modified",
		Description: "/etc/ld.so.preload modification detected",
		Evaluate: func(evt *event.HookEvent) *event.PolicyResult {
			if evt.EventType != event.EventExecInjection {
				return nil
			}
			if evt.ExecInjectionDetail == nil {
				return nil
			}
			if evt.ExecInjectionDetail.SetBy != "/etc/ld.so.preload" {
				return nil
			}
			return &event.PolicyResult{
				Action: event.ActionAlert,
				Reason: fmt.Sprintf("rule:ld_so_preload_modified — /etc/ld.so.preload changed on %s (library=%s)",
					evt.Hostname, evt.ExecInjectionDetail.LibraryPath),
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

// ruleLinkerConfigModified fires when a linker configuration file is modified.
// These files (/etc/ld.so.preload, /etc/ld.so.conf) affect every dynamically-
// linked process on the host.
func ruleLinkerConfigModified() Rule {
	return Rule{
		Name:        "linker_config_modified",
		Description: "Linker configuration file modified",
		Evaluate: func(evt *event.HookEvent) *event.PolicyResult {
			if evt.EventType != event.EventLinkerConfig {
				return nil
			}
			filePath := "unknown"
			if evt.LinkerConfigDetail != nil {
				filePath = evt.LinkerConfigDetail.FilePath
			}
			return &event.PolicyResult{
				Action: event.ActionAlert,
				Reason: fmt.Sprintf("rule:linker_config_modified — %s changed on %s",
					filePath, evt.Hostname),
			}
		},
	}
}

// rulePtraceFromNonDebugger fires when ptrace is used by a process that isn't
// a known debugger. PTRACE_POKETEXT/POKEDATA can inject arbitrary code.
func rulePtraceFromNonDebugger() Rule {
	return Rule{
		Name:        "ptrace_injection",
		Description: "Ptrace code injection detected",
		Evaluate: func(evt *event.HookEvent) *event.PolicyResult {
			if evt.EventType != event.EventPtraceInject {
				return nil
			}
			if evt.PtraceDetail == nil {
				return nil
			}
			return &event.PolicyResult{
				Action: event.ActionAlert,
				Reason: fmt.Sprintf("rule:ptrace_injection — %s on pid %d from %s (pid=%d) on %s",
					evt.PtraceDetail.RequestName, evt.PtraceDetail.TargetPID,
					evt.Comm, evt.PID, evt.Hostname),
			}
		},
	}
}

// ruleLibraryReplacement fires when a shared library is modified on disk.
// This could indicate a supply-chain attack or trojanized library.
func ruleLibraryReplacement() Rule {
	return Rule{
		Name:        "library_replacement",
		Description: "Shared library modified on disk",
		Evaluate: func(evt *event.HookEvent) *event.PolicyResult {
			if evt.EventType != event.EventLibIntegrity {
				return nil
			}
			if evt.LibIntegrityDetail == nil {
				return nil
			}
			return &event.PolicyResult{
				Action: event.ActionAlert,
				Reason: fmt.Sprintf("rule:library_replacement — %s %s on %s",
					evt.LibIntegrityDetail.Operation,
					evt.LibIntegrityDetail.LibraryPath, evt.Hostname),
			}
		},
	}
}

// ruleElfRpathSuspicious fires when an ELF binary has CRITICAL risk RPATH/RUNPATH entries.
// These entries allow attacker-controlled library search paths baked into the binary.
func ruleElfRpathSuspicious() Rule {
	return Rule{
		Name:        "elf_rpath_suspicious",
		Description: "ELF binary with suspicious RPATH/RUNPATH entries",
		Evaluate: func(evt *event.HookEvent) *event.PolicyResult {
			if evt.EventType != event.EventElfRpath {
				return nil
			}
			if evt.ElfRpathDetail == nil {
				return nil
			}
			if evt.ElfRpathDetail.HighestRisk != event.RpathRiskCritical {
				return nil
			}
			return &event.PolicyResult{
				Action: event.ActionAlert,
				Reason: fmt.Sprintf("rule:elf_rpath_suspicious — CRITICAL RPATH/RUNPATH in %s on %s",
					evt.ExePath, evt.Hostname),
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

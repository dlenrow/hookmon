package policy

import (
	"path/filepath"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Matches reports whether the given allowlist entry matches the event.
// All non-empty fields in the entry must match (AND logic).
// Disabled entries and expired entries never match.
func Matches(entry *event.AllowlistEntry, evt *event.HookEvent) bool {
	if !entry.Enabled {
		return false
	}
	if entry.Expires != nil && entry.Expires.Before(time.Now()) {
		return false
	}

	// EventTypes: if specified, the event type must appear in the list.
	if len(entry.EventTypes) > 0 {
		if !eventTypeIn(evt.EventType, entry.EventTypes) {
			return false
		}
	}

	// ExeHash: exact match on the binary hash.
	if entry.ExeHash != "" {
		if evt.ExeHash != entry.ExeHash {
			return false
		}
	}

	// ExePath: glob match on the executable path.
	if entry.ExePath != "" {
		matched, err := filepath.Match(entry.ExePath, evt.ExePath)
		if err != nil || !matched {
			return false
		}
	}

	// LibraryHash: exact match on the library hash from ExecInjectionDetail or DlopenDetail.
	if entry.LibraryHash != "" {
		if !matchLibraryHash(entry.LibraryHash, evt) {
			return false
		}
	}

	// LibraryPath: glob match on the library path from ExecInjectionDetail or DlopenDetail.
	if entry.LibraryPath != "" {
		if !matchLibraryPath(entry.LibraryPath, evt) {
			return false
		}
	}

	// ProgName: glob match on BPF program name.
	if entry.ProgName != "" {
		if evt.BPFDetail == nil {
			return false
		}
		matched, err := filepath.Match(entry.ProgName, evt.BPFDetail.ProgName)
		if err != nil || !matched {
			return false
		}
	}

	// ProgType: exact match on BPF program type.
	if entry.ProgType != nil {
		if evt.BPFDetail == nil {
			return false
		}
		if evt.BPFDetail.ProgType != *entry.ProgType {
			return false
		}
	}

	// ProgHash: exact match on BPF bytecode hash.
	if entry.ProgHash != "" {
		if evt.BPFDetail == nil {
			return false
		}
		if evt.BPFDetail.ProgHash != entry.ProgHash {
			return false
		}
	}

	// HostPattern: glob match on hostname.
	if entry.HostPattern != "" {
		matched, err := filepath.Match(entry.HostPattern, evt.Hostname)
		if err != nil || !matched {
			return false
		}
	}

	// UIDRange: UID must fall within [Min, Max].
	if entry.UIDRange != nil {
		if evt.UID < entry.UIDRange.Min || evt.UID > entry.UIDRange.Max {
			return false
		}
	}

	// ContainerImage: exact or glob match.
	if entry.ContainerImage != "" {
		if !matchContainerImage(entry.ContainerImage, evt) {
			return false
		}
	}

	// AllowedRpaths: each RPATH entry in the event must match at least one allowed glob.
	if len(entry.AllowedRpaths) > 0 {
		if !matchAllowedRpaths(entry.AllowedRpaths, evt) {
			return false
		}
	}

	return true
}

// eventTypeIn checks whether the given event type is present in the list.
func eventTypeIn(et event.EventType, types []event.EventType) bool {
	for _, t := range types {
		if t == et {
			return true
		}
	}
	return false
}

// matchLibraryHash checks the library hash against ExecInjectionDetail or DlopenDetail.
func matchLibraryHash(hash string, evt *event.HookEvent) bool {
	if evt.ExecInjectionDetail != nil && evt.ExecInjectionDetail.LibraryHash == hash {
		return true
	}
	if evt.DlopenDetail != nil && evt.DlopenDetail.LibraryHash == hash {
		return true
	}
	return false
}

// matchLibraryPath checks the library path glob against ExecInjectionDetail or DlopenDetail.
func matchLibraryPath(pattern string, evt *event.HookEvent) bool {
	if evt.ExecInjectionDetail != nil {
		matched, err := filepath.Match(pattern, evt.ExecInjectionDetail.LibraryPath)
		if err == nil && matched {
			return true
		}
	}
	if evt.DlopenDetail != nil {
		matched, err := filepath.Match(pattern, evt.DlopenDetail.LibraryPath)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// matchContainerImage checks the container image against the event's Namespace
// or ContainerID. It first tries an exact match, then falls back to a glob.
func matchContainerImage(pattern string, evt *event.HookEvent) bool {
	// ContainerID is the closest field we have. In practice the image name
	// would come from enrichment; we match against ContainerID here.
	target := evt.ContainerID
	if target == "" {
		return false
	}
	if target == pattern {
		return true
	}
	matched, err := filepath.Match(pattern, target)
	return err == nil && matched
}

// matchAllowedRpaths checks that every RPATH entry in the event's ElfRpathDetail
// matches at least one of the allowed path globs.
func matchAllowedRpaths(allowed []string, evt *event.HookEvent) bool {
	if evt.ElfRpathDetail == nil || len(evt.ElfRpathDetail.Entries) == 0 {
		return true // no entries to check
	}
	for _, entry := range evt.ElfRpathDetail.Entries {
		if !matchAnyGlob(entry.Path, allowed) {
			return false
		}
	}
	return true
}

// matchAnyGlob returns true if value matches at least one of the glob patterns.
func matchAnyGlob(value string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, value)
		if err == nil && matched {
			return true
		}
	}
	return false
}

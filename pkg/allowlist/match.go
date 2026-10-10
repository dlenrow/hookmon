// Package allowlist decides whether allowlist entries match an event, and
// computes an event's learning-mode key. The server's policy engine and the
// e2e policy tests both use it, so there is one matcher.
package allowlist

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Matches reports whether entry matches evt now. See MatchesAt.
func Matches(entry *event.AllowlistEntry, evt *event.HookEvent) bool {
	return MatchesAt(entry, evt, time.Now())
}

// MatchesAt reports whether entry matches evt at time now. An entry matches
// when it is in force (enabled, not expired, not PENDING) and every
// criterion it sets matches (AND logic); an empty criterion matches
// anything. A learned entry also requires the event's key to equal its key
// exactly, so it matches only what learning mode saw.
func MatchesAt(entry *event.AllowlistEntry, evt *event.HookEvent, now time.Time) bool {
	if !InForce(entry, now) {
		return false
	}
	if entry.Learned != nil && KeyOf(evt) != entry.Learned.Key {
		return false
	}
	return matchCriteria(entry, evt)
}

// InForce reports whether entry can match events at time now: it is
// enabled, not expired, and not a PENDING candidate.
func InForce(entry *event.AllowlistEntry, now time.Time) bool {
	if !entry.Enabled || entry.Status == event.StatusPending {
		return false
	}
	return entry.Expires == nil || entry.Expires.After(now)
}

// matchCriteria checks every field criterion except the learned key.
func matchCriteria(entry *event.AllowlistEntry, evt *event.HookEvent) bool {
	// HostID: the entry is scoped to one host.
	if entry.HostID != "" && entry.HostID != evt.HostID {
		return false
	}

	// EventTypes: if specified, the event type must appear in the list.
	if len(entry.EventTypes) > 0 && !eventTypeIn(evt.EventType, entry.EventTypes) {
		return false
	}

	// ExeHash: the binary's "sha256:<hex>".
	if entry.ExeHash != "" && !SameFileHash(entry.ExeHash, evt.ExeHash) {
		return false
	}

	// ExePath: glob match on the executable path.
	if entry.ExePath != "" && !glob(entry.ExePath, evt.ExePath) {
		return false
	}

	// LibraryHash: the "sha256:<hex>" of the library from ExecInjectionDetail or DlopenDetail.
	if entry.LibraryHash != "" && !matchLibraryHash(entry.LibraryHash, evt) {
		return false
	}

	// LibraryPath: glob match on the library path from ExecInjectionDetail or DlopenDetail.
	if entry.LibraryPath != "" && !matchLibraryPath(entry.LibraryPath, evt) {
		return false
	}

	// ProgName: glob match on BPF program name.
	if entry.ProgName != "" && (evt.BPFDetail == nil || !glob(entry.ProgName, evt.BPFDetail.ProgName)) {
		return false
	}

	// ProgType: exact match on BPF program type.
	if entry.ProgType != nil && (evt.BPFDetail == nil || evt.BPFDetail.ProgType != *entry.ProgType) {
		return false
	}

	// ProgHash: the kernel program tag.
	if entry.ProgHash != "" && (evt.BPFDetail == nil || !SameProgTag(entry.ProgHash, evt.BPFDetail.ProgHash)) {
		return false
	}

	// HostPattern: glob match on hostname.
	if entry.HostPattern != "" && !glob(entry.HostPattern, evt.Hostname) {
		return false
	}

	// UIDRange: UID must fall within [Min, Max].
	if entry.UIDRange != nil && (evt.UID < entry.UIDRange.Min || evt.UID > entry.UIDRange.Max) {
		return false
	}

	// ContainerImage: exact or glob match.
	if entry.ContainerImage != "" && !matchContainerImage(entry.ContainerImage, evt) {
		return false
	}

	// AllowedRpaths: each RPATH entry in the event must match at least one allowed glob.
	if len(entry.AllowedRpaths) > 0 && !matchAllowedRpaths(entry.AllowedRpaths, evt) {
		return false
	}

	return true
}

// Set is a compiled allowlist: the entries in force, with learned entries
// indexed by key.
type Set struct {
	entries []*event.AllowlistEntry
	byKey   map[event.LearnedKey][]int
	plain   []int
}

// NewSet compiles entries. PENDING and disabled entries are left out, since
// they never match; expiry is checked at match time.
func NewSet(entries []*event.AllowlistEntry) *Set {
	s := &Set{byKey: make(map[event.LearnedKey][]int)}
	for _, e := range entries {
		if e == nil || !e.Enabled || e.Status == event.StatusPending {
			continue
		}
		i := len(s.entries)
		s.entries = append(s.entries, e)
		if e.Learned != nil {
			s.byKey[e.Learned.Key] = append(s.byKey[e.Learned.Key], i)
		} else {
			s.plain = append(s.plain, i)
		}
	}
	return s
}

// Len is the number of entries that can match.
func (s *Set) Len() int { return len(s.entries) }

// Match returns the entry that decides evt at time now, or nil if none
// matches. When several entries match, the most restrictive action wins
// (DENY, then ALERT, then ALLOW), so allowing something fleet-wide never
// overrides a rejection for one host. Among equal actions an entry scoped
// to the host wins over a fleet entry, then the earlier entry.
func (s *Set) Match(evt *event.HookEvent, now time.Time) *event.AllowlistEntry {
	var best *event.AllowlistEntry
	consider := func(e *event.AllowlistEntry) {
		if !InForce(e, now) || !matchCriteria(e, evt) {
			return
		}
		if best == nil || outranks(e, best) {
			best = e
		}
	}
	if len(s.byKey) > 0 {
		for _, i := range s.byKey[KeyOf(evt)] {
			consider(s.entries[i])
		}
	}
	for _, i := range s.plain {
		consider(s.entries[i])
	}
	return best
}

// Match returns the entry among entries that decides evt now, or nil.
func Match(entries []*event.AllowlistEntry, evt *event.HookEvent) *event.AllowlistEntry {
	return NewSet(entries).Match(evt, time.Now())
}

// outranks reports whether a should decide an event over b, where b came
// earlier in the list.
func outranks(a, b *event.AllowlistEntry) bool {
	if ra, rb := actionRank(a.Action), actionRank(b.Action); ra != rb {
		return ra > rb
	}
	return a.HostID != "" && b.HostID == ""
}

// actionRank orders actions by how restrictive they are. An unknown action
// ranks with ALERT.
func actionRank(a event.PolicyAction) int {
	switch a {
	case event.ActionAllow:
		return 0
	case event.ActionDeny:
		return 2
	default:
		return 1
	}
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

// glob reports whether value matches pattern (path.Match syntax: * does not
// cross a "/"). A malformed pattern matches nothing.
func glob(pattern, value string) bool {
	matched, err := filepath.Match(pattern, value)
	return err == nil && matched
}

// matchLibraryHash checks the library hash against ExecInjectionDetail or DlopenDetail.
func matchLibraryHash(hash string, evt *event.HookEvent) bool {
	if evt.ExecInjectionDetail != nil && evt.ExecInjectionDetail.LibraryHash != "" &&
		SameFileHash(hash, evt.ExecInjectionDetail.LibraryHash) {
		return true
	}
	if evt.DlopenDetail != nil && evt.DlopenDetail.LibraryHash != "" &&
		SameFileHash(hash, evt.DlopenDetail.LibraryHash) {
		return true
	}
	return false
}

// matchLibraryPath checks the library path glob against ExecInjectionDetail or DlopenDetail.
func matchLibraryPath(pattern string, evt *event.HookEvent) bool {
	if evt.ExecInjectionDetail != nil && glob(pattern, evt.ExecInjectionDetail.LibraryPath) {
		return true
	}
	if evt.DlopenDetail != nil && glob(pattern, evt.DlopenDetail.LibraryPath) {
		return true
	}
	return false
}

// matchContainerImage matches the pattern against the event's container
// ID, exactly or as a glob. The bus reports a container ID, not an image
// name. An event outside any container never matches.
func matchContainerImage(pattern string, evt *event.HookEvent) bool {
	target := evt.ContainerID
	if target == "" {
		return false
	}
	return target == pattern || glob(pattern, target)
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
		if glob(pattern, value) {
			return true
		}
	}
	return false
}

// lower returns s in lower case without allocating when it already is.
func lower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			return strings.ToLower(s)
		}
	}
	return s
}

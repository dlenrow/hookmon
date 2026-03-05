package policy

import (
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

func TestMatches_DisabledEntryNeverMatches(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: false}
	evt := &event.HookEvent{EventType: event.EventBPFLoad}
	if Matches(entry, evt) {
		t.Error("disabled entry should not match")
	}
}

func TestMatches_ExpiredEntryNeverMatches(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	entry := &event.AllowlistEntry{Enabled: true, Expires: &past}
	evt := &event.HookEvent{EventType: event.EventBPFLoad}
	if Matches(entry, evt) {
		t.Error("expired entry should not match")
	}
}

func TestMatches_FutureExpiryMatches(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	entry := &event.AllowlistEntry{Enabled: true, Expires: &future}
	evt := &event.HookEvent{EventType: event.EventBPFLoad}
	if !Matches(entry, evt) {
		t.Error("entry with future expiry should match")
	}
}

func TestMatches_EmptyEntryMatchesAll(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true}
	evt := &event.HookEvent{EventType: event.EventBPFLoad}
	if !Matches(entry, evt) {
		t.Error("empty entry (all fields zero) should match any event")
	}
}

func TestMatches_EventTypes(t *testing.T) {
	entry := &event.AllowlistEntry{
		Enabled:    true,
		EventTypes: []event.EventType{event.EventBPFLoad, event.EventBPFAttach},
	}
	if !Matches(entry, &event.HookEvent{EventType: event.EventBPFLoad}) {
		t.Error("BPF_LOAD should match")
	}
	if !Matches(entry, &event.HookEvent{EventType: event.EventBPFAttach}) {
		t.Error("BPF_ATTACH should match")
	}
	if Matches(entry, &event.HookEvent{EventType: event.EventExecInjection}) {
		t.Error("EXEC_INJECTION should not match")
	}
}

func TestMatches_ExeHash(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, ExeHash: "sha256:abc"}
	if !Matches(entry, &event.HookEvent{ExeHash: "sha256:abc"}) {
		t.Error("matching hash should match")
	}
	if Matches(entry, &event.HookEvent{ExeHash: "sha256:different"}) {
		t.Error("different hash should not match")
	}
}

func TestMatches_ExePathGlob(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, ExePath: "/usr/bin/cilium*"}
	if !Matches(entry, &event.HookEvent{ExePath: "/usr/bin/cilium-agent"}) {
		t.Error("cilium-agent should match glob")
	}
	if Matches(entry, &event.HookEvent{ExePath: "/usr/bin/falco"}) {
		t.Error("falco should not match cilium glob")
	}
}

func TestMatches_LibraryHash_ExecInjection(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, LibraryHash: "sha256:lib123"}
	evt := &event.HookEvent{
		ExecInjectionDetail: &event.ExecInjectionDetail{LibraryHash: "sha256:lib123"},
	}
	if !Matches(entry, evt) {
		t.Error("matching library hash should match")
	}
	evt.ExecInjectionDetail.LibraryHash = "sha256:other"
	if Matches(entry, evt) {
		t.Error("different library hash should not match")
	}
}

func TestMatches_LibraryHash_Dlopen(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, LibraryHash: "sha256:dl456"}
	evt := &event.HookEvent{
		DlopenDetail: &event.DlopenDetail{LibraryHash: "sha256:dl456"},
	}
	if !Matches(entry, evt) {
		t.Error("dlopen library hash should match")
	}
}

func TestMatches_LibraryHash_NoDetail(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, LibraryHash: "sha256:x"}
	evt := &event.HookEvent{} // no detail
	if Matches(entry, evt) {
		t.Error("no detail means no library hash — should not match")
	}
}

func TestMatches_LibraryPathGlob(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, LibraryPath: "/usr/lib/lib*.so"}
	evt := &event.HookEvent{
		ExecInjectionDetail: &event.ExecInjectionDetail{LibraryPath: "/usr/lib/libfoo.so"},
	}
	if !Matches(entry, evt) {
		t.Error("matching library path glob should match")
	}
	evt.ExecInjectionDetail.LibraryPath = "/tmp/evil.so"
	if Matches(entry, evt) {
		t.Error("non-matching library path should not match")
	}
}

func TestMatches_ProgName(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, ProgName: "trace_*"}
	evt := &event.HookEvent{
		BPFDetail: &event.BPFDetail{ProgName: "trace_tcp_connect"},
	}
	if !Matches(entry, evt) {
		t.Error("prog name glob should match")
	}
	evt.BPFDetail.ProgName = "other_prog"
	if Matches(entry, evt) {
		t.Error("non-matching prog name should not match")
	}
}

func TestMatches_ProgName_NoBPFDetail(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, ProgName: "trace_*"}
	evt := &event.HookEvent{} // no BPFDetail
	if Matches(entry, evt) {
		t.Error("no BPFDetail means prog name can't match")
	}
}

func TestMatches_ProgType(t *testing.T) {
	pt := uint32(1) // BPF_PROG_TYPE_KPROBE
	entry := &event.AllowlistEntry{Enabled: true, ProgType: &pt}
	evt := &event.HookEvent{
		BPFDetail: &event.BPFDetail{ProgType: 1},
	}
	if !Matches(entry, evt) {
		t.Error("matching prog type should match")
	}
	evt.BPFDetail.ProgType = 2
	if Matches(entry, evt) {
		t.Error("different prog type should not match")
	}
}

func TestMatches_ProgHash(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, ProgHash: "sha256:bpfcode"}
	evt := &event.HookEvent{
		BPFDetail: &event.BPFDetail{ProgHash: "sha256:bpfcode"},
	}
	if !Matches(entry, evt) {
		t.Error("matching prog hash should match")
	}
	evt.BPFDetail.ProgHash = "sha256:tampered"
	if Matches(entry, evt) {
		t.Error("tampered prog hash should not match")
	}
}

func TestMatches_HostPattern(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, HostPattern: "web-*"}
	if !Matches(entry, &event.HookEvent{Hostname: "web-01"}) {
		t.Error("web-01 should match web-*")
	}
	if Matches(entry, &event.HookEvent{Hostname: "db-01"}) {
		t.Error("db-01 should not match web-*")
	}
}

func TestMatches_UIDRange(t *testing.T) {
	entry := &event.AllowlistEntry{
		Enabled:  true,
		UIDRange: &event.UIDRange{Min: 1000, Max: 2000},
	}
	if !Matches(entry, &event.HookEvent{UID: 1000}) {
		t.Error("UID 1000 should be in range [1000,2000]")
	}
	if !Matches(entry, &event.HookEvent{UID: 1500}) {
		t.Error("UID 1500 should be in range")
	}
	if !Matches(entry, &event.HookEvent{UID: 2000}) {
		t.Error("UID 2000 should be in range (inclusive)")
	}
	if Matches(entry, &event.HookEvent{UID: 999}) {
		t.Error("UID 999 should be below range")
	}
	if Matches(entry, &event.HookEvent{UID: 2001}) {
		t.Error("UID 2001 should be above range")
	}
}

func TestMatches_ContainerImage(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, ContainerImage: "app-*"}
	if !Matches(entry, &event.HookEvent{ContainerID: "app-xyz"}) {
		t.Error("app-xyz should match app-*")
	}
	if Matches(entry, &event.HookEvent{ContainerID: ""}) {
		t.Error("empty container ID should not match")
	}
	if Matches(entry, &event.HookEvent{ContainerID: "other-abc"}) {
		t.Error("other-abc should not match app-*")
	}
}

func TestMatches_ContainerImage_ExactMatch(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, ContainerImage: "my-container-id"}
	if !Matches(entry, &event.HookEvent{ContainerID: "my-container-id"}) {
		t.Error("exact container ID should match")
	}
}

func TestMatches_AllowedRpaths(t *testing.T) {
	// filepath.Match `*` does not cross `/` separators, so use exact paths or simple globs.
	entry := &event.AllowlistEntry{
		Enabled:       true,
		AllowedRpaths: []string{"/usr/lib64", "/lib64"},
	}

	// Event with only allowed paths.
	evt := &event.HookEvent{
		ElfRpathDetail: &event.ElfRpathDetail{
			Entries: []event.RpathEntry{
				{Path: "/usr/lib64"},
				{Path: "/lib64"},
			},
		},
	}
	if !Matches(entry, evt) {
		t.Error("all paths match allowed globs — should match")
	}

	// Event with one disallowed path.
	evt.ElfRpathDetail.Entries = append(evt.ElfRpathDetail.Entries, event.RpathEntry{Path: "/tmp/evil"})
	if Matches(entry, evt) {
		t.Error("/tmp/evil not in allowed globs — should not match")
	}
}

func TestMatches_AllowedRpaths_NoDetail(t *testing.T) {
	entry := &event.AllowlistEntry{
		Enabled:       true,
		AllowedRpaths: []string{"/usr/lib*"},
	}
	evt := &event.HookEvent{} // no ElfRpathDetail
	if !Matches(entry, evt) {
		t.Error("no ElfRpathDetail means nothing to check — should match (vacuously true)")
	}
}

func TestMatches_ANDLogic(t *testing.T) {
	// Both ExeHash and EventTypes must match.
	entry := &event.AllowlistEntry{
		Enabled:    true,
		EventTypes: []event.EventType{event.EventBPFLoad},
		ExeHash:    "sha256:abc",
	}
	// Both match.
	if !Matches(entry, &event.HookEvent{EventType: event.EventBPFLoad, ExeHash: "sha256:abc"}) {
		t.Error("both match — should match")
	}
	// Event type matches, hash doesn't.
	if Matches(entry, &event.HookEvent{EventType: event.EventBPFLoad, ExeHash: "sha256:other"}) {
		t.Error("hash mismatch — should not match")
	}
	// Hash matches, event type doesn't.
	if Matches(entry, &event.HookEvent{EventType: event.EventExecInjection, ExeHash: "sha256:abc"}) {
		t.Error("event type mismatch — should not match")
	}
}

func TestMatchAnyGlob(t *testing.T) {
	patterns := []string{"/usr/lib*", "/opt/app/*"}
	if !matchAnyGlob("/usr/lib64", patterns) {
		t.Error("/usr/lib64 should match /usr/lib*")
	}
	if !matchAnyGlob("/opt/app/lib", patterns) {
		t.Error("/opt/app/lib should match /opt/app/*")
	}
	if matchAnyGlob("/tmp/evil", patterns) {
		t.Error("/tmp/evil should not match any pattern")
	}
	// Verify * does not cross path separator.
	if matchAnyGlob("/usr/lib/subdir/deep", patterns) {
		t.Error("/usr/lib/subdir/deep should NOT match /usr/lib* (no separator crossing)")
	}
}

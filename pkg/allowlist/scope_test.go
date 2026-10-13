package allowlist

import (
	"strings"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Fields and states added in step 7c. match_test.go covers the original
// fields.

func TestMatches_HostIDScope(t *testing.T) {
	entry := &event.AllowlistEntry{Enabled: true, HostID: "host-a"}
	if !Matches(entry, &event.HookEvent{HostID: "host-a"}) {
		t.Error("entry scoped to host-a should match host-a")
	}
	if Matches(entry, &event.HookEvent{HostID: "host-b"}) {
		t.Error("entry scoped to host-a should not match host-b")
	}
	if !Matches(&event.AllowlistEntry{Enabled: true}, &event.HookEvent{HostID: "host-b"}) {
		t.Error("fleet entry should match any host")
	}
}

func TestMatches_Status(t *testing.T) {
	evt := &event.HookEvent{EventType: event.EventBPFLoad}
	for status, want := range map[event.EntryStatus]bool{
		"":                   true,
		event.StatusApproved: true,
		event.StatusRejected: true,
		event.StatusPending:  false,
	} {
		if got := Matches(&event.AllowlistEntry{Enabled: true, Status: status}, evt); got != want {
			t.Errorf("status %q: match %v, want %v", status, got, want)
		}
	}
}

// File hashes match in the unified "sha256:<hex>" format whatever the case
// or prefix the entry was written with; anything else matches nothing.
func TestMatches_FileHashFormats(t *testing.T) {
	hex := strings.Repeat("0a", 32)
	evt := &event.HookEvent{
		ExeHash:             "sha256:" + hex,
		ExecInjectionDetail: &event.ExecInjectionDetail{LibraryHash: "sha256:" + hex},
	}
	for _, h := range []string{"sha256:" + hex, hex, strings.ToUpper(hex), "SHA256:" + strings.ToUpper(hex)} {
		if !Matches(&event.AllowlistEntry{Enabled: true, ExeHash: h}, evt) {
			t.Errorf("exe_hash %q should match the bus's sha256:<hex>", h)
		}
		if !Matches(&event.AllowlistEntry{Enabled: true, LibraryHash: h}, evt) {
			t.Errorf("library_hash %q should match the bus's sha256:<hex>", h)
		}
	}
	for _, h := range []string{"sha256:" + hex[:62], "md5:" + hex, hex + "00"} {
		if Matches(&event.AllowlistEntry{Enabled: true, ExeHash: h}, evt) {
			t.Errorf("exe_hash %q should not match", h)
		}
	}
	// An event with no library hash never matches a library_hash entry.
	if Matches(&event.AllowlistEntry{Enabled: true, LibraryHash: hex},
		&event.HookEvent{DlopenDetail: &event.DlopenDetail{LibraryPath: "/x.so"}}) {
		t.Error("library_hash matched an event without one")
	}
}

// ProgHash is the kernel program tag; case does not matter, and pinning the
// program type separates programs that share a tag.
func TestMatches_ProgTagAndType(t *testing.T) {
	pt := uint32(5)
	entry := &event.AllowlistEntry{Enabled: true, ProgHash: "A04F5EEF06A7F555", ProgType: &pt}
	if !Matches(entry, &event.HookEvent{BPFDetail: &event.BPFDetail{ProgHash: "a04f5eef06a7f555", ProgType: 5}}) {
		t.Error("same tag (other case) and type should match")
	}
	if Matches(entry, &event.HookEvent{BPFDetail: &event.BPFDetail{ProgHash: "a04f5eef06a7f555", ProgType: 1}}) {
		t.Error("same tag, other program type should not match when the type is pinned")
	}
}

// A learned entry matches exactly its key: an empty part of the key (no
// exe hash, no container) is not a wildcard.
func TestMatches_LearnedKeyIsExact(t *testing.T) {
	evt := &event.HookEvent{
		EventType: event.EventLibIntegrity, HostID: "h",
		LibIntegrityDetail: &event.LibIntegrityDetail{LibraryPath: "/usr/lib/libz.so.1"},
	}
	entry := &event.AllowlistEntry{Enabled: true, Learned: &event.Learned{Key: KeyOf(evt)}}
	if !Matches(entry, evt) {
		t.Fatal("learned entry should match the event it was learned from")
	}
	// ExeHash and container are context, not part of the key, so they
	// must NOT prevent a match.
	for name, mod := range map[string]func(*event.HookEvent){
		"a hashed writer": func(e *event.HookEvent) { e.ExeHash = "sha256:" + strings.Repeat("1", 64) },
		"in a container":  func(e *event.HookEvent) { e.ContainerID = "c" },
	} {
		other := *evt
		d := *evt.LibIntegrityDetail
		other.LibIntegrityDetail = &d
		mod(&other)
		if !Matches(entry, &other) {
			t.Errorf("learned entry should still match %s (not part of the key)", name)
		}
	}
	// What was loaded IS part of the key: different library, different
	// mechanism (event type).
	for name, mod := range map[string]func(*event.HookEvent){
		"another library":    func(e *event.HookEvent) { e.LibIntegrityDetail.LibraryPath = "/usr/lib/libc.so.6" },
		"another event type": func(e *event.HookEvent) { e.EventType = event.EventLinkerConfig },
	} {
		other := *evt
		d := *evt.LibIntegrityDetail
		other.LibIntegrityDetail = &d
		mod(&other)
		if Matches(entry, &other) {
			t.Errorf("learned entry matched %s", name)
		}
	}
	// Other criteria still apply on top of the key.
	scoped := *entry
	scoped.HostID = "other-host"
	if Matches(&scoped, evt) {
		t.Error("learned entry scoped to another host matched")
	}
}

func TestSet_MostRestrictiveWins(t *testing.T) {
	evt := &event.HookEvent{EventType: event.EventBPFLoad, HostID: "h"}
	allowFleet := &event.AllowlistEntry{ID: "allow-fleet", Enabled: true, Action: event.ActionAllow}
	allowHost := &event.AllowlistEntry{ID: "allow-host", Enabled: true, Action: event.ActionAllow, HostID: "h"}
	alertHost := &event.AllowlistEntry{ID: "alert-host", Enabled: true, Action: event.ActionAlert, HostID: "h", Status: event.StatusRejected}
	deny := &event.AllowlistEntry{ID: "deny", Enabled: true, Action: event.ActionDeny}
	now := time.Now()
	cases := []struct {
		entries []*event.AllowlistEntry
		want    string
	}{
		{[]*event.AllowlistEntry{allowFleet}, "allow-fleet"},
		{[]*event.AllowlistEntry{allowFleet, allowHost}, "allow-host"},
		{[]*event.AllowlistEntry{allowHost, allowFleet}, "allow-host"},
		{[]*event.AllowlistEntry{allowFleet, alertHost}, "alert-host"},
		{[]*event.AllowlistEntry{alertHost, allowFleet, deny}, "deny"},
		{nil, ""},
	}
	for i, c := range cases {
		got := NewSet(c.entries).Match(evt, now)
		gotID := ""
		if got != nil {
			gotID = got.ID
		}
		if gotID != c.want {
			t.Errorf("case %d: matched %q, want %q", i, gotID, c.want)
		}
	}
}

func TestSet_SkipsPendingDisabledAndExpired(t *testing.T) {
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	evt := &event.HookEvent{EventType: event.EventDlopen, DlopenDetail: &event.DlopenDetail{LibraryPath: "/x.so"}}
	key := KeyOf(evt)
	s := NewSet([]*event.AllowlistEntry{
		{ID: "pending", Enabled: true, Status: event.StatusPending, Action: event.ActionAllow, Learned: &event.Learned{Key: key}},
		{ID: "disabled", Enabled: false, Action: event.ActionAllow},
		{ID: "expires", Enabled: true, Action: event.ActionAllow, Expires: &future},
		{ID: "expired", Enabled: true, Action: event.ActionDeny, Expires: &past},
	})
	if s.Len() != 2 {
		t.Errorf("Len %d, want 2 (pending and disabled left out)", s.Len())
	}
	if got := s.Match(evt, time.Now()); got == nil || got.ID != "expires" {
		t.Errorf("matched %+v, want expires", got)
	}
	if got := s.Match(evt, future.Add(time.Second)); got != nil {
		t.Errorf("after expiry matched %+v", got)
	}
}

func TestNormalize(t *testing.T) {
	hex := strings.Repeat("Ab", 32)
	e := &event.AllowlistEntry{ExeHash: hex, LibraryHash: "SHA256:" + hex, ProgHash: "A04F5EEF06A7F555"}
	if err := Normalize(e); err != nil {
		t.Fatal(err)
	}
	want := "sha256:" + strings.ToLower(hex)
	if e.ExeHash != want || e.LibraryHash != want || e.ProgHash != "a04f5eef06a7f555" {
		t.Errorf("normalized: %q %q %q", e.ExeHash, e.LibraryHash, e.ProgHash)
	}
	for name, bad := range map[string]*event.AllowlistEntry{
		"short exe hash":           {ExeHash: "sha256:abc"},
		"non-hex library hash":     {LibraryHash: strings.Repeat("zz", 32)},
		"sha256 prog hash (pre-4)": {ProgHash: "sha256:" + strings.Repeat("ab", 32)},
		"short tag":                {ProgHash: "a04f5eef"},
	} {
		if err := Normalize(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	empty := &event.AllowlistEntry{}
	if err := Normalize(empty); err != nil || empty.ExeHash != "" || empty.LibraryHash != "" || empty.ProgHash != "" {
		t.Errorf("empty entry: %v %+v", err, empty)
	}
}

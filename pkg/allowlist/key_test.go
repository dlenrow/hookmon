package allowlist

import (
	"strings"
	"testing"

	"github.com/dlenrow/hookmon/pkg/event"
)

var (
	polExeHash = "sha256:" + strings.Repeat("ab", 32)
	polLibHash = "sha256:" + strings.Repeat("cd", 32)
)

// TestKeyOf_PerEventType: the key's subject for each event type.
func TestKeyOf_PerEventType(t *testing.T) {
	base := func(et event.EventType) *event.HookEvent {
		return &event.HookEvent{EventType: et, ExeHash: polExeHash, ExePath: "/usr/bin/x", HostID: "h", PID: 1}
	}
	cases := []struct {
		name string
		evt  *event.HookEvent
		want event.LearnedKey
	}{
		{"BPF load: tag and type", func() *event.HookEvent {
			e := base(event.EventBPFLoad)
			e.BPFDetail = &event.BPFDetail{ProgType: 5, ProgHash: "A04F5EEF06A7F555", ProgName: "hello"}
			return e
		}(), event.LearnedKey{EventType: event.EventBPFLoad, ExeHash: polExeHash, SubjectKind: SubjectBPFTag, Subject: "a04f5eef06a7f555", ProgType: 5}},
		{"BPF attach without a tag: name stands in", func() *event.HookEvent {
			e := base(event.EventBPFAttach)
			e.BPFDetail = &event.BPFDetail{ProgType: 5, ProgName: "hello"}
			return e
		}(), event.LearnedKey{EventType: event.EventBPFAttach, ExeHash: polExeHash, SubjectKind: SubjectBPFName, Subject: "hello", ProgType: 5}},
		{"BPF inventory: no process", &event.HookEvent{EventType: event.EventBPFInventory,
			BPFDetail: &event.BPFDetail{ProgType: 8, ProgHash: "0011223344556677"}},
			event.LearnedKey{EventType: event.EventBPFInventory, SubjectKind: SubjectBPFTag, Subject: "0011223344556677", ProgType: 8}},
		{"exec injection: library hash, in canonical form", func() *event.HookEvent {
			e := base(event.EventExecInjection)
			e.ExecInjectionDetail = &event.ExecInjectionDetail{LibraryPath: "/tmp/x.so", LibraryHash: strings.ToUpper(polLibHash[7:]), EnvVar: "LD_PRELOAD"}
			return e
		}(), event.LearnedKey{EventType: event.EventExecInjection, ExeHash: polExeHash, SubjectKind: SubjectLibraryHash, Subject: polLibHash}},
		{"exec injection: path when there is no hash", func() *event.HookEvent {
			e := base(event.EventExecInjection)
			e.ExecInjectionDetail = &event.ExecInjectionDetail{LibraryPath: "libx.so", EnvVar: "LD_PRELOAD"}
			return e
		}(), event.LearnedKey{EventType: event.EventExecInjection, ExeHash: polExeHash, SubjectKind: SubjectLibraryPath, Subject: "libx.so"}},
		{"exec injection: scan truncated has no subject", func() *event.HookEvent {
			e := base(event.EventExecInjection)
			e.ExecInjectionDetail = &event.ExecInjectionDetail{ScanTruncated: true}
			return e
		}(), event.LearnedKey{EventType: event.EventExecInjection, ExeHash: polExeHash}},
		{"dlopen: library hash", func() *event.HookEvent {
			e := base(event.EventDlopen)
			e.DlopenDetail = &event.DlopenDetail{LibraryPath: "/opt/p.so", LibraryHash: polLibHash}
			return e
		}(), event.LearnedKey{EventType: event.EventDlopen, ExeHash: polExeHash, SubjectKind: SubjectLibraryHash, Subject: polLibHash}},
		{"dlopen: path", func() *event.HookEvent {
			e := base(event.EventDlopen)
			e.DlopenDetail = &event.DlopenDetail{LibraryPath: "/opt/p.so"}
			return e
		}(), event.LearnedKey{EventType: event.EventDlopen, ExeHash: polExeHash, SubjectKind: SubjectLibraryPath, Subject: "/opt/p.so"}},
		{"lib integrity: library path, not its new hash", func() *event.HookEvent {
			e := base(event.EventLibIntegrity)
			e.LibIntegrityDetail = &event.LibIntegrityDetail{LibraryPath: "/usr/lib/libz.so.1", NewHash: polLibHash}
			return e
		}(), event.LearnedKey{EventType: event.EventLibIntegrity, ExeHash: polExeHash, SubjectKind: SubjectLibraryPath, Subject: "/usr/lib/libz.so.1"}},
		{"linker config: file path", func() *event.HookEvent {
			e := base(event.EventLinkerConfig)
			e.LinkerConfigDetail = &event.LinkerConfigDetail{FilePath: "/etc/ld.so.cache"}
			return e
		}(), event.LearnedKey{EventType: event.EventLinkerConfig, ExeHash: polExeHash, SubjectKind: SubjectFilePath, Subject: "/etc/ld.so.cache"}},
		{"shm: the bus's pattern, not the random name", func() *event.HookEvent {
			e := base(event.EventSHMCreate)
			e.SHMDetail = &event.SHMDetail{SHMName: ".org.chromium.Chromium.F04up4", Pattern: "unknown"}
			return e
		}(), event.LearnedKey{EventType: event.EventSHMCreate, ExeHash: polExeHash, SubjectKind: SubjectSHMPattern, Subject: "unknown"}},
		{"shm: segment name when there is no pattern", func() *event.HookEvent {
			e := base(event.EventSHMCreate)
			e.SHMDetail = &event.SHMDetail{SHMName: "/dev/shm/seg"}
			return e
		}(), event.LearnedKey{EventType: event.EventSHMCreate, ExeHash: polExeHash, SubjectKind: SubjectSHMName, Subject: "/dev/shm/seg"}},
		{"ptrace: no subject", func() *event.HookEvent {
			e := base(event.EventPtraceInject)
			e.PtraceDetail = &event.PtraceDetail{TargetPID: 99, TargetComm: "sshd"}
			return e
		}(), event.LearnedKey{EventType: event.EventPtraceInject, ExeHash: polExeHash}},
		{"ELF RPATH: no subject", func() *event.HookEvent {
			e := base(event.EventElfRpath)
			e.ElfRpathDetail = &event.ElfRpathDetail{HighestRisk: event.RpathRiskMedium}
			return e
		}(), event.LearnedKey{EventType: event.EventElfRpath, ExeHash: polExeHash}},
		{"bare-hex exe hash is canonicalized", &event.HookEvent{EventType: event.EventPtraceInject, ExeHash: strings.ToUpper(polExeHash[7:])},
			event.LearnedKey{EventType: event.EventPtraceInject, ExeHash: polExeHash}},
	}
	for _, c := range cases {
		if got := KeyOf(c.evt); got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}

// TestKeyOf_Dedupe: what makes two events the same candidate, and what
// does not.
func TestKeyOf_Dedupe(t *testing.T) {
	dl := func(mod func(*event.HookEvent)) *event.HookEvent {
		e := &event.HookEvent{
			ID: "1", HostID: "host-a", Hostname: "a", PID: 10, UID: 1000, Comm: "app",
			EventType: event.EventDlopen, ExeHash: polExeHash, ExePath: "/usr/bin/app",
			DlopenDetail: &event.DlopenDetail{LibraryPath: "/opt/p.so", LibraryHash: polLibHash},
		}
		if mod != nil {
			mod(e)
		}
		return e
	}
	same := map[string]func(*event.HookEvent){
		"other host":                  func(e *event.HookEvent) { e.HostID, e.Hostname = "host-b", "b" },
		"other PID, UID, comm":        func(e *event.HookEvent) { e.PID, e.UID, e.Comm = 11, 0, "other" },
		"other exe path, same binary": func(e *event.HookEvent) { e.ExePath = "/opt/copy/app" },
		"same library at another path (hash keyed)": func(e *event.HookEvent) {
			e.DlopenDetail.LibraryPath = "/usr/lib/p.so"
		},
		"another container of any image": func(e *event.HookEvent) { e.ContainerID = "c2" },
	}
	ref := KeyOf(dl(nil))
	inC1 := KeyOf(dl(func(e *event.HookEvent) { e.ContainerID = "c1" }))
	for name, mod := range same {
		got := KeyOf(dl(mod))
		want := ref
		if name == "another container of any image" {
			want = inC1
		}
		if got != want {
			t.Errorf("%s: key changed: %+v vs %+v", name, got, want)
		}
	}
	differ := map[string]func(*event.HookEvent){
		"event type": func(e *event.HookEvent) {
			e.EventType = event.EventExecInjection
			e.ExecInjectionDetail = &event.ExecInjectionDetail{LibraryHash: polLibHash}
		},
		"exe hash":       func(e *event.HookEvent) { e.ExeHash = "sha256:" + strings.Repeat("ef", 32) },
		"no exe hash":    func(e *event.HookEvent) { e.ExeHash = "" },
		"library hash":   func(e *event.HookEvent) { e.DlopenDetail.LibraryHash = "sha256:" + strings.Repeat("01", 32) },
		"in a container": func(e *event.HookEvent) { e.ContainerID = "c1" },
	}
	for name, mod := range differ {
		if KeyOf(dl(mod)) == ref {
			t.Errorf("%s: same key, want a different one", name)
		}
	}

	// SHM: Chromium's randomly named segments share a key; a bpftime segment
	// from the same binary does not.
	shm := func(name, pattern string) event.LearnedKey {
		return KeyOf(&event.HookEvent{EventType: event.EventSHMCreate, ExeHash: polExeHash,
			SHMDetail: &event.SHMDetail{SHMName: name, Pattern: pattern}})
	}
	if shm(".org.chromium.Chromium.F04up4", "unknown") != shm(".org.chromium.Chromium.x9Qz1a", "unknown") {
		t.Error("two generic segments from one binary have different keys")
	}
	if shm("bpftime_maps_shm", "bpftime") == shm(".org.chromium.Chromium.F04up4", "unknown") {
		t.Error("a bpftime segment shares a key with a generic one")
	}

	// BPF: the same tag with another program type is another key.
	bpf := func(pt uint32) *event.HookEvent {
		return &event.HookEvent{EventType: event.EventBPFLoad, ExeHash: polExeHash,
			BPFDetail: &event.BPFDetail{ProgType: pt, ProgHash: "a04f5eef06a7f555"}}
	}
	if KeyOf(bpf(1)) == KeyOf(bpf(5)) {
		t.Error("program type is not part of the BPF key")
	}
}

func TestKeyHash(t *testing.T) {
	k := event.LearnedKey{EventType: event.EventDlopen, ExeHash: polExeHash, SubjectKind: SubjectLibraryPath, Subject: "/opt/p.so"}
	h := KeyHash(k)
	if len(h) != 64 || !isHex(h) || h != KeyHash(k) {
		t.Fatalf("KeyHash %q: want 64 stable hex digits", h)
	}
	seen := map[string]event.LearnedKey{h: k}
	for _, other := range []event.LearnedKey{
		{EventType: event.EventDlopen, ExeHash: polExeHash, SubjectKind: SubjectLibraryPath, Subject: "/opt/p.so", InContainer: true},
		{EventType: event.EventDlopen, ExeHash: polExeHash, SubjectKind: SubjectLibraryPath, Subject: "/opt/p.so", ProgType: 1},
		{EventType: event.EventDlopen, ExeHash: polExeHash, SubjectKind: SubjectLibraryHash, Subject: "/opt/p.so"},
		// Field boundaries matter: "ab"+"c" is not "a"+"bc".
		{EventType: "ab", ExeHash: "c"},
		{EventType: "a", ExeHash: "bc"},
		// A long path still gives a 64-digit ID.
		{EventType: event.EventDlopen, Subject: strings.Repeat("/x", 4000)},
	} {
		oh := KeyHash(other)
		if prev, dup := seen[oh]; dup {
			t.Errorf("KeyHash collision: %+v and %+v", prev, other)
		}
		if len(oh) != 64 {
			t.Errorf("KeyHash length %d", len(oh))
		}
		seen[oh] = other
	}
}

func TestDescribe(t *testing.T) {
	k := event.LearnedKey{EventType: event.EventBPFLoad, ExeHash: polExeHash, SubjectKind: SubjectBPFTag, Subject: "a04f5eef06a7f555", ProgType: 5, InContainer: true}
	got := Describe(k, "/usr/bin/loader")
	want := "learned: BPF_LOAD by /usr/bin/loader in a container: BPF tag a04f5eef06a7f555, prog type 5"
	if got != want {
		t.Errorf("Describe:\n got %q\nwant %q", got, want)
	}
	got = Describe(event.LearnedKey{EventType: event.EventSHMCreate, SubjectKind: SubjectSHMName, Subject: "/dev/shm/x"}, "")
	if got != "learned: SHM_CREATE: shm name /dev/shm/x" {
		t.Errorf("Describe shm: %q", got)
	}
}

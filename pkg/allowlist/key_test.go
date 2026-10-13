package allowlist

import (
	"strings"
	"testing"

	"github.com/dlenrow/hookmon/pkg/event"
)

var (
	polExeHash = "sha256:" + strings.Repeat("ab", 32)
	polLibHash = "sha256:" + strings.Repeat("cd", 32)
	polNewHash = "sha256:" + strings.Repeat("ef", 32)
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
		}(), event.LearnedKey{SubjectKind: SubjectBPFTag, Subject: "a04f5eef06a7f555", ProgType: 5}},
		{"BPF attach shares key with load", func() *event.HookEvent {
			e := base(event.EventBPFAttach)
			e.BPFDetail = &event.BPFDetail{ProgType: 5, ProgHash: "A04F5EEF06A7F555", ProgName: "hello"}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectBPFTag, Subject: "a04f5eef06a7f555", ProgType: 5}},
		{"BPF attach without a tag: name stands in", func() *event.HookEvent {
			e := base(event.EventBPFAttach)
			e.BPFDetail = &event.BPFDetail{ProgType: 5, ProgName: "hello"}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectBPFName, Subject: "hello", ProgType: 5}},
		{"BPF inventory: no process, same key as load", &event.HookEvent{EventType: event.EventBPFInventory,
			BPFDetail: &event.BPFDetail{ProgType: 8, ProgHash: "0011223344556677"}},
			event.LearnedKey{SubjectKind: SubjectBPFTag, Subject: "0011223344556677", ProgType: 8}},
		{"LD_PRELOAD: library hash", func() *event.HookEvent {
			e := base(event.EventExecInjection)
			e.ExecInjectionDetail = &event.ExecInjectionDetail{LibraryPath: "/tmp/x.so", LibraryHash: strings.ToUpper(polLibHash[7:]), EnvVar: "LD_PRELOAD"}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectLDPreload, Subject: polLibHash}},
		{"LD_PRELOAD: path when there is no hash", func() *event.HookEvent {
			e := base(event.EventExecInjection)
			e.ExecInjectionDetail = &event.ExecInjectionDetail{LibraryPath: "libx.so", EnvVar: "LD_PRELOAD"}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectLDPreload, Subject: "libx.so"}},
		{"LD_AUDIT: library hash", func() *event.HookEvent {
			e := base(event.EventExecInjection)
			e.ExecInjectionDetail = &event.ExecInjectionDetail{LibraryPath: "/tmp/x.so", LibraryHash: polLibHash, EnvVar: "LD_AUDIT"}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectLDAudit, Subject: polLibHash}},
		{"LD_LIBRARY_PATH: directory list", func() *event.HookEvent {
			e := base(event.EventExecInjection)
			e.ExecInjectionDetail = &event.ExecInjectionDetail{LibraryPath: "/opt/lib:/usr/local/lib", EnvVar: "LD_LIBRARY_PATH"}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectLDLibraryPath, Subject: "/opt/lib:/usr/local/lib"}},
		{"LD_DEBUG: variable name only", func() *event.HookEvent {
			e := base(event.EventExecInjection)
			e.ExecInjectionDetail = &event.ExecInjectionDetail{LibraryPath: "all", EnvVar: "LD_DEBUG"}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectLDDebug}},
		{"exec injection: scan truncated", func() *event.HookEvent {
			e := base(event.EventExecInjection)
			e.ExecInjectionDetail = &event.ExecInjectionDetail{ScanTruncated: true}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectScanTruncated}},
		{"exec injection: no EnvVar defaults to LD_PRELOAD", func() *event.HookEvent {
			e := base(event.EventExecInjection)
			e.ExecInjectionDetail = &event.ExecInjectionDetail{LibraryPath: "/tmp/x.so", LibraryHash: polLibHash}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectLDPreload, Subject: polLibHash}},
		{"dlopen: library hash", func() *event.HookEvent {
			e := base(event.EventDlopen)
			e.DlopenDetail = &event.DlopenDetail{LibraryPath: "/opt/p.so", LibraryHash: polLibHash}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectDlopen, Subject: polLibHash}},
		{"dlopen: path", func() *event.HookEvent {
			e := base(event.EventDlopen)
			e.DlopenDetail = &event.DlopenDetail{LibraryPath: "/opt/p.so"}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectDlopen, Subject: "/opt/p.so"}},
		{"lib integrity: path + new hash", func() *event.HookEvent {
			e := base(event.EventLibIntegrity)
			e.LibIntegrityDetail = &event.LibIntegrityDetail{LibraryPath: "/usr/lib/libz.so.1", NewHash: polNewHash}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectLibReplace, Subject: "/usr/lib/libz.so.1", ContentHash: polNewHash}},
		{"linker config: path + new hash", func() *event.HookEvent {
			e := base(event.EventLinkerConfig)
			e.LinkerConfigDetail = &event.LinkerConfigDetail{FilePath: "/etc/ld.so.cache", NewHash: polNewHash}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectLinkerConfig, Subject: "/etc/ld.so.cache", ContentHash: polNewHash}},
		{"shm: the bus's pattern, not the random name", func() *event.HookEvent {
			e := base(event.EventSHMCreate)
			e.SHMDetail = &event.SHMDetail{SHMName: ".org.chromium.Chromium.F04up4", Pattern: "unknown"}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectSHMPattern, Subject: "unknown"}},
		{"shm: segment name when there is no pattern", func() *event.HookEvent {
			e := base(event.EventSHMCreate)
			e.SHMDetail = &event.SHMDetail{SHMName: "/dev/shm/seg"}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectSHMName, Subject: "/dev/shm/seg"}},
		{"ptrace: tracer's exe hash", func() *event.HookEvent {
			e := base(event.EventPtraceInject)
			e.PtraceDetail = &event.PtraceDetail{TargetPID: 99, TargetComm: "sshd"}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectPtrace, Subject: polExeHash}},
		{"ELF RPATH: binary's exe hash", func() *event.HookEvent {
			e := base(event.EventElfRpath)
			e.ElfRpathDetail = &event.ElfRpathDetail{HighestRisk: event.RpathRiskMedium}
			return e
		}(), event.LearnedKey{SubjectKind: SubjectRpath, Subject: polExeHash}},
	}
	for _, c := range cases {
		if got := KeyOf(c.evt); got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}

// TestKeyOf_BPFUnified: load, attach and inventory for the same program
// produce the same key, regardless of who loaded it.
func TestKeyOf_BPFUnified(t *testing.T) {
	tag := "a04f5eef06a7f555"
	pt := uint32(5)
	load := &event.HookEvent{EventType: event.EventBPFLoad, ExeHash: polExeHash,
		BPFDetail: &event.BPFDetail{ProgType: pt, ProgHash: tag}}
	attach := &event.HookEvent{EventType: event.EventBPFAttach, ExeHash: "sha256:" + strings.Repeat("99", 32),
		BPFDetail: &event.BPFDetail{ProgType: pt, ProgHash: tag}}
	inv := &event.HookEvent{EventType: event.EventBPFInventory,
		BPFDetail: &event.BPFDetail{ProgType: pt, ProgHash: tag}}

	kLoad, kAttach, kInv := KeyOf(load), KeyOf(attach), KeyOf(inv)
	if kLoad != kAttach {
		t.Errorf("load and attach have different keys:\n load:   %+v\n attach: %+v", kLoad, kAttach)
	}
	if kLoad != kInv {
		t.Errorf("load and inventory have different keys:\n load: %+v\n inv:  %+v", kLoad, kInv)
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
	ref := KeyOf(dl(nil))

	same := map[string]func(*event.HookEvent){
		"other host":                  func(e *event.HookEvent) { e.HostID, e.Hostname = "host-b", "b" },
		"other PID, UID, comm":        func(e *event.HookEvent) { e.PID, e.UID, e.Comm = 11, 0, "other" },
		"other exe path, same binary": func(e *event.HookEvent) { e.ExePath = "/opt/copy/app" },
		"different exe hash":          func(e *event.HookEvent) { e.ExeHash = "sha256:" + strings.Repeat("ef", 32) },
		"no exe hash":                 func(e *event.HookEvent) { e.ExeHash = "" },
		"same library at another path (hash keyed)": func(e *event.HookEvent) {
			e.DlopenDetail.LibraryPath = "/usr/lib/p.so"
		},
		"in a container":    func(e *event.HookEvent) { e.ContainerID = "c1" },
		"another container": func(e *event.HookEvent) { e.ContainerID = "c2" },
	}
	for name, mod := range same {
		if got := KeyOf(dl(mod)); got != ref {
			t.Errorf("%s: key changed: %+v vs %+v", name, got, ref)
		}
	}

	differ := map[string]func(*event.HookEvent){
		"library hash": func(e *event.HookEvent) { e.DlopenDetail.LibraryHash = "sha256:" + strings.Repeat("01", 32) },
	}
	for name, mod := range differ {
		if KeyOf(dl(mod)) == ref {
			t.Errorf("%s: same key, want a different one", name)
		}
	}

	// SHM: Chromium's randomly named segments share a key; a bpftime segment
	// does not.
	shm := func(name, pattern string) event.LearnedKey {
		return KeyOf(&event.HookEvent{EventType: event.EventSHMCreate, ExeHash: polExeHash,
			SHMDetail: &event.SHMDetail{SHMName: name, Pattern: pattern}})
	}
	if shm(".org.chromium.Chromium.F04up4", "unknown") != shm(".org.chromium.Chromium.x9Qz1a", "unknown") {
		t.Error("two generic segments have different keys")
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

	// LD_PRELOAD and dlopen for the same library are different keys.
	preload := &event.HookEvent{EventType: event.EventExecInjection, ExeHash: polExeHash,
		ExecInjectionDetail: &event.ExecInjectionDetail{LibraryHash: polLibHash, EnvVar: "LD_PRELOAD"}}
	dlopenEvt := &event.HookEvent{EventType: event.EventDlopen, ExeHash: polExeHash,
		DlopenDetail: &event.DlopenDetail{LibraryHash: polLibHash}}
	if KeyOf(preload) == KeyOf(dlopenEvt) {
		t.Error("LD_PRELOAD and dlopen for the same library share a key")
	}

	// LD_PRELOAD and LD_AUDIT for the same library are different keys.
	audit := &event.HookEvent{EventType: event.EventExecInjection, ExeHash: polExeHash,
		ExecInjectionDetail: &event.ExecInjectionDetail{LibraryHash: polLibHash, EnvVar: "LD_AUDIT"}}
	if KeyOf(preload) == KeyOf(audit) {
		t.Error("LD_PRELOAD and LD_AUDIT for the same library share a key")
	}
}

func TestKeyHash(t *testing.T) {
	k := event.LearnedKey{SubjectKind: SubjectDlopen, Subject: "/opt/p.so"}
	h := KeyHash(k)
	if len(h) != 64 || !isHex(h) || h != KeyHash(k) {
		t.Fatalf("KeyHash %q: want 64 stable hex digits", h)
	}
	seen := map[string]event.LearnedKey{h: k}
	for _, other := range []event.LearnedKey{
		{SubjectKind: SubjectDlopen, Subject: "/opt/p.so", ProgType: 1},
		{SubjectKind: SubjectLDPreload, Subject: "/opt/p.so"},
		{SubjectKind: SubjectLibReplace, Subject: "/opt/p.so", ContentHash: polNewHash},
		{SubjectKind: SubjectLibReplace, Subject: "/opt/p.so"},
		// Field boundaries matter: "ab"+"c" is not "a"+"bc".
		{SubjectKind: "ab", Subject: "c"},
		{SubjectKind: "a", Subject: "bc"},
		// A long path still gives a 64-digit ID.
		{SubjectKind: SubjectDlopen, Subject: strings.Repeat("/x", 4000)},
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
	k := event.LearnedKey{SubjectKind: SubjectBPFTag, Subject: "a04f5eef06a7f555", ProgType: 5}
	got := Describe(k, "/usr/bin/loader")
	want := "learned: BPF tag a04f5eef06a7f555, prog type 5 [/usr/bin/loader]"
	if got != want {
		t.Errorf("Describe:\n got %q\nwant %q", got, want)
	}
	got = Describe(event.LearnedKey{SubjectKind: SubjectSHMName, Subject: "/dev/shm/x"}, "")
	if got != "learned: shm name /dev/shm/x" {
		t.Errorf("Describe shm: %q", got)
	}
}

func TestEventTypesFor(t *testing.T) {
	cases := []struct {
		kind string
		want []event.EventType
	}{
		{SubjectBPFTag, []event.EventType{event.EventBPFLoad, event.EventBPFAttach, event.EventBPFInventory}},
		{SubjectBPFName, []event.EventType{event.EventBPFLoad, event.EventBPFAttach, event.EventBPFInventory}},
		{SubjectLDPreload, []event.EventType{event.EventExecInjection}},
		{SubjectLDAudit, []event.EventType{event.EventExecInjection}},
		{SubjectLDLibraryPath, []event.EventType{event.EventExecInjection}},
		{SubjectLDDebug, []event.EventType{event.EventExecInjection}},
		{SubjectScanTruncated, []event.EventType{event.EventExecInjection}},
		{SubjectDlopen, []event.EventType{event.EventDlopen}},
		{SubjectLibReplace, []event.EventType{event.EventLibIntegrity}},
		{SubjectLinkerConfig, []event.EventType{event.EventLinkerConfig}},
		{SubjectSHMPattern, []event.EventType{event.EventSHMCreate}},
		{SubjectSHMName, []event.EventType{event.EventSHMCreate}},
		{SubjectRpath, []event.EventType{event.EventElfRpath}},
		{SubjectPtrace, []event.EventType{event.EventPtraceInject}},
	}
	for _, c := range cases {
		got := EventTypesFor(event.LearnedKey{SubjectKind: c.kind})
		if len(got) != len(c.want) {
			t.Errorf("EventTypesFor(%s): %v, want %v", c.kind, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("EventTypesFor(%s)[%d]: %s, want %s", c.kind, i, got[i], c.want[i])
			}
		}
	}
}

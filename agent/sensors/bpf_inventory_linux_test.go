//go:build linux

package sensors

import (
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// TestProgramDetail loads a trivial program and checks the kernel's record
// of it as programDetail and listPrograms read it. It needs root.
func TestProgramDetail(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading a BPF program needs root")
	}
	before := time.Now()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "hm_detail_test",
		Type:         ebpf.SocketFilter,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		License:      "MIT",
	})
	if err != nil {
		t.Fatalf("load program: %v", err)
	}
	defer prog.Close()
	after := time.Now()

	info, err := prog.Info()
	if err != nil {
		t.Fatalf("program info: %v", err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("kernel reported no program ID")
	}

	d, err := programDetail(id)
	if err != nil {
		t.Fatalf("programDetail(%d): %v", id, err)
	}
	if d.ProgID != uint32(id) || d.ProgHash != info.Tag || d.ProgName != "hm_detail_test" ||
		d.ProgType != uint32(ebpf.SocketFilter) {
		t.Errorf("detail %+v, want id %d tag %s name hm_detail_test type %d",
			d, id, info.Tag, ebpf.SocketFilter)
	}
	if d.CreatedByUID == nil || *d.CreatedByUID != 0 {
		t.Errorf("created_by_uid %v, want 0", d.CreatedByUID)
	}
	const slack = time.Second
	if d.LoadTime == nil || d.LoadTime.Before(before.Add(-slack)) || d.LoadTime.After(after.Add(slack)) {
		t.Errorf("load_time %v, want between %v and %v", d.LoadTime, before, after)
	}

	found := false
	for _, p := range listPrograms() {
		if p.ProgID == uint32(id) {
			found = p.ProgHash == info.Tag
		}
	}
	if !found {
		t.Errorf("listPrograms did not report program %d with tag %s", id, info.Tag)
	}
}

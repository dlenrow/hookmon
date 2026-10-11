package sensors

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A syscalls:sys_enter_*/sys_exit_* program must take its tracepoint's own
// record, struct syscall_trace_enter/_exit. struct trace_event_raw_sys_enter
// is the raw_syscalls record, which RHEL 9 lays out differently (see
// bpf_syscall.c), and the kernels the e2e tests run on do not show it.
func TestSyscallTracepointContext(t *testing.T) {
	prog := regexp.MustCompile(`SEC\("tracepoint/syscalls/sys_(enter|exit)_(\w+)"\)\s*\n\s*int\s+\w+\(\s*struct\s+(\w+)\s*\*`)
	files, err := filepath.Glob("*.c")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		matches := prog.FindAllStringSubmatch(string(src), -1)
		if n := strings.Count(string(src), `SEC("tracepoint/syscalls/`); n != len(matches) {
			t.Errorf("%s: %d syscalls tracepoint programs, %d with a context this test can read", f, n, len(matches))
		}
		for _, m := range matches {
			checked++
			if want := "syscall_trace_" + m[1]; m[3] != want {
				t.Errorf("%s: sys_%s_%s takes struct %s, want struct %s", f, m[1], m[2], m[3], want)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no syscalls tracepoint programs found")
	}
}

//go:build linux

package sensors

import (
	"errors"
	"testing"
	"time"
)

// TestCheckAttached_ReportsReadErrors: every ring buffer sensor's
// CheckAttached returns its read loop's error while the loop is failing,
// so the health checker records a miss with that reason and, if it
// lasts, the sensor goes dead. Needs no root: the sensors are not started.
func TestCheckAttached_ReportsReadErrors(t *testing.T) {
	bpf, dl, rp := &BPFSyscallSensor{}, &DlopenMonitorSensor{}, &ElfRpathSensor{}
	ex, pt, sh := &ExecInjectionSensor{}, &PtraceMonitorSensor{}, &SHMMonitorSensor{}
	cases := []struct {
		name string
		h    BPFHealth
		r    *readErrors
	}{
		{"bpf_syscall", bpf, &bpf.readErrs},
		{"dlopen_monitor", dl, &dl.readErrs},
		{"elf_rpath", rp, &rp.readErrs},
		{"exec_injection", ex, &ex.readErrs},
		{"ptrace_monitor", pt, &pt.readErrs},
		{"shm_monitor", sh, &sh.readErrs},
	}
	fail := errors.New("read sample: bad header")
	for _, c := range cases {
		c.r.sleep = func(time.Duration, <-chan struct{}) bool { return true }
		for i := 0; i < readFailingAfter; i++ {
			c.r.handle(fail, make(chan struct{}))
		}
		if err := c.h.CheckAttached(); !errors.Is(err, fail) {
			t.Errorf("%s: CheckAttached %v, want the read error", c.name, err)
		}
	}
}

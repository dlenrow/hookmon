//go:build linux

package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// probeTimeout bounds each probe child.
const probeTimeout = 5 * time.Second

// ptraceProbeRequest is not a valid ptrace request. sys_enter_ptrace fires
// before the kernel looks at it, and the ptrace sensor only reports
// ATTACH, SEIZE, POKETEXT, POKEDATA, POKEUSER, SETREGS and SETREGSET.
const ptraceProbeRequest = ^uintptr(0)

// hookProber fires each eBPF sensor's hook with a call that does nothing and
// that the sensor's own filter does not report.
type hookProber struct {
	dlopenHelper string
	logger       *zap.Logger
}

func newHookProber(dlopenHelper string, logger *zap.Logger) *hookProber {
	return &hookProber{dlopenHelper: dlopenHelper, logger: logger}
}

func (p *hookProber) probe(names []string) map[string]string {
	unverifiable := make(map[string]string)
	execProbed := false
	for _, name := range names {
		switch name {
		case "bpf_syscall":
			// Nothing to do: reading the heartbeat maps right after the
			// probes is a bpf() call, and sys_enter_bpf fires before the
			// lookup runs.
		case "shm_monitor":
			// sys_enter_openat and sys_enter_openat2 fire for any path; the
			// sensor hooks both and checks both heartbeats. /dev/null is not
			// under /dev/shm and is opened without O_CREAT.
			fd, err := unix.Openat(unix.AT_FDCWD, "/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				p.logger.Warn("shm_monitor probe: openat failed", zap.Error(err))
			} else {
				unix.Close(fd)
			}
			fd, err = unix.Openat2(unix.AT_FDCWD, "/dev/null", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC})
			if err != nil {
				p.logger.Warn("shm_monitor probe: openat2 failed", zap.Error(err))
			} else {
				unix.Close(fd)
			}
		case "ptrace_monitor":
			// pid 0 never names a tracee, so the kernel returns ESRCH.
			unix.Syscall6(unix.SYS_PTRACE, ptraceProbeRequest, 0, 0, 0, 0, 0)
		case "exec_injection", "elf_rpath":
			// One /bin/true run fires both hooks: exec_injection and
			// elf_rpath both attach to sched_process_exec, which fires
			// once the exec succeeds.
			//
			// Every cycle, not once a minute as the fix plan suggested: a
			// sensor is dead after two missed cycles (15 s threshold), so a
			// minute between probes would mark a healthy sensor dead on a
			// host that execs nothing else. A clean environment carries no
			// LD_* variable to report, and /bin/true has no RPATH.
			if execProbed {
				continue
			}
			execProbed = true
			if err := runProbeChild("/bin/true"); err != nil {
				p.logger.Warn("exec probe: /bin/true failed", zap.String("sensor", name), zap.Error(err))
			}
		case "dlopen_monitor":
			if reason := p.runDlopenHelper(); reason != "" {
				unverifiable[name] = reason
			}
		}
	}
	return unverifiable
}

// runDlopenHelper runs the C helper that calls libc's dlopen, the symbol the
// uprobe is attached to. The Go bus is static and cannot call it itself.
func (p *hookProber) runDlopenHelper() string {
	fi, err := os.Stat(p.dlopenHelper)
	if err != nil {
		return fmt.Sprintf("dlopen probe helper unavailable: %v", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
		return fmt.Sprintf("dlopen probe helper %s is not an executable file", p.dlopenHelper)
	}
	if err := runProbeChild(p.dlopenHelper); err != nil {
		return fmt.Sprintf("dlopen probe helper %s failed: %v", p.dlopenHelper, err)
	}
	return ""
}

// runProbeChild runs path with no arguments, an empty environment and
// stdio on /dev/null, so nothing reaches the bus's console output.
func runProbeChild(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.Env = []string{}
	return cmd.Run()
}

// monotonicNow returns CLOCK_MONOTONIC in nanoseconds, the clock behind
// bpf_ktime_get_ns().
func monotonicNow() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

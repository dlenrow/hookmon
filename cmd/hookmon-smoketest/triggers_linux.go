//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func triggerBPF(variant bool) error {
	imm := int32(0)
	if variant {
		imm = 1
	}
	spec := &ebpf.ProgramSpec{
		Name:    "hm_smoketest",
		Type:    ebpf.TracePoint,
		License: "Apache-2.0",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, imm),
			asm.Return(),
		},
	}
	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		return fmt.Errorf("load program: %w", err)
	}
	defer prog.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_getpid", prog, nil)
	if err != nil {
		prog.Close()
		return fmt.Errorf("attach tracepoint: %w", err)
	}
	tp.Close()
	return nil
}

func triggerExecInjection(libPath string) error {
	cmd := exec.Command("/bin/true")
	cmd.Env = []string{"LD_PRELOAD=" + libPath}
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func triggerSHM() error {
	name := "/dev/shm/bpftime_hookmon_smoketest"
	fd, err := unix.Openat(unix.AT_FDCWD, name, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0644)
	if err != nil {
		return fmt.Errorf("openat: %w", err)
	}
	unix.Close(fd)
	unix.Unlink(name)
	return nil
}

func triggerDlopen(helperPath, libPath string) error {
	cmd := exec.Command(helperPath, "dlopen", libPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func triggerPtrace() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command("/bin/sleep", "2")
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: false}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start child: %w", err)
	}
	pid := cmd.Process.Pid
	time.Sleep(100 * time.Millisecond)

	if err := syscall.PtraceAttach(pid); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return fmt.Errorf("PTRACE_ATTACH pid %d: %w", pid, err)
	}

	var ws syscall.WaitStatus
	syscall.Wait4(pid, &ws, 0, nil)

	var zero [8]byte
	syscall.PtracePokeData(pid, 0, zero[:])

	syscall.PtraceDetach(pid)
	cmd.Process.Kill()
	cmd.Wait()
	return nil
}

func triggerLinkerConfig() error {
	path := "/etc/ld.so.conf.d/hookmon-smoketest.conf"
	if err := os.WriteFile(path, []byte("# hookmon smoketest\n"), 0644); err != nil {
		return err
	}
	time.Sleep(200 * time.Millisecond)
	os.Remove(path)
	return nil
}

func triggerLibIntegrity(libSrc string) error {
	dst := "/usr/lib/libhookmon_smoketest_canary.so"
	data, err := os.ReadFile(libSrc)
	if err != nil {
		return fmt.Errorf("read library: %w", err)
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return err
	}
	time.Sleep(200 * time.Millisecond)
	os.Remove(dst)
	return nil
}

func triggerElfRpath(helperPath string) error {
	cmd := exec.Command(helperPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}


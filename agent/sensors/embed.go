//go:build linux

package sensors

import _ "embed"

//go:embed bpf_syscall.o
var bpfSyscallBPF []byte

//go:embed execve_preload.o
var execvePreloadBPF []byte

//go:embed shm_monitor.o
var shmMonitorBPF []byte

//go:embed dlopen_monitor.o
var dlopenMonitorBPF []byte

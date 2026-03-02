//go:build !linux

package sensors

import (
	"fmt"
	"runtime"

	"github.com/dlenrow/hookmon/pkg/event"
)

var errNotLinux = fmt.Errorf("eBPF sensors require Linux (current OS: %s)", runtime.GOOS)

// Stub sensor for non-Linux platforms. All sensors share this implementation.
type stubSensor struct {
	name    string
	eventCh chan *event.HookEvent
}

func (s *stubSensor) Name() string                      { return s.name }
func (s *stubSensor) Start() error                      { return errNotLinux }
func (s *stubSensor) Stop() error                       { return nil }
func (s *stubSensor) Events() <-chan *event.HookEvent   { return s.eventCh }

func newStub(name string) *stubSensor {
	return &stubSensor{name: name, eventCh: make(chan *event.HookEvent)}
}

func NewBPFSyscallSensor() Sensor       { return newStub("bpf_syscall") }
func NewExecvePreloadSensor() Sensor    { return newStub("execve_preload") }
func NewSHMMonitorSensor() Sensor       { return newStub("shm_monitor") }
func NewDlopenMonitorSensor() Sensor    { return newStub("dlopen_monitor") }

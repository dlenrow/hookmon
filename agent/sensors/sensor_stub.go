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
	name       string
	sensorType SensorType
	eventCh    chan *event.HookEvent
}

func (s *stubSensor) Name() string                      { return s.name }
func (s *stubSensor) Type() SensorType                  { return s.sensorType }
func (s *stubSensor) Start() error                      { return errNotLinux }
func (s *stubSensor) Stop() error                       { return nil }
func (s *stubSensor) Events() <-chan *event.HookEvent   { return s.eventCh }

func newStub(name string, st SensorType) *stubSensor {
	return &stubSensor{name: name, sensorType: st, eventCh: make(chan *event.HookEvent)}
}

func NewBPFSyscallSensor() Sensor        { return newStub("bpf_syscall", SensorTypeBPF) }
func NewExecInjectionSensor() Sensor     { return newStub("exec_injection", SensorTypeBPF) }
func NewSHMMonitorSensor() Sensor        { return newStub("shm_monitor", SensorTypeBPF) }
func NewDlopenMonitorSensor() Sensor     { return newStub("dlopen_monitor", SensorTypeBPF) }
func NewLinkerConfigSensor() Sensor      { return newStub("linker_config", SensorTypeFanotify) }
func NewPtraceMonitorSensor() Sensor     { return newStub("ptrace_monitor", SensorTypeBPF) }
func NewLibIntegritySensor() Sensor      { return newStub("lib_integrity", SensorTypeFanotify) }

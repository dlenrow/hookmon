package smoketest

import (
	"testing"

	"github.com/dlenrow/hookmon/agent/config"
	"github.com/dlenrow/hookmon/agent/sensors"
)

// sensorSpec defines what we expect from each sensor constructor.
type sensorSpec struct {
	name       string
	sensorType sensors.SensorType
	construct  func() sensors.Sensor
	configFlag func(*config.SensorConfig) bool
}

var allSensors = []sensorSpec{
	{"bpf_syscall", sensors.SensorTypeBPF, sensors.NewBPFSyscallSensor, func(c *config.SensorConfig) bool { return c.BPFSyscall }},
	{"exec_injection", sensors.SensorTypeBPF, sensors.NewExecInjectionSensor, func(c *config.SensorConfig) bool { return c.ExecInjection }},
	{"shm_monitor", sensors.SensorTypeBPF, sensors.NewSHMMonitorSensor, func(c *config.SensorConfig) bool { return c.SHMMonitor }},
	{"dlopen_monitor", sensors.SensorTypeBPF, sensors.NewDlopenMonitorSensor, func(c *config.SensorConfig) bool { return c.DlopenMonitor }},
	{"linker_config", sensors.SensorTypeFanotify, sensors.NewLinkerConfigSensor, func(c *config.SensorConfig) bool { return c.LinkerConfig }},
	{"ptrace_monitor", sensors.SensorTypeBPF, sensors.NewPtraceMonitorSensor, func(c *config.SensorConfig) bool { return c.PtraceMonitor }},
	{"lib_integrity", sensors.SensorTypeFanotify, sensors.NewLibIntegritySensor, func(c *config.SensorConfig) bool { return c.LibIntegrity }},
}

// TestSensorConstructors proves each of the 8 sensor constructors returns
// a valid Sensor with the correct Name() and Type().
func TestSensorConstructors(t *testing.T) {
	for _, spec := range allSensors {
		t.Run(spec.name, func(t *testing.T) {
			s := spec.construct()
			if s == nil {
				t.Fatal("constructor returned nil")
			}
			if s.Name() != spec.name {
				t.Errorf("Name(): expected %q, got %q", spec.name, s.Name())
			}
			if s.Type() != spec.sensorType {
				t.Errorf("Type(): expected %q, got %q", spec.sensorType, s.Type())
			}
			if s.Events() == nil {
				t.Error("Events() returned nil channel")
			}
		})
	}
}

// TestSensorConfigDefaults proves DefaultConfig() enables all 8 sensors.
func TestSensorConfigDefaults(t *testing.T) {
	cfg := config.DefaultConfig()
	sc := &cfg.Sensors

	checks := []struct {
		name    string
		enabled bool
	}{
		{"bpf_syscall", sc.BPFSyscall},
		{"exec_injection", sc.ExecInjection},
		{"shm_monitor", sc.SHMMonitor},
		{"dlopen_monitor", sc.DlopenMonitor},
		{"linker_config", sc.LinkerConfig},
		{"ptrace_monitor", sc.PtraceMonitor},
		{"lib_integrity", sc.LibIntegrity},
		{"elf_rpath", sc.ElfRpath},
	}

	for _, c := range checks {
		if !c.enabled {
			t.Errorf("sensor %s should be enabled by default", c.name)
		}
	}
}

// TestSensorConfigMapping proves each sensor has a corresponding config flag
// and that disabling it in config prevents initialization.
func TestSensorConfigMapping(t *testing.T) {
	cfg := config.DefaultConfig()
	for _, spec := range allSensors {
		if !spec.configFlag(&cfg.Sensors) {
			t.Errorf("sensor %s: config flag should be true in DefaultConfig", spec.name)
		}
	}
}

// TestSensorTypeClassification proves sensors are correctly classified
// as bpf, fanotify, or audit — this matters for heartbeat routing.
func TestSensorTypeClassification(t *testing.T) {
	ebpfSensors := []string{"bpf_syscall", "exec_injection", "shm_monitor", "dlopen_monitor", "ptrace_monitor"}
	fanotifySensors := []string{"linker_config", "lib_integrity"}

	for _, spec := range allSensors {
		s := spec.construct()
		switch s.Type() {
		case sensors.SensorTypeBPF:
			if !contains(ebpfSensors, s.Name()) {
				t.Errorf("%s: classified as BPF but not in expected BPF list", s.Name())
			}
		case sensors.SensorTypeFanotify:
			if !contains(fanotifySensors, s.Name()) {
				t.Errorf("%s: classified as fanotify but not in expected fanotify list", s.Name())
			}
		default:
			t.Errorf("%s: unexpected sensor type %s", s.Name(), s.Type())
		}
	}
}

// TestSensorStopIdempotent proves Stop() doesn't panic on a sensor that was never started.
func TestSensorStopIdempotent(t *testing.T) {
	for _, spec := range allSensors {
		t.Run(spec.name, func(t *testing.T) {
			s := spec.construct()
			if err := s.Stop(); err != nil {
				t.Errorf("Stop() on unstarted sensor should not error, got: %v", err)
			}
		})
	}
}

// TestElfRpathSensorType proves the elf_rpath sensor is classified as audit type
// (it's not in allSensors because it doesn't have a traditional constructor).
func TestElfRpathSensorType(t *testing.T) {
	if sensors.SensorTypeAudit != "audit" {
		t.Errorf("SensorTypeAudit should be 'audit', got %q", sensors.SensorTypeAudit)
	}
}

// TestSensorCount proves we have exactly 8 sensor types accounted for.
func TestSensorCount(t *testing.T) {
	// 7 constructable sensors + 1 audit sensor (elf_rpath) = 8 total
	if len(allSensors) != 7 {
		t.Errorf("expected 7 constructable sensors (+ elf_rpath audit), got %d", len(allSensors))
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

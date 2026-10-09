package sensors

import "github.com/dlenrow/hookmon/pkg/event"

// SensorType identifies the underlying mechanism a sensor uses.
type SensorType string

const (
	SensorTypeBPF      SensorType = "bpf"      // uses eBPF tracepoints/uprobes
	SensorTypeFanotify SensorType = "fanotify"  // uses fanotify file monitoring
	SensorTypeAudit    SensorType = "audit"    // userspace post-enrichment audit
)

// Sensor is the common interface for all sensors.
type Sensor interface {
	// Name returns the sensor identifier.
	Name() string

	// Type returns the underlying mechanism (bpf, fanotify).
	Type() SensorType

	// Start loads the sensor program and begins emitting events.
	Start() error

	// Stop unloads the sensor and releases resources.
	Stop() error

	// Events returns the channel on which detected events are delivered.
	Events() <-chan *event.HookEvent
}

// BPFHealth is implemented by the eBPF sensors. The bus uses it after firing
// each hook itself to decide whether the hook still runs.
type BPFHealth interface {
	// HeartbeatNs returns key 0 of the sensor's hookmon_heartbeat_<name> map:
	// the bpf_ktime_get_ns() (CLOCK_MONOTONIC) time the hook last ran.
	HeartbeatNs() (uint64, error)

	// CheckAttached verifies, independently of the heartbeat map, that the
	// sensor's program and link still exist and that the kernel still has
	// the program attached to the hook's perf event.
	CheckAttached() error
}

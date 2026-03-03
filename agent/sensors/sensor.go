package sensors

import "github.com/dlenrow/hookmon/pkg/event"

// SensorType identifies the underlying mechanism a sensor uses.
type SensorType string

const (
	SensorTypeBPF      SensorType = "bpf"      // uses eBPF tracepoints/uprobes
	SensorTypeFanotify SensorType = "fanotify"  // uses fanotify file monitoring
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

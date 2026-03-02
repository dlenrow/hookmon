package sensors

import "github.com/dlenrow/hookmon/pkg/event"

// Sensor is the common interface for all eBPF-based sensors.
type Sensor interface {
	// Name returns the sensor identifier.
	Name() string

	// Start loads the eBPF program and begins emitting events.
	Start() error

	// Stop unloads the eBPF program and releases resources.
	Stop() error

	// Events returns the channel on which detected events are delivered.
	Events() <-chan *event.HookEvent
}

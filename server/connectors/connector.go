package connectors

import "github.com/dlenrow/hookmon/pkg/event"

// Connector sends events to external SIEM systems.
type Connector interface {
	Name() string
	Send(evt *event.HookEvent) error
	Close() error
}

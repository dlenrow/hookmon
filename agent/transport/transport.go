package transport

import (
	"context"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Transport is the interface for sending events from the agent.
type Transport interface {
	// Run maintains the connection to the server until ctx is cancelled.
	Run(ctx context.Context) error
	SendEvent(evt *event.HookEvent) error
	SendHeartbeat() error
	IsConnected() bool
	Close() error
}

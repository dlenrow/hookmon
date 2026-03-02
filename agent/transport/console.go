package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/dlenrow/hookmon/pkg/event"
)

// ConsoleTransport prints events to stdout as formatted JSON.
type ConsoleTransport struct{}

// NewConsoleTransport creates a console transport for --console mode.
func NewConsoleTransport() *ConsoleTransport {
	return &ConsoleTransport{}
}

func (t *ConsoleTransport) Connect(_ context.Context) error { return nil }
func (t *ConsoleTransport) IsConnected() bool               { return true }
func (t *ConsoleTransport) Close() error                    { return nil }
func (t *ConsoleTransport) SendHeartbeat() error            { return nil }

func (t *ConsoleTransport) SendEvent(evt *event.HookEvent) error {
	data, err := json.MarshalIndent(evt, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	_, err = fmt.Fprintf(os.Stdout, "%s\n", data)
	return err
}

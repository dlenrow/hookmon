package transport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/dlenrow/hookmon/pkg/event"
)

// FallbackLogger writes events to a local JSONL file when the server is unreachable.
type FallbackLogger struct {
	path string
	mu   sync.Mutex
	file *os.File
}

// NewFallbackLogger creates a fallback logger that writes to the given path.
func NewFallbackLogger(path string) *FallbackLogger {
	return &FallbackLogger{path: path}
}

// Write appends an event as a JSON line to the fallback log file.
func (f *FallbackLogger) Write(evt *event.HookEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.file == nil {
		if err := os.MkdirAll(filepath.Dir(f.path), 0750); err != nil {
			return fmt.Errorf("create fallback dir: %w", err)
		}
		file, err := os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return fmt.Errorf("open fallback log: %w", err)
		}
		f.file = file
	}

	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	data = append(data, '\n')

	_, err = f.file.Write(data)
	return err
}

// Close closes the fallback log file.
func (f *FallbackLogger) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file != nil {
		return f.file.Close()
	}
	return nil
}

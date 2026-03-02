package policy

import (
	"fmt"
	"sync"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
	"go.uber.org/zap"
)

// alertKey is the deduplication key for alerts. Events with the same
// event type, host, and executable path within the dedup window are
// considered duplicates.
type alertKey struct {
	EventType event.EventType
	HostID    string
	ExePath   string
}

// alertRecord tracks when an alert was last emitted for a given key.
type alertRecord struct {
	lastAlerted time.Time
}

// AlertManager handles alert generation and deduplication. It suppresses
// duplicate alerts for the same event type + host + executable within a
// configurable time window.
type AlertManager struct {
	mu          sync.Mutex
	recent      map[alertKey]*alertRecord
	dedupWindow time.Duration
	logger      *zap.Logger
}

// NewAlertManager creates an AlertManager with the given dedup window.
// A typical production value is 5 minutes.
func NewAlertManager(logger *zap.Logger, dedupWindow time.Duration) *AlertManager {
	am := &AlertManager{
		recent:      make(map[alertKey]*alertRecord),
		dedupWindow: dedupWindow,
		logger:      logger,
	}
	return am
}

// ShouldAlert returns true if an alert should be emitted for this event,
// and false if a duplicate alert was already emitted within the dedup window.
// Calling ShouldAlert does NOT record the event; call GenerateAlert to do that.
func (am *AlertManager) ShouldAlert(evt *event.HookEvent) bool {
	am.mu.Lock()
	defer am.mu.Unlock()

	key := makeAlertKey(evt)
	record, exists := am.recent[key]
	if !exists {
		return true
	}
	return time.Since(record.lastAlerted) >= am.dedupWindow
}

// GenerateAlert wraps the event with alert metadata and records it in the
// dedup map. The event's Severity should already be set by the policy engine.
// Returns the event with PolicyResult updated to reflect alert generation.
func (am *AlertManager) GenerateAlert(evt *event.HookEvent) *event.HookEvent {
	am.mu.Lock()
	defer am.mu.Unlock()

	key := makeAlertKey(evt)
	am.recent[key] = &alertRecord{
		lastAlerted: time.Now(),
	}

	// Ensure the event has a PolicyResult; if not, create one.
	if evt.PolicyResult == nil {
		evt.PolicyResult = &event.PolicyResult{
			Action: event.ActionAlert,
			Reason: fmt.Sprintf("alert generated for %s event on %s", evt.EventType, evt.Hostname),
		}
	}

	am.logger.Info("alert generated",
		zap.String("event_id", evt.ID),
		zap.String("event_type", string(evt.EventType)),
		zap.String("hostname", evt.Hostname),
		zap.String("exe_path", evt.ExePath),
		zap.String("severity", string(evt.Severity)),
	)

	// Prune expired entries opportunistically.
	am.pruneLocked()

	return evt
}

// pruneLocked removes stale entries from the dedup map. Must be called with
// am.mu held.
func (am *AlertManager) pruneLocked() {
	now := time.Now()
	for key, record := range am.recent {
		if now.Sub(record.lastAlerted) >= am.dedupWindow*2 {
			delete(am.recent, key)
		}
	}
}

// makeAlertKey builds the dedup key for an event.
func makeAlertKey(evt *event.HookEvent) alertKey {
	return alertKey{
		EventType: evt.EventType,
		HostID:    evt.HostID,
		ExePath:   evt.ExePath,
	}
}

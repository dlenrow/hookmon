package policy

import (
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/allowlist"
	"github.com/dlenrow/hookmon/pkg/event"
)

// alertKey is the deduplication key for alerts: the host, the acting
// binary's path, and the event's learning-mode key (event type, exe hash,
// subject, program type, in-container; see allowlist.KeyOf). Two
// different BPF programs, or two different libraries, from the same
// binary are different alerts.
type alertKey struct {
	HostID  string
	ExePath string
	Key     string // allowlist.KeyHash of allowlist.KeyOf(evt)
}

// AlertManager drops repeats of an alert: an alert whose key was admitted
// less than the dedup window ago. The connector dispatcher consults it for
// connectors that receive alerts (min_severity ALERT or CRITICAL).
type AlertManager struct {
	mu          sync.Mutex
	recent      map[alertKey]time.Time // key -> when it was last admitted
	lastPrune   time.Time
	dedupWindow time.Duration
	now         func() time.Time
	logger      *zap.Logger
}

// NewAlertManager creates an AlertManager with the given dedup window.
// The server uses 5 minutes.
func NewAlertManager(logger *zap.Logger, dedupWindow time.Duration) *AlertManager {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AlertManager{
		recent:      make(map[alertKey]time.Time),
		dedupWindow: dedupWindow,
		now:         time.Now,
		logger:      logger,
	}
}

// Admit reports whether evt is a new alert, and if so records it, in one
// step, so two streams racing with the same alert admit it once. It
// returns false for a repeat within the dedup window. It does not change
// evt.
func (am *AlertManager) Admit(evt *event.HookEvent) bool {
	key := makeAlertKey(evt)
	now := am.now()

	am.mu.Lock()
	defer am.mu.Unlock()
	if last, ok := am.recent[key]; ok && now.Sub(last) < am.dedupWindow {
		am.logger.Debug("alert suppressed as a repeat",
			zap.String("event_id", evt.ID),
			zap.String("event_type", string(evt.EventType)),
			zap.String("host_id", evt.HostID),
		)
		return false
	}
	am.recent[key] = now
	am.pruneLocked(now)

	am.logger.Info("alert generated",
		zap.String("event_id", evt.ID),
		zap.String("event_type", string(evt.EventType)),
		zap.String("hostname", evt.Hostname),
		zap.String("exe_path", evt.ExePath),
		zap.String("severity", string(evt.Severity)),
	)
	return true
}

// pruneLocked drops keys last admitted more than a window ago, at most
// once per window. Must be called with am.mu held.
func (am *AlertManager) pruneLocked(now time.Time) {
	if now.Sub(am.lastPrune) < am.dedupWindow {
		return
	}
	am.lastPrune = now
	for key, last := range am.recent {
		if now.Sub(last) >= am.dedupWindow {
			delete(am.recent, key)
		}
	}
}

// makeAlertKey builds the dedup key for an event.
func makeAlertKey(evt *event.HookEvent) alertKey {
	return alertKey{
		HostID:  evt.HostID,
		ExePath: evt.ExePath,
		Key:     allowlist.KeyHash(allowlist.KeyOf(evt)),
	}
}

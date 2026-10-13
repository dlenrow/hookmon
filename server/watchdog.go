package server

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// WatchdogConfig controls the anti-tampering heartbeat watchdog.
type WatchdogConfig struct {
	// CheckInterval is how often the watchdog scans for stale hosts.
	CheckInterval time.Duration `yaml:"check_interval"`

	// HeartbeatTimeout is how long since last heartbeat before a host
	// is considered unresponsive. Should be >= 2x agent heartbeat interval.
	HeartbeatTimeout time.Duration `yaml:"heartbeat_timeout"`

	// MarkerTimeout is how long a host can go without an end-to-end marker
	// before it is considered wedged. Zero disables the check.
	MarkerTimeout time.Duration `yaml:"marker_timeout"`
}

// DefaultWatchdogConfig returns sensible defaults.
func DefaultWatchdogConfig() WatchdogConfig {
	return WatchdogConfig{
		CheckInterval:    15 * time.Second,
		HeartbeatTimeout: 60 * time.Second,
		MarkerTimeout:    3 * time.Minute,
	}
}

// Watchdog monitors host heartbeats and generates AGENT_OFFLINE alerts
// when hosts go unresponsive.
type Watchdog struct {
	cfg      WatchdogConfig
	store    WatchdogStore
	alerts   AlertSink
	shutdown ShutdownChecker
	markers  MarkerChecker
	logger   *zap.Logger
	wedged   map[string]bool // hosts already marked wedged
}

// WatchdogStore is the storage interface the watchdog requires.
type WatchdogStore interface {
	GetStaleHosts(ctx context.Context, threshold time.Duration) ([]*event.Host, error)
	GetHost(ctx context.Context, id string) (*event.Host, error)
	// MarkHostUnresponsive sets an ONLINE host UNRESPONSIVE if its last
	// heartbeat is still before staleBefore, and reports whether it did.
	MarkHostUnresponsive(ctx context.Context, hostID string, staleBefore time.Time) (bool, error)
	InsertEvent(ctx context.Context, evt *event.HookEvent) error
}

// AlertSink receives alert events for dispatch to connectors.
type AlertSink interface {
	Dispatch(evt *event.HookEvent)
}

// ShutdownChecker knows whether a host announced a clean shutdown.
type ShutdownChecker interface {
	HostShutdownAnnounced(hostID string) bool
}

// MarkerChecker detects wedged hosts: reachable but no marker for too long.
type MarkerChecker interface {
	WedgedHosts(threshold time.Duration) []string
}

// NewWatchdog creates a new heartbeat watchdog.
func NewWatchdog(cfg WatchdogConfig, store WatchdogStore, alerts AlertSink, logger *zap.Logger) *Watchdog {
	return &Watchdog{
		cfg:    cfg,
		store:  store,
		alerts: alerts,
		logger: logger,
		wedged: make(map[string]bool),
	}
}

// SetShutdownChecker gives the watchdog access to shutdown announcements so
// it can suppress AGENT_OFFLINE for hosts that stopped cleanly.
func (w *Watchdog) SetShutdownChecker(sc ShutdownChecker) {
	w.shutdown = sc
}

// SetMarkerChecker gives the watchdog access to end-to-end marker times so
// it can detect wedged hosts (reachable but not processing events).
func (w *Watchdog) SetMarkerChecker(mc MarkerChecker) {
	w.markers = mc
}

// Run starts the watchdog loop. Blocks until the context is cancelled.
func (w *Watchdog) Run(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.CheckInterval)
	defer ticker.Stop()

	w.logger.Info("watchdog started",
		zap.Duration("check_interval", w.cfg.CheckInterval),
		zap.Duration("heartbeat_timeout", w.cfg.HeartbeatTimeout),
	)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("watchdog stopped")
			return
		case <-ticker.C:
			w.check(ctx)
		}
	}
}

func (w *Watchdog) check(ctx context.Context) {
	staleBefore := time.Now().UTC().Add(-w.cfg.HeartbeatTimeout)
	staleHosts, err := w.store.GetStaleHosts(ctx, w.cfg.HeartbeatTimeout)
	if err != nil {
		w.logger.Error("watchdog: failed to query stale hosts", zap.Error(err))
		return
	}

	for _, host := range staleHosts {
		if host.Status == event.HostUnresponsive || host.Status == event.HostOffline {
			continue // Already marked
		}

		if w.shutdown != nil && w.shutdown.HostShutdownAnnounced(host.ID) {
			w.logger.Debug("host announced shutdown, skipping AGENT_OFFLINE",
				zap.String("host_id", host.ID))
			continue
		}

		// Mark the host unresponsive only if no heartbeat arrived since the
		// query; otherwise it is back online and there is nothing to raise.
		marked, err := w.store.MarkHostUnresponsive(ctx, host.ID, staleBefore)
		if err != nil {
			w.logger.Error("watchdog: failed to update host status", zap.Error(err))
			continue
		}
		if !marked {
			continue
		}

		w.logger.Warn("host heartbeat timeout — generating AGENT_OFFLINE alert",
			zap.String("host_id", host.ID),
			zap.String("hostname", host.Hostname),
			zap.Time("last_heartbeat", host.LastHeartbeat),
		)

		// Generate AGENT_OFFLINE event (CRITICAL / SEV-1)
		alertEvt := &event.HookEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now().UTC(),
			HostID:    host.ID,
			Hostname:  host.Hostname,
			EventType: event.EventAgentOffline,
			Severity:  event.SeverityCritical,
			PolicyResult: &event.PolicyResult{
				Action: event.ActionAlert,
				Reason: "Agent heartbeat timeout — possible tampering or agent failure",
			},
		}

		if err := w.store.InsertEvent(ctx, alertEvt); err != nil {
			w.logger.Error("watchdog: failed to store AGENT_OFFLINE event", zap.Error(err))
		}

		// Dispatch to all SIEM connectors
		w.alerts.Dispatch(alertEvt)
	}

	// Wedged detection: hosts that send heartbeats but no end-to-end marker.
	if w.markers != nil && w.cfg.MarkerTimeout > 0 {
		wedgedIDs := w.markers.WedgedHosts(w.cfg.MarkerTimeout)
		nowWedged := make(map[string]bool, len(wedgedIDs))
		for _, id := range wedgedIDs {
			nowWedged[id] = true
			if w.wedged[id] {
				continue
			}
			host, err := w.store.GetHost(ctx, id)
			if err != nil {
				w.logger.Error("watchdog: failed to look up wedged host", zap.String("host_id", id), zap.Error(err))
				continue
			}
			w.logger.Warn("host marker stale — generating AGENT_WEDGED alert",
				zap.String("host_id", id),
				zap.String("hostname", host.Hostname),
			)
			alertEvt := &event.HookEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now().UTC(),
				HostID:    id,
				Hostname:  host.Hostname,
				EventType: event.EventAgentWedged,
				Severity:  event.SeverityCritical,
				PolicyResult: &event.PolicyResult{
					Action: event.ActionAlert,
					Reason: "End-to-end marker missing — bus may be wedged",
				},
			}
			if err := w.store.InsertEvent(ctx, alertEvt); err != nil {
				w.logger.Error("watchdog: failed to store AGENT_WEDGED event", zap.Error(err))
			}
			w.alerts.Dispatch(alertEvt)
		}
		// Clear hosts that are no longer wedged.
		for id := range w.wedged {
			if !nowWedged[id] {
				delete(w.wedged, id)
			}
		}
		w.wedged = nowWedged
	}
}

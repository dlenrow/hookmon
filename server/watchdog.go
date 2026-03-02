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
	CheckInterval time.Duration

	// HeartbeatTimeout is how long since last heartbeat before a host
	// is considered unresponsive. Should be >= 2x agent heartbeat interval.
	HeartbeatTimeout time.Duration
}

// DefaultWatchdogConfig returns sensible defaults.
func DefaultWatchdogConfig() WatchdogConfig {
	return WatchdogConfig{
		CheckInterval:    15 * time.Second,
		HeartbeatTimeout: 60 * time.Second,
	}
}

// Watchdog monitors host heartbeats and generates AGENT_OFFLINE alerts
// when hosts go unresponsive.
type Watchdog struct {
	cfg    WatchdogConfig
	store  WatchdogStore
	alerts AlertSink
	logger *zap.Logger
}

// WatchdogStore is the storage interface the watchdog requires.
type WatchdogStore interface {
	GetStaleHosts(ctx context.Context, threshold time.Duration) ([]*event.Host, error)
	UpsertHost(ctx context.Context, host *event.Host) error
	InsertEvent(ctx context.Context, evt *event.HookEvent) error
}

// AlertSink receives alert events for dispatch to connectors.
type AlertSink interface {
	Dispatch(evt *event.HookEvent)
}

// NewWatchdog creates a new heartbeat watchdog.
func NewWatchdog(cfg WatchdogConfig, store WatchdogStore, alerts AlertSink, logger *zap.Logger) *Watchdog {
	return &Watchdog{
		cfg:    cfg,
		store:  store,
		alerts: alerts,
		logger: logger,
	}
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
	staleHosts, err := w.store.GetStaleHosts(ctx, w.cfg.HeartbeatTimeout)
	if err != nil {
		w.logger.Error("watchdog: failed to query stale hosts", zap.Error(err))
		return
	}

	for _, host := range staleHosts {
		if host.Status == event.HostUnresponsive || host.Status == event.HostOffline {
			continue // Already marked
		}

		w.logger.Warn("host heartbeat timeout — generating AGENT_OFFLINE alert",
			zap.String("host_id", host.ID),
			zap.String("hostname", host.Hostname),
			zap.Time("last_heartbeat", host.LastHeartbeat),
		)

		// Mark host as unresponsive
		host.Status = event.HostUnresponsive
		if err := w.store.UpsertHost(ctx, host); err != nil {
			w.logger.Error("watchdog: failed to update host status", zap.Error(err))
		}

		// Generate AGENT_OFFLINE event (CRITICAL / SEV-1)
		alertEvt := &event.HookEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
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
}

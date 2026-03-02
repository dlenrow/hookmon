package agent

import (
	"context"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/agent/config"
	"github.com/dlenrow/hookmon/agent/enrichment"
	"github.com/dlenrow/hookmon/agent/observability"
	"github.com/dlenrow/hookmon/agent/sensors"
	"github.com/dlenrow/hookmon/agent/transport"
)

// Agent is the hookmon-agent daemon that loads sensors and streams events to the server.
type Agent struct {
	cfg       *config.AgentConfig
	logger    *zap.Logger
	transport transport.Transport
	sensors   []sensors.Sensor
	hostname  string
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	loki    *observability.LokiPusher
	metrics *observability.Metrics
}

// New creates a new Agent with the given configuration.
func New(cfg *config.AgentConfig, logger *zap.Logger) *Agent {
	hostname, _ := os.Hostname()

	var t transport.Transport
	if cfg.ConsoleMode {
		t = transport.NewConsoleTransport()
	} else {
		t = transport.NewGRPCTransport(cfg, logger)
	}

	a := &Agent{
		cfg:       cfg,
		logger:    logger,
		transport: t,
		hostname:  hostname,
	}

	if cfg.LokiURL != "" {
		a.loki = observability.NewLokiPusher(cfg.LokiURL, logger)
		logger.Info("loki pusher enabled", zap.String("url", cfg.LokiURL))
	}

	if cfg.PrometheusPort > 0 {
		m, err := observability.NewMetrics(cfg.PrometheusPort, logger)
		if err != nil {
			logger.Error("failed to start prometheus metrics", zap.Error(err))
		} else {
			a.metrics = m
		}
	}

	return a
}

// Run starts the agent: connects to the server, starts sensors, and begins
// streaming events. Blocks until the context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	ctx, a.cancel = context.WithCancel(ctx)

	if a.cfg.ConsoleMode {
		a.logger.Info("running in console mode — events will print to stdout")
	} else {
		// Connect to server with retry
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			transport.RetryLoop(ctx, transport.DefaultRetryConfig(), a.logger, func(ctx context.Context) error {
				return a.transport.Connect(ctx)
			})
		}()
	}

	// Start sensors
	a.initSensors()
	activeSensors := 0
	for _, s := range a.sensors {
		if err := s.Start(); err != nil {
			a.logger.Warn("sensor failed to start", zap.String("sensor", s.Name()), zap.Error(err))
			if a.metrics != nil {
				a.metrics.RecordSensorError(s.Name())
			}
			continue
		}
		activeSensors++
		a.logger.Info("sensor started", zap.String("sensor", s.Name()))

		// Fan events from each sensor into the transport
		a.wg.Add(1)
		go a.forwardEvents(ctx, s)
	}
	if a.metrics != nil {
		a.metrics.SetSensorsActive(activeSensors)
	}

	// Heartbeat loop (skip in console mode)
	if !a.cfg.ConsoleMode {
		a.wg.Add(1)
		go a.heartbeatLoop(ctx)
	}

	<-ctx.Done()
	a.logger.Info("agent shutting down")
	return a.shutdown()
}

// Stop gracefully shuts down the agent.
func (a *Agent) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
}

func (a *Agent) initSensors() {
	if a.cfg.Sensors.BPFSyscall {
		a.sensors = append(a.sensors, sensors.NewBPFSyscallSensor())
	}
	if a.cfg.Sensors.ExecvePreload {
		a.sensors = append(a.sensors, sensors.NewExecvePreloadSensor())
	}
	if a.cfg.Sensors.SHMMonitor {
		a.sensors = append(a.sensors, sensors.NewSHMMonitorSensor())
	}
	if a.cfg.Sensors.DlopenMonitor {
		a.sensors = append(a.sensors, sensors.NewDlopenMonitorSensor())
	}
}

func (a *Agent) forwardEvents(ctx context.Context, s sensors.Sensor) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-s.Events():
			if !ok {
				return
			}
			evt.HostID = a.cfg.HostID
			evt.Hostname = a.hostname

			enrichment.EnrichProcess(evt)

			// Hash the binary if we have the path
			if evt.ExePath != "" && evt.ExeHash == "" {
				evt.ExeHash = enrichment.SHA256File(evt.ExePath)
			}

			if err := a.transport.SendEvent(evt); err != nil {
				a.logger.Error("send event failed", zap.Error(err))
			}

			if a.loki != nil {
				a.loki.Push(evt)
			}
			if a.metrics != nil {
				a.metrics.RecordEvent(evt)
			}
		}
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	defer a.wg.Done()
	ticker := time.NewTicker(a.cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.transport.SendHeartbeat(); err != nil {
				a.logger.Debug("heartbeat send failed", zap.Error(err))
			}
		}
	}
}

func (a *Agent) shutdown() error {
	for _, s := range a.sensors {
		if err := s.Stop(); err != nil {
			a.logger.Warn("sensor stop error", zap.String("sensor", s.Name()), zap.Error(err))
		}
	}
	a.wg.Wait()

	if a.loki != nil {
		a.loki.Close()
	}
	if a.metrics != nil {
		a.metrics.Close()
	}

	return a.transport.Close()
}

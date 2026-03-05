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
	"github.com/dlenrow/hookmon/agent/registry"
	"github.com/dlenrow/hookmon/agent/sensors"
	"github.com/dlenrow/hookmon/agent/transport"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/pkg/version"
	"github.com/google/uuid"
)

// allSensorNames returns the list of all sensor names matching the config.
func allSensorNames(cfg *config.AgentConfig) []string {
	var names []string
	if cfg.Sensors.BPFSyscall {
		names = append(names, "bpf_syscall")
	}
	if cfg.Sensors.ExecInjection {
		names = append(names, "exec_injection")
	}
	if cfg.Sensors.SHMMonitor {
		names = append(names, "shm_monitor")
	}
	if cfg.Sensors.DlopenMonitor {
		names = append(names, "dlopen_monitor")
	}
	if cfg.Sensors.LinkerConfig {
		names = append(names, "linker_config")
	}
	if cfg.Sensors.PtraceMonitor {
		names = append(names, "ptrace_monitor")
	}
	if cfg.Sensors.LibIntegrity {
		names = append(names, "lib_integrity")
	}
	if cfg.Sensors.ElfRpath {
		names = append(names, "elf_rpath")
	}
	return names
}

// Agent is the hookmon sensor bus daemon that loads sensors and streams events.
type Agent struct {
	cfg       *config.AgentConfig
	logger    *zap.Logger
	transport transport.Transport
	sensors   []sensors.Sensor
	hostname  string
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	rpathCache *sensors.RpathCache
	registry   *registry.Registry

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

	sensorNames := allSensorNames(cfg)
	reg := registry.New(sensorNames)

	// Determine the HTTP port: StatusPort takes precedence, fall back to PrometheusPort.
	httpPort := cfg.StatusPort
	if httpPort == 0 {
		httpPort = cfg.PrometheusPort
	}

	a := &Agent{
		cfg:        cfg,
		logger:     logger,
		transport:  t,
		hostname:   hostname,
		rpathCache: sensors.NewRpathCache(10000),
		registry:   reg,
	}

	if cfg.LokiURL != "" {
		a.loki = observability.NewLokiPusher(cfg.LokiURL, logger)
		logger.Info("loki pusher enabled", zap.String("url", cfg.LokiURL))
	}

	if httpPort > 0 {
		m, err := observability.NewMetrics(httpPort, logger)
		if err != nil {
			logger.Error("failed to start HTTP server", zap.Error(err))
		} else {
			a.metrics = m
			m.RegisterStatusHandler(observability.StatusHandler(reg, hostname, version.Version))
		}
	}

	return a
}

// Run starts the sensor bus: connects to the server, starts sensors, and begins
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

		// Mark the sensor as alive in the registry
		a.registry.Beat(s.Name())

		// Fan events from each sensor into the transport
		a.wg.Add(1)
		go a.forwardEvents(ctx, s)

		// Start Go-side heartbeat tickers for fanotify and audit sensors
		if s.Type() == sensors.SensorTypeFanotify || s.Type() == sensors.SensorTypeAudit {
			a.wg.Add(1)
			go a.sensorHeartbeatTicker(ctx, s.Name())
		}
	}
	if a.metrics != nil {
		a.metrics.SetSensorsActive(activeSensors)
	}

	// Registry evaluator + metrics updater
	a.wg.Add(1)
	go a.registryLoop(ctx)

	// Heartbeat loop to server (skip in console mode)
	if !a.cfg.ConsoleMode {
		a.wg.Add(1)
		go a.heartbeatLoop(ctx)
	}

	<-ctx.Done()
	a.logger.Info("sensor bus shutting down")
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
	if a.cfg.Sensors.ExecInjection {
		a.sensors = append(a.sensors, sensors.NewExecInjectionSensor())
	}
	if a.cfg.Sensors.SHMMonitor {
		a.sensors = append(a.sensors, sensors.NewSHMMonitorSensor())
	}
	if a.cfg.Sensors.DlopenMonitor {
		a.sensors = append(a.sensors, sensors.NewDlopenMonitorSensor())
	}
	if a.cfg.Sensors.LinkerConfig {
		a.sensors = append(a.sensors, sensors.NewLinkerConfigSensor())
	}
	if a.cfg.Sensors.PtraceMonitor {
		a.sensors = append(a.sensors, sensors.NewPtraceMonitorSensor())
	}
	if a.cfg.Sensors.LibIntegrity {
		a.sensors = append(a.sensors, sensors.NewLibIntegritySensor())
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

			// eBPF sensors: the heartbeat comes from BPF map reads (handled separately).
			// For fanotify/audit sensors, the ticker handles it.
			// We also beat on event receipt as a secondary signal.
			a.registry.Beat(s.Name())

			a.sendEvent(evt)

			// ELF RPATH audit: analyze the binary and emit a supplementary event if risky.
			if a.cfg.Sensors.ElfRpath && evt.ExePath != "" {
				a.analyzeAndEmitRpath(evt)
			}
		}
	}
}

// sendEvent dispatches an event to transport, Loki, and metrics.
func (a *Agent) sendEvent(evt *event.HookEvent) {
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

// analyzeAndEmitRpath checks the binary's ELF RPATH/RUNPATH and emits an
// ELF_RPATH event if the highest risk is MEDIUM or above.
func (a *Agent) analyzeAndEmitRpath(origEvt *event.HookEvent) {
	// Check cache first.
	inode, mtime, err := sensors.FileInodeAndMtime(origEvt.ExePath)
	if err != nil {
		return
	}

	detail := a.rpathCache.Get(origEvt.ExePath, inode, mtime.UnixNano())
	if detail == nil {
		var analyzeErr error
		detail, analyzeErr = sensors.AnalyzeElfRpath(origEvt.ExePath)
		if analyzeErr != nil || detail == nil {
			return
		}
		a.rpathCache.Put(origEvt.ExePath, inode, mtime.UnixNano(), detail)
	}

	// Only emit if risk is MEDIUM or above.
	if sensors.RiskBelow(detail.HighestRisk, event.RpathRiskMedium) {
		return
	}

	rpathEvt := &event.HookEvent{
		ID:          uuid.New().String(),
		Timestamp:   origEvt.Timestamp,
		HostID:      origEvt.HostID,
		Hostname:    origEvt.Hostname,
		EventType:   event.EventElfRpath,
		PID:         origEvt.PID,
		PPID:        origEvt.PPID,
		UID:         origEvt.UID,
		GID:         origEvt.GID,
		Comm:        origEvt.Comm,
		Cmdline:     origEvt.Cmdline,
		ExePath:     origEvt.ExePath,
		ExeHash:     origEvt.ExeHash,
		CgroupPath:  origEvt.CgroupPath,
		ContainerID: origEvt.ContainerID,
		Namespace:   origEvt.Namespace,
		ElfRpathDetail: detail,
	}

	a.sendEvent(rpathEvt)
}

// sensorHeartbeatTicker periodically beats the registry for Go-side sensors.
func (a *Agent) sensorHeartbeatTicker(ctx context.Context, name string) {
	defer a.wg.Done()
	interval := a.cfg.HeartbeatSensorInterval
	if interval == 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.registry.Beat(name)
		}
	}
}

// registryLoop evaluates sensor health and updates Prometheus metrics.
func (a *Agent) registryLoop(ctx context.Context) {
	defer a.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.registry.Evaluate()
			if a.metrics != nil {
				a.metrics.UpdateSensorHealth(a.registry)
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

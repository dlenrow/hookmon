package agent

import (
	"context"
	"os"
	"path/filepath"
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
)

// allSensorNames returns the names of the enabled sensors, which are the ones
// the registry tracks.
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

// sensorInterval returns how often sensors are checked.
func sensorInterval(cfg *config.AgentConfig) time.Duration {
	if cfg.HeartbeatSensorInterval > 0 {
		return cfg.HeartbeatSensorInterval
	}
	return 10 * time.Second
}

// deadThreshold returns the configured threshold, or 1.5 check intervals.
func deadThreshold(cfg *config.AgentConfig) time.Duration {
	if cfg.DeadThreshold > 0 {
		return cfg.DeadThreshold
	}
	return sensorInterval(cfg) * 3 / 2
}

// dlopenProbePath returns the configured dlopen helper, or
// hookmon-dlopen-probe next to the running binary.
func dlopenProbePath(cfg *config.AgentConfig) string {
	if cfg.DlopenProbePath != "" {
		return cfg.DlopenProbePath
	}
	exe, err := os.Executable()
	if err != nil {
		return "hookmon-dlopen-probe"
	}
	return filepath.Join(filepath.Dir(exe), "hookmon-dlopen-probe")
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

	registry   *registry.Registry
	health     *healthChecker
	filter     probeFilter
	healthDone chan struct{}

	loki    *observability.LokiPusher
	metrics *observability.Metrics

	enricher *enrichment.Enricher
}

// New creates a new Agent with the given configuration.
func New(cfg *config.AgentConfig, logger *zap.Logger) *Agent {
	hostname, _ := os.Hostname()

	var t transport.Transport
	if cfg.ConsoleMode {
		t = transport.NewConsoleTransport()
	} else {
		t = transport.NewGRPCTransport(cfg, logger, transport.DefaultRetryConfig())
	}

	sensorNames := allSensorNames(cfg)
	reg := registry.NewWithThreshold(sensorNames, deadThreshold(cfg))
	if reg.Threshold() <= sensorInterval(cfg) {
		logger.Warn("dead_threshold is not above heartbeat_sensor_interval; healthy sensors will flap",
			zap.Duration("dead_threshold", reg.Threshold()), zap.Duration("interval", sensorInterval(cfg)))
	}

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
		registry:   reg,
		filter:     probeFilter{self: uint32(os.Getpid())},
		healthDone: make(chan struct{}),
		enricher:   enrichment.NewEnricher(),
	}
	prober := newHookProber(dlopenProbePath(cfg), logger)
	a.health = newHealthChecker(reg, prober.probe, monotonicNow, logger)

	if cfg.LokiURL != "" {
		a.loki = observability.NewLokiPusher(cfg.LokiURL, logger)
		logger.Info("loki pusher enabled", zap.String("url", cfg.LokiURL))
	}

	if httpPort > 0 {
		m, err := observability.NewMetricsOn(cfg.StatusAddr, httpPort, logger)
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
		// Keep the stream to the server up, reconnecting with backoff after
		// any failure, until ctx is cancelled.
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			if err := a.transport.Run(ctx); err != nil {
				a.logger.Error("transport stopped", zap.Error(err))
			}
		}()
	}

	// Start sensors
	a.initSensors()
	activeSensors := 0
	for _, s := range a.sensors {
		if err := s.Start(); err != nil {
			a.logger.Warn("sensor failed to start", zap.String("sensor", s.Name()), zap.Error(err))
			a.registry.Fail(s.Name(), err.Error())
			if a.metrics != nil {
				a.metrics.RecordSensorError(s.Name())
			}
			continue
		}
		activeSensors++
		a.logger.Info("sensor started", zap.String("sensor", s.Name()))

		// eBPF sensors stay "unknown" until the first probe cycle confirms
		// their hook runs. Go-side sensors are alive once started.
		if s.Type() == sensors.SensorTypeBPF {
			if hb, ok := s.(sensors.BPFHealth); ok {
				a.health.add(s.Name(), hb)
			} else {
				a.registry.Unverifiable(s.Name(), "sensor exposes no heartbeat map")
			}
		} else {
			a.registry.Beat(s.Name())
		}

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

	// Probe hooks, read heartbeats, evaluate and update metrics.
	go a.healthLoop(ctx)

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
	if a.cfg.Sensors.ElfRpath {
		a.sensors = append(a.sensors, sensors.NewElfRpathSensor())
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
			if a.filter.drop(evt) {
				continue
			}
			evt.HostID = a.cfg.HostID
			evt.Hostname = a.hostname

			// Process context and the exe hash, cached by file version.
			a.enricher.Enrich(evt)

			// eBPF sensors beat only from the heartbeat map check in the
			// health loop. Go-side sensors also beat on event receipt.
			if s.Type() != sensors.SensorTypeBPF {
				a.registry.Beat(s.Name())
			}

			a.sendEvent(evt)
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

// sensorHeartbeatTicker periodically beats the registry for Go-side sensors.
func (a *Agent) sensorHeartbeatTicker(ctx context.Context, name string) {
	defer a.wg.Done()
	ticker := time.NewTicker(sensorInterval(a.cfg))
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

// healthLoop runs a probe/read/evaluate cycle at start and then once per
// sensor interval, and publishes the result to Prometheus.
func (a *Agent) healthLoop(ctx context.Context) {
	defer close(a.healthDone)
	ticker := time.NewTicker(sensorInterval(a.cfg))
	defer ticker.Stop()

	for {
		a.health.cycle()
		if a.metrics != nil {
			a.metrics.UpdateSensorHealth(a.registry)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
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
	// The health loop reads sensor maps and links; let it finish first.
	<-a.healthDone
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

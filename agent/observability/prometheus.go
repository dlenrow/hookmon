package observability

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/agent/registry"
	"github.com/dlenrow/hookmon/pkg/event"
)

// Metrics exposes Prometheus metrics for the hookmon sensor bus.
type Metrics struct {
	eventsTotal     *prometheus.CounterVec
	sensorErrors    *prometheus.CounterVec
	sensorsActive   prometheus.Gauge
	bpfInsnCount    *prometheus.HistogramVec

	// Per-sensor health metrics
	sensorAlive       *prometheus.GaugeVec
	sensorLastBeat    *prometheus.GaugeVec
	sensorLastBeatAge *prometheus.GaugeVec
	busOverall        *prometheus.GaugeVec

	mux    *http.ServeMux
	server *http.Server
	logger *zap.Logger
}

// NewMetrics creates and registers Prometheus metrics, and starts the HTTP server.
// If reg is non-nil, a /status endpoint is also served. If statusHandler is non-nil,
// it is added to the mux.
func NewMetrics(port int, logger *zap.Logger) (*Metrics, error) {
	promReg := prometheus.NewRegistry()

	m := &Metrics{
		logger: logger,
		eventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hookmon_events_total",
			Help: "Total hook events detected by the sensor bus.",
		}, []string{"event_type", "severity", "comm"}),

		sensorErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hookmon_sensor_errors_total",
			Help: "Total sensor start failures.",
		}, []string{"sensor"}),

		sensorsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hookmon_sensors_active",
			Help: "Number of currently running sensors.",
		}),

		bpfInsnCount: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hookmon_bpf_insn_count",
			Help:    "Distribution of BPF program instruction counts.",
			Buckets: prometheus.ExponentialBuckets(10, 2, 12), // 10, 20, 40, ..., 20480
		}, []string{"prog_name"}),

		sensorAlive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hookmon_sensor_alive",
			Help: "Whether a sensor is alive (1) or dead (0).",
		}, []string{"sensor"}),

		sensorLastBeat: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hookmon_sensor_last_beat_seconds",
			Help: "Unix timestamp of the sensor's last heartbeat.",
		}, []string{"sensor"}),

		sensorLastBeatAge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hookmon_sensor_last_beat_age_seconds",
			Help: "Seconds since the sensor's last heartbeat.",
		}, []string{"sensor"}),

		busOverall: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hookmon_bus_overall",
			Help: "Sensor bus overall status (1 for active state).",
		}, []string{"status"}),
	}

	promReg.MustRegister(
		m.eventsTotal, m.sensorErrors, m.sensorsActive, m.bpfInsnCount,
		m.sensorAlive, m.sensorLastBeat, m.sensorLastBeatAge, m.busOverall,
	)

	m.mux = http.NewServeMux()
	m.mux.Handle("/metrics", promhttp.HandlerFor(promReg, promhttp.HandlerOpts{}))

	m.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: m.mux,
	}

	go func() {
		logger.Info("sensor bus HTTP server starting", zap.Int("port", port))
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	return m, nil
}

// RegisterStatusHandler adds the /status endpoint to the HTTP mux.
func (m *Metrics) RegisterStatusHandler(handler http.HandlerFunc) {
	m.mux.HandleFunc("/status", handler)
}

// UpdateSensorHealth updates per-sensor Prometheus metrics from the registry.
func (m *Metrics) UpdateSensorHealth(reg *registry.Registry) {
	snap := reg.Snapshot()
	now := time.Now()
	for _, s := range snap {
		var alive float64
		if s.Status == "alive" {
			alive = 1
		}
		m.sensorAlive.WithLabelValues(s.Name).Set(alive)

		if !s.LastBeat.IsZero() {
			m.sensorLastBeat.WithLabelValues(s.Name).Set(float64(s.LastBeat.Unix()))
			m.sensorLastBeatAge.WithLabelValues(s.Name).Set(now.Sub(s.LastBeat).Seconds())
		}
	}

	overall := reg.Overall()
	for _, st := range []string{"alive", "degraded", "dead"} {
		var v float64
		if st == overall {
			v = 1
		}
		m.busOverall.WithLabelValues(st).Set(v)
	}
}

// RecordEvent records a hook event in Prometheus metrics.
func (m *Metrics) RecordEvent(evt *event.HookEvent) {
	m.eventsTotal.WithLabelValues(string(evt.EventType), string(evt.Severity), evt.Comm).Inc()

	if evt.BPFDetail != nil && evt.BPFDetail.InsnCount > 0 {
		progName := evt.BPFDetail.ProgName
		if progName == "" {
			progName = "unknown"
		}
		m.bpfInsnCount.WithLabelValues(progName).Observe(float64(evt.BPFDetail.InsnCount))
	}
}

// RecordSensorError increments the sensor error counter.
func (m *Metrics) RecordSensorError(sensor string) {
	m.sensorErrors.WithLabelValues(sensor).Inc()
}

// SetSensorsActive sets the active sensor gauge.
func (m *Metrics) SetSensorsActive(n int) {
	m.sensorsActive.Set(float64(n))
}

// Close shuts down the HTTP server.
func (m *Metrics) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.server.Shutdown(ctx); err != nil {
		m.logger.Warn("HTTP server shutdown error", zap.Error(err))
	}
}

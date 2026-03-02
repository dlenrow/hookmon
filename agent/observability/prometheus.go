package observability

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Metrics exposes Prometheus metrics for the hookmon agent.
type Metrics struct {
	eventsTotal     *prometheus.CounterVec
	sensorErrors    *prometheus.CounterVec
	sensorsActive   prometheus.Gauge
	bpfInsnCount    *prometheus.HistogramVec

	server *http.Server
	logger *zap.Logger
}

// NewMetrics creates and registers Prometheus metrics, and starts the HTTP server.
func NewMetrics(port int, logger *zap.Logger) (*Metrics, error) {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		logger: logger,
		eventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hookmon_events_total",
			Help: "Total hook events detected by the agent.",
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
	}

	reg.MustRegister(m.eventsTotal, m.sensorErrors, m.sensorsActive, m.bpfInsnCount)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	m.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		logger.Info("prometheus metrics server starting", zap.Int("port", port))
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("prometheus server error", zap.Error(err))
		}
	}()

	return m, nil
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

// Close shuts down the Prometheus HTTP server.
func (m *Metrics) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.server.Shutdown(ctx); err != nil {
		m.logger.Warn("prometheus server shutdown error", zap.Error(err))
	}
}

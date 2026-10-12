package observability

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/agent/registry"
	"github.com/dlenrow/hookmon/agent/suppress"
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
	sensorStatus      *prometheus.GaugeVec
	busOverall        *prometheus.GaugeVec

	mux    *http.ServeMux
	server *http.Server
	logger *zap.Logger
}

// NewMetrics creates and registers Prometheus metrics, and starts the HTTP
// server on all interfaces. Use RegisterStatusHandler to add /status.
func NewMetrics(port int, logger *zap.Logger) (*Metrics, error) {
	return NewMetricsOn("", port, logger)
}

// NewMetricsOn is NewMetrics bound to addr:port. An empty addr binds all
// interfaces.
func NewMetricsOn(addr string, port int, logger *zap.Logger) (*Metrics, error) {
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
			Help: "Whether a sensor is alive (1) or not (0): dead, failed, unverifiable or unknown.",
		}, []string{"sensor"}),

		sensorStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hookmon_sensor_status",
			Help: "Sensor status (1 for the sensor's current status, as reported by /status).",
		}, []string{"sensor", "status"}),

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
		m.sensorAlive, m.sensorLastBeat, m.sensorLastBeatAge, m.sensorStatus, m.busOverall,
		suppressedCollector{},
	)

	m.mux = http.NewServeMux()
	m.mux.Handle("/metrics", promhttp.HandlerFor(promReg, promhttp.HandlerOpts{}))

	m.server = &http.Server{
		Addr:    net.JoinHostPort(addr, strconv.Itoa(port)),
		Handler: m.mux,
	}

	go func() {
		logger.Info("sensor bus HTTP server starting", zap.String("addr", m.server.Addr))
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	return m, nil
}

// suppressedDesc describes hookmon_events_suppressed_total, read from the
// suppress package's counts at each scrape.
var suppressedDesc = prometheus.NewDesc(
	"hookmon_events_suppressed_total",
	"Events a sensor saw and dropped because they cannot be a stealth hook, by sensor and reason.",
	[]string{"sensor", "reason"}, nil,
)

// suppressedCollector exports the suppress package's counts, so the sensors
// count without importing Prometheus.
type suppressedCollector struct{}

func (suppressedCollector) Describe(ch chan<- *prometheus.Desc) { ch <- suppressedDesc }

func (suppressedCollector) Collect(ch chan<- prometheus.Metric) {
	for _, c := range suppress.Snapshot() {
		ch <- prometheus.MustNewConstMetric(suppressedDesc, prometheus.CounterValue, float64(c.N), c.Sensor, c.Reason)
	}
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
		if s.Status == registry.StatusAlive {
			alive = 1
		}
		m.sensorAlive.WithLabelValues(s.Name).Set(alive)
		for _, st := range sensorStatuses {
			var v float64
			if st == s.Status {
				v = 1
			}
			m.sensorStatus.WithLabelValues(s.Name, st).Set(v)
		}

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

// sensorStatuses lists every status a sensor can report.
var sensorStatuses = []string{
	registry.StatusUnknown, registry.StatusAlive, registry.StatusDead,
	registry.StatusFailed, registry.StatusUnverifiable,
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

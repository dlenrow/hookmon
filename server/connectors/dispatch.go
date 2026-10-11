package connectors

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// AlertFilter decides whether an alert is new or repeats one sent recently.
// policy.AlertManager implements it. Admit records the alert when it
// returns true.
type AlertFilter interface {
	Admit(evt *event.HookEvent) bool
}

// Dispatcher routes events to the connectors' queues. Ingestion calls Send
// for every stored event; the watchdog calls Dispatch for AGENT_OFFLINE and
// the heartbeat handler for AGENT_RECOVERED. Both only enqueue, so they
// never wait for a sink.
//
// Routing, per connector (see Delivery.MinSeverity):
//   - Alert connectors (min_severity ALERT or CRITICAL) receive alerts:
//     events at or above min_severity whose policy action is not ALLOW. A
//     repeat of an alert sent within the AlertFilter's window is dropped.
//   - Event-feed connectors (min_severity INFO or WARN) receive every event
//     at or above min_severity, allowed or not, repeats included.
//   - Host status events (Dispatch) go to every connector, whatever its
//     min_severity, and are never treated as repeats: each AGENT_OFFLINE
//     marks a host going UNRESPONSIVE, and each AGENT_RECOVERED (INFO) the
//     end of that outage, which an alert connector that got the
//     AGENT_OFFLINE needs to close it.
type Dispatcher struct {
	mu     sync.RWMutex
	closed bool
	queues []*queue

	alerts AlertFilter
	// dedup is set when some connector is an alert connector, so the
	// filter is consulted (and records the alert) only when it matters.
	dedup bool

	// workCtx is the workers' context. Close cancels it if the queues have
	// not drained by its deadline, which aborts deliveries and retries.
	workCtx context.Context
	cancel  context.CancelFunc

	logger *zap.Logger
}

// New builds the connectors cfg enables, checks that each one can start
// (a syslog connection, the Kafka producer, the Elasticsearch ILM setup),
// and starts their workers. If any connector fails, the ones already built
// are closed and the error is returned: the server must not start with a
// connector it was told to run but cannot.
func New(ctx context.Context, cfg Config, alerts AlertFilter, logger *zap.Logger) (*Dispatcher, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	type built struct {
		c Connector
		d Delivery
	}
	var all []built
	fail := func(err error) (*Dispatcher, error) {
		for _, b := range all {
			b.c.Close()
		}
		return nil, err
	}

	if c := cfg.Syslog; c != nil {
		conn, err := NewSyslogConnector(*c, logger)
		if err != nil {
			return fail(fmt.Errorf("connectors.syslog: %w", err))
		}
		all = append(all, built{conn, c.Delivery.withDefaults(1)})
	}
	if c := cfg.Splunk; c != nil {
		conn, err := NewSplunkConnector(*c, logger)
		if err != nil {
			return fail(fmt.Errorf("connectors.splunk: %w", err))
		}
		all = append(all, built{conn, c.Delivery.withDefaults(100)})
	}
	if c := cfg.Elastic; c != nil {
		conn, err := NewElasticConnector(*c, logger)
		if err != nil {
			return fail(fmt.Errorf("connectors.elasticsearch: %w", err))
		}
		if err := conn.Setup(ctx); err != nil {
			conn.Close()
			return fail(fmt.Errorf("connectors.elasticsearch: %w", err))
		}
		all = append(all, built{conn, c.Delivery.withDefaults(100)})
	}
	if c := cfg.Webhook; c != nil {
		d := c.Delivery.withDefaults(1)
		conn, err := NewWebhookConnector(*c, d.BatchSize > 1, logger)
		if err != nil {
			return fail(fmt.Errorf("connectors.webhook: %w", err))
		}
		all = append(all, built{conn, d})
	}
	if c := cfg.Kafka; c != nil {
		conn, err := NewKafkaConnector(*c, logger)
		if err != nil {
			return fail(fmt.Errorf("connectors.kafka: %w", err))
		}
		all = append(all, built{conn, c.Delivery.withDefaults(100)})
	}

	d := newDispatcher(alerts, logger)
	for _, b := range all {
		d.add(b.c, b.d, defaultRetry)
	}
	d.start()
	return d, nil
}

func newDispatcher(alerts AlertFilter, logger *zap.Logger) *Dispatcher {
	if logger == nil {
		logger = zap.NewNop()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Dispatcher{alerts: alerts, workCtx: ctx, cancel: cancel, logger: logger}
}

// add registers a connector. Call it before start.
func (d *Dispatcher) add(c Connector, del Delivery, retry retryPolicy) {
	q := &queue{
		conn:      c,
		min:       severityRank(del.MinSeverity),
		ch:        make(chan *event.HookEvent, del.QueueSize),
		batchSize: del.BatchSize,
		flush:     del.FlushInterval,
		retry:     retry,
		done:      make(chan struct{}),
		logger:    d.logger.With(zap.String("connector", c.Name())),
	}
	if q.min >= severityRank(event.SeverityAlert) {
		d.dedup = true
	}
	d.queues = append(d.queues, q)
	d.logger.Info("connector enabled",
		zap.String("connector", c.Name()),
		zap.String("min_severity", string(del.MinSeverity)),
		zap.Int("queue_size", del.QueueSize),
		zap.Int("batch_size", del.BatchSize),
		zap.Duration("flush_interval", del.FlushInterval),
	)
}

func (d *Dispatcher) start() {
	for _, q := range d.queues {
		go q.run(d.workCtx)
	}
}

// Len is the number of connectors.
func (d *Dispatcher) Len() int { return len(d.queues) }

// Send queues a stored event for the connectors that take it. It never
// blocks and never fails; it implements ingestion.Connector.
func (d *Dispatcher) Send(evt *event.HookEvent) error {
	d.route(evt)
	return nil
}

// Dispatch queues a host status event the server raised (AGENT_OFFLINE,
// AGENT_RECOVERED) for every connector. It implements the watchdog's
// AlertSink and the ingestion server's StatusSink.
func (d *Dispatcher) Dispatch(evt *event.HookEvent) {
	if evt == nil {
		return
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return
	}
	for _, q := range d.queues {
		q.enqueue(evt)
	}
}

func (d *Dispatcher) route(evt *event.HookEvent) {
	if evt == nil || len(d.queues) == 0 {
		return
	}
	sev := severityRank(evt.Severity)
	if sev == 0 {
		sev = severityRank(event.SeverityInfo)
	}
	alert := sev >= severityRank(event.SeverityAlert) &&
		(evt.PolicyResult == nil || evt.PolicyResult.Action != event.ActionAllow)
	fresh := true
	if alert && d.dedup && d.alerts != nil {
		fresh = d.alerts.Admit(evt)
	}

	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return
	}
	for _, q := range d.queues {
		if sev < q.min {
			continue
		}
		if q.min >= severityRank(event.SeverityAlert) && (!alert || !fresh) {
			continue
		}
		q.enqueue(evt)
	}
}

// Close stops taking events, lets each worker deliver what it has queued
// until ctx is done, then aborts what is left and closes the connectors.
func (d *Dispatcher) Close(ctx context.Context) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	for _, q := range d.queues {
		close(q.ch)
	}
	d.mu.Unlock()

	for _, q := range d.queues {
		select {
		case <-q.done:
		case <-ctx.Done():
			d.cancel()
			<-q.done
		}
	}
	d.cancel()

	var errs []string
	for _, q := range d.queues {
		st := q.stats()
		q.logger.Info("connector stopped",
			zap.Uint64("sent", st.Sent),
			zap.Uint64("dropped", st.Dropped),
			zap.Uint64("failed", st.Failed),
		)
		if err := q.conn.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", q.conn.Name(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close connectors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Stats is one connector's delivery counts since the server started.
type Stats struct {
	Connector string
	// Sent events were accepted by the sink.
	Sent uint64
	// Dropped events found the connector's queue full.
	Dropped uint64
	// Failed events were in a batch the sink refused, or that still failed
	// after the retries.
	Failed uint64
	// Queued events are waiting in the queue now.
	Queued int
}

// Stats returns each connector's counts, in config order.
func (d *Dispatcher) Stats() []Stats {
	out := make([]Stats, 0, len(d.queues))
	for _, q := range d.queues {
		out = append(out, q.stats())
	}
	return out
}

// severityRank orders severities; 0 is not a severity.
func severityRank(s event.Severity) int {
	switch s {
	case event.SeverityInfo:
		return 1
	case event.SeverityWarn:
		return 2
	case event.SeverityAlert:
		return 3
	case event.SeverityCritical:
		return 4
	}
	return 0
}

// retryPolicy is how a worker retries a batch that failed with a
// retryable error: attempts in all, waiting base, then 2*base, and so on.
type retryPolicy struct {
	attempts int
	base     time.Duration
}

var defaultRetry = retryPolicy{attempts: 3, base: 500 * time.Millisecond}

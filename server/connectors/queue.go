package connectors

import (
	"context"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// queue is one connector's bounded queue and its worker.
type queue struct {
	conn      Connector
	min       int // severityRank of min_severity
	ch        chan *event.HookEvent
	batchSize int
	flush     time.Duration
	retry     retryPolicy
	done      chan struct{}
	logger    *zap.Logger

	sent, dropped, failed atomic.Uint64
}

// enqueue adds evt without waiting. A full queue drops it; the first drop
// and every 1000th after it are logged.
func (q *queue) enqueue(evt *event.HookEvent) {
	select {
	case q.ch <- evt:
	default:
		n := q.dropped.Add(1)
		if n == 1 || n%1000 == 0 {
			q.logger.Warn("connector queue full; dropping events",
				zap.Uint64("dropped_total", n),
				zap.Int("queue_size", cap(q.ch)),
				zap.String("event_id", evt.ID),
			)
		}
	}
}

func (q *queue) stats() Stats {
	return Stats{
		Connector: q.conn.Name(),
		Sent:      q.sent.Load(),
		Dropped:   q.dropped.Load(),
		Failed:    q.failed.Load(),
		Queued:    len(q.ch),
	}
}

// run delivers batches until the channel is closed and drained. A batch
// goes out when it holds batchSize events or flush has passed since its
// first event.
func (q *queue) run(ctx context.Context) {
	defer close(q.done)
	batch := make([]*event.HookEvent, 0, q.batchSize)
	var timer *time.Timer
	var timerC <-chan time.Time
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
			timer, timerC = nil, nil
		}
	}
	send := func() {
		stopTimer()
		if len(batch) == 0 {
			return
		}
		q.deliver(ctx, batch)
		batch = make([]*event.HookEvent, 0, q.batchSize)
	}
	for {
		select {
		case evt, ok := <-q.ch:
			if !ok {
				send()
				return
			}
			batch = append(batch, evt)
			if len(batch) >= q.batchSize {
				send()
			} else if timer == nil {
				timer = time.NewTimer(q.flush)
				timerC = timer.C
			}
		case <-timerC:
			timer, timerC = nil, nil
			send()
		}
	}
}

// deliver sends one batch, retrying a retryable failure with exponential
// backoff. It runs on the worker goroutine, never on the ingestion path.
func (q *queue) deliver(ctx context.Context, batch []*event.HookEvent) {
	n := uint64(len(batch))
	var err error
	attempt := 0
	for ; attempt < q.retry.attempts; attempt++ {
		if attempt > 0 {
			delay := q.retry.base << (attempt - 1)
			q.logger.Debug("connector retry", zap.Int("attempt", attempt+1), zap.Duration("delay", delay), zap.Error(err))
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
			case <-t.C:
			}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
			break
		}
		err = q.conn.Send(ctx, batch)
		if err == nil {
			q.sent.Add(n)
			return
		}
		if !isRetryable(err) {
			attempt++
			break
		}
	}
	q.failed.Add(n)
	q.logger.Error("connector delivery failed; events dropped",
		zap.Int("events", len(batch)),
		zap.Int("attempts", attempt),
		zap.String("first_event_id", batch[0].ID),
		zap.Error(err),
	)
}

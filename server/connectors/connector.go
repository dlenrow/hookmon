// Package connectors delivers HookMon events to SIEM systems: Syslog/CEF
// (RFC 5424), Splunk HEC, Elasticsearch, a generic JSON webhook and Kafka.
//
// Every connector runs behind its own bounded queue and worker goroutine
// (see Dispatcher). Ingestion only enqueues, so a slow or unreachable sink
// never holds up a bus's event stream; when a queue is full its events are
// dropped and counted.
package connectors

import (
	"context"
	"errors"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Connector delivers batches of events to one sink. Its worker calls Send
// from a single goroutine, with at most the connector's batch_size events,
// and must not change them: the same events go to every connector and to
// the dashboard's live feed. Send honours ctx, which is cancelled when the
// server stops and the queue has not drained in time.
//
// Send returns an error made with retryable for a failure worth retrying
// (network error, timeout, HTTP 429 or 5xx); the worker then retries the
// whole batch with backoff. Any other error drops the batch.
type Connector interface {
	Name() string
	Send(ctx context.Context, batch []*event.HookEvent) error
	Close() error
}

// retryableError marks a delivery failure worth retrying.
type retryableError struct{ err error }

func (e *retryableError) Error() string { return e.err.Error() }
func (e *retryableError) Unwrap() error { return e.err }

// retryable marks err as worth retrying. It returns nil for nil.
func retryable(err error) error {
	if err == nil {
		return nil
	}
	return &retryableError{err: err}
}

// isRetryable reports whether err, or an error it wraps, was marked with
// retryable.
func isRetryable(err error) bool {
	var r *retryableError
	return errors.As(err, &r)
}

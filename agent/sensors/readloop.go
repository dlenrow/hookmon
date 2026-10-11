package sensors

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Pacing for a ring buffer read loop that gets errors other than the reader
// closing. Before step 7f such a loop went straight back to Read and spun a
// core for as long as the error lasted.
const (
	readBackoffMin = 10 * time.Millisecond
	readBackoffMax = time.Second

	// readFailingAfter consecutive errors, the last within readFailingFor,
	// make the sensor report itself failing (readErrors.err).
	readFailingAfter = 3
	readFailingFor   = 5 * time.Second
)

// readErrors tracks a sensor's ring buffer read errors. The read loop calls
// handle on an error and ok after a good read; CheckAttached reports err,
// so the health checker records a miss and, if it lasts, marks the sensor
// dead with the read error as the reason. A read loop that keeps failing
// therefore shows up in /status and the alerts instead of losing events
// while the sensor still looks alive.
type readErrors struct {
	// source names what is read, for the error; "ring buffer" if empty.
	source string

	consecutive atomic.Int32

	mu    sync.Mutex
	last  error
	at    time.Time
	delay time.Duration

	// now and sleep are the clock and the wait; nil means time.Now and a
	// timer. sleep returns false if done closed first.
	now   func() time.Time
	sleep func(d time.Duration, done <-chan struct{}) bool
}

// handle deals with an error from the reader. It returns false when the
// read loop must end: the reader is closed or done is closed. Otherwise it
// records the error and waits before the next read, 10 ms at first and
// doubling to 1 s while errors continue.
func (r *readErrors) handle(err error, done <-chan struct{}) bool {
	if errors.Is(err, os.ErrClosed) {
		return false
	}
	select {
	case <-done:
		return false
	default:
	}
	r.consecutive.Add(1)
	r.mu.Lock()
	r.last, r.at = err, r.clock()
	if r.delay == 0 {
		r.delay = readBackoffMin
	} else if r.delay < readBackoffMax {
		r.delay = min(2*r.delay, readBackoffMax)
	}
	d := r.delay
	r.mu.Unlock()
	return r.wait(d, done)
}

// ok records a successful read: the next error starts the backoff again.
func (r *readErrors) ok() {
	if r.consecutive.Load() == 0 {
		return
	}
	r.consecutive.Store(0)
	r.mu.Lock()
	r.delay = 0
	r.mu.Unlock()
}

// err returns the read error while the loop is failing: at least
// readFailingAfter errors in a row, the last one less than readFailingFor
// ago. A loop that recovered, or that has been blocked in Read since its
// last error, reports nil.
func (r *readErrors) err() error {
	n := r.consecutive.Load()
	if n < readFailingAfter {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.clock().Sub(r.at) >= readFailingFor {
		return nil
	}
	source := r.source
	if source == "" {
		source = "ring buffer"
	}
	return fmt.Errorf("%s read failing (%d errors in a row): %w", source, n, r.last)
}

func (r *readErrors) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

func (r *readErrors) wait(d time.Duration, done <-chan struct{}) bool {
	if r.sleep != nil {
		return r.sleep(d, done)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-done:
		return false
	case <-t.C:
		return true
	}
}

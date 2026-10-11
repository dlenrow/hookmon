package sensors

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// robReadLoop is the shape of every ring buffer read loop: read, and on an
// error ask handle whether to go on. It returns how many reads it made.
func robReadLoop(r *readErrors, read func() error, done <-chan struct{}) int {
	n := 0
	for {
		n++
		if err := read(); err != nil {
			if !r.handle(err, done) {
				return n
			}
			continue
		}
		r.ok()
	}
}

// TestReadErrors_NoSpin: a reader that fails with anything but "closed"
// is retried with backoff, not in a tight loop. Before step 7f the read
// loops went straight back to Read: here that is millions of calls in
// 300 ms; with the backoff it is a handful.
func TestReadErrors_NoSpin(t *testing.T) {
	var r readErrors
	done := make(chan struct{})
	time.AfterFunc(300*time.Millisecond, func() { close(done) })
	reads := robReadLoop(&r, func() error { return errors.New("epoll_wait: bad file descriptor") }, done)
	// 10+20+40+80+160 ms of waits fit in 300 ms: at most 6 reads.
	if reads > 8 {
		t.Errorf("%d reads in 300 ms with a failing reader; the loop spins", reads)
	}
	t.Logf("%d reads in 300 ms", reads)
}

// TestReadErrors_ClosedEndsLoop: a closed reader ends the loop at once,
// without waiting for done (which the loops used to spin until).
func TestReadErrors_ClosedEndsLoop(t *testing.T) {
	var r readErrors
	start := time.Now()
	reads := robReadLoop(&r, func() error { return fmt.Errorf("ringbuffer: %w", os.ErrClosed) }, make(chan struct{}))
	if reads != 1 || time.Since(start) > 100*time.Millisecond {
		t.Errorf("closed reader: %d reads in %v, want 1 at once", reads, time.Since(start))
	}
}

// TestReadErrors_BackoffAndReport: waits double from 10 ms to 1 s; after 3
// errors in a row, the last within 5 s, err reports the read error (which
// CheckAttached passes to the health checker). A good read resets both,
// and so does 5 s with no error (the loop is blocked in Read again).
func TestReadErrors_BackoffAndReport(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	var waits []time.Duration
	r := readErrors{
		now: func() time.Time { return now },
		sleep: func(d time.Duration, _ <-chan struct{}) bool {
			waits = append(waits, d)
			return true
		},
	}
	fail := errors.New("read sample: bad header")
	done := make(chan struct{})

	for i := 0; i < 2; i++ {
		r.handle(fail, done)
	}
	if err := r.err(); err != nil {
		t.Errorf("after 2 errors: %v, want nil", err)
	}
	for i := 0; i < 8; i++ {
		r.handle(fail, done)
	}
	want := []time.Duration{10, 20, 40, 80, 160, 320, 640, 1000, 1000, 1000}
	for i := range want {
		want[i] *= time.Millisecond
	}
	if fmt.Sprint(waits) != fmt.Sprint(want) {
		t.Errorf("waits %v, want %v", waits, want)
	}
	err := r.err()
	if err == nil || !errors.Is(err, fail) || !strings.Contains(err.Error(), "10 errors in a row") {
		t.Errorf("after 10 errors: %v", err)
	}

	now = now.Add(5 * time.Second)
	if err := r.err(); err != nil {
		t.Errorf("5 s after the last error: %v, want nil", err)
	}

	r.ok()
	waits = nil
	r.handle(fail, done)
	if r.err() != nil || len(waits) != 1 || waits[0] != readBackoffMin {
		t.Errorf("after a good read: err %v, waits %v; want nil and a fresh 10 ms", r.err(), waits)
	}

	// Stopping during a wait ends the loop.
	close(done)
	if r.handle(fail, done) {
		t.Error("handle after done closed: true, want false")
	}
}

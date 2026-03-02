package ingestion

import (
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiter enforces per-host event rate limits. Each host is assigned an
// independent token-bucket limiter the first time it is seen. This prevents
// a single misbehaving or compromised agent from overwhelming the ingestion
// pipeline.
type RateLimiter struct {
	// perHostRate is the steady-state events per second allowed per host.
	perHostRate rate.Limit

	// burst is the maximum burst size (bucket depth) per host.
	burst int

	// limiters maps host ID to its rate.Limiter. sync.Map is used instead
	// of a mutex-protected map because the access pattern is read-heavy
	// with occasional inserts, which is the ideal case for sync.Map.
	limiters sync.Map
}

// NewRateLimiter creates a RateLimiter that allows perHostRate events per
// second with the given burst size for each host. A burst of at least 1 is
// enforced to avoid permanently blocking hosts.
//
// Example: NewRateLimiter(100, 200) allows 100 events/sec steady state
// with bursts up to 200 events per host.
func NewRateLimiter(perHostRate float64, burst int) *RateLimiter {
	if burst < 1 {
		burst = 1
	}
	return &RateLimiter{
		perHostRate: rate.Limit(perHostRate),
		burst:       burst,
	}
}

// Allow checks whether a single event from the specified host should be
// permitted. It returns true if the event is within the rate limit and false
// if it should be rejected. A new limiter is created lazily for hosts that
// have not been seen before.
func (rl *RateLimiter) Allow(hostID string) bool {
	limiter, ok := rl.limiters.Load(hostID)
	if !ok {
		// First event from this host — create a new limiter.
		newLimiter := rate.NewLimiter(rl.perHostRate, rl.burst)
		// LoadOrStore handles the race where two goroutines create limiters
		// for the same hostID concurrently — only one is kept.
		actual, _ := rl.limiters.LoadOrStore(hostID, newLimiter)
		limiter = actual
	}
	return limiter.(*rate.Limiter).Allow()
}

// Reset removes the rate limiter state for a specific host. This can be
// useful when a host is re-enrolled or its rate limit configuration changes.
func (rl *RateLimiter) Reset(hostID string) {
	rl.limiters.Delete(hostID)
}

// ResetAll clears all per-host rate limiter state. New limiters will be
// created on demand for subsequent events.
func (rl *RateLimiter) ResetAll() {
	rl.limiters.Range(func(key, _ any) bool {
		rl.limiters.Delete(key)
		return true
	})
}

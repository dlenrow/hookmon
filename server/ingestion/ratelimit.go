package ingestion

import (
	"container/list"
	"sync"

	"golang.org/x/time/rate"
)

// DefaultRateLimiterHosts bounds how many hosts' limiters a RateLimiter
// keeps. It is far above any fleet the server is meant for, so evictions
// happen only under churn of many identities.
const DefaultRateLimiterHosts = 10000

// RateLimiter enforces per-host event rate limits. Each host gets its own
// token bucket the first time it is seen. This keeps a single misbehaving
// or compromised bus from overwhelming the ingestion pipeline.
//
// The key is the authenticated host ID (the CN of the bus's verified client
// certificate), never a value from a message; see IngestionServer. The table
// of limiters is bounded: when it is full, the host seen least recently is
// evicted. An evicted host starts again with a full bucket, so a host could
// reset its own limit only by making more than maxHosts other identities
// send in between, and each identity is a certificate the CA signed at
// enrollment.
type RateLimiter struct {
	// perHostRate is the steady-state events per second allowed per host.
	perHostRate rate.Limit

	// burst is the maximum burst size (bucket depth) per host.
	burst int

	// maxHosts bounds the number of limiters kept.
	maxHosts int

	mu sync.Mutex
	// byKey maps a host ID to its element in lru. lru runs from most to
	// least recently seen; each element's Value is a *rlEntry.
	byKey map[string]*list.Element
	lru   *list.List
}

type rlEntry struct {
	key     string
	limiter *rate.Limiter
}

// NewRateLimiter creates a RateLimiter that allows perHostRate events per
// second with the given burst size for each host, for up to
// DefaultRateLimiterHosts hosts. A burst of at least 1 is enforced to avoid
// permanently blocking hosts.
//
// Example: NewRateLimiter(100, 200) allows 100 events/sec steady state
// with bursts up to 200 events per host.
func NewRateLimiter(perHostRate float64, burst int) *RateLimiter {
	return NewRateLimiterSize(perHostRate, burst, DefaultRateLimiterHosts)
}

// NewRateLimiterSize is NewRateLimiter with an explicit bound on the number
// of hosts tracked. A bound below 1 means 1.
func NewRateLimiterSize(perHostRate float64, burst, maxHosts int) *RateLimiter {
	if burst < 1 {
		burst = 1
	}
	if maxHosts < 1 {
		maxHosts = 1
	}
	return &RateLimiter{
		perHostRate: rate.Limit(perHostRate),
		burst:       burst,
		maxHosts:    maxHosts,
		byKey:       make(map[string]*list.Element),
		lru:         list.New(),
	}
}

// Allow checks whether a single event from the specified host should be
// permitted. It returns true if the event is within the rate limit and false
// if it should be rejected. A new limiter is created for a host not seen
// before, evicting the least recently seen host if the table is full.
func (rl *RateLimiter) Allow(hostID string) bool {
	return rl.limiter(hostID).Allow()
}

func (rl *RateLimiter) limiter(hostID string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if el, ok := rl.byKey[hostID]; ok {
		rl.lru.MoveToFront(el)
		return el.Value.(*rlEntry).limiter
	}
	e := &rlEntry{key: hostID, limiter: rate.NewLimiter(rl.perHostRate, rl.burst)}
	rl.byKey[hostID] = rl.lru.PushFront(e)
	for rl.lru.Len() > rl.maxHosts {
		oldest := rl.lru.Back()
		rl.lru.Remove(oldest)
		delete(rl.byKey, oldest.Value.(*rlEntry).key)
	}
	return e.limiter
}

// Len returns the number of hosts whose limiters are kept.
func (rl *RateLimiter) Len() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.lru.Len()
}

// Reset removes the rate limiter state for a specific host. This can be
// useful when a host is re-enrolled or its rate limit configuration changes.
func (rl *RateLimiter) Reset(hostID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if el, ok := rl.byKey[hostID]; ok {
		rl.lru.Remove(el)
		delete(rl.byKey, hostID)
	}
}

// ResetAll clears all per-host rate limiter state. New limiters will be
// created on demand for subsequent events.
func (rl *RateLimiter) ResetAll() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.byKey = make(map[string]*list.Element)
	rl.lru.Init()
}

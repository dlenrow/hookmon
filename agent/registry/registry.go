package registry

import (
	"sync"
	"time"
)

// DeadThreshold is the default staleness limit. The bus checks every sensor
// once per 10 s cycle and evaluates right after, so a healthy sensor's beat
// is ~0 s old at evaluation, one missed cycle makes it ~10 s old and two make
// it ~20 s old. 15 s sits between those: one miss never flips a sensor, two
// consecutive misses always do. A hook that stops running just after a check
// is therefore reported dead at most two cycles (20 s) later.
const DeadThreshold = 15 * time.Second

// Sensor statuses.
const (
	StatusUnknown      = "unknown"      // registered, liveness not yet confirmed
	StatusAlive        = "alive"        // beat within the threshold
	StatusDead         = "dead"         // no beat within the threshold
	StatusFailed       = "failed"       // Start returned an error
	StatusUnverifiable = "unverifiable" // the bus cannot test this sensor
)

// SensorStatus tracks the health of a single sensor.
type SensorStatus struct {
	Name     string    `json:"name"`
	LastBeat time.Time `json:"last_beat"`
	Status   string    `json:"status"` // one of the Status* constants
	Reason   string    `json:"reason,omitempty"`

	registered time.Time
}

// Registry tracks heartbeat status for all sensors.
type Registry struct {
	mu        sync.RWMutex
	sensors   map[string]*SensorStatus
	threshold time.Duration
}

// New creates a Registry pre-populated with the given sensor names in
// "unknown" state, using the default DeadThreshold.
func New(names []string) *Registry {
	return NewWithThreshold(names, DeadThreshold)
}

// NewWithThreshold is New with a configurable dead threshold. A non-positive
// threshold selects the default.
func NewWithThreshold(names []string, threshold time.Duration) *Registry {
	if threshold <= 0 {
		threshold = DeadThreshold
	}
	now := time.Now()
	r := &Registry{sensors: make(map[string]*SensorStatus, len(names)), threshold: threshold}
	for _, n := range names {
		r.sensors[n] = &SensorStatus{Name: n, Status: StatusUnknown, registered: now}
	}
	return r
}

// Threshold returns the dead threshold in use.
func (r *Registry) Threshold() time.Duration { return r.threshold }

// Beat records a heartbeat from the named sensor. It does not revive a
// sensor that failed to start.
func (r *Registry) Beat(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sensors[name]; ok && s.Status != StatusFailed {
		s.LastBeat = time.Now()
		s.Status = StatusAlive
		s.Reason = ""
	}
}

// Miss records why a check of the named sensor did not produce a beat. The
// status is left to Evaluate.
func (r *Registry) Miss(name, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sensors[name]; ok && s.Status != StatusFailed {
		s.Reason = reason
	}
}

// Fail marks the named sensor as failed to start. Failed is permanent for the
// life of the bus.
func (r *Registry) Fail(name, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sensors[name]; ok {
		s.Status = StatusFailed
		s.Reason = reason
	}
}

// Unverifiable marks the named sensor as one the bus cannot currently test.
// A later Beat clears it.
func (r *Registry) Unverifiable(name, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sensors[name]; ok && s.Status != StatusFailed {
		s.Status = StatusUnverifiable
		s.Reason = reason
	}
}

// Evaluate updates status for all sensors based on staleness. An alive
// sensor whose last beat is older than the threshold becomes dead, and so
// does an unknown sensor that has not beaten within the threshold of being
// registered.
func (r *Registry) Evaluate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for _, s := range r.sensors {
		switch s.Status {
		case StatusAlive:
			if now.Sub(s.LastBeat) > r.threshold {
				s.Status = StatusDead
			}
		case StatusUnknown:
			if now.Sub(s.registered) > r.threshold {
				s.Status = StatusDead
				if s.Reason == "" {
					s.Reason = "no heartbeat since start"
				}
			}
		}
	}
}

// Snapshot returns a copy of current status for all sensors.
func (r *Registry) Snapshot() []SensorStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SensorStatus, 0, len(r.sensors))
	for _, s := range r.sensors {
		out = append(out, *s)
	}
	return out
}

// ForceLastBeat sets a sensor's last beat time directly (for testing).
func (r *Registry) ForceLastBeat(name string, t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sensors[name]; ok {
		s.LastBeat = t
		if s.Status == StatusUnknown {
			s.Status = StatusAlive
		}
	}
}

// Overall returns "alive" only when every registered sensor is alive,
// "dead" when none is, and "degraded" otherwise. Unknown, failed and
// unverifiable sensors count as not alive.
func (r *Registry) Overall() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	alive := 0
	for _, s := range r.sensors {
		if s.Status == StatusAlive {
			alive++
		}
	}
	switch {
	case len(r.sensors) > 0 && alive == len(r.sensors):
		return "alive"
	case alive == 0:
		return "dead"
	default:
		return "degraded"
	}
}

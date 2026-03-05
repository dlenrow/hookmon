package registry

import (
	"sync"
	"time"
)

const DeadThreshold = 35 * time.Second // 3x heartbeat interval + buffer

// SensorStatus tracks the health of a single sensor.
type SensorStatus struct {
	Name     string    `json:"name"`
	LastBeat time.Time `json:"last_beat"`
	Status   string    `json:"status"` // "alive", "dead", "unknown"
}

// Registry tracks heartbeat status for all sensors.
type Registry struct {
	mu      sync.RWMutex
	sensors map[string]*SensorStatus
}

// New creates a Registry pre-populated with the given sensor names in "unknown" state.
func New(names []string) *Registry {
	r := &Registry{sensors: make(map[string]*SensorStatus, len(names))}
	for _, n := range names {
		r.sensors[n] = &SensorStatus{Name: n, Status: "unknown"}
	}
	return r
}

// Beat records a heartbeat from the named sensor.
func (r *Registry) Beat(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sensors[name]; ok {
		s.LastBeat = time.Now()
		s.Status = "alive"
	}
}

// Evaluate updates status for all sensors based on staleness.
func (r *Registry) Evaluate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for _, s := range r.sensors {
		if s.Status == "unknown" {
			continue
		}
		if now.Sub(s.LastBeat) > DeadThreshold {
			s.Status = "dead"
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
		if s.Status == "unknown" {
			s.Status = "alive"
		}
	}
}

// Overall returns "alive", "degraded", or "dead".
func (r *Registry) Overall() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	dead, alive := 0, 0
	for _, s := range r.sensors {
		switch s.Status {
		case "dead":
			dead++
		case "alive":
			alive++
		}
	}
	if dead == 0 {
		return "alive"
	}
	if alive == 0 {
		return "dead"
	}
	return "degraded"
}

package registry

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	r := New([]string{"a", "b"})
	snap := r.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 sensors, got %d", len(snap))
	}
	for _, s := range snap {
		if s.Status != "unknown" {
			t.Errorf("expected unknown status for %s, got %s", s.Name, s.Status)
		}
	}
}

func TestBeat(t *testing.T) {
	r := New([]string{"sensor1"})
	r.Beat("sensor1")

	snap := r.Snapshot()
	if snap[0].Status != "alive" {
		t.Errorf("expected alive after beat, got %s", snap[0].Status)
	}
	if snap[0].LastBeat.IsZero() {
		t.Error("expected non-zero last beat")
	}
}

func TestBeatUnknownSensor(t *testing.T) {
	r := New([]string{"sensor1"})
	r.Beat("nonexistent") // should not panic
}

func TestEvaluateAlive(t *testing.T) {
	r := New([]string{"sensor1"})
	r.Beat("sensor1")
	r.Evaluate()

	snap := r.Snapshot()
	if snap[0].Status != "alive" {
		t.Errorf("expected alive, got %s", snap[0].Status)
	}
}

func TestEvaluateDead(t *testing.T) {
	r := New([]string{"sensor1"})
	// Manually set a stale beat time
	r.mu.Lock()
	r.sensors["sensor1"].LastBeat = time.Now().Add(-40 * time.Second)
	r.sensors["sensor1"].Status = "alive"
	r.mu.Unlock()

	r.Evaluate()

	snap := r.Snapshot()
	if snap[0].Status != "dead" {
		t.Errorf("expected dead, got %s", snap[0].Status)
	}
}

func TestEvaluateSkipsUnknown(t *testing.T) {
	r := New([]string{"sensor1"})
	r.Evaluate()

	snap := r.Snapshot()
	if snap[0].Status != "unknown" {
		t.Errorf("expected unknown to remain, got %s", snap[0].Status)
	}
}

func TestOverallAlive(t *testing.T) {
	r := New([]string{"a", "b"})
	r.Beat("a")
	r.Beat("b")
	if got := r.Overall(); got != "alive" {
		t.Errorf("expected alive, got %s", got)
	}
}

func TestOverallDead(t *testing.T) {
	r := New([]string{"a", "b"})
	r.mu.Lock()
	for _, s := range r.sensors {
		s.Status = "dead"
	}
	r.mu.Unlock()

	if got := r.Overall(); got != "dead" {
		t.Errorf("expected dead, got %s", got)
	}
}

func TestOverallDegraded(t *testing.T) {
	r := New([]string{"a", "b"})
	r.Beat("a")
	r.mu.Lock()
	r.sensors["b"].Status = "dead"
	r.mu.Unlock()

	if got := r.Overall(); got != "degraded" {
		t.Errorf("expected degraded, got %s", got)
	}
}

func TestOverallAllUnknown(t *testing.T) {
	r := New([]string{"a", "b"})
	// Unknown means liveness is unconfirmed, which is not alive. Reporting
	// "alive" here let a host with a sensor that never started look healthy.
	if got := r.Overall(); got != "dead" {
		t.Errorf("expected dead when all unknown, got %s", got)
	}
}

func TestSnapshot(t *testing.T) {
	r := New([]string{"x", "y", "z"})
	r.Beat("x")
	r.Beat("z")

	snap := r.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("expected 3 sensors, got %d", len(snap))
	}

	statuses := make(map[string]string)
	for _, s := range snap {
		statuses[s.Name] = s.Status
	}
	if statuses["x"] != "alive" {
		t.Errorf("x: expected alive, got %s", statuses["x"])
	}
	if statuses["y"] != "unknown" {
		t.Errorf("y: expected unknown, got %s", statuses["y"])
	}
	if statuses["z"] != "alive" {
		t.Errorf("z: expected alive, got %s", statuses["z"])
	}
}

func TestNewWithThreshold(t *testing.T) {
	if got := NewWithThreshold(nil, 7*time.Second).Threshold(); got != 7*time.Second {
		t.Errorf("threshold = %v, want 7s", got)
	}
	if got := NewWithThreshold(nil, 0).Threshold(); got != DeadThreshold {
		t.Errorf("zero threshold = %v, want default %v", got, DeadThreshold)
	}
}

// setBeatAge makes the named sensor alive with a last beat age ago.
func setBeatAge(r *Registry, name string, age time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sensors[name].LastBeat = time.Now().Add(-age)
	r.sensors[name].Status = StatusAlive
}

func TestEvaluateUsesConfiguredThreshold(t *testing.T) {
	r := NewWithThreshold([]string{"s"}, 5*time.Second)
	setBeatAge(r, "s", 6*time.Second)
	r.Evaluate()
	if got := r.Snapshot()[0].Status; got != StatusDead {
		t.Errorf("6s-old beat with 5s threshold: got %s, want dead", got)
	}

	r = NewWithThreshold([]string{"s"}, time.Minute)
	setBeatAge(r, "s", 40*time.Second)
	r.Evaluate()
	if got := r.Snapshot()[0].Status; got != StatusAlive {
		t.Errorf("40s-old beat with 1m threshold: got %s, want alive", got)
	}
}

// With the default threshold and a 10 s check cycle, one missed cycle must
// not flip a sensor and two consecutive misses must.
func TestDefaultThresholdMissedCycles(t *testing.T) {
	r := New([]string{"s"})
	setBeatAge(r, "s", 10*time.Second+500*time.Millisecond)
	r.Evaluate()
	if got := r.Snapshot()[0].Status; got != StatusAlive {
		t.Errorf("one missed cycle: got %s, want alive", got)
	}
	setBeatAge(r, "s", 20*time.Second-500*time.Millisecond)
	r.Evaluate()
	if got := r.Snapshot()[0].Status; got != StatusDead {
		t.Errorf("two missed cycles: got %s, want dead", got)
	}
}

func TestEvaluateUnknownBecomesDead(t *testing.T) {
	r := NewWithThreshold([]string{"s"}, time.Second)
	r.mu.Lock()
	r.sensors["s"].registered = time.Now().Add(-2 * time.Second)
	r.mu.Unlock()
	r.Evaluate()
	s := r.Snapshot()[0]
	if s.Status != StatusDead {
		t.Errorf("unknown past threshold: got %s, want dead", s.Status)
	}
	if s.Reason == "" {
		t.Error("expected a reason for a sensor that never beat")
	}
}

func TestFailCountsAgainstOverall(t *testing.T) {
	r := New([]string{"a", "b"})
	r.Beat("a")
	r.Fail("b", "attach tracepoint: permission denied")
	if got := r.Overall(); got != "degraded" {
		t.Errorf("overall with one failed sensor: got %s, want degraded", got)
	}

	// Failed is permanent: neither beats nor evaluation change it.
	r.Beat("b")
	r.Evaluate()
	for _, s := range r.Snapshot() {
		if s.Name == "b" && (s.Status != StatusFailed || s.Reason == "") {
			t.Errorf("b: got status %q reason %q, want failed with reason", s.Status, s.Reason)
		}
	}
}

func TestUnverifiableNeverAlive(t *testing.T) {
	r := New([]string{"a", "b"})
	r.Beat("a")
	r.Beat("b")
	r.Unverifiable("b", "probe helper missing")
	r.Evaluate()
	snap := map[string]SensorStatus{}
	for _, s := range r.Snapshot() {
		snap[s.Name] = s
	}
	if snap["b"].Status != StatusUnverifiable || snap["b"].Reason != "probe helper missing" {
		t.Errorf("b: got %+v", snap["b"])
	}
	if got := r.Overall(); got != "degraded" {
		t.Errorf("overall with an unverifiable sensor: got %s, want degraded", got)
	}

	// A successful check clears it.
	r.Beat("b")
	if got := r.Overall(); got != "alive" {
		t.Errorf("overall after b beats again: got %s, want alive", got)
	}
}

func TestMissRecordsReasonOnly(t *testing.T) {
	r := New([]string{"s"})
	r.Beat("s")
	r.Miss("s", "heartbeat did not advance")
	s := r.Snapshot()[0]
	if s.Status != StatusAlive || s.Reason != "heartbeat did not advance" {
		t.Errorf("got status %q reason %q", s.Status, s.Reason)
	}
	r.Beat("s")
	if s := r.Snapshot()[0]; s.Reason != "" {
		t.Errorf("beat should clear reason, got %q", s.Reason)
	}
}

func TestOverallAliveRequiresEverySensor(t *testing.T) {
	r := New([]string{"a", "b", "c"})
	r.Beat("a")
	r.Beat("b")
	if got := r.Overall(); got != "degraded" {
		t.Errorf("two of three alive: got %s, want degraded", got)
	}
	r.Beat("c")
	if got := r.Overall(); got != "alive" {
		t.Errorf("all alive: got %s, want alive", got)
	}
}

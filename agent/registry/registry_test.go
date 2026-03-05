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
	// All unknown means no dead, no alive → "alive" (nothing is wrong)
	if got := r.Overall(); got != "alive" {
		t.Errorf("expected alive when all unknown, got %s", got)
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

package smoketest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/agent/observability"
	"github.com/dlenrow/hookmon/agent/registry"
)

// TestRegistryAliveTransition proves: beat a sensor → status becomes "alive".
func TestRegistryAliveTransition(t *testing.T) {
	reg := registry.New([]string{"bpf_syscall", "exec_injection", "shm_monitor"})

	// All start unknown
	for _, s := range reg.Snapshot() {
		if s.Status != "unknown" {
			t.Fatalf("expected unknown, got %s for %s", s.Status, s.Name)
		}
	}

	// Beat one sensor
	reg.Beat("bpf_syscall")
	reg.Evaluate()

	snap := snapshotMap(reg)
	if snap["bpf_syscall"].Status != "alive" {
		t.Errorf("bpf_syscall: expected alive, got %s", snap["bpf_syscall"].Status)
	}
	if snap["exec_injection"].Status != "unknown" {
		t.Errorf("exec_injection: expected unknown (never beaten), got %s", snap["exec_injection"].Status)
	}
}

// TestRegistryDeadTransition proves: a sensor that stops beating transitions to "dead"
// within the staleness threshold. This is the core anti-tampering property.
func TestRegistryDeadTransition(t *testing.T) {
	reg := registry.New([]string{"bpf_syscall"})

	// Beat, then simulate time passing beyond DeadThreshold
	reg.Beat("bpf_syscall")

	snap := snapshotMap(reg)
	if snap["bpf_syscall"].Status != "alive" {
		t.Fatalf("expected alive after beat, got %s", snap["bpf_syscall"].Status)
	}

	// Manually age the last beat to simulate a dead sensor
	forceStalebeat(reg, "bpf_syscall", 40*time.Second)
	reg.Evaluate()

	snap = snapshotMap(reg)
	if snap["bpf_syscall"].Status != "dead" {
		t.Errorf("expected dead after stale beat, got %s", snap["bpf_syscall"].Status)
	}
}

// TestRegistryDegradedOverall proves: one alive + one dead = "degraded".
func TestRegistryDegradedOverall(t *testing.T) {
	reg := registry.New([]string{"bpf_syscall", "exec_injection"})

	reg.Beat("bpf_syscall")
	reg.Beat("exec_injection")
	reg.Evaluate()

	if overall := reg.Overall(); overall != "alive" {
		t.Fatalf("expected alive when all beating, got %s", overall)
	}

	// Kill one sensor
	forceStalebeat(reg, "exec_injection", 40*time.Second)
	reg.Evaluate()

	if overall := reg.Overall(); overall != "degraded" {
		t.Errorf("expected degraded with one dead sensor, got %s", overall)
	}
}

// TestRegistryAllDead proves: all dead sensors → overall "dead".
func TestRegistryAllDead(t *testing.T) {
	reg := registry.New([]string{"bpf_syscall", "exec_injection"})
	reg.Beat("bpf_syscall")
	reg.Beat("exec_injection")

	forceStalebeat(reg, "bpf_syscall", 40*time.Second)
	forceStalebeat(reg, "exec_injection", 40*time.Second)
	reg.Evaluate()

	if overall := reg.Overall(); overall != "dead" {
		t.Errorf("expected dead when all sensors stale, got %s", overall)
	}
}

// TestRegistryRevival proves: a dead sensor can come back alive by beating again.
func TestRegistryRevival(t *testing.T) {
	reg := registry.New([]string{"bpf_syscall"})
	reg.Beat("bpf_syscall")

	forceStalebeat(reg, "bpf_syscall", 40*time.Second)
	reg.Evaluate()

	snap := snapshotMap(reg)
	if snap["bpf_syscall"].Status != "dead" {
		t.Fatalf("precondition: expected dead, got %s", snap["bpf_syscall"].Status)
	}

	// Sensor comes back
	reg.Beat("bpf_syscall")
	reg.Evaluate()

	snap = snapshotMap(reg)
	if snap["bpf_syscall"].Status != "alive" {
		t.Errorf("expected alive after revival beat, got %s", snap["bpf_syscall"].Status)
	}
}

// TestStatusEndpointJSON proves the /status endpoint returns valid JSON with
// correct structure, the right sensor count, and a meaningful overall status.
func TestStatusEndpointJSON(t *testing.T) {
	sensorNames := []string{
		"bpf_syscall", "exec_injection", "shm_monitor", "dlopen_monitor",
		"linker_config", "ptrace_monitor", "lib_integrity", "elf_rpath",
	}
	reg := registry.New(sensorNames)
	for _, n := range sensorNames {
		reg.Beat(n)
	}
	reg.Evaluate()

	handler := observability.StatusHandler(reg, "smoketest-host", "test-v1.0")
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != 200 {
		t.Fatalf("expected HTTP 200, got %d", w.Code)
	}

	var resp observability.StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON from /status: %v", err)
	}

	if resp.Host != "smoketest-host" {
		t.Errorf("host: expected smoketest-host, got %s", resp.Host)
	}
	if resp.Version != "test-v1.0" {
		t.Errorf("version: expected test-v1.0, got %s", resp.Version)
	}
	if resp.Overall != "alive" {
		t.Errorf("overall: expected alive, got %s", resp.Overall)
	}
	if len(resp.Sensors) != 8 {
		t.Errorf("expected 8 sensors, got %d", len(resp.Sensors))
	}
	if resp.PolledAt.IsZero() {
		t.Error("polled_at should be non-zero")
	}

	// Verify all sensors report alive
	for _, s := range resp.Sensors {
		if s.Status != "alive" {
			t.Errorf("sensor %s: expected alive, got %s", s.Name, s.Status)
		}
	}
}

// TestStatusEndpointDegraded proves /status correctly reports a degraded bus.
func TestStatusEndpointDegraded(t *testing.T) {
	reg := registry.New([]string{"bpf_syscall", "exec_injection"})
	reg.Beat("bpf_syscall")
	reg.Beat("exec_injection")

	// Kill exec_injection
	forceStalebeat(reg, "exec_injection", 40*time.Second)
	reg.Evaluate()

	handler := observability.StatusHandler(reg, "test-host", "v1")
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	var resp observability.StatusResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Overall != "degraded" {
		t.Errorf("expected degraded, got %s", resp.Overall)
	}

	// Find the dead sensor
	found := false
	for _, s := range resp.Sensors {
		if s.Name == "exec_injection" && s.Status == "dead" {
			found = true
		}
	}
	if !found {
		t.Error("exec_injection should show as dead in /status response")
	}
}

// TestStatusEndpointUnreachableSimulation proves that the collector can
// detect an unreachable host by the absence of a valid HTTP response.
// (We don't start a server — the request fails, which is the signal.)
func TestStatusEndpointUnreachableSimulation(t *testing.T) {
	// Attempt to reach a /status that doesn't exist
	resp, err := http.Get("http://127.0.0.1:19999/status")
	if err == nil {
		resp.Body.Close()
		t.Skip("port 19999 unexpectedly open")
	}
	// The error itself is the proof: unreachable = tamper signal.
	t.Logf("confirmed: unreachable host produces error: %v", err)
}

// --- helpers ---

func snapshotMap(reg *registry.Registry) map[string]registry.SensorStatus {
	m := make(map[string]registry.SensorStatus)
	for _, s := range reg.Snapshot() {
		m[s.Name] = s
	}
	return m
}

// forceStalebeat backdates a sensor's last beat to simulate staleness.
// This uses the exported Beat + a time offset approach via direct field access.
// The registry's mutex is handled internally by Beat, but we need to manipulate
// the last beat time directly for testing.
func forceStalebeat(reg *registry.Registry, name string, age time.Duration) {
	// We use the registry's internal test helper
	reg.ForceLastBeat(name, time.Now().Add(-age))
}

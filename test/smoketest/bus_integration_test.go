package smoketest

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/agent/observability"
	"github.com/dlenrow/hookmon/agent/registry"
	"github.com/dlenrow/hookmon/pkg/version"
)

// TestBusStatusEndpointLive starts a real HTTP server with /status and /metrics,
// hits it with real HTTP requests, and verifies the response.
func TestBusStatusEndpointLive(t *testing.T) {
	port := findFreePort(t)

	sensorNames := []string{
		"bpf_syscall", "exec_injection", "shm_monitor", "dlopen_monitor",
		"linker_config", "ptrace_monitor", "lib_integrity", "elf_rpath",
	}
	reg := registry.New(sensorNames)

	// Beat all sensors
	for _, n := range sensorNames {
		reg.Beat(n)
	}
	reg.Evaluate()

	// Start real metrics server
	m, err := observability.NewMetrics(port, noopLogger(t))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	defer m.Close()

	m.RegisterStatusHandler(observability.StatusHandler(reg, "integration-test", version.Version))

	// Give server time to bind
	time.Sleep(100 * time.Millisecond)

	// --- Test /status ---
	statusURL := fmt.Sprintf("http://127.0.0.1:%d/status", port)
	resp, err := http.Get(statusURL)
	if err != nil {
		t.Fatalf("GET /status failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: expected application/json, got %s", ct)
	}

	body, _ := io.ReadAll(resp.Body)
	var status observability.StatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, body)
	}

	if status.Host != "integration-test" {
		t.Errorf("host: expected integration-test, got %s", status.Host)
	}
	if status.Overall != "alive" {
		t.Errorf("overall: expected alive, got %s", status.Overall)
	}
	if len(status.Sensors) != 8 {
		t.Errorf("sensors: expected 8, got %d", len(status.Sensors))
	}

	t.Logf("/status response: overall=%s, sensors=%d, version=%s",
		status.Overall, len(status.Sensors), status.Version)

	// --- Test /metrics ---
	metricsURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	mresp, err := http.Get(metricsURL)
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer mresp.Body.Close()

	if mresp.StatusCode != 200 {
		t.Fatalf("/metrics: expected 200, got %d", mresp.StatusCode)
	}

	mbody, _ := io.ReadAll(mresp.Body)
	metricsText := string(mbody)

	// Verify key metrics are registered.
	// Note: CounterVec metrics (events_total, sensor_errors_total) only appear
	// after the first observation — we check the gauge which is always present.
	if !containsStr(metricsText, "hookmon_sensors_active") {
		t.Error("/metrics missing: hookmon_sensors_active")
	}

	t.Logf("/metrics endpoint verified (%d bytes)", len(mbody))
}

// TestBusStatusWithSensorHealthMetrics proves that UpdateSensorHealth
// populates the per-sensor Prometheus metrics correctly.
func TestBusStatusWithSensorHealthMetrics(t *testing.T) {
	port := findFreePort(t)

	reg := registry.New([]string{"bpf_syscall", "exec_injection"})
	reg.Beat("bpf_syscall")
	// exec_injection never beaten (stays unknown)

	m, err := observability.NewMetrics(port, noopLogger(t))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	defer m.Close()

	// Update sensor health metrics from registry
	m.UpdateSensorHealth(reg)

	time.Sleep(100 * time.Millisecond)

	metricsURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	resp, err := http.Get(metricsURL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	// bpf_syscall should be alive (1)
	if !containsStr(text, `hookmon_sensor_alive{sensor="bpf_syscall"} 1`) {
		t.Error("expected hookmon_sensor_alive{sensor=\"bpf_syscall\"} 1")
	}
	// exec_injection should be 0 (unknown → reported as not alive)
	if !containsStr(text, `hookmon_sensor_alive{sensor="exec_injection"} 0`) {
		t.Error("expected hookmon_sensor_alive{sensor=\"exec_injection\"} 0")
	}
	// overall should be alive (no dead sensors, unknown doesn't count as dead)
	if !containsStr(text, `hookmon_bus_overall{status="alive"} 1`) {
		t.Error("expected hookmon_bus_overall{status=\"alive\"} 1")
	}

	t.Logf("sensor health metrics verified")
}

// TestBusDegradedMetrics proves degraded state appears in Prometheus.
func TestBusDegradedMetrics(t *testing.T) {
	port := findFreePort(t)

	reg := registry.New([]string{"bpf_syscall", "exec_injection"})
	reg.Beat("bpf_syscall")
	reg.Beat("exec_injection")

	// Kill exec_injection
	reg.ForceLastBeat("exec_injection", time.Now().Add(-40*time.Second))
	reg.Evaluate()

	m, err := observability.NewMetrics(port, noopLogger(t))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	defer m.Close()

	m.UpdateSensorHealth(reg)
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	if !containsStr(text, `hookmon_sensor_alive{sensor="exec_injection"} 0`) {
		t.Error("dead sensor should show alive=0")
	}
	if !containsStr(text, `hookmon_bus_overall{status="degraded"} 1`) {
		t.Error("expected degraded overall status")
	}
	if !containsStr(text, `hookmon_bus_overall{status="alive"} 0`) {
		t.Error("alive should be 0 when degraded")
	}

	t.Logf("degraded metrics verified")
}

// --- helpers ---

func findFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func containsStr(haystack, needle string) bool {
	return len(haystack) > 0 && len(needle) > 0 &&
		// Use simple substring search
		stringContains(haystack, needle)
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

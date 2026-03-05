package observability

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dlenrow/hookmon/agent/registry"
)

func TestStatusHandler(t *testing.T) {
	reg := registry.New([]string{"bpf_syscall", "exec_injection"})
	reg.Beat("bpf_syscall")

	handler := StatusHandler(reg, "test-host", "1.0.0-test")
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}

	var resp StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Host != "test-host" {
		t.Errorf("expected host test-host, got %s", resp.Host)
	}
	if resp.Version != "1.0.0-test" {
		t.Errorf("expected version 1.0.0-test, got %s", resp.Version)
	}
	if resp.Overall != "alive" {
		t.Errorf("expected overall alive, got %s", resp.Overall)
	}
	if len(resp.Sensors) != 2 {
		t.Fatalf("expected 2 sensors, got %d", len(resp.Sensors))
	}
	if resp.PolledAt.IsZero() {
		t.Error("expected non-zero polled_at")
	}
}

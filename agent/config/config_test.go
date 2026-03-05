package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ServerAddr != "localhost:9443" {
		t.Errorf("ServerAddr = %q, want localhost:9443", cfg.ServerAddr)
	}
	if cfg.HeartbeatInterval != 30*time.Second {
		t.Errorf("HeartbeatInterval = %v, want 30s", cfg.HeartbeatInterval)
	}
	if cfg.FallbackLogPath != "/var/log/hookmon/fallback.jsonl" {
		t.Errorf("FallbackLogPath = %q, want /var/log/hookmon/fallback.jsonl", cfg.FallbackLogPath)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}

	// All sensors should be enabled by default.
	sensors := cfg.Sensors
	if !sensors.BPFSyscall {
		t.Error("BPFSyscall should be true by default")
	}
	if !sensors.ExecInjection {
		t.Error("ExecInjection should be true by default")
	}
	if !sensors.SHMMonitor {
		t.Error("SHMMonitor should be true by default")
	}
	if !sensors.DlopenMonitor {
		t.Error("DlopenMonitor should be true by default")
	}
	if !sensors.LinkerConfig {
		t.Error("LinkerConfig should be true by default")
	}
	if !sensors.PtraceMonitor {
		t.Error("PtraceMonitor should be true by default")
	}
	if !sensors.LibIntegrity {
		t.Error("LibIntegrity should be true by default")
	}
	if !sensors.ElfRpath {
		t.Error("ElfRpath should be true by default")
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	yaml := `
host_id: test-host-001
server_addr: hookmon.internal:9443
heartbeat_interval: 15s
log_level: debug
loki_url: http://loki:3100
prometheus_port: 2112
sensors:
  bpf_syscall: true
  exec_injection: false
  shm_monitor: true
  dlopen_monitor: false
  linker_config: true
  ptrace_monitor: false
  lib_integrity: true
  elf_rpath: false
tls:
  cert_file: /etc/hookmon/agent.crt
  key_file: /etc/hookmon/agent.key
  ca_file: /etc/hookmon/ca.crt
  server_name: hookmon.internal
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.HostID != "test-host-001" {
		t.Errorf("HostID = %q, want test-host-001", cfg.HostID)
	}
	if cfg.ServerAddr != "hookmon.internal:9443" {
		t.Errorf("ServerAddr = %q", cfg.ServerAddr)
	}
	if cfg.HeartbeatInterval != 15*time.Second {
		t.Errorf("HeartbeatInterval = %v, want 15s", cfg.HeartbeatInterval)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}
	if cfg.LokiURL != "http://loki:3100" {
		t.Errorf("LokiURL = %q", cfg.LokiURL)
	}
	if cfg.PrometheusPort != 2112 {
		t.Errorf("PrometheusPort = %d, want 2112", cfg.PrometheusPort)
	}

	// Sensors.
	if !cfg.Sensors.BPFSyscall {
		t.Error("BPFSyscall should be true")
	}
	if cfg.Sensors.ExecInjection {
		t.Error("ExecInjection should be false")
	}
	if cfg.Sensors.DlopenMonitor {
		t.Error("DlopenMonitor should be false")
	}
	if cfg.Sensors.PtraceMonitor {
		t.Error("PtraceMonitor should be false")
	}
	if cfg.Sensors.ElfRpath {
		t.Error("ElfRpath should be false")
	}

	// TLS.
	if cfg.TLS.CertFile != "/etc/hookmon/agent.crt" {
		t.Errorf("TLS.CertFile = %q", cfg.TLS.CertFile)
	}
	if cfg.TLS.ServerName != "hookmon.internal" {
		t.Errorf("TLS.ServerName = %q", cfg.TLS.ServerName)
	}
}

func TestLoad_PartialYAML_MergesWithDefaults(t *testing.T) {
	// Only set host_id — everything else should be default.
	yaml := `host_id: partial-host`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.HostID != "partial-host" {
		t.Errorf("HostID = %q", cfg.HostID)
	}
	// Defaults should still be set.
	if cfg.ServerAddr != "localhost:9443" {
		t.Errorf("ServerAddr should remain default, got %q", cfg.ServerAddr)
	}
	if !cfg.Sensors.BPFSyscall {
		t.Error("BPFSyscall should remain true (default)")
	}
}

func TestLoad_NonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	// Use a YAML tab indentation error — tabs are not allowed in YAML.
	if err := os.WriteFile(path, []byte("key:\n\t- broken"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

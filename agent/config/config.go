package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// AgentConfig holds the hookmon-agent configuration.
type AgentConfig struct {
	// HostID is the unique identifier for this agent (assigned during enrollment).
	HostID string `yaml:"host_id"`

	// ServerAddr is the hookmon-server gRPC endpoint (host:port).
	ServerAddr string `yaml:"server_addr"`

	// TLS configuration for mTLS.
	TLS TLSConfig `yaml:"tls"`

	// HeartbeatInterval is how often the agent sends heartbeats.
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`

	// Sensors controls which sensors are enabled.
	Sensors SensorConfig `yaml:"sensors"`

	// FallbackLogPath is where events are written if the server is unreachable.
	FallbackLogPath string `yaml:"fallback_log_path"`

	// LogLevel controls agent logging verbosity.
	LogLevel string `yaml:"log_level"`

	// ConsoleMode prints events to stdout as JSON instead of sending to server.
	ConsoleMode bool `yaml:"-"`

	// LokiURL is the base URL for the Loki server (e.g. http://localhost:3100).
	// Empty means disabled.
	LokiURL string `yaml:"loki_url"`

	// PrometheusPort is the port to expose Prometheus metrics on (e.g. 2112).
	// Zero means disabled. Deprecated: use StatusPort instead.
	PrometheusPort int `yaml:"prometheus_port"`

	// StatusPort is the port for /status and /metrics endpoints.
	// Defaults to 2112. Zero means disabled.
	StatusPort int `yaml:"status_port"`

	// StatusAddr is the address the /status and /metrics server binds to,
	// e.g. "127.0.0.1". Empty means all interfaces.
	StatusAddr string `yaml:"status_addr"`

	// HeartbeatSensorInterval is how often the bus fires every eBPF hook
	// itself, reads the heartbeat maps and evaluates sensor health. The
	// fanotify sensors beat on the same interval.
	HeartbeatSensorInterval time.Duration `yaml:"heartbeat_sensor_interval"`

	// DeadThreshold is how long since last heartbeat before a sensor is marked
	// dead. The default of 15 s is 1.5 check intervals: one missed check is
	// tolerated, two consecutive misses mark the sensor dead (within 20 s).
	// Zero means 1.5 x HeartbeatSensorInterval.
	DeadThreshold time.Duration `yaml:"dead_threshold"`

	// DlopenProbePath is the helper the bus runs to fire the dlopen uprobe.
	// Empty means hookmon-dlopen-probe in the bus binary's directory.
	DlopenProbePath string `yaml:"dlopen_probe_path"`
}

// TLSConfig holds mTLS certificate paths.
type TLSConfig struct {
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
	ServerName string `yaml:"server_name"`
	Insecure   bool   `yaml:"insecure"`
}

// SensorConfig controls which sensors are enabled.
type SensorConfig struct {
	BPFSyscall     bool `yaml:"bpf_syscall"`
	ExecInjection  bool `yaml:"exec_injection"`
	SHMMonitor     bool `yaml:"shm_monitor"`
	DlopenMonitor  bool `yaml:"dlopen_monitor"`
	LinkerConfig   bool `yaml:"linker_config"`
	PtraceMonitor  bool `yaml:"ptrace_monitor"`
	LibIntegrity   bool `yaml:"lib_integrity"`
	ElfRpath       bool `yaml:"elf_rpath"`
}

// DefaultConfig returns an AgentConfig with sensible defaults.
func DefaultConfig() *AgentConfig {
	return &AgentConfig{
		ServerAddr:              "localhost:9443",
		HeartbeatInterval:       30 * time.Second,
		FallbackLogPath:         "/var/log/hookmon/fallback.jsonl",
		LogLevel:                "info",
		StatusPort:              2112,
		HeartbeatSensorInterval: 10 * time.Second,
		DeadThreshold:           15 * time.Second,
		Sensors: SensorConfig{
			BPFSyscall:    true,
			ExecInjection: true,
			SHMMonitor:    true,
			DlopenMonitor: true,
			LinkerConfig:  true,
			PtraceMonitor: true,
			LibIntegrity:  true,
			ElfRpath:      true,
		},
	}
}

// Load reads an AgentConfig from a YAML file.
func Load(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

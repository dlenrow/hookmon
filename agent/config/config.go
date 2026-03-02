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
	// Zero means disabled.
	PrometheusPort int `yaml:"prometheus_port"`
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
	ExecvePreload  bool `yaml:"execve_preload"`
	SHMMonitor     bool `yaml:"shm_monitor"`
	DlopenMonitor  bool `yaml:"dlopen_monitor"`
}

// DefaultConfig returns an AgentConfig with sensible defaults.
func DefaultConfig() *AgentConfig {
	return &AgentConfig{
		ServerAddr:        "localhost:9443",
		HeartbeatInterval: 30 * time.Second,
		FallbackLogPath:   "/var/log/hookmon/fallback.jsonl",
		LogLevel:          "info",
		Sensors: SensorConfig{
			BPFSyscall:    true,
			ExecvePreload: true,
			SHMMonitor:    true,
			DlopenMonitor: true,
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

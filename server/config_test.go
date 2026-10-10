package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func enrWriteConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadConfig_Example loads deploy/server.example.yaml, so the shipped
// example always parses and passes validation.
func TestLoadConfig_Example(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("..", "deploy", "server.example.yaml"))
	if err != nil {
		t.Fatalf("LoadConfig(example): %v", err)
	}
	if cfg.GRPCAddr != ":9443" || cfg.EnrollAddr != ":9444" || cfg.HTTPAddr != ":8443" {
		t.Errorf("addresses: %q %q %q", cfg.GRPCAddr, cfg.EnrollAddr, cfg.HTTPAddr)
	}
	if cfg.TLS.CAKeyFile != "/etc/hookmon/tls/ca.key" || !cfg.UseTLS() || cfg.CheckTLS() != nil {
		t.Errorf("tls: %+v", cfg.TLS)
	}
	if cfg.DashboardDir != DefaultDashboardDir {
		t.Errorf("dashboard_dir: %q", cfg.DashboardDir)
	}
	if len(cfg.Enrollment.Tokens) != 1 {
		t.Fatalf("tokens: %+v", cfg.Enrollment.Tokens)
	}
	tok := cfg.Enrollment.Tokens[0]
	if tok.Name != "initial-rollout" || tok.SingleUse || !tok.Expires.Equal(time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("token: %+v", tok)
	}
	if cfg.Enrollment.CertValidity != 8760*time.Hour {
		t.Errorf("cert_validity: %v", cfg.Enrollment.CertValidity)
	}
	if cfg.Watchdog.CheckInterval != 15*time.Second || cfg.Watchdog.HeartbeatTimeout != 60*time.Second {
		t.Errorf("watchdog: %+v", cfg.Watchdog)
	}
}

func TestLoadConfig_DefaultsAndErrors(t *testing.T) {
	cfg, err := LoadConfig(enrWriteConfig(t, ""))
	if err != nil {
		t.Fatalf("empty file: %v", err)
	}
	if cfg.GRPCAddr != ":9443" || cfg.Watchdog.HeartbeatTimeout != 60*time.Second || cfg.UseTLS() {
		t.Errorf("empty file should give defaults: %+v", cfg)
	}

	const tlsBlock = `
tls:
  cert_file: s.crt
  key_file: s.key
  ca_file: ca.crt
`
	const goodToken = `
enrollment:
  tokens:
    - name: a
      secret: "0123456789abcdef0123456789abcdef"
      expires: 2030-01-01T00:00:00Z
`
	cases := map[string]string{
		"unknown key":               "grpc_adr: \":1\"\n",
		"unknown connector":         "connectors:\n  splunkk:\n    url: http://x\n",
		"unknown connector key":     "connectors:\n  webhook:\n    url: http://x\n    retries: 3\n",
		"webhook without url":       "connectors:\n  webhook:\n    headers: {X: y}\n",
		"syslog bad protocol":       "connectors:\n  syslog:\n    address: siem:514\n    protocol: tls\n",
		"splunk without token":      "connectors:\n  splunk:\n    url: https://splunk:8088/services/collector/event\n",
		"bad min_severity":          "connectors:\n  kafka:\n    brokers: [k:9092]\n    topic: t\n    min_severity: HIGH\n",
		"short token":               tlsBlock + "  ca_key_file: ca.key\nenrollment:\n  tokens:\n    - {name: a, secret: short, expires: 2030-01-01T00:00:00Z}\n",
		"token without expiry":      tlsBlock + "  ca_key_file: ca.key\nenrollment:\n  tokens:\n    - {name: a, secret: \"0123456789abcdef0123456789abcdef\"}\n",
		"enrollment without TLS":    goodToken,
		"enrollment without CA key": tlsBlock + goodToken,
		"TLS without CA":            "tls:\n  cert_file: s.crt\n  key_file: s.key\n",
		"cert without key":          "tls:\n  cert_file: s.crt\n  ca_file: ca.crt\n",
		"bad duration":              "watchdog:\n  check_interval: soon\n",
		"zero watchdog":             "watchdog:\n  heartbeat_timeout: 0s\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(enrWriteConfig(t, body)); err == nil {
				t.Fatalf("LoadConfig accepted:\n%s", body)
			}
		})
	}

	ok := tlsBlock + "  ca_key_file: ca.key\n" + goodToken
	if _, err := LoadConfig(enrWriteConfig(t, ok)); err != nil {
		t.Errorf("valid enrollment config: %v", err)
	}

	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil ||
		!strings.Contains(err.Error(), "read config") {
		t.Errorf("missing file: got %v", err)
	}
}

// TestLoadConfig_Connectors parses a connectors section with every
// connector and its secrets.
func TestLoadConfig_Connectors(t *testing.T) {
	cfg, err := LoadConfig(enrWriteConfig(t, `
connectors:
  syslog:
    address: siem.example.com:6514
    protocol: tcp
    framing: lf
    facility: local4
    min_severity: WARN
    queue_size: 2048
  splunk:
    url: https://splunk.example.com:8088/services/collector/event
    token: hec-token
    index: security
    batch_size: 50
    flush_interval: 2s
  elasticsearch:
    url: https://es.example.com:9200
    username: hookmon
    password: es-secret
    index_prefix: hookmon-events
    ilm:
      setup: false
      delete_after: 30d
  webhook:
    url: https://hooks.example.com/hookmon
    headers:
      Authorization: Bearer abc
  kafka:
    brokers: [k1:9092, k2:9092]
    topic: hookmon
    min_severity: INFO
`))
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Connectors
	if c.Syslog == nil || c.Syslog.Address != "siem.example.com:6514" || c.Syslog.Framing != "lf" || c.Syslog.Facility != "local4" ||
		c.Syslog.MinSeverity != "WARN" || c.Syslog.QueueSize != 2048 {
		t.Errorf("syslog %+v", c.Syslog)
	}
	if c.Splunk == nil || c.Splunk.Token != "hec-token" || c.Splunk.Index != "security" || c.Splunk.BatchSize != 50 || c.Splunk.FlushInterval != 2*time.Second {
		t.Errorf("splunk %+v", c.Splunk)
	}
	if e := c.Elastic; e == nil || e.Username != "hookmon" || e.Password != "es-secret" || e.ILM.Setup == nil || *e.ILM.Setup || e.ILM.DeleteAfter != "30d" {
		t.Errorf("elasticsearch %+v", c.Elastic)
	}
	if c.Webhook == nil || c.Webhook.Headers["Authorization"] != "Bearer abc" {
		t.Errorf("webhook %+v", c.Webhook)
	}
	if c.Kafka == nil || len(c.Kafka.Brokers) != 2 || c.Kafka.Topic != "hookmon" || c.Kafka.MinSeverity != "INFO" {
		t.Errorf("kafka %+v", c.Kafka)
	}
}

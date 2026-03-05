package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/dlenrow/hookmon/agent/observability"
	"github.com/dlenrow/hookmon/pkg/version"
)

// CollectorConfig is the top-level config for the collector.
type CollectorConfig struct {
	PollInterval  time.Duration `yaml:"poll_interval"`
	PushGateway   string        `yaml:"push_gateway"`
	FleetStatusFile string      `yaml:"fleet_status_file"`
	Hosts         []HostConfig  `yaml:"hosts"`
}

// HostConfig configures a single host to poll.
type HostConfig struct {
	Hostname  string `yaml:"hostname"`
	StatusURL string `yaml:"status_url"` // direct HTTP mode
	SSHHost   string `yaml:"ssh_host"`   // SSH transport mode
	SSHUser   string `yaml:"ssh_user"`
	SSHKey    string `yaml:"ssh_key"`
}

// HostResult is the poll result for one host.
type HostResult struct {
	Hostname    string                         `json:"hostname"`
	Reachable   bool                           `json:"reachable"`
	Overall     string                         `json:"overall"`
	Sensors     []observability.SensorSnapshot  `json:"sensors,omitempty"`
	BusVersion  string                         `json:"bus_version,omitempty"`
	LastPoll    time.Time                      `json:"last_poll"`
	Error       string                         `json:"error,omitempty"`
}

// FleetStatus is the full fleet summary written to disk and pushed to Pushgateway.
type FleetStatus struct {
	PollTime       time.Time    `json:"poll_time"`
	TotalHosts     int          `json:"total_hosts"`
	AliveHosts     int          `json:"alive_hosts"`
	DegradedHosts  int          `json:"degraded_hosts"`
	UnreachableHosts int        `json:"unreachable_hosts"`
	Hosts          []HostResult `json:"hosts"`
}

func main() {
	configPath := flag.String("config", "/etc/hookmon/collector.yaml", "path to collector config")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		logger.Fatal("failed to load config", zap.Error(err))
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.FleetStatusFile == "" {
		cfg.FleetStatusFile = "/var/lib/hookmon/fleet-status.json"
	}

	logger.Info("starting hookmon-collector",
		zap.String("version", version.Version),
		zap.Int("hosts", len(cfg.Hosts)),
		zap.Duration("poll_interval", cfg.PollInterval),
	)

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	runPollLoop(ctx, cfg, logger)
}

func loadConfig(path string) (*CollectorConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg CollectorConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

func runPollLoop(ctx context.Context, cfg *CollectorConfig, logger *zap.Logger) {
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	// Poll once immediately
	pollAll(ctx, cfg, logger)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pollAll(ctx, cfg, logger)
		}
	}
}

func pollAll(ctx context.Context, cfg *CollectorConfig, logger *zap.Logger) {
	var mu sync.Mutex
	results := make([]HostResult, len(cfg.Hosts))
	var wg sync.WaitGroup

	for i, h := range cfg.Hosts {
		wg.Add(1)
		go func(idx int, host HostConfig) {
			defer wg.Done()
			result := pollHost(ctx, host, logger)
			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, h)
	}
	wg.Wait()

	// Compute fleet summary
	fleet := FleetStatus{
		PollTime:   time.Now().UTC(),
		TotalHosts: len(results),
		Hosts:      results,
	}
	for _, r := range results {
		if !r.Reachable {
			fleet.UnreachableHosts++
		} else if r.Overall == "alive" {
			fleet.AliveHosts++
		} else {
			fleet.DegradedHosts++
		}
	}

	logger.Info("poll complete",
		zap.Int("total", fleet.TotalHosts),
		zap.Int("alive", fleet.AliveHosts),
		zap.Int("degraded", fleet.DegradedHosts),
		zap.Int("unreachable", fleet.UnreachableHosts),
	)

	// Write fleet status to file
	writeFleetStatus(cfg.FleetStatusFile, &fleet, logger)

	// Push to Pushgateway
	if cfg.PushGateway != "" {
		pushToGateway(cfg.PushGateway, &fleet, logger)
	}
}

func pollHost(ctx context.Context, host HostConfig, logger *zap.Logger) HostResult {
	result := HostResult{
		Hostname: host.Hostname,
		LastPoll: time.Now().UTC(),
	}

	var body []byte
	var err error

	if host.SSHHost != "" && host.SSHUser != "" {
		body, err = pollViaSSH(ctx, host)
	} else if host.StatusURL != "" {
		body, err = pollViaHTTP(ctx, host.StatusURL)
	} else {
		result.Error = "no status_url or ssh_host configured"
		return result
	}

	if err != nil {
		result.Error = err.Error()
		logger.Warn("host unreachable", zap.String("host", host.Hostname), zap.Error(err))
		return result
	}

	var status observability.StatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		result.Error = fmt.Sprintf("invalid status JSON: %v", err)
		return result
	}

	result.Reachable = true
	result.Overall = status.Overall
	result.BusVersion = status.Version
	result.Sensors = make([]observability.SensorSnapshot, len(status.Sensors))
	for i, s := range status.Sensors {
		result.Sensors[i] = observability.SensorSnapshot{
			Name:     s.Name,
			Status:   s.Status,
			LastBeat: s.LastBeat,
		}
	}

	return result
}

func pollViaHTTP(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func pollViaSSH(ctx context.Context, host HostConfig) ([]byte, error) {
	keyData, err := os.ReadFile(host.SSHKey)
	if err != nil {
		return nil, fmt.Errorf("read SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse SSH key: %w", err)
	}

	sshCfg := &ssh.ClientConfig{
		User:            host.SSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	sshHost := host.SSHHost
	if !strings.Contains(sshHost, ":") {
		sshHost += ":22"
	}

	client, err := ssh.Dial("tcp", sshHost, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("SSH connect: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	output, err := session.Output("curl -s http://localhost:2112/status")
	if err != nil {
		return nil, fmt.Errorf("SSH command: %w", err)
	}
	return output, nil
}

func writeFleetStatus(path string, fleet *FleetStatus, logger *zap.Logger) {
	data, err := json.MarshalIndent(fleet, "", "  ")
	if err != nil {
		logger.Error("failed to marshal fleet status", zap.Error(err))
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		logger.Warn("failed to write fleet status file", zap.String("path", path), zap.Error(err))
	}
}

func pushToGateway(gatewayURL string, fleet *FleetStatus, logger *zap.Logger) {
	var sb strings.Builder

	// Fleet-wide rollup
	fmt.Fprintf(&sb, "# HELP hookmon_fleet_hosts_total Total enrolled hosts\n")
	fmt.Fprintf(&sb, "# TYPE hookmon_fleet_hosts_total gauge\n")
	fmt.Fprintf(&sb, "hookmon_fleet_hosts_total %d\n", fleet.TotalHosts)

	fmt.Fprintf(&sb, "# HELP hookmon_fleet_hosts_alive Hosts with all sensors alive\n")
	fmt.Fprintf(&sb, "# TYPE hookmon_fleet_hosts_alive gauge\n")
	fmt.Fprintf(&sb, "hookmon_fleet_hosts_alive %d\n", fleet.AliveHosts)

	fmt.Fprintf(&sb, "# HELP hookmon_fleet_hosts_degraded Hosts with some sensors dead\n")
	fmt.Fprintf(&sb, "# TYPE hookmon_fleet_hosts_degraded gauge\n")
	fmt.Fprintf(&sb, "hookmon_fleet_hosts_degraded %d\n", fleet.DegradedHosts)

	fmt.Fprintf(&sb, "# HELP hookmon_fleet_hosts_unreachable Unreachable hosts\n")
	fmt.Fprintf(&sb, "# TYPE hookmon_fleet_hosts_unreachable gauge\n")
	fmt.Fprintf(&sb, "hookmon_fleet_hosts_unreachable %d\n", fleet.UnreachableHosts)

	// Per-host metrics
	fmt.Fprintf(&sb, "# HELP hookmon_fleet_host_reachable Whether host is reachable\n")
	fmt.Fprintf(&sb, "# TYPE hookmon_fleet_host_reachable gauge\n")
	fmt.Fprintf(&sb, "# HELP hookmon_fleet_host_status Host overall status\n")
	fmt.Fprintf(&sb, "# TYPE hookmon_fleet_host_status gauge\n")
	fmt.Fprintf(&sb, "# HELP hookmon_fleet_sensor_alive Per-sensor alive status\n")
	fmt.Fprintf(&sb, "# TYPE hookmon_fleet_sensor_alive gauge\n")

	for _, h := range fleet.Hosts {
		var reachable float64
		if h.Reachable {
			reachable = 1
		}
		fmt.Fprintf(&sb, "hookmon_fleet_host_reachable{host=%q} %g\n", h.Hostname, reachable)

		for _, st := range []string{"alive", "degraded", "dead"} {
			var v float64
			if h.Overall == st {
				v = 1
			}
			fmt.Fprintf(&sb, "hookmon_fleet_host_status{host=%q,status=%q} %g\n", h.Hostname, st, v)
		}

		for _, s := range h.Sensors {
			var alive float64
			if s.Status == "alive" {
				alive = 1
			}
			fmt.Fprintf(&sb, "hookmon_fleet_sensor_alive{host=%q,sensor=%q} %g\n", h.Hostname, s.Name, alive)
		}
	}

	url := strings.TrimSuffix(gatewayURL, "/") + "/metrics/job/hookmon-collector"
	resp, err := http.Post(url, "text/plain", strings.NewReader(sb.String()))
	if err != nil {
		logger.Warn("pushgateway push failed", zap.Error(err))
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		logger.Warn("pushgateway returned error", zap.Int("status", resp.StatusCode))
	}
}

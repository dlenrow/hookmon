# HookMon Deployment Guide

## Overview

A HookMon deployment has three parts:

1. **Appliance** — runs Grafana, Loki, Prometheus, and the collector. Receives events from sensor buses. You view the dashboard here.
2. **Sensor Bus(es)** — run on each monitored Linux host. Detect eBPF loads, LD_PRELOAD injection, ptrace abuse, library tampering, and more. Push events to the appliance.
3. **Collector** — runs on the appliance. Polls each enrolled host's `/status` endpoint to track fleet health.

Enforcement mode is off by default and explicitly opt-in. All sensors are read-only by default — they observe and report but do not block or modify process behavior.

## Prerequisites

### Appliance Host
- Any Linux machine with Docker (x86_64 or arm64)
- 2GB+ RAM (Grafana ~50MB, Loki ~200MB, Prometheus ~100MB)
- Network reachable from monitored hosts on ports 3100 (Loki) and 9090 (Prometheus)
- Port 3000 reachable from your browser (Grafana)

### Sensor Bus Host
- Linux with kernel 5.8+ (BTF support required)
- Root access (required for eBPF tracepoints and uprobes)
- Build tools: Go 1.22+, clang, llvm, libbpf-dev, bpftool
- Network access to appliance on port 3100

## Step 1: Deploy the Appliance

```bash
# Clone the repo
git clone https://github.com/dlenrow/hookmon.git
cd hookmon

# Start the stack
docker compose -f deploy/docker/docker-compose.grafana.yml up -d
```

Verify:
```bash
docker compose -f deploy/docker/docker-compose.grafana.yml ps
curl -s localhost:3000/api/health        # Grafana
curl -s localhost:3100/ready             # Loki
curl -s localhost:9090/-/ready           # Prometheus
```

Default Grafana login: `admin` / `hookmon`

### Configure Prometheus Scrape Targets

Edit `deploy/docker/prometheus.yml` to list your sensor bus hosts:

```yaml
scrape_configs:
  - job_name: hookmon-bus
    static_configs:
      - targets: ["bus-host-1:2112"]
        labels:
          instance: bus-host-1
      - targets: ["bus-host-2:2112"]
        labels:
          instance: bus-host-2
```

Then restart Prometheus:
```bash
docker compose -f deploy/docker/docker-compose.grafana.yml restart prometheus
```

## Step 2: Build the Sensor Bus

On each monitored host:

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install -y clang llvm libbpf-dev
# bpftool is usually in linux-tools-$(uname -r)
# Go: https://go.dev/dl/

# Clone
git clone https://github.com/dlenrow/hookmon.git
cd hookmon

# Generate vmlinux.h from kernel BTF
cd agent/sensors
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile eBPF programs
for f in *.c; do
  clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c $f -o ${f%.c}.o
done
cd ../..

# Build the sensor bus
mkdir -p bin
go build -o bin/hookmon-bus ./cmd/hookmon-bus/
```

## Step 3: Run the Sensor Bus

```bash
sudo ./bin/hookmon-bus --console \
  --loki-url http://<appliance-hostname>:3100 \
  --status-port 2112
```

The sensor bus will:
1. Load all eBPF sensors
2. Print events to stdout as JSON (console mode)
3. Push events to Loki on the appliance
4. Expose `/status` and `/metrics` endpoints on the status port

### Sensor Bus Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--console` | false | Print events to stdout instead of gRPC |
| `--config` | `/etc/hookmon/bus.yaml` | Path to YAML config file |
| `--loki-url` | (disabled) | Loki base URL, e.g. `http://appliance:3100` |
| `--status-port` | 2112 | Port for `/status` and `/metrics` endpoints |
| `--prometheus-port` | — | Deprecated alias for `--status-port` |
| `--version` | — | Print version and exit |

### YAML Configuration

The sensor bus can also be configured via `/etc/hookmon/bus.yaml`:

```yaml
host_id: "prod-web-01"
server_addr: "hookmon.internal:9443"
loki_url: "http://hookmon.internal:3100"
status_port: 2112
log_level: "info"
fallback_log_path: "/var/log/hookmon/fallback.jsonl"
sensors:
  bpf_syscall: true
  execve_preload: true
  shm_monitor: true
  dlopen_monitor: true
```

CLI flags override YAML values.

### Running as a systemd Service

```ini
# /etc/systemd/system/hookmon-bus.service
[Unit]
Description=HookMon Sensor Bus
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hookmon-bus \
  --config /etc/hookmon/bus.yaml \
  --loki-url http://hookmon.internal:3100 \
  --status-port 2112
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hookmon-bus
```

## Step 4: Configure the Collector

The hookmon-collector runs on the appliance and polls each enrolled host's `/status` endpoint.

### Install

```bash
go build -o bin/hookmon-collector ./cmd/hookmon-collector/
sudo cp bin/hookmon-collector /usr/local/bin/
```

### Configure

Create `/etc/hookmon/collector.yaml`:

```yaml
poll_interval: 30s
push_gateway: http://localhost:9091
fleet_status_file: /var/lib/hookmon/fleet-status.json
hosts:
  - hostname: prod-web-01
    status_url: http://10.0.1.101:2112/status
  - hostname: prod-web-02
    status_url: http://10.0.1.102:2112/status
```

For SSH transport (when direct HTTP is not allowed):

```yaml
hosts:
  - hostname: prod-web-01
    ssh_host: 10.0.1.101
    ssh_user: hookmon-collector
    ssh_key: /etc/hookmon/collector_rsa
```

The SSH user needs minimal privileges — it only needs to run `curl -s http://localhost:2112/status` on the remote host.

### Run

```bash
hookmon-collector --config /etc/hookmon/collector.yaml
```

### Verify

```bash
# Check collector is polling
curl -s http://localhost:9091/metrics | grep hookmon_fleet

# Check fleet status file
cat /var/lib/hookmon/fleet-status.json | jq .
```

### systemd Service

```ini
# /etc/systemd/system/hookmon-collector.service
[Unit]
Description=HookMon Collector
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hookmon-collector --config /etc/hookmon/collector.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Step 5: View the Dashboard

Open `http://<appliance-hostname>:3000/d/hookmon-main/hookmon` in your browser.

The dashboard auto-refreshes every 5 seconds and shows:
- Sensor status and event counters
- Real-time event timeline from Loki
- Event breakdown by type and severity
- BPF program tables with bytecode hashes
- LD_PRELOAD detection tables

## Verification

Test that the full pipeline works:

```bash
# On the sensor bus host, trigger a test BPF load
sudo bpftool prog load /path/to/test.o /sys/fs/bpf/test

# Or trigger an LD_PRELOAD event
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libc.so.6 /bin/true
```

You should see the event in:
1. Sensor bus stdout (console mode)
2. Grafana Event Timeline panel (Loki)
3. Prometheus counters incrementing

## Network Requirements

| From | To | Port | Protocol | Purpose |
|------|----|------|----------|---------|
| Sensor Bus | Appliance | 3100 | HTTP | Loki event push |
| Appliance | Sensor Bus | 2112 | HTTP | Prometheus scrape |
| Collector | Sensor Bus | 2112 | HTTP | Collector polling /status |
| Collector | Pushgateway | 9091 | HTTP | Fleet health metrics push |
| Browser | Appliance | 3000 | HTTP | Grafana dashboard |
| Sensor Bus | Appliance | 9443 | gRPC/TLS | Server connection (future) |

## Troubleshooting

**Sensor bus fails to start sensors:**
- Ensure running as root (`sudo`)
- Check kernel has BTF: `ls /sys/kernel/btf/vmlinux`
- Check kernel version: 5.8+ required for ring buffer support

**No events in Grafana:**
- Check Loki is receiving: `curl http://<appliance>:3100/loki/api/v1/query?query={service="hookmon"}`
- Check Prometheus is scraping: `curl http://<appliance>:9090/api/v1/targets`
- Verify sensor bus can reach appliance: `curl http://<appliance>:3100/ready` from sensor bus host

**Self-detection events:**
The sensor bus loads its own eBPF programs at startup — you will see BPF_LOAD events from `hookmon-bus`. This is normal and expected. These are the first events to add to an allowlist.

**Sensor shows dead in dashboard but sensor bus process is running:**
- Check the BPF map heartbeat directly: `bpftool map dump name hookmon_heartbeat_SENSORNAME`
- If the map exists but the heartbeat timestamp is stale, the eBPF program may have been unloaded or is not firing. Restart the sensor bus.

**Collector shows host unreachable but host is up:**
- Verify the firewall allows collector to reach the sensor bus on port 2112.
- For SSH transport, verify the SSH credentials and that the `hookmon-collector` user can run `curl -s http://localhost:2112/status` on the remote host.

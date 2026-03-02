# HookMon Deployment Guide

## Overview

A HookMon deployment has two parts:

1. **Appliance** — runs Grafana, Loki, and Prometheus. Receives events from agents. You view the dashboard here.
2. **Agent(s)** — run on each monitored Linux host. Detect eBPF loads and LD_PRELOAD injection, push events to the appliance.

## Prerequisites

### Appliance Host
- Any Linux machine with Docker (x86_64 or arm64)
- 2GB+ RAM (Grafana ~50MB, Loki ~200MB, Prometheus ~100MB)
- Network reachable from monitored hosts on ports 3100 (Loki) and 9090 (Prometheus)
- Port 3000 reachable from your browser (Grafana)

### Agent Host
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

Edit `deploy/docker/prometheus.yml` to list your agent hosts:

```yaml
scrape_configs:
  - job_name: hookmon-agent
    static_configs:
      - targets: ["agent-host-1:2112"]
        labels:
          instance: agent-host-1
      - targets: ["agent-host-2:2112"]
        labels:
          instance: agent-host-2
```

Then restart Prometheus:
```bash
docker compose -f deploy/docker/docker-compose.grafana.yml restart prometheus
```

## Step 2: Build the Agent

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

# Build the agent
mkdir -p bin
go build -o bin/hookmon-agent ./cmd/hookmon-agent/
```

## Step 3: Run the Agent

```bash
sudo ./bin/hookmon-agent --console \
  --loki-url http://<appliance-hostname>:3100 \
  --prometheus-port 2112
```

The agent will:
1. Load all four eBPF sensors
2. Print events to stdout as JSON (console mode)
3. Push events to Loki on the appliance
4. Expose Prometheus metrics on port 2112

### Agent Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--console` | false | Print events to stdout instead of gRPC |
| `--config` | `/etc/hookmon/agent.yaml` | Path to YAML config file |
| `--loki-url` | (disabled) | Loki base URL, e.g. `http://appliance:3100` |
| `--prometheus-port` | 0 (disabled) | Port for Prometheus metrics endpoint |
| `--version` | — | Print version and exit |

### YAML Configuration

The agent can also be configured via `/etc/hookmon/agent.yaml`:

```yaml
host_id: "prod-web-01"
server_addr: "hookmon.internal:9443"
loki_url: "http://hookmon.internal:3100"
prometheus_port: 2112
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
# /etc/systemd/system/hookmon-agent.service
[Unit]
Description=HookMon Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hookmon-agent \
  --config /etc/hookmon/agent.yaml \
  --loki-url http://hookmon.internal:3100 \
  --prometheus-port 2112
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hookmon-agent
```

## Step 4: View the Dashboard

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
# On the agent host, trigger a test BPF load
sudo bpftool prog load /path/to/test.o /sys/fs/bpf/test

# Or trigger an LD_PRELOAD event
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libc.so.6 /bin/true
```

You should see the event in:
1. Agent stdout (console mode)
2. Grafana Event Timeline panel (Loki)
3. Prometheus counters incrementing

## Network Requirements

| From | To | Port | Protocol | Purpose |
|------|----|------|----------|---------|
| Agent | Appliance | 3100 | HTTP | Loki event push |
| Appliance | Agent | 2112 | HTTP | Prometheus scrape |
| Browser | Appliance | 3000 | HTTP | Grafana dashboard |
| Agent | Appliance | 9443 | gRPC/TLS | Server connection (future) |

## Troubleshooting

**Agent fails to start sensors:**
- Ensure running as root (`sudo`)
- Check kernel has BTF: `ls /sys/kernel/btf/vmlinux`
- Check kernel version: 5.8+ required for ring buffer support

**No events in Grafana:**
- Check Loki is receiving: `curl http://<appliance>:3100/loki/api/v1/query?query={service="hookmon"}`
- Check Prometheus is scraping: `curl http://<appliance>:9090/api/v1/targets`
- Verify agent can reach appliance: `curl http://<appliance>:3100/ready` from agent host

**Self-detection events:**
The agent loads its own eBPF programs at startup — you will see BPF_LOAD events from `hookmon-agent`. This is normal and expected. These are the first events to add to an allowlist.

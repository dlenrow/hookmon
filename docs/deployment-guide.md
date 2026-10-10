# HookMon Deployment Guide

## Overview

This guide sets up the observability path, which works today. It has three parts:

1. **Observability stack:** Grafana, Loki, Prometheus, Pushgateway and Alertmanager, run with Docker Compose. Today this compose stack is the whole "appliance". The appliance images (ISO, OVA, QCOW2, VHD) do not build a working image yet (fix plan step 7g).
2. **Sensor buses:** `hookmon-bus` on each monitored Linux host. Each detects eBPF loads, linker environment injection, ptrace abuse, library tampering and more, and pushes events to Loki.
3. **Collector:** `hookmon-collector`, run on the stack's host but outside Compose. It polls each host's `/status` endpoint and pushes fleet health to Pushgateway.

The server path (`hookmon-server`, PostgreSQL, the dashboard, enrollment, SIEM connectors) is not covered here. Parts of it don't work yet; see [architecture.md](architecture.md#server). Packages (DEB, RPM) and Ansible roles don't work yet either (step 7g). Until they do, you build the bus from source.

All sensors are read-only. They observe and report, and cannot block or change anything. There is no enforcement mode.

## Prerequisites

### Stack Host
- Any Linux machine with Docker and the Compose plugin (x86_64 or arm64)
- 2 GB+ RAM
- Reachable from monitored hosts on port 3100 (Loki)
- Able to reach each monitored host on port 2112 (Prometheus scrapes and collector polls)
- Port 3000 reachable from your browser (Grafana)
- Go 1.23 or newer to build the collector

### Sensor Bus Host
- Linux with BTF (`/sys/kernel/btf/vmlinux`). Tested on 5.19 only.
  - 5.9 or newer is required: the file sensors need fanotify directory-entry events.
  - On kernels before 5.15 there are no perf-event link objects, so the health check skips the link and only asks the kernel which program the perf event has attached.
  - On kernels before 5.17, `exec_injection` scans fewer environment variables (512 reads instead of 8192).
- Root (eBPF, fanotify)
- To build: Go 1.23+, make, clang, llvm-strip, libbpf headers, bpftool and a C compiler
- Can reach the stack host on port 3100

## Step 1: Deploy the Observability Stack

```bash
git clone https://github.com/dlenrow/hookmon.git
cd hookmon
docker compose -f deploy/docker/docker-compose.grafana.yml up -d
```

Verify:
```bash
docker compose -f deploy/docker/docker-compose.grafana.yml ps
curl -s localhost:3000/api/health        # Grafana
curl -s localhost:3100/ready             # Loki
curl -s localhost:9090/-/ready           # Prometheus
curl -s localhost:9093/-/ready           # Alertmanager
```

Default Grafana login: `admin` / `hookmon`

### Configure Prometheus Scrape Targets

Edit `deploy/docker/prometheus.yml` and list your sensor bus hosts under the `hookmon-bus` job:

```yaml
  - job_name: hookmon-bus
    static_configs:
      - targets: ["bus-host-1:2112", "bus-host-2:2112"]
```

The `HookMonNoEvents24h` alert uses these scrapes. Then restart Prometheus:
```bash
docker compose -f deploy/docker/docker-compose.grafana.yml restart prometheus
```

### Configure Alertmanager

`deploy/docker/alertmanager.yml` ships with a placeholder receiver. Add a webhook URL there, or alerts show in Alertmanager and notify nobody.

## Step 2: Build the Sensor Bus

On each monitored host, or on a build host with the same kernel and architecture (the eBPF objects are built from the running kernel's BTF):

```bash
# Dependencies (Debian/Ubuntu). bpftool is usually in linux-tools-$(uname -r).
sudo apt-get install -y make gcc clang llvm libbpf-dev
# Go: https://go.dev/dl/

git clone https://github.com/dlenrow/hookmon.git
cd hookmon

# Builds vmlinux.h and the eBPF objects (make bpf), then the bus and the dlopen helper
make build-bus build-dlopen-probe
```

This produces `bin/hookmon-bus` and `bin/hookmon-dlopen-probe`. The bus looks for the helper in its own directory. Install both together, or set `dlopen_probe_path` (or `--dlopen-probe`). Without the helper, `dlopen_monitor` is reported `unverifiable` and the host `degraded`.

## Step 3: Run the Sensor Bus

```bash
sudo ./bin/hookmon-bus --console \
  --loki-url http://<stack-host>:3100 \
  --status-port 2112
```

The sensor bus will:
1. Load and attach all eight sensors
2. Print events to stdout as JSON (console mode)
3. Push events to Loki
4. Serve `/status` and `/metrics` on port 2112
5. Every 10 seconds, fire each eBPF hook itself to check that it still runs

Without `--console`, the bus also streams events over gRPC to `hookmon-server` at `server_addr` (default `localhost:9443`). If no server answers, the events are written to `fallback_log_path`. Use `--console` if you run no server.

### Sensor Bus Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--console` | false | Print events to stdout as JSON; no server connection |
| `--config` | `/etc/hookmon/bus.yaml` | Path to the YAML config file. If it can't be read, built-in defaults are used. |
| `--loki-url` | (disabled) | Loki base URL, e.g. `http://stack-host:3100` |
| `--status-port` | 2112 (from config) | Port for `/status` and `/metrics` |
| `--status-addr` | all interfaces | Bind address for `/status` and `/metrics`, e.g. `127.0.0.1` |
| `--dlopen-probe` | `hookmon-dlopen-probe` next to the bus binary | Path to the dlopen helper |
| `--scan-rpath <dir>` | — | Scan a directory's ELF binaries for RPATH issues, print JSON, and exit |
| `--version` | — | Print version and exit |

`hookmon-bus` has no `--prometheus-port` flag. Only the deprecated `hookmon-agent` binary still accepts it (as an alias for the status port); `hookmon-agent` reads `/etc/hookmon/agent.yaml` by default.

### YAML Configuration

`/etc/hookmon/bus.yaml` (all keys are optional; these are the defaults, except `host_id` and `loki_url`):

```yaml
host_id: "prod-web-01"            # self-asserted until enrollment works (fix plan step 7a)
server_addr: "localhost:9443"
loki_url: "http://hookmon.internal:3100"
status_port: 2112
status_addr: ""                   # empty: all interfaces
log_level: "info"
fallback_log_path: "/var/log/hookmon/fallback.jsonl"
heartbeat_interval: 30s           # heartbeat RPC to the server
heartbeat_sensor_interval: 10s    # probe and health-check cycle
dead_threshold: 15s               # no confirmed beat for this long: dead
dlopen_probe_path: ""             # empty: next to the bus binary
tls:                              # gRPC to the server; plaintext if unset
  cert_file: ""
  key_file: ""
  ca_file: ""
  server_name: ""
  insecure: false
sensors:
  bpf_syscall: true
  exec_injection: true
  shm_monitor: true
  dlopen_monitor: true
  linker_config: true
  ptrace_monitor: true
  lib_integrity: true
  elf_rpath: true
```

Command-line flags override YAML values.

### Running as a systemd Service

```ini
# /etc/systemd/system/hookmon-bus.service
[Unit]
Description=HookMon Sensor Bus
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hookmon-bus \
  --console \
  --config /etc/hookmon/bus.yaml \
  --loki-url http://hookmon.internal:3100 \
  --status-port 2112
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Install `hookmon-dlopen-probe` to `/usr/local/bin/` too. With `--console`, events also go to the journal; drop it if you run `hookmon-server`.

```bash
sudo install -m 0755 bin/hookmon-bus bin/hookmon-dlopen-probe /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable --now hookmon-bus
```

## Step 4: Configure the Collector

`hookmon-collector` runs on the stack host and polls each host's `/status` endpoint. It is not part of the compose stack.

### Install

```bash
make build-collector
sudo install -m 0755 bin/hookmon-collector /usr/local/bin/
sudo mkdir -p /etc/hookmon /var/lib/hookmon
```

### Configure

Create `/etc/hookmon/collector.yaml`. Every monitored host must be listed here; there is no command that registers hosts. Restart the collector after you change the file.

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

In SSH mode the collector runs `curl -s http://localhost:2112/status` on the host, so the bus must use port 2112 there and `curl` must be installed. The SSH user needs no other privileges. The collector does not verify the SSH host key. SSH mode returns the same `/status` answer as HTTP mode; it is not an independent check.

### Run

```bash
sudo hookmon-collector --config /etc/hookmon/collector.yaml
```

### Verify

```bash
# The collector has pushed fleet metrics
curl -s http://localhost:9091/metrics | grep hookmon_fleet

# Fleet status file
jq . /var/lib/hookmon/fleet-status.json
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

If the collector stops, `HookMonCollectorSilent` fires after about two minutes (90 s without a push, held for 30 s).

## Step 5: View the Dashboard

Open `http://<stack-host>:3000/d/hookmon-main/hookmon` in your browser.

The dashboard refreshes every 5 seconds and shows:
- Fleet health, per-host status and a 24-hour sensor health grid
- Sensor and event counters
- The event timeline from Loki
- Events by type and severity
- Recent BPF loads, with the kernel program tag
- Exec injection detections

## Verification

Check the pipeline end to end:

```bash
# On the sensor bus host: an LD_PRELOAD exec (EXEC_INJECTION)
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libc.so.6 /bin/true

# Or load and pin a BPF program (BPF_LOAD), then remove it
sudo bpftool prog load /path/to/test.o /sys/fs/bpf/test
sudo rm /sys/fs/bpf/test
```

You should see the event in:
1. The bus's stdout (console mode)
2. Grafana's Event Timeline panel (Loki)
3. `hookmon_events_total` in Prometheus

Health:
```bash
curl -s http://<bus-host>:2112/status | jq .
```

`overall` should be `alive`, and each of the eight sensors `alive`.

## Network Requirements

| From | To | Port | Protocol | Purpose |
|------|----|------|----------|---------|
| Sensor bus | Stack host | 3100 | HTTP | Loki event push |
| Prometheus | Sensor bus | 2112 | HTTP | `/metrics` scrape |
| Collector | Sensor bus | 2112 (or 22 for SSH) | HTTP / SSH | `/status` poll |
| Collector | Pushgateway | 9091 | HTTP | Fleet health push |
| Browser | Stack host | 3000 | HTTP | Grafana |
| Sensor bus | Server | 9443 | gRPC | Server path only; plaintext unless TLS is configured (step 7b) |

The status port is unauthenticated. Restrict it with a host firewall or `--status-addr`. Loki pushes are unauthenticated plain HTTP.

## Troubleshooting

**Sensor bus fails to start sensors:**
- Run as root (`sudo`).
- Check for BTF: `ls /sys/kernel/btf/vmlinux`.
- The file sensors fail on kernels older than 5.9 (no `FAN_REPORT_DFID_NAME`).
- Rebuild the eBPF objects on the target kernel (`make bpf`, then rebuild the bus). They are built from the running kernel's BTF.
- `curl -s localhost:2112/status | jq .` shows `failed` and a reason for each sensor that did not start.

**No events in Grafana:**
- Check that Loki receives events: `curl -G http://<stack-host>:3100/loki/api/v1/query --data-urlencode 'query={service="hookmon"}'`
- Check that Prometheus scrapes the bus: `curl http://<stack-host>:9090/api/v1/targets`
- From the bus host: `curl http://<stack-host>:3100/ready`

**The bus's own activity:**
The bus drops events whose PID or parent PID is its own: its own `bpf()` calls when it loads the sensors, and the probe processes it runs every 10 seconds. You won't see BPF_LOAD events from `hookmon-bus`. Its programs do appear in the BPF_INVENTORY events that `bpf_syscall` sends at startup and every 5 minutes.

**A sensor shows dead, failed or unverifiable while the bus is running:**
- `curl -s localhost:2112/status | jq '.sensors[] | {name, status, reason}'` gives the reason.
- `dlopen_monitor` `unverifiable`: the bus can't find `hookmon-dlopen-probe`. Put it next to the bus binary or set `--dlopen-probe`.
- `dead`: the hook did not run when the bus fired it, or its program or link is gone. List what is attached with `sudo bpftool prog show` and `sudo bpftool link show`. Restart the bus.

**Collector shows a host unreachable but the host is up:**
- Check that the firewall lets the collector reach the bus on port 2112.
- For SSH transport, check the SSH credentials and that `curl -s http://localhost:2112/status` works on the host as the collector's user.

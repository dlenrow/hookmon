# HookMon Deployment Guide

## Overview

This guide sets up the observability path, which works today, and then the server path. The observability path has three parts:

1. **Observability stack:** Grafana, Loki, Prometheus, Pushgateway and Alertmanager, run with Docker Compose. Today this compose stack is the whole "appliance". The appliance images (ISO, OVA, QCOW2, VHD) do not build a working image yet (fix plan step 7g).
2. **Sensor buses:** `hookmon-bus` on each monitored Linux host. Each detects eBPF loads, linker environment injection, ptrace abuse, library tampering and more, and pushes events to Loki.
3. **Collector:** `hookmon-collector`, run on the stack's host but outside Compose. It polls each host's `/status` endpoint and pushes fleet health to Pushgateway.

[Server Path](#server-path) sets up `hookmon-server`, PostgreSQL, bus enrollment and the dashboard. Parts of the server path don't work yet; see [architecture.md](architecture.md#server). Packages (DEB, RPM) and Ansible roles don't work yet either (step 7g). Until they do, you build the bus and the server from source.

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

Without `--console`, the bus also streams events over mutual-TLS gRPC to `hookmon-server` at `server_addr` (default `localhost:9443`). If no server answers, the events are written to `fallback_log_path`. A bus without `--console` needs a client certificate, which it gets by enrolling (see [Server Path](#server-path)). With no certificate and no enrollment token it refuses to start:

```
enrollment: no client certificate and no enrollment token: refusing to connect to the server without TLS; enroll with --enroll-token and --ca-file, set tls.cert_file, or pass --insecure to connect without TLS (development only)
```

Use `--console` if you run no server.

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
| `--server-addr` | `localhost:9443` (from config) | `hookmon-server` gRPC address |
| `--enroll-token-file` | — | File holding the enrollment secret (mode 0600). Used on the first start, when the bus has no certificate yet. Preferred: the secret stays out of the process list |
| `--enroll-token` | — | The enrollment secret itself. Visible in the process list while the bus enrolls; prefer `--enroll-token-file` or `HOOKMON_ENROLL_TOKEN` |
| `--enroll-addr` | the `--server-addr` host, port 9444 | `hookmon-server` enrollment address |
| `--ca-file` | — | CA certificate that signed the server's certificate. Required to enroll |
| `--state-dir` | `/var/lib/hookmon` (from config) | Where the enrolled key and certificates are stored |
| `--insecure` | false | Connect to the server without TLS. Development only |
| `--version` | — | Print version and exit |

The environment variable `HOOKMON_ENROLL_TOKEN` also gives the enrollment secret, when neither token flag does. It is readable by root and the bus's own user (`/proc/<pid>/environ`), not by everyone; the bus unsets it once read, so the helpers it runs do not inherit it.

`hookmon-bus` has no `--prometheus-port` flag. Only the deprecated `hookmon-agent` binary still accepts it (as an alias for the status port); `hookmon-agent` reads `/etc/hookmon/agent.yaml` by default.

### YAML Configuration

`/etc/hookmon/bus.yaml` (all keys are optional; these are the defaults, except `host_id` and `loki_url`):

```yaml
host_id: "prod-web-01"            # replaced by the certificate's host ID; the server ignores it except with --insecure
server_addr: "localhost:9443"
enroll_addr: ""                   # empty: the server_addr host on port 9444
state_dir: "/var/lib/hookmon"     # bus.key, bus.crt and ca.crt from enrollment, mode 0600
loki_url: "http://hookmon.internal:3100"
status_port: 2112
status_addr: ""                   # empty: all interfaces
log_level: "info"
fallback_log_path: "/var/log/hookmon/fallback.jsonl"
heartbeat_interval: 30s           # heartbeat RPC to the server
heartbeat_sensor_interval: 10s    # probe and health-check cycle
dead_threshold: 15s               # no confirmed beat for this long: dead
dlopen_probe_path: ""             # empty: next to the bus binary
tls:                              # mutual TLS to the server
  cert_file: ""                   # empty: the enrolled certificate in state_dir
  key_file: ""
  ca_file: ""                     # same as --ca-file
  server_name: ""                 # empty: the host in server_addr
  insecure: false                 # true: plaintext gRPC (development only)
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

Install `hookmon-dlopen-probe` to `/usr/local/bin/` too. With `--console`, events also go to the journal. If you run `hookmon-server`, drop `--console` and enroll the bus first (see [Server Path](#server-path)); the unit then needs no token.

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
ssh_known_hosts: /etc/hookmon/collector_known_hosts
hosts:
  - hostname: prod-web-01
    ssh_host: 10.0.1.101
    ssh_user: hookmon-collector
    ssh_key: /etc/hookmon/collector_rsa
    status_port: 2112            # the bus's status_port on this host (default 2112)
    # ssh_known_hosts: /etc/hookmon/other_known_hosts   # per-host override
```

SSH mode verifies each host's key against `ssh_known_hosts` (OpenSSH's known_hosts format; hashed entries work). It fails closed: the collector refuses to start if a host uses SSH and no known_hosts file is set or readable, and a host whose key is missing from the file, or does not match it, is reported unreachable with the presented key's fingerprint. Build the file with `ssh-keyscan`, and check each fingerprint against the host's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the host) before you trust it:

```bash
ssh-keyscan -t ed25519 10.0.1.101 | sudo tee -a /etc/hookmon/collector_known_hosts
ssh-keygen -lf /etc/hookmon/collector_known_hosts
```

A file that lists only some of a host's key types is enough. The collector then runs `curl -s http://localhost:<status_port>/status` on the host, so `curl` must be installed there. The SSH user needs no other privileges. SSH mode proves the collector reached the real host, but it returns the same `/status` answer as HTTP mode; it is not an independent check of the bus.

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

## Server Path

The server path sends events from each bus to `hookmon-server`, which stores them in PostgreSQL and serves the REST API and the dashboard. Every connection uses TLS, from one CA you create.

### Build

```bash
make build-server build-cli
make build-dashboard                      # needs Node.js 20+; writes dashboard/dist
sudo install -m 0755 bin/hookmon-server bin/hookmon-cli /usr/local/bin/
sudo mkdir -p /usr/share/hookmon/dashboard
sudo cp -r dashboard/dist/. /usr/share/hookmon/dashboard/
```

You also need a PostgreSQL database and a user that can create tables in it. The server runs its migrations at every start.

### Certificates

Make a CA and a server certificate. The certificate must name the address buses and browsers use (a DNS or IP SAN):

```bash
sudo mkdir -p /etc/hookmon/tls && cd /etc/hookmon/tls
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ca.key -out ca.crt -days 3650 -subj "/CN=hookmon CA"
sudo openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server.key -out server.csr -subj "/CN=hookmon.internal"
sudo bash -c 'openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -out server.crt \
  -extfile <(printf "subjectAltName=DNS:hookmon.internal\nextendedKeyUsage=serverAuth")'
sudo chmod 0600 ca.key server.key
```

`ca.key` signs every bus certificate at enrollment. Keep it root-only.

### Configure and Start the Server

```bash
sudo install -m 0600 deploy/server.example.yaml /etc/hookmon/server.yaml
```

Edit `/etc/hookmon/server.yaml`:
- `database.url`: your PostgreSQL connection string.
- `api.tokens`: one or more bearer tokens for the REST API and the dashboard.
- `api.allowed_origins`: leave it empty when browsers load the dashboard from this server. The live event feed accepts a WebSocket only from the server's own origin and from origins listed here (`https://host[:port]`), such as a dashboard served by another host or the Vite dev server (`http://localhost:5173`).
- `enrollment.tokens`: replace the example secret with the output of `openssl rand -hex 32`, and set `expires`. Set `single_use: true` for a token that should enroll one host.
- `tls`: the paths above are the defaults in the example.

```bash
sudo hookmon-server                        # reads /etc/hookmon/server.yaml
curl --cacert /etc/hookmon/tls/ca.crt https://hookmon.internal:8443/api/v1/health
```

The server listens on 9443 (bus gRPC, mutual TLS), 9444 (enrollment, only when tokens are configured) and 8443 (HTTPS: REST API, WebSocket and dashboard). Flags override the file; `hookmon-server --help` lists them. Without a certificate the server refuses to start:

```
no TLS certificate configured: set tls.cert_file, tls.key_file and tls.ca_file (or --tls-cert, --tls-key and --tls-ca), or pass --insecure to run gRPC and REST in plaintext (development only)
```

### Enroll Each Sensor Bus

Copy `ca.crt` (not `ca.key`) to the host, put the enrollment token in a root-only file, then start the bus once with it:

```bash
sudo install -m 0600 /dev/null /etc/hookmon/enroll.token
sudo sh -c 'cat > /etc/hookmon/enroll.token'    # paste the secret, then Ctrl-D
sudo hookmon-bus --enroll-token-file /etc/hookmon/enroll.token \
  --server-addr hookmon.internal:9443 \
  --ca-file /path/to/ca.crt \
  --loki-url http://<stack-host>:3100
```

`HOOKMON_ENROLL_TOKEN=<secret>` works too (for example from a systemd `EnvironmentFile=` with mode 0600). `--enroll-token <secret>` also works, but the secret then shows in the process list while the first start runs. The bus warns about that, and about a token file other users can read.

The bus generates a key, enrolls on port 9444, and stores `bus.key`, `bus.crt` and `ca.crt` in `/var/lib/hookmon` (mode 0600). The server assigns the host's ID and writes it into the certificate, and records the host's hostname; events from this host are stored under that hostname, whatever the bus later reports. Later starts use the stored identity and need no token, so the systemd unit above works without `--console` once `server_addr` is set in `/etc/hookmon/bus.yaml`. Delete the token file once the host has enrolled.

If `--ca-file` is not the CA that signed the server's certificate, or the server address is not a name in that certificate, the bus exits at once:

```
enrollment: enroll with hookmon.internal:9444: the server's TLS certificate does not verify against the CA file: ...; check that --ca-file (tls.ca_file) is the CA that signed the server's certificate, and that the server address is a name in that certificate (or set tls.server_name)
```

Check the inventory:

```bash
curl --cacert /etc/hookmon/tls/ca.crt -H "Authorization: Bearer <api-token>" \
  https://hookmon.internal:8443/api/v1/hosts
```

The host shows `ONLINE` with its sensors' health. If its heartbeats stop for `watchdog.heartbeat_timeout` (default 60 s), the server marks it `UNRESPONSIVE` and stores an AGENT_OFFLINE event. When the bus heartbeats again the host goes back to `ONLINE` and the server stores an AGENT_RECOVERED event. Both appear in the dashboard's live feed and go to every connector.

`hookmon-cli` defaults to `https://localhost:8443`. Pass `--server https://hookmon.internal:8443 --token <api-token> --ca-file ca.crt`, or set `HOOKMON_CA_FILE`.

### Build the Allowlist with Learning Mode

Start learning mode once the buses are enrolled, for the whole fleet or for one host, with an end time (a duration such as `90m`, `36h` or `7d`, or `--until` an RFC 3339 time):

```bash
hookmon-cli $FLAGS learning start --fleet --for 7d
hookmon-cli $FLAGS learning start --host <host-id> --until 2026-11-01T00:00:00Z
hookmon-cli $FLAGS learning                  # windows, and whether each is active
```

`$FLAGS` stands for `--server`, `--token` and `--ca-file` as above. The windows are stored in PostgreSQL, so a restarted server keeps learning until the end time. While a window is open, each event that matches no allowlist entry becomes a PENDING entry for its tuple (event type, executable hash, BPF tag and type / library hash or path / file path / shared memory pattern, in a container or not), with a count, first and last seen times, and the hosts that saw it. Events are still rated and alerted on as usual.

Review the candidates, then approve or reject each one for the fleet or for one host:

```bash
hookmon-cli $FLAGS policies pending
hookmon-cli $FLAGS policies approve <entry-id> --fleet
hookmon-cli $FLAGS policies approve <entry-id> --host <host-id>
hookmon-cli $FLAGS policies reject <entry-id> --fleet       # keeps alerting; not proposed again
hookmon-cli $FLAGS learning stop --fleet                    # end early; PENDING entries stay
```

An approved entry allows exactly the tuple it was learned from. A change through the API applies to the next event. To apply changes made directly in the database, send the server `SIGHUP` (`sudo kill -HUP $(pidof hookmon-server)`); it rereads the allowlist and learning windows, not the config file.

### Configure SIEM Connectors

Add a `connectors:` section to `/etc/hookmon/server.yaml`, with a block for each connector you want, and restart the server. `deploy/server.example.yaml` has every setting, commented. For example, CEF over syslog for alerts, and the full event feed to Splunk:

```yaml
connectors:
  syslog:
    address: siem.example.com:514
    protocol: tcp            # or udp
    # framing: lf            # newline framing, for receivers that do not
    #                        # take RFC 6587 octet counting
  splunk:
    url: https://splunk.example.com:8088/services/collector/event
    token: <HEC token>
    index: security
    min_severity: INFO       # every event, not only alerts
```

`min_severity` decides what a connector gets. With `ALERT` (the default) or `CRITICAL`, it gets alerts: events at or above that severity that no allowlist entry allowed, sent once per 5 minutes per host, binary and subject. With `INFO` or `WARN`, it gets every stored event at or above that severity. Every connector also gets AGENT_OFFLINE when a host stops sending heartbeats, and AGENT_RECOVERED when it starts again.

The other connectors:

- `elasticsearch`: `url`, then `api_key`, or `username` and `password`. Events go to `hookmon-events-YYYY.MM.DD`. At startup the server installs an ILM policy that deletes each index after `ilm.delete_after` (default `90d`), and a matching index template. This needs the `manage_ilm` and `manage_index_templates` cluster privileges. On OpenSearch, or if you manage the policy yourself, set `ilm.setup: false`.
- `webhook`: `url` and optional `headers` (for example `Authorization`). Each POST carries one event as a JSON object. With `batch_size` above 1, each POST carries a JSON array.
- `kafka`: `brokers` and `topic`. There are no TLS or SASL settings yet.

For a sink with a certificate from a private CA, set `ca_file` (Splunk, Elasticsearch, webhook). The config file now holds connector secrets, so keep it owned by root with mode 0600.

At startup the server logs "connector enabled" for each connector. If a connector can't start, the server exits with status 1 and names the connector, for example `start connectors: connectors.syslog: dial syslog tcp://siem.example.com:514: connection refused`. A bad setting is reported when the file loads (`failed to load config`).

The server never waits for a SIEM. Each connector has its own queue (`queue_size`, default 1024). If a sink is slow or down, its queue fills, and the server logs "connector queue full; dropping events" with the running total. When the server stops, each connector logs how many events it sent, dropped and failed.

To check a connector, load a BPF program that is not on the allowlist, as in [Verification](#verification). It is rated WARN, or CRITICAL as root, so it reaches an alert connector within about a second.

### Open the Dashboard

Browse to `https://hookmon.internal:8443/` from a machine that trusts `ca.crt`. Enter an API token on the Settings page and reload; the browser keeps it in local storage. The server serves the dashboard from `dashboard_dir` (default `/usr/share/hookmon/dashboard`).

- **Settings** shows the enrollment command for this server (its gRPC and enrollment ports, `--enroll-token`, `--ca-file`, `--state-dir`), the enrollment tokens by name and expiry, and each connector's sent, failed and dropped counts. No secret is shown.
- **Events** is live: the sidebar shows "Live" while the WebSocket is connected. Every open tab gets every event. A tab that falls more than 256 events behind is disconnected and reconnects by itself, reloading recent events.
- **Allowlist** on an event (in the feed or on its Investigation page) allows exactly that kind of event on its host or on every host.
- **Pending Approval** lists learning-mode candidates; approve or reject each for the fleet or for one host.
- **Hosts** shows each sensor's health from the host's latest heartbeat.
- **Policies** edits, disables and deletes entries.

If the sidebar says "Disconnected, retrying", check the token, and that the address in the browser is the server's own (or is listed in `api.allowed_origins`); the server logs "websocket refused: origin not allowed" for a wrong origin.

To work on the dashboard, run `npm run dev` in `dashboard/` with `HOOKMON_API_URL` (default `https://localhost:8443`) and `HOOKMON_CA_FILE` set, add `http://localhost:5173` to `api.allowed_origins`, and open `http://localhost:5173`. The Playwright smoke test runs against a seeded server: `HOOKMON_E2E_URL=https://hookmon.internal:8443 HOOKMON_E2E_CA=ca.crt HOOKMON_E2E_TOKEN=<api-token> npm run test:e2e` (after `npx playwright install chromium`).

### Development Without TLS

`hookmon-server --insecure` and `hookmon-bus --insecure` run gRPC and REST in plaintext. The server then takes each host ID from the message, so any host can report as any other, and enrollment can't be used. Use it only on a test machine.

## Network Requirements

| From | To | Port | Protocol | Purpose |
|------|----|------|----------|---------|
| Sensor bus | Stack host | 3100 | HTTP | Loki event push |
| Prometheus | Sensor bus | 2112 | HTTP | `/metrics` scrape |
| Collector | Sensor bus | 2112 (or 22 for SSH) | HTTP / SSH | `/status` poll |
| Collector | Pushgateway | 9091 | HTTP | Fleet health push |
| Browser | Stack host | 3000 | HTTP | Grafana |
| Sensor bus | Server | 9443 | gRPC, mutual TLS | Server path: events and heartbeats |
| Sensor bus | Server | 9444 | gRPC, TLS | Server path: enrollment, first start only |
| Browser, `hookmon-cli` | Server | 8443 | HTTPS | Server path: REST API, WebSocket and dashboard |
| Server | SIEM | as configured | syslog (TCP/UDP), HTTPS, Kafka | Server path: SIEM connectors |

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
- For SSH transport, check the SSH credentials and that `curl -s http://localhost:<status_port>/status` works on the host as the collector's user. An error saying the host key "is not in" or "does not match" the known_hosts file means the collector refused the host: add its key after checking the fingerprint, or find out why it changed.

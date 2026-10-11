# HookMon Deployment Guide

## Overview

This guide sets up the observability path, which works today, and then the server path. The observability path has three parts:

1. **Observability stack:** Grafana, Loki, Prometheus, Pushgateway and Alertmanager, run with Docker Compose (`deploy/docker/docker-compose.grafana.yml`). For the whole server path on one host, use the [compose appliance](#compose-appliance) instead. For the server path alone, there is also an [appliance image](#appliance-image) (QCOW2, VHD, OVA; no ISO) and an [Ansible role](#ansible-appliance-role) for an existing Ubuntu 24.04 host.
2. **Sensor buses:** `hookmon-bus` on each monitored Linux host. Each detects eBPF loads, linker environment injection, ptrace abuse, library tampering and more, and pushes events to Loki.
3. **Collector:** `hookmon-collector`, run on the stack's host but outside Compose. It polls each host's `/status` endpoint and pushes fleet health to Pushgateway.

[Server Path](#server-path) sets up `hookmon-server`, PostgreSQL, bus enrollment and the dashboard. Parts of the server path don't work yet; see [architecture.md](architecture.md#server). For the server path, the bus can be installed from a DEB or RPM package or with an Ansible role ([Install the Sensor Bus from a Package](#install-the-sensor-bus-from-a-package)). The server comes from source, the [compose appliance](#compose-appliance), the [appliance image](#appliance-image) or the [Ansible appliance role](#ansible-appliance-role).

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
- Linux with BTF (`/sys/kernel/btf/vmlinux`). The e2e suite has run on 5.19 (Ubuntu 22.10) and 6.17 (Ubuntu 24.04).
  - 5.9 or newer is required: the file sensors need fanotify directory-entry events.
  - On kernels before 5.15 there are no perf-event link objects, so the health check skips the link and only asks the kernel which program the perf event has attached.
  - On kernels before 5.17, `exec_injection` scans fewer environment variables (512 reads instead of 8192).
- Root (eBPF, fanotify)
- To build: Go 1.23+, make, clang, llvm-strip, libbpf headers, bpftool and a C compiler
- Can reach the stack host on port 3100

### All Hosts
- Clocks kept in sync (NTP). Certificates are valid from the moment they are made, so a host whose clock runs behind rejects a new server or bus certificate until it catches up.

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
enrollment: no client certificate and no enrollment token: refusing to connect to the server without TLS; enroll with --enroll-token-file and --ca-file, set tls.cert_file, or pass --insecure to connect without TLS (development only)
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

This unit is for a bus built from source. The DEB and RPM packages install their own `hookmon-bus.service` for the server path; see [Install the Sensor Bus from a Package](#install-the-sensor-bus-from-a-package).

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

## Compose Appliance

The compose appliance runs the server path and the observability stack together on one Docker host (`deploy/appliance/docker-compose.yml`):

```bash
git clone https://github.com/dlenrow/hookmon.git
cd hookmon
sudo deploy/appliance/hookmon-init.sh --mode compose --hostname hookmon.internal --ip <server-ip>
sudo docker compose -f deploy/appliance/docker-compose.yml up -d --build --wait
```

`hookmon-init.sh` writes the CA, the server certificate, an enrollment token, the API token, the database and Grafana passwords, `server.yaml` and `collector.yaml` under `/etc/hookmon` (`--out-dir` to change it; the compose file reads `HOOKMON_CONFIG_DIR`). Secrets are mode 0600. Re-running it changes nothing unless you pass `--new-enroll-token` or `--force`. At the end it prints the bus enrollment command and the CA fingerprint.

The stack runs `hookmon-server` (dashboard and API on :8443, buses on :9443, enrollment on :9444), PostgreSQL (internal only), the collector, Grafana (:3000), Loki (:3100), and Prometheus, Pushgateway and Alertmanager (127.0.0.1 only, since they have no authentication). Every image is pinned by digest. `deploy/appliance/check-stack.sh` checks a running stack; CI runs it on every push.

Then enroll each bus with the printed command (see [Server Path](#server-path) for what enrollment does), and open `https://hookmon.internal:8443` with the CA from `/etc/hookmon/tls/ca.crt` trusted, or Grafana on :3000.

## Appliance Image

A VM image with the server path: Ubuntu 24.04, `hookmon-server`, the dashboard and PostgreSQL 16. Three formats are shipped, all built from one Packer build:

| Format | File | For | Tested |
|--------|------|-----|--------|
| QCOW2 | `hookmon-appliance.qcow2` | KVM, Proxmox, OpenStack | Booted under QEMU/KVM |
| VHD (dynamic) | `hookmon-appliance.vhd` | Hyper-V | The disk booted under QEMU/KVM; Hyper-V import not tested |
| OVA | `hookmon-appliance.ova` | VMware | The VMDK booted under QEMU/KVM; import into VMware or VirtualBox not tested |

There is no ISO (bare-metal installer). For bare metal, install Ubuntu 24.04 and use the [Ansible appliance role](#ansible-appliance-role).

### Build

On a Linux host with KVM, [Packer](https://developer.hashicorp.com/packer/install) 1.11 or newer, `qemu-system-x86` and `qemu-utils`, Go and Node.js 20+:

```bash
make appliance-qcow2   # builds hookmon-server and the dashboard, then the image (a few minutes)
make appliance-vhd     # converts the qcow2 (qemu-img)
make appliance-ova     # converts the qcow2: OVF descriptor, SHA-256 manifest, streamOptimized VMDK
```

The images are written to `appliance/packer/output/`. The base is Ubuntu's 24.04 cloud image, pinned by URL and SHA-256 in `appliance/packer/hookmon.pkr.hcl`. Packer boots it with a NoCloud seed, upgrades its packages, installs PostgreSQL, the server, the dashboard and `hookmon-init.sh`, and removes the build user, SSH host keys, machine ID and cloud-init state. The image holds no keys, tokens or passwords. For Azure, which wants a fixed-size VHD, see the comment in `appliance/packer/convert.sh`.

### What Runs in the VM

- `hookmon-server` as user `hookmon`, with `--config /etc/hookmon/server.yaml`: dashboard and REST API on 8443 (HTTPS), bus gRPC on 9443 (mutual TLS), enrollment on 9444. The server terminates TLS itself and serves the dashboard, so there is no nginx.
- PostgreSQL 16, on the loopback interface only.
- ufw, allowing only 22, 8443, 9443 and 9444. Unattended security upgrades are on.
- No collector, Grafana, Prometheus or Loki. For the observability path, run the [compose appliance](#compose-appliance) or the observability stack elsewhere.

### First Boot

`hookmon-firstboot` runs once, after cloud-init has set the hostname (when the platform provides one):

1. `hookmon-init.sh --mode host`, with the VM's FQDN (or hostname) and each global IP address it has: the CA, the server certificate, the enrollment and API tokens, the database password, and `server.yaml`.
2. `hookmon-db-setup`: the `hookmon` database role, with that password, and the database.
3. `hookmon-server` starts.

The console then shows the dashboard URL, the certificate's names and the CA's SHA-256 fingerprint. `sudo cat /etc/hookmon/secrets/firstboot.txt` shows `hookmon-init.sh`'s full report, with the bus enrollment command. The API token is in `/etc/hookmon/secrets/api-token`. If first boot fails, it runs again at the next boot.

### Logging In

There are no passwords. Log in over SSH as `ubuntu`, with a key that cloud-init installs on first boot:

- **KVM, Proxmox, OpenStack:** the platform's own cloud-init key settings.
- **VMware (OVA):** the `public-keys` property at deploy time. `hostname` sets the hostname the certificate is made for.
- **Hyper-V, VirtualBox, or KVM without cloud-init support:** attach a NoCloud seed ISO (volume label `cidata`) holding `meta-data` and a `user-data` with `ssh_authorized_keys`, for example made with `cloud-localds seed.iso user-data meta-data`.

Without any of these, the appliance still comes up and serves on 8443, but nobody can log in to read the tokens.

### Addresses and Tokens

The network is DHCP on every Ethernet interface (`/etc/netplan/01-hookmon.yaml`; edit it for a static address). The server certificate names the hostname and addresses the VM had at first boot. If they change, or for a new enrollment token, run `hookmon-init.sh` again and restart the server; it keeps the CA and every token you don't ask it to replace:

```bash
sudo hookmon-init.sh --mode host --hostname hookmon.example.internal --ip 10.0.0.5   # new names
sudo hookmon-init.sh --mode host --hostname hookmon.example.internal --ip 10.0.0.5 --new-enroll-token
sudo systemctl restart hookmon-server
```

Give the same `--hostname`, `--dns` and `--ip` values as before (`/etc/hookmon/tls/server.san`) unless you mean to change them: different values issue a new server certificate. `hookmon-init.sh` writes `server.yaml` and the private keys as root; the server's unit hands them to the `hookmon` user at every start, so a restart is all a re-run needs.

## Ansible Appliance Role

`appliance/ansible/playbook.yml` sets up the same server on an existing Ubuntu 24.04 host, with the same systemd unit and first-run steps as the image. It needs `ansible-core` (tested with 2.20) and no collections. From the repository root:

```bash
make appliance-server build-dashboard    # bin/linux-amd64/hookmon-server, dashboard/dist
cp appliance/ansible/inventory.example.ini inventory.ini   # then edit it
ansible-playbook -i inventory.ini appliance/ansible/playbook.yml
```

- `hookmon_postgres` installs PostgreSQL 16 and starts it. It leaves the PostgreSQL config alone; Ubuntu's default listens on localhost only.
- `hookmon_server` installs `hookmon-server`, the dashboard, `hookmon-init.sh` and `hookmon-db-setup`, runs `hookmon-init.sh --mode host` and `hookmon-db-setup`, installs the unit and waits for `/api/v1/health` over TLS.
- Variables (`roles/hookmon_server/defaults/main.yml`): `hookmon_server_hostname` (default: the host's FQDN), `hookmon_server_ip_addresses` (default: its default IPv4 address), `hookmon_server_dns_names`, `hookmon_server_init_extra_args`, and the controller paths of the binary, the dashboard and `hookmon-init.sh`.
- A second run with nothing changed reports `changed=0`. Changing the hostname or address lists issues a new server certificate from the same CA and restarts the server.
- **Firewall:** the roles change none. Open TCP 8443 to browsers and `hookmon-cli`, and 9443 and 9444 to bus hosts (see [Network Requirements](#network-requirements)). Keep PostgreSQL on localhost.

The tokens and the CA are in `/etc/hookmon` on the host, as on the image. `sudo hookmon-init.sh` with the same arguments prints the enrollment command again and changes nothing.

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

With the DEB or RPM, see [Install the Sensor Bus from a Package](#install-the-sensor-bus-from-a-package). With a bus built from source, copy `ca.crt` (not `ca.key`) to the host, put the enrollment token in a root-only file, then start the bus once with it:

```bash
sudo install -m 0600 /dev/null /etc/hookmon/enroll-token
sudo sh -c 'cat > /etc/hookmon/enroll-token'    # paste the secret, then Ctrl-D
sudo hookmon-bus --enroll-token-file /etc/hookmon/enroll-token \
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

`hookmon-cli` defaults to `https://localhost:8443`. Pass `--server https://hookmon.internal:8443 --token <api-token> --ca-file ca.crt`, or set `HOOKMON_CA_FILE`. Every REST endpoint and its CLI equivalent is in [api-reference.md](api-reference.md).

### Install the Sensor Bus from a Package

The DEB and RPM install the bus for the server path. Build them on a Linux host of the target architecture, with the tools from [Step 2](#step-2-build-the-sensor-bus):

```bash
make package-deb     # bin/hookmon-bus_<version>_<arch>.deb (needs dpkg-deb)
make package-rpm     # bin/hookmon-bus-<version>-1.<arch>.rpm (needs rpmbuild)
```

Each target builds the eBPF objects from the build host's kernel BTF, then the dlopen helper with `$(CC)`, then a static `hookmon-bus`, and packs them. Objects built on 5.19 have loaded unchanged on 6.17 (see [claims.md](claims.md)). To build the RPM on a host that has `rpmbuild` but no eBPF toolchain, copy `bin/hookmon-bus` and `bin/hookmon-dlopen-probe` from a build host and run `PREBUILT=1 scripts/build-agent.sh rpm`. The package version comes from `git describe`; `PKG_VERSION` overrides it.

What the package installs:

| Path | Purpose |
|------|---------|
| `/usr/bin/hookmon-bus`, `/usr/bin/hookmon-dlopen-probe` | The bus, and the dlopen helper it finds next to itself |
| `/lib/systemd/system/hookmon-bus.service` (DEB), `/usr/lib/systemd/system/hookmon-bus.service` (RPM) | The service |
| `/etc/hookmon/bus.yaml` | The default configuration. It is a conffile (DEB) or `%config(noreplace)` (RPM), so upgrades keep your edits |
| `/var/lib/hookmon` (0700), `/var/log/hookmon` (0750) | The enrolled key and certificates, and the fallback log |

**When the service runs.** Installing enables `hookmon-bus.service`, but the service starts only once the host is configured, meaning one of these files exists:

- `/etc/hookmon/enroll-token`: an enrollment token, mode 0600. While it exists, the unit passes it with `--enroll-token-file`.
- `/var/lib/hookmon/bus.crt`: the certificate from an earlier enrollment.

The unit's `ConditionPathExists=` lines apply this rule at boot and on `systemctl start`: an unconfigured host skips the service ("start condition unmet") instead of leaving it failing. An upgrade restarts a configured bus.

**Configure and enroll:**

```bash
sudo dpkg -i hookmon-bus_<version>_amd64.deb    # or: sudo dnf install ./hookmon-bus-<version>-1.el9.x86_64.rpm
sudo sed -i 's|^server_addr: .*|server_addr: "hookmon.internal:9443"|' /etc/hookmon/bus.yaml
sudo install -m 0644 ca.crt /etc/hookmon/ca.crt  # the CA that signed the server's certificate (tls.ca_file)
sudo install -m 0600 /dev/null /etc/hookmon/enroll-token
sudo sh -c 'cat > /etc/hookmon/enroll-token'     # paste the secret, then Ctrl-D
sudo systemctl start hookmon-bus
sudo ls -l /var/lib/hookmon                      # bus.key, bus.crt and ca.crt, mode 0600
sudo rm /etc/hookmon/enroll-token                # once enrolled; later starts use the certificate
```

A rejected token or a wrong CA shows in `journalctl -u hookmon-bus`, and the unit retries every 10 seconds. The host then appears in the inventory as described above.

**Hardening.** The bus runs as root, limited to the capabilities it uses: CAP_BPF, CAP_PERFMON and CAP_SYS_ADMIN for the eBPF programs, the inventory and fanotify; CAP_DAC_READ_SEARCH for fanotify's file handles; CAP_SYS_PTRACE for other processes' `/proc` entries; CAP_SYS_RESOURCE for the memlock limit on older kernels. It also runs with `NoNewPrivileges` and a seccomp filter: native system calls only, no mount, module, clock, reboot, swap or raw I/O calls, no new namespaces, no realtime scheduling, and only Unix, IPv4, IPv6 and netlink sockets. The unit uses no option that gives the service its own mount namespace (`ProtectSystem`, `ProtectHome`, `PrivateTmp` and the like): the bus compares each process's mount namespace with its own to decide where an executable's path resolves, and it must see `/tmp`, `/home` and `/dev/shm` as the processes it watches do. `RestrictSUIDSGID` is left out too, because it makes `openat2()` fail, and both the shm_monitor health probe and the bus's safe opens inside a process's root use it. The packaged unit runs the bus in server mode only; for console mode, run the bus as in [Step 3](#step-3-run-the-sensor-bus).

**Remove and purge.** `dpkg -r hookmon-bus` stops and disables the service, and keeps the configuration and the enrolled identity, so a reinstall reconnects as the same host. `dpkg --purge hookmon-bus` and `rpm -e hookmon-bus` also remove the token, `/etc/hookmon/ca.crt`, the identity in `/var/lib/hookmon` and the fallback log, then those directories if nothing else is in them; files that belong to `hookmon-server` or `hookmon-collector` stay. RPM keeps an edited `bus.yaml` as `bus.yaml.rpmsave`.

### Install the Sensor Bus with Ansible

The role `deploy/ansible/roles/hookmon-agent` installs the DEB or RPM, writes `/etc/hookmon/bus.yaml`, `/etc/hookmon/ca.crt` and the token file, starts the service, waits until the host has enrolled, and then deletes the token. A host that has already enrolled is not given the token again, so a second run changes nothing. It supports apt (Debian, Ubuntu) and dnf (RHEL family) hosts. `deploy/ansible/hookmon-bus.yml` applies it to the `hookmon_buses` group.

| Variable | Default | Description |
|----------|---------|-------------|
| `hookmon_agent_package_file` | `""` | The `.deb` or `.rpm` on the controller (an absolute path, or relative to the playbook). It is copied to `hookmon_agent_package_cache_dir` (`/var/cache/hookmon`) and installed from there |
| `hookmon_agent_package_url` | `""` | A URL the host downloads the package from. Set exactly one of the two |
| `hookmon_agent_server_addr` | required | `server_addr`, e.g. `hookmon.internal:9443` |
| `hookmon_agent_ca_cert_file` | required | The server's CA certificate on the controller; installed as `/etc/hookmon/ca.crt` |
| `hookmon_agent_enroll_token` | `""` | The enrollment secret. Required until the host has enrolled. Keep it in Ansible Vault |
| `hookmon_agent_enroll_addr`, `hookmon_agent_tls_server_name` | `""` | `enroll_addr` and `tls.server_name` |
| `hookmon_agent_enroll_timeout` | `120` | Seconds to wait for `/var/lib/hookmon/bus.crt` |
| `hookmon_agent_remove_token` | `true` | Delete `/etc/hookmon/enroll-token` once the host has enrolled |
| `hookmon_agent_loki_url`, `hookmon_agent_status_port` (2112), `hookmon_agent_status_addr`, `hookmon_agent_log_level`, `hookmon_agent_sensors` | see `defaults/main.yml` | The other `bus.yaml` settings |

A change to `bus.yaml` or the CA certificate restarts the bus.

```ini
# inventory
[hookmon_buses]
web-01
web-02

[hookmon_buses:vars]
hookmon_agent_package_file=/srv/hookmon/hookmon-bus_1.0.0_amd64.deb
hookmon_agent_server_addr=hookmon.internal:9443
hookmon_agent_ca_cert_file=/srv/hookmon/ca.crt
```

```bash
ansible-playbook -i inventory deploy/ansible/hookmon-bus.yml -e @vault.yml --ask-vault-pass
```

`vault.yml` sets `hookmon_agent_enroll_token`.

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

An approved entry allows exactly the tuple it was learned from. [allowlist-guide.md](allowlist-guide.md) covers matching, review, scopes, severity and the pitfalls. A change through the API applies to the next event. To apply changes made directly in the database, send the server `SIGHUP` (`sudo kill -HUP $(pidof hookmon-server)`); it rereads the allowlist and learning windows, not the config file.

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

- **Settings** shows the enrollment command for this server (its gRPC and enrollment ports, `--enroll-token-file`, `--ca-file`, `--state-dir`), the enrollment tokens by name and expiry, and each connector's sent, failed and dropped counts. No secret is shown.
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

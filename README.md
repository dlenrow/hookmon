# HookMon

**Monitoring for the main ways code gets into a Linux process.**

HookMon detects eBPF program loading, library injection through the dynamic linker's environment variables, bpftime-style shared memory, runtime `dlopen`, linker configuration tampering, ptrace code injection, shared library replacement, and risky ELF RPATH entries. Each event carries process context. Events go to Loki and Prometheus, and optionally to a central server that checks them against an allowlist.

HookMon does not cover every way code enters a process. [docs/threat-model.md](docs/threat-model.md) lists each way, and which sensor covers it or that none does. HookMon is a reference implementation. [docs/claims.md](docs/claims.md) records what has been tested and what has not. Parts of the server path don't work yet. This README marks each one with the fix plan step that addresses it.

## Eight Read-Only Sensors

The detection layer is eight sensors. They observe and report. They cannot block or change anything. There is no enforcement mode.

| Sensor | Mechanism | Detects |
|--------|-----------|---------|
| `bpf_syscall` | `sys_enter_bpf` and `sys_exit_bpf` tracepoints (eBPF), plus a list of all loaded programs at startup and every 5 minutes | BPF program loads, with the kernel's program tag; attaches through `bpf()` (`PROG_ATTACH`, `LINK_CREATE`, `RAW_TRACEPOINT_OPEN`); programs loaded before HookMon started |
| `exec_injection` | `sched_process_exec` tracepoint (eBPF) | `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `LD_DEBUG` in a new process's environment, for `execve` and `execveat` |
| `shm_monitor` | `sys_enter_openat` and `sys_enter_openat2` tracepoints (eBPF) | `/dev/shm` segments created with `O_CREAT`; bpftime's segment names are CRITICAL |
| `dlopen_monitor` | uprobe on `dlopen` in every glibc that a process has mapped (eBPF) | Runtime library loading, on the host and in containers that bring their own glibc |
| `linker_config` | fanotify (Go) | Changes to `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` and `/etc/ld.so.cache` |
| `ptrace_monitor` | `sys_enter_ptrace` tracepoint (eBPF) | `PTRACE_ATTACH`, `SEIZE`, `POKETEXT`, `POKEDATA`, `POKEUSER`, `SETREGS`, `SETREGSET` |
| `lib_integrity` | fanotify (Go) | Writes, creates, deletes and renames of `.so` files under `/usr/lib`, `/usr/lib64`, `/lib` and `/lib64` |
| `elf_rpath` | `sched_process_exec` tracepoint (eBPF), then `debug/elf` analysis (Go) | Risky `DT_RPATH` and `DT_RUNPATH` entries in each executed binary, reported once per binary version |

The bus adds process context to every event: PID, PPID, UID, GID, cmdline, exe path, exe hash (`sha256:<hex>`), cgroup path and container ID. Most of it comes from `/proc`, so a process that exits before the bus reads it gets less.

## Two Paths

Events leave the sensor bus (`hookmon-bus`) on two paths.

**Observability path (works today).** The bus pushes events to Loki and serves `/metrics` and `/status`. `hookmon-collector` polls `/status` on every host and pushes fleet health to Pushgateway. Grafana shows events and health. Prometheus alert rules go to Alertmanager. This path is tested end to end; see [docs/claims.md](docs/claims.md).

**Server path (partly working).** The bus enrolls with `hookmon-server` once, with a token, and gets a client certificate. It then streams events over mutual-TLS gRPC. The server takes each host's ID from its certificate, checks each event against an allowlist, sets its severity, stores it in PostgreSQL, and serves a REST API, a WebSocket feed and the React dashboard over HTTPS. It sends alerts, or the full event feed, to SIEM connectors. A policy change through the API applies to the next event, with no restart. Learning mode turns what the hosts do into PENDING allowlist entries for review. The dashboard shows live events, allowlists an event in one click, approves or rejects PENDING entries, edits and disables policies, shows each host's sensor health, and gives the real enrollment command. Its WebSocket feed checks the API token and the page's Origin, and every open tab gets every event. `hookmon-cli` talks to the REST API. The server and the bus refuse to run without TLS unless `--insecure` is given. What doesn't work yet:

- `hookmon-cli` defaults to `https://localhost:8443`. Pass `--ca-file` (or set `HOOKMON_CA_FILE`) with the HookMon CA.
- Only one e2e test covers the server path: `TestSIEM_RealStackCanaryReachesSyslogAndWebhook` (step 7d) runs a root bus, enrolled, against the server binary and PostgreSQL. It needs `HOOKMON_TEST_PG_DSN` and `HOOKMON_SERVER_BIN` and skips without them. Every other e2e test runs the bus with `--console`. The full-path test through the WebSocket is step 7h.

## Why This Exists

Loading an eBPF program or injecting a library via `LD_PRELOAD` are two of the most powerful instrumentation capabilities in Linux, and two of the most dangerous. An attacker who can do either one can intercept function calls, read data, and install backdoors that `ps`, `lsof` and most detection tools don't show.

The conventional threat model assumes this requires root (or `CAP_BPF`). That assumption is now wrong.

### The bpftime Problem

[bpftime-go](https://github.com/tylerflint/bpftime-go) is a Go module that runs eBPF programs **entirely in userspace**: no root, no `CAP_BPF`, no kernel eBPF subsystem. It emulates the eBPF VM in a userspace runtime and attaches to target processes via `LD_PRELOAD` and shared memory.

This means:

- **An unprivileged user** can hook `malloc`, `open`, `SSL_read`, `SSL_write`, or any dynamically linked function in any process they can launch.
- **The kernel `bpf()` syscall is never called.** No audit log entry. No `bpftool` visibility. No kernel BPF program list.
- **Few traces in `/proc`.** The hooks live in the target's memory and in shared memory segments. What `/proc` shows is the `LD_PRELOAD` value in the process environment and the runtime library in its memory map.
- **Every process the attacker launches inherits the hooks** via `LD_PRELOAD`.

The main detection signals are the `LD_PRELOAD` variable (which legitimate tools also use), shared memory segments in `/dev/shm`, and the runtime binary itself.

If you were monitoring the `bpf()` syscall to detect eBPF abuse, you are blind to this class of attack, which gets the same result without that syscall.

### The Broader Problem

Even before userspace eBPF, detection of kernel eBPF abuse was poor. An attacker with brief root access loads an eBPF program that hooks syscalls or network functions. The program persists in kernel space. Traditional security tooling doesn't track what BPF programs are loaded, who loaded them, or whether they're authorized.

Meanwhile, legitimate eBPF use is growing fast. Cilium, Falco, Datadog, Tetragon, Tracee and many other tools load eBPF programs as part of normal operations. Few people track whether those programs are the authorized versions.

### The Insight

**Code injection events are rare in production.** A typical server sees a handful of BPF program loads at boot and then few or none for months. Shared libraries change with OS updates. `/etc/ld.so.preload` rarely exists on a production host. An event that doesn't match a known, approved pattern is worth a look.

That suits allowlist-based monitoring: the base rate of legitimate new activity is low.

## Architecture

```
  Monitored hosts                          Observability stack (docker compose)
 ┌────────────────────┐                   ┌──────────────────────────────────┐
 │ hookmon-bus        │── Loki push ─────▶│ Loki :3100                       │
 │  8 sensors         │                   │ Prometheus :9090 ──▶ Alertmanager│
 │  :2112 /metrics    │◀── scrape ────────│ Pushgateway :9091                │
 │  :2112 /status     │◀── poll 30s ──┐   │ Grafana :3000                    │
 └─────────┬──────────┘               │   └───────────────▲──────────────────┘
           │ gRPC (mutual TLS)        │                   │ push
           ▼                          └──── hookmon-collector (runs on its own)
 ┌────────────────────────────────┐
 │ hookmon-server (server path)   │
 │  enrollment :9444, allowlist,  │
 │  PostgreSQL, HTTPS :8443       │
 │  (REST, WebSocket, dashboard)  │
 └────────────────────────────────┘
```

The sensor bus exposes Prometheus metrics and pushes structured logs to Loki. The `/status` endpoint reports each sensor's health, and the collector polls it from outside the host. The compose stack runs Grafana with a pre-built dashboard. See [docs/architecture.md](docs/architecture.md) for details.

## How HookMon Knows It's Still Running

A detector that dies silently is worse than none. HookMon checks its own sensors, and the collector checks the bus from outside:

1. **Active probes.** Every 10 seconds the bus fires each eBPF sensor's hook itself with a harmless call: an `openat` and `openat2` of `/dev/null`, an invalid `ptrace`, a run of `/bin/true`, and a `dlopen` through a small helper (`hookmon-dlopen-probe`). Each hook writes a kernel timestamp to its heartbeat map. A sensor counts as alive only if its map moved forward and its program and link are still attached. The two fanotify sensors are marked alive by a timer in the bus. That shows the bus is running, not that the watch still fires.
2. **The bus reports.** `/status` returns JSON with each sensor's status (`alive`, `dead`, `failed`, `unverifiable` or `unknown`), its last heartbeat and a reason. A sensor is dead after 15 seconds without a confirmed beat (`dead_threshold`).
3. **The collector polls.** `hookmon-collector` polls `/status` on every host in its config file every 30 seconds. It pushes the results to Pushgateway and writes them to a JSON file (`fleet_status_file`).
4. **Prometheus fires.** Alert rules fire when a host is unreachable, a sensor is dead, the fleet is degraded, or the collector stops pushing (`HookMonCollectorSilent`). Alertmanager routes the alerts. The Grafana "Fleet Health" panel shows the state.

The key property: the collector reaches out to the bus. If the bus process is killed, the collector notices at its next poll, because `/status` stops answering. If one sensor stops but the bus keeps running, `/status` reports that sensor dead. One case is not detected: a root attacker can kill the bus and serve a fake "alive" `/status`. See [SECURITY.md](SECURITY.md).

## Why This Should Generate Little Alert Noise

HookMon watches operations that are rare in production. It does not score probabilities. It reports concrete, discrete operations:

- **BPF programs** load at boot and change when a tool is updated. A host might see 5-10 loads at startup, then few or none for weeks.
- **Shared libraries** change with OS updates. A modified `.so` outside an update is a fact that needs an explanation.
- **`/etc/ld.so.preload`** rarely exists on a production host. If it appears, someone should look at it.
- **`LD_PRELOAD` at exec** is uncommon in steady state, and each instance should map to a specific tool (for example `jemalloc` or `libfaketime`).
- **Ptrace injection** outside debugger sessions is rare. `PTRACE_POKETEXT` from a non-debugger process is not noise.

Not every sensor is this quiet. `dlopen_monitor` reports each new (binary, library) pair, and interpreters such as Python call `dlopen` often; the bus reports each pair at most once an hour. `shm_monitor` reports every `/dev/shm` creation, at INFO unless the name looks like bpftime or BPF. `bpf_syscall` sends an INFO inventory every 5 minutes.

Each unallowlisted event needs a decision: approve it or investigate it. Learning mode builds the first allowlist from what the hosts actually do (see [Allowlist Workflow](#allowlist-workflow)).

The expectation is that most hosts raise no alerts in a typical week. That has not been measured; step 8 of the fix plan records the first minutes on real hosts.

## Quick Start

This sets up the observability path. For the server path, see [Server Path](docs/deployment-guide.md#server-path) in the deployment guide.

### 1. Deploy the Observability Stack

On your appliance host (any Linux box with Docker):

```bash
git clone https://github.com/dlenrow/hookmon.git
cd hookmon
docker compose -f deploy/docker/docker-compose.grafana.yml up -d
```

This starts Grafana (:3000), Loki (:3100), Prometheus (:9090), Pushgateway (:9091) and Alertmanager (:9093), with the HookMon dashboard pre-provisioned. All services use host networking. Default Grafana login: `admin` / `hookmon`. The collector is not part of the stack; step 3 runs it.

Before use:
- Add each sensor bus (`<host>:2112`) as a target under `hookmon-bus` in `deploy/docker/prometheus.yml`.
- Add a webhook URL in `deploy/docker/alertmanager.yml`. Until you do, alerts show in Alertmanager but notify nobody.

### Or: the Compose Appliance (Server Path on One Host)

The whole server path in one compose project:

```bash
git clone https://github.com/dlenrow/hookmon.git
cd hookmon
sudo deploy/appliance/hookmon-init.sh --mode compose --hostname hookmon.internal --ip <server-ip>
sudo docker compose -f deploy/appliance/docker-compose.yml up -d --build --wait
```

`hookmon-init.sh` writes the CA, the server certificate, an enrollment token, the API token, the database and Grafana passwords, `server.yaml` and `collector.yaml` under `/etc/hookmon` (`--out-dir` to change it; the compose file reads `HOOKMON_CONFIG_DIR`). Secrets are mode 0600. Re-running it changes nothing unless you pass `--new-enroll-token` or `--force`. At the end it prints the bus enrollment command and the CA fingerprint.

The stack runs `hookmon-server` (dashboard and API on :8443, buses on :9443, enrollment on :9444), PostgreSQL (internal only), the collector, Grafana (:3000), Loki (:3100), and Prometheus, Pushgateway and Alertmanager (127.0.0.1 only, since they have no authentication). Every image is pinned by digest. `deploy/appliance/check-stack.sh` checks a running stack; CI runs it on every push.

### 2. Build and Run the Sensor Bus

On each monitored Linux host (kernel with BTF; tested on 5.19):

```bash
# Build dependencies (Debian/Ubuntu). bpftool is in linux-tools-$(uname -r).
sudo apt install -y make gcc clang llvm libbpf-dev
# Go 1.23 or newer: https://go.dev/dl/

git clone https://github.com/dlenrow/hookmon.git
cd hookmon
make build-bus build-dlopen-probe   # builds the eBPF objects from this kernel's BTF first

sudo bin/hookmon-bus --console \
  --loki-url http://<appliance>:3100 \
  --status-port 2112
```

Keep `hookmon-dlopen-probe` in the same directory as `hookmon-bus`, or pass `--dlopen-probe <path>`. Without it, `dlopen_monitor` is reported `unverifiable` and the host `degraded`.

`--console` prints events to stdout and stops the bus from connecting to a server. Without it, the bus streams events to `hookmon-server` at `server_addr` (default `localhost:9443`) over mutual TLS, and writes the events it can't send to `fallback_log_path`. It needs a client certificate for that: on first start it enrolls with a token from `--enroll-token-file` (preferred: a 0600 file keeps the secret out of the process list), `HOOKMON_ENROLL_TOKEN` or `--enroll-token`. A bus with no certificate and no token refuses to start unless `--insecure` is given, which connects in plaintext (development only). A `--ca-file` that did not sign the server's certificate stops the bus with an error rather than a retry loop.

### 3. Run the Collector

On the appliance, list each host in the collector's config file. There is no command to register hosts; edit the file and restart the collector.

```bash
make build-collector
sudo mkdir -p /etc/hookmon /var/lib/hookmon
sudo tee /etc/hookmon/collector.yaml <<'EOF'
poll_interval: 30s
push_gateway: http://localhost:9091
hosts:
  - hostname: web-prod-01
    status_url: http://10.1.2.3:2112/status
EOF
sudo bin/hookmon-collector --config /etc/hookmon/collector.yaml
```

The collector polls each host's `/status` every 30 seconds. It can also reach a host over SSH (`ssh_host`, `ssh_user`, `ssh_key`); that needs a known_hosts file (`ssh_known_hosts`), and the collector refuses any host whose key is not in it (see the [deployment guide](docs/deployment-guide.md)).

### 4. View the Dashboard

Open `http://<appliance>:3000/d/hookmon-main/hookmon` in your browser.

### Install the Sensor Bus from a Package (Server Path)

`make package-deb` or `make package-rpm` builds `hookmon-bus` for the build host's architecture. Its eBPF objects are compiled against that host's kernel BTF; objects built on 5.19 have loaded unchanged on 6.17 ([claims](docs/claims.md)). The package installs `hookmon-bus` and `hookmon-dlopen-probe` in `/usr/bin`, a hardened `hookmon-bus.service`, and `/etc/hookmon/bus.yaml`, which upgrades keep. The service is enabled but stays stopped until the host is configured: an enrollment token in `/etc/hookmon/enroll-token`, or a certificate from an earlier enrollment in `/var/lib/hookmon`.

```bash
sudo dpkg -i bin/hookmon-bus_<version>_amd64.deb      # or: sudo dnf install ./bin/hookmon-bus-<version>-1.el9.x86_64.rpm
sudo sed -i 's|^server_addr: .*|server_addr: "hookmon.internal:9443"|' /etc/hookmon/bus.yaml
sudo install -m 0644 ca.crt /etc/hookmon/ca.crt       # the CA that signed the server's certificate
sudo install -m 0600 /dev/null /etc/hookmon/enroll-token
sudo sh -c 'cat > /etc/hookmon/enroll-token'          # paste the token, then Ctrl-D
sudo systemctl start hookmon-bus                      # enrolls; the token file can be deleted afterwards
```

The Ansible role `deploy/ansible/roles/hookmon-agent` does the same on many hosts and leaves each one enrolled; see the [deployment guide](docs/deployment-guide.md#install-the-sensor-bus-from-a-package). Purging the package (`dpkg --purge`, `rpm -e`) removes the bus's binaries, unit, configuration, token and enrolled identity.

### Not Working Yet: Appliance Images

- **Appliance images (ISO, OVA, QCOW2, VHD).** None of them builds a working image. The Packer template defines only a QEMU (qcow2) build, `make appliance-ova` names a VMware build that does not exist, and the ISO's `appliance/iso/user-data.yaml` is missing. Today the only "appliance" is the compose stack above. (fix plan step 7g)
- **Appliance Ansible.** The appliance playbook (`appliance/ansible/playbook.yml`) refers to roles and templates that do not exist. (step 7g)
- **Enrollment script.** Earlier docs showed `curl -sSL https://hookmon.internal:9443/enroll | sudo bash -s -- --token <token>`. No such endpoint or script exists. A bus enrolls with `hookmon-bus --enroll-token-file` instead (see the [deployment guide](docs/deployment-guide.md#server-path)); the packages pass it the token file.

## Allowlist Workflow

- **Learning mode.** Turn it on for the fleet or for one host, always with an end time: `hookmon-cli learning start --fleet --for 7d` (or `--host <host-id>`, `--until <RFC 3339 time>`). Until then, the server records each unmatched event as a PENDING allowlist entry, one per unique tuple of event type, executable hash, subject (BPF program tag and type, library hash or path, file path, or the shared memory pattern) and whether it ran in a container. Each entry counts its occurrences and records when it was first and last seen and on which hosts. Learning mode changes no severity and suppresses no alert. The windows are stored in PostgreSQL, so a restarted server keeps learning until the end time.
- **Review.** The dashboard's Pending Approval page, or `hookmon-cli policies pending`, lists the candidates. `hookmon-cli policies approve <id> --fleet` allows the tuple on every host; `--host <host-id>` allows it on that host only. `reject` works the same way: a rejected tuple keeps alerting and is not proposed again. A learned entry matches exactly its tuple; an empty executable hash, for example, is not a wildcard.
- **Writing entries by hand.** `hookmon-cli policies create` (JSON on stdin) or `POST /api/v1/policies`. File hashes are `sha256:<hex>`. `prog_hash` is the kernel's BPF program tag (16 hex digits, as `bpftool prog show` prints it); pin `prog_type` with it, because identical instructions of different program types share a tag. `host_id` limits an entry to one host. `action` must be ALLOW, ALERT or DENY. `PUT` and `PATCH /api/v1/policies/{id}` edit an entry or turn it off (`{"enabled": false}`), as the dashboard's Policy Manager does. When several entries match an event, the most restrictive action wins (DENY, then ALERT, then ALLOW).
- **Allowlist one event.** The "Allowlist" button on an event in the dashboard (`POST /api/v1/events/{id}/allowlist`) creates an ALLOW entry for exactly that event's tuple, as learning mode would, for its host or the fleet.
- **Changes apply at once.** Every write through the API reloads the policy before it answers. `SIGHUP` makes the server reread the allowlist and learning windows from the database, for changes made there directly.
- **Monitoring mode.** The steady state. Unmatched events raise alerts. Nothing is blocked.
- **Enforcement mode: does not exist.** No code blocks anything, and the fix plan does not add it.

The allowlist guide (`docs/allowlist-guide.md`) and the API reference (`docs/api-reference.md`) will be written after step 7.

## SIEM Integration

`hookmon-server` sends events to SIEM systems. Each connector runs when its block is present under `connectors:` in the server config (see `deploy/server.example.yaml` and the [deployment guide](docs/deployment-guide.md#configure-siem-connectors)):

- **Syslog/CEF**: RFC 5424 messages whose body is an ArcSight CEF record, over TCP (octet-counting or newline framing) or UDP. Each event type has its own CEF fields; the mapping is in [architecture.md](docs/architecture.md#siem-connectors).
- **Splunk** HTTP Event Collector (HEC), batched, with the HEC token.
- **Elasticsearch** `_bulk` API, batched, into one index per day (`hookmon-events-YYYY.MM.DD`), with basic or API-key authentication. At startup the server installs an ILM policy that deletes each daily index 90 days after it is created (`ilm.delete_after`), and an index template that applies the policy. Set `ilm.setup: false` to manage both yourself, or on OpenSearch, which has no ILM.
- **Webhook**: JSON POST to any URL, with custom headers and optional batching.
- **Kafka**: JSON messages keyed by host ID. There are no TLS or SASL settings yet.

A connector gets alerts or the full event feed, depending on its `min_severity`. With `ALERT` (the default) or `CRITICAL`, it gets events at or above that severity that no allowlist entry allowed. A repeat of the same alert within 5 minutes is not sent again. With `INFO` or `WARN`, it gets every stored event at or above that severity. Every connector gets AGENT_OFFLINE when a host stops sending heartbeats, and AGENT_RECOVERED when it starts again.

Delivery never holds up ingestion. Each connector has its own bounded queue and worker. Transient failures (network errors, HTTP 429 and 5xx) are retried with backoff. When a queue is full, new events for that connector are dropped and counted in the log. If a connector can't start, the server stops at startup.

The syslog and webhook connectors are tested end to end: a real bus and server send a BPF canary load to receivers in containers. Splunk HEC, Elasticsearch and Kafka are tested only against stand-ins (Go `httptest` servers and sarama's mock producer), not real clusters.

## What HookMon Is Not

HookMon **complements** runtime security tools. It doesn't replace them.

- **Falco/Tetragon/Tracee** answer: "What syscalls is this container making?"
- **HookMon** answers: "Who loaded that Falco eBPF program, when, was it the expected program, and has anything changed since deployment?"

HookMon monitors the monitors. It provides an authorization and inventory layer underneath the runtime security layer.

**HookMon is read-only.** Its sensors use tracepoints, uprobes and notification-only fanotify. The bus cannot block, change or delay any operation on the host. It does not inject code into other processes, change their memory, or alter their environment. Its own probes (described above) are ordinary system calls that change nothing. There is no enforcement mode.

## Documentation

- [Architecture](docs/architecture.md): components, data flow, health checks
- [Deployment Guide](docs/deployment-guide.md): observability stack, sensor bus, collector, server and enrollment
- [Theory of Operations](docs/theory-of-operations.md): attack classes, detection approach, allowlist strategy, tests
- [Threat Model](docs/threat-model.md): every way code enters a Linux process, and which sensor covers it
- [Claims Ledger](docs/claims.md): what has been tested, and how
- [Security Policy](SECURITY.md): trust boundaries and known limitations
- API reference and allowlist guide: written after fix plan step 7

## Building from Source

```bash
# Linux with a BTF-enabled kernel. Needs Go 1.23+, make, clang, llvm-strip,
# libbpf headers, bpftool and a C compiler. Node.js 20+ for the dashboard.
make build-all        # eBPF objects, then hookmon-bus, -agent, -server, -cli, -collector and hookmon-dlopen-probe, into bin/
make build-dashboard  # dashboard/dist, which hookmon-server serves from dashboard_dir
make package-deb      # bin/hookmon-bus_<version>_<arch>.deb (needs dpkg-deb)
make package-rpm      # bin/hookmon-bus-<version>-1.<arch>.rpm (needs rpmbuild)
```

On macOS the Go binaries build with stub sensors. No sensor works there.

## License

Apache 2.0

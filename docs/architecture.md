# HookMon Architecture

## System Overview

HookMon has three parts:

- **Sensor buses** (`hookmon-bus`) on monitored hosts.
- An **observability stack** (Loki, Prometheus, Pushgateway, Alertmanager, Grafana) run with Docker Compose, plus `hookmon-collector`.
- A **central server** (`hookmon-server`, PostgreSQL, `hookmon-cli`, the React dashboard).

Events reach people by two paths:

- **Observability path:** bus → Loki and Prometheus; collector → Pushgateway → Prometheus → Alertmanager and Grafana. This path works and has end-to-end tests (see [claims.md](claims.md)).
- **Server path:** bus → gRPC → `hookmon-server` → policy → PostgreSQL → REST, WebSocket and SIEM connectors. The code exists and builds. Parts of it don't work yet; the [Server](#server) section lists them with the fix plan step for each.

```
  Monitored Host (Linux)                     Observability stack (docker compose)
 ┌─────────────────────────────────┐       ┌──────────────────────────────────┐
 │  hookmon-bus (root)             │       │  Grafana :3000                   │
 │  ┌─────────────────────────┐   │       │    └─ HookMon dashboard          │
 │  │ Sensors                 │   │       │  Loki :3100                      │
 │  │  bpf_syscall            │   │       │    └─ event log store            │
 │  │  exec_injection         │   │       │  Prometheus :9090                │
 │  │  shm_monitor            │   │       │    └─ scrapes bus /metrics       │
 │  │  dlopen_monitor         │   │       │    └─ scrapes Pushgateway        │
 │  │  linker_config          │   │       │    └─ alert rules ─▶ Alertmanager│
 │  │  ptrace_monitor         │   │       │  Pushgateway :9091               │
 │  │  lib_integrity          │   │       │    └─ fleet health metrics       │
 │  │  elf_rpath              │   │       │  Alertmanager :9093              │
 │  │  heartbeat BPF maps     │   │       └────────▲─────────▲───────▲──────┘
 │  └──────────┬──────────────┘   │                │         │       │ push
 │             │ events           │                │         │  ┌────┴──────────────┐
 │  ┌──────────▼──────────────┐   │                │         │  │ hookmon-collector │
 │  │ Enrichment (/proc)      │   │                │         │  │ (runs on its own) │
 │  └──────────┬──────────────┘   │                │         │  └────┬──────────────┘
 │  ┌──────────▼──────────────┐   │  POST JSON     │         │       │ GET /status
 │  │ Loki pusher ────────────│───│────────────────┘         │       │ every 30 s
 │  └─────────────────────────┘   │  GET /metrics            │       │
 │  ┌─────────────────────────┐   │◀─────────────────────────┘       │
 │  │ :2112 /metrics, /status │◀──│──────────────────────────────────┘
 │  └─────────────────────────┘   │
 │  ┌─────────────────────────┐   │  gRPC (TLS opt-in)  ┌─────────────────────────┐
 │  │ gRPC transport          │───│────────────────────▶│ hookmon-server          │
 │  │  or console (stdout)    │   │                     │  PostgreSQL, REST :8443 │
 │  └─────────────────────────┘   │                     └─────────────────────────┘
 └─────────────────────────────────┘
```

## Sensor Bus Components

### Sensors

Each sensor watches one way code gets into a process. The eBPF sensors use tracepoints or uprobes; the file sensors use fanotify. Events flow to the bus for enrichment and forwarding.

| Sensor | Hook point | Type | What it captures |
|--------|-----------|------|-----------------|
| `bpf_syscall` | `tracepoint/syscalls/sys_enter_bpf` and `sys_exit_bpf`; a program list at startup and every 5 minutes | eBPF tracepoint, plus Go | `BPF_PROG_LOAD` (BPF_LOAD), and `BPF_PROG_ATTACH`, `BPF_LINK_CREATE` and `BPF_RAW_TRACEPOINT_OPEN` (BPF_ATTACH), with program name, type, instruction count, ID and the kernel's program tag. Every loaded program as BPF_INVENTORY. `BPF_MAP_CREATE` is not reported. |
| `exec_injection` | `tracepoint/sched/sched_process_exec` | eBPF tracepoint | `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `LD_DEBUG` in the new process's environment, for `execve` and `execveat` |
| `shm_monitor` | `tracepoint/syscalls/sys_enter_openat` and `sys_enter_openat2` | eBPF tracepoint | Opens with `O_CREAT` under `/dev/shm/`; the name is classified as `bpftime`, `bpf_related` or `unknown` |
| `dlopen_monitor` | uprobe on `dlopen` in each distinct glibc mapped by any process | eBPF uprobe | Library path and flags. glibc copies are found in `/proc/*/maps` at startup and every 5 minutes, including containers' |
| `linker_config` | `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.cache`, `/etc/ld.so.conf.d/` | fanotify, directory-entry events | Writes, creates, deletes and renames, with old and new hashes |
| `ptrace_monitor` | `tracepoint/syscalls/sys_enter_ptrace` | eBPF tracepoint | `PTRACE_ATTACH`, `SEIZE`, `POKETEXT`, `POKEDATA`, `POKEUSER`, `SETREGS`, `SETREGSET`, with target PID, target comm and address |
| `lib_integrity` | `/usr/lib`, `/usr/lib64`, `/lib`, `/lib64` and everything below | fanotify, directory-entry events | Writes, creates, deletes and renames of `*.so` and `*.so.*`, with old and new hashes and whether `ld.so.cache` lists the library |
| `elf_rpath` | `tracepoint/sched/sched_process_exec` | eBPF tracepoint, plus Go `debug/elf` | `DT_RPATH` and `DT_RUNPATH` of every executed binary, ranked by risk; one event per binary version, at MEDIUM or above |

All sensors implement the `Sensor` interface (`agent/sensors/sensor.go`):

```go
type SensorType string
const (
    SensorTypeBPF      SensorType = "bpf"
    SensorTypeFanotify SensorType = "fanotify"
    SensorTypeAudit    SensorType = "audit" // no sensor uses it since step 4
)

type Sensor interface {
    Name() string
    Type() SensorType
    Start() error
    Stop() error
    Events() <-chan *event.HookEvent
}
```

The eBPF sensors also implement `BPFHealth` (`HeartbeatNs`, `CheckAttached`), which the health check uses.

The eBPF programs are compiled by `make bpf` from the running kernel's BTF and embedded in the binary with `go:embed`. Build tags (`//go:build linux`) keep eBPF code out of other builds. Stub sensors let the Go code build on macOS, where no sensor works.

### Enrichment

After a sensor emits an event, the bus adds process context (`agent/enrichment`):

- **From the kernel, in the sensor's event:** PID, PPID, UID, GID, comm.
- **From `/proc/<pid>/`:** cmdline, exe path, cgroup path.
- **Container ID:** parsed from the cgroup path. Docker, cri-containerd, CRI-O and libpod are recognized.
- **Exe hash:** `sha256:<hex>` of the executable, cached by (device, inode, mtime, ctime). A process in another mount namespace is hashed through `/proc/<pid>/root`, so a container process gets its own binary's hash.

If the process has exited before the bus reads `/proc`, these fields are empty. A file-sensor event whose writer has exited gets UID 4294967295 ("unknown").

The program tag on BPF events is not enrichment. The `bpf_syscall` program reads it from the kernel when the program loads.

### Self-filtering

The bus drops events whose PID or parent PID is its own. That removes its own `bpf()` calls when it loads the sensors, and the probe processes it runs for health checks. BPF_INVENTORY events carry no PID, so HookMon's own programs appear in every inventory.

### Transports

- **Console** (`--console`): JSON lines on stdout. No server connection.
- **gRPC** (default when `--console` is not given): streams events to `hookmon-server` at `server_addr`. TLS is used only when `tls.cert_file` and the related settings are configured; otherwise it is plaintext (fix plan step 7b). Events the server did not acknowledge go to `fallback_log_path`. Nothing replays them.
- **Loki** (`--loki-url`): batched HTTP POST to Loki's push API, alongside either transport. Events are labeled with `service`, `event_type`, `severity`, `hostname` and `sensor`. Batches flush every 1 s or at 10 events.
- **Prometheus and `/status`** (`--status-port`, default 2112; `--status-addr` sets the bind address): one HTTP server serves `/metrics` and `/status`. The old `--prometheus-port` flag exists only on the deprecated `hookmon-agent` binary.

### Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `hookmon_events_total` | Counter | `event_type`, `severity`, `comm` | Events reported, including BPF_INVENTORY |
| `hookmon_sensor_errors_total` | Counter | `sensor` | Sensor start failures |
| `hookmon_sensors_active` | Gauge | -- | Number of running sensors |
| `hookmon_bpf_insn_count` | Histogram | `prog_name` | BPF instruction count distribution |
| `hookmon_sensor_alive` | Gauge | `sensor` | 1 if alive; 0 if dead, failed, unverifiable or unknown |
| `hookmon_sensor_status` | Gauge | `sensor`, `status` | 1 for the sensor's current status |
| `hookmon_sensor_last_beat_seconds` | Gauge | `sensor` | Unix time of the last confirmed heartbeat |
| `hookmon_sensor_last_beat_age_seconds` | Gauge | `sensor` | Seconds since the last confirmed heartbeat |
| `hookmon_bus_overall` | Gauge | `status` | 1 for the bus's overall status (`alive`, `degraded` or `dead`) |
| `hookmon_fleet_sensor_alive` | Gauge | `host`, `sensor` | Per host, per sensor alive (from the collector) |
| `hookmon_fleet_host_reachable` | Gauge | `host` | Host reachable (from the collector) |
| `hookmon_fleet_host_status` | Gauge | `host`, `status` | Host status (from the collector) |
| `hookmon_fleet_hosts_total` | Gauge | -- | Fleet rollup: total hosts |
| `hookmon_fleet_hosts_alive` | Gauge | -- | Fleet rollup: alive hosts |
| `hookmon_fleet_hosts_degraded` | Gauge | -- | Fleet rollup: degraded hosts |
| `hookmon_fleet_hosts_unreachable` | Gauge | -- | Fleet rollup: unreachable hosts |

The `hookmon_fleet_*` metrics are pushed by `hookmon-collector` to Pushgateway, and Prometheus scrapes them from there.

## Sensor Health

A heartbeat that only proves a program is loaded is not enough: an attacker can detach a hook and leave the program in place. So the bus checks that each hook still runs, by running it.

```
Every heartbeat_sensor_interval (default 10 s), the bus:

  1. Fires each eBPF hook with a harmless call
       bpf_syscall     its own bpf() map reads in step 2
       shm_monitor     openat and openat2 of /dev/null
       ptrace_monitor  ptrace with pid 0 (the kernel returns ESRCH)
       exec_injection  one run of /bin/true with a clean environment
       elf_rpath       (the same /bin/true run)
       dlopen_monitor  runs hookmon-dlopen-probe, which calls dlopen(NULL)

  2. Reads key 0 of each hookmon_heartbeat_<sensor> map
       the hook writes bpf_ktime_get_ns() (CLOCK_MONOTONIC) before any filter,
       at most once a second
       alive only if the value moved forward since the last check
       and is under 5 s old

  3. Checks, separately, that each program and link still exist and that the
     kernel still has the program attached (CheckAttached)

  4. Marks a sensor dead when no beat was confirmed for dead_threshold
     (default 15 s, so two missed cycles; worst case about 20 s)

The fanotify sensors are beaten by a Go timer on the same interval.

/status returns the registry: overall status, and per sensor its status
(alive, dead, failed, unverifiable, unknown), last beat and reason.

hookmon-collector (every 30 s, per host):
  GET /status, directly or by running curl over SSH on the host
    success: push per-sensor metrics to Pushgateway
    failure: push "unreachable"
  write the fleet summary to fleet_status_file

Prometheus rules (deploy/docker/grafana/alerts/hookmon-alerts.yaml):
  HookMonHostUnreachable, HookMonSensorDead, HookMonFleetDegraded,
  HookMonCollectorSilent, HookMonNoEvents24h  ─▶ Alertmanager
```

Notes:

- A sensor that fails to start is `failed`. One the bus cannot test (for example, the dlopen helper is missing) is `unverifiable`. Both count against the overall status, so the host shows `degraded`.
- The fanotify timer shows the bus is running. It does not show that the fanotify watch still fires.
- A container's own glibc can't be fired by the host helper, so for those `dlopen_monitor` attachments the only signal is `CheckAttached`.
- A root attacker can forge a heartbeat map or serve a fake `/status`. See [SECURITY.md](../SECURITY.md).

### Data Flow

```
Sensor (eBPF)            Sensor bus                     Observability stack
 heartbeat map ─[read]─▶ Registry ──[/status]──▶ hookmon-collector ──▶ Pushgateway
                            │                                              │
                            └──[/metrics]──────────────▶ Prometheus ◀──────┘
                                                            │
                                                  alert rules ─▶ Alertmanager
                                                            │
                                                         Grafana
```

## Event Data Model

Every detection produces a `HookEvent` (`pkg/event/event.go`) with:

- **Identity:** UUID, nanosecond timestamp, host ID, hostname
- **Classification:** event type and severity. Event types: BPF_LOAD, BPF_ATTACH, BPF_INVENTORY, EXEC_INJECTION, SHM_CREATE, DLOPEN, LINKER_CONFIG, PTRACE_INJECT, LIB_INTEGRITY, ELF_RPATH, and the server's AGENT_OFFLINE and AGENT_RECOVERED
- **Process context:** PID, PPID, UID, GID, comm, cmdline, exe path, exe hash, cgroup path, container ID. The `namespace` field (Kubernetes namespace) is never filled.
- **Type-specific detail:** `BPFDetail`, `BPFInventoryDetail`, `ExecInjectionDetail`, `SHMDetail`, `DlopenDetail`, `LinkerConfigDetail`, `PtraceDetail`, `LibIntegrityDetail` or `ElfRpathDetail`
- **Policy result:** filled by the server

`BPFDetail.ProgHash` holds the kernel's program tag (16 hex digits, as `bpftool prog show` prints it), not a SHA-256.

## Observability Stack

`deploy/docker/docker-compose.grafana.yml` runs these containers, all with host networking:

| Service | Port | Purpose |
|---------|------|---------|
| Grafana | 3000 | Dashboard with pre-provisioned HookMon panels |
| Loki | 3100 | Log store; receives event pushes from sensor buses |
| Prometheus | 9090 | Scrapes bus `/metrics` and Pushgateway; evaluates the alert rules |
| Pushgateway | 9091 | Receives fleet health metrics from `hookmon-collector` |
| Alertmanager | 9093 | Routes alerts; ships with a placeholder webhook receiver |

`hookmon-collector` is not in the compose file. Run it on the same host (see the [deployment guide](deployment-guide.md)). The server and PostgreSQL are not in it either; a compose file with the whole server path is fix plan step 7g.

### Grafana Dashboard

The dashboard (`deploy/docker/grafana/dashboards/hookmon.json`, uid `hookmon-main`) has these panels:

- **Fleet Health**: one stat for the whole fleet
- **Fleet Status**: per-host table from the collector
- **Sensor Health Grid (24h)**: per-sensor state timeline
- **Active Sensors**, **Total Events**, **Sensor Errors**: stat panels
- **Event Rate**: events per second by type
- **Events by Type**: bar chart
- **Events by Severity**: pie chart
- **Event Timeline**: Loki log panel with full event JSON
- **Recent BPF Loads**: table with prog_name, prog_hash (the kernel tag) and comm
- **Exec Injection Detections**: table with library_path, target_binary and env_var
- **BPF Instruction Count Distribution**: histogram

## Server

`hookmon-server` (`server/`) runs:

- **Ingestion** (`server/ingestion`): the `AgentService` gRPC service on `--grpc-addr` (default `:9443`), with `StreamEvents` and `Enroll` RPCs, schema validation and a per-host rate limit.
- **Policy** (`server/policy`): matches events against allowlist entries and built-in rules, and sets severity.
- **Store** (`server/store`): PostgreSQL (`--db`), with `events`, `allowlist`, `hosts` and `audit_log` tables. Migrations are in `server/store/migrations/`.
- **REST API and WebSocket** (`server/api`) on `--http-addr` (default `:8443`): events, policies, hosts and health under `/api/v1/`, and a live event feed at `/api/v1/ws/events`. API tokens come from `--api-tokens`. The API reference is written after fix plan step 7.
- **Connectors** (`server/connectors`): Syslog/CEF, Splunk HEC, Elasticsearch, webhook, Kafka.
- **Watchdog**: marks a host offline after 60 s without a heartbeat and raises AGENT_OFFLINE.

`hookmon-cli` is a REST client: `events`, `hosts`, `policies` (list, `create` from JSON on stdin, `delete <id>`) and `health`.

Not working yet:

| Gap | Fix plan step |
|-----|---------------|
| gRPC TLS is opt-in, and plaintext when no certificate is given, with no warning. REST is always plain HTTP. | 7b |
| `Enroll` returns the CA certificate as the "signed" certificate; enrollment tokens are never passed to the server, so every enrollment is rejected; the bus has no enrollment code. | 7a |
| The HostID in events and heartbeats is whatever the bus sends. | 7a |
| Nothing sets connector configuration, so no connector runs. The alert manager is created but never called. | 7d |
| The allowlist loads once at startup. | 7c |
| The server overrides the severity the bus set. | 7c |
| Learning mode and PENDING entries do not exist. | 7c |
| The WebSocket accepts any non-empty token and any Origin, and one shared channel splits events across open clients. | 7e |
| The server does not serve the dashboard. | 7b |
| No end-to-end test covers this path. | 7h |

## Dashboard

`dashboard/` is a React and TypeScript app built with Vite (`make build-dashboard` writes `dashboard/dist`). It has five pages: Event Feed, Policy Manager, Host Inventory, Investigation and Settings. It talks to the server's REST API and WebSocket.

Not working yet: the server does not serve the built files (step 7b). The Vite dev server proxies `/api` to `https://localhost:8443`, but the server speaks plain HTTP there (step 7e). There is no PENDING-approval page and no per-sensor health on Host Inventory (step 7e).

## Directory Structure

```
hookmon/
├── cmd/
│   ├── hookmon-bus/main.go        # Sensor bus
│   ├── hookmon-agent/main.go      # Deprecated alias for hookmon-bus
│   ├── hookmon-collector/main.go  # Fleet health collector
│   ├── hookmon-server/main.go     # Central server
│   └── hookmon-cli/main.go        # REST client
├── agent/
│   ├── agent.go                   # Bus lifecycle, event pipeline, self-filter
│   ├── health.go                  # Probe, read and evaluate cycle
│   ├── probe_linux.go             # The probes that fire each hook
│   ├── probe/dlopen_probe.c       # hookmon-dlopen-probe helper
│   ├── config/config.go           # YAML config
│   ├── sensors/                   # eBPF (.c + .go) and fanotify sensors
│   ├── enrichment/                # Process context, hashing, container IDs
│   ├── transport/                 # Console, gRPC, fallback, retry
│   ├── registry/                  # Sensor health registry
│   └── observability/
│       ├── loki.go                # Loki pusher
│       ├── prometheus.go          # Metrics and the /metrics + /status server
│       └── status.go              # /status handler
├── server/                        # Central server: ingestion, policy, store, connectors, api
├── dashboard/                     # React + TypeScript UI
├── proto/                         # Protobuf definitions (buf.yaml, buf.gen.yaml)
├── gen/hookmon/v1/                # Generated protobuf and gRPC code
├── pkg/                           # event, crypto, version
├── deploy/docker/                 # Compose stack, Prometheus, Alertmanager, Grafana provisioning
├── test/e2e/                      # End-to-end tests (Linux, root, -tags e2e)
├── test/canary/                   # Programs the e2e tests run
├── test/smoketest/                # Unprivileged smoketests
├── test/transport/                # Wire and transport tests
└── docs/
```

## Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Sensor bus language | Go | cilium/ebpf ecosystem, static linking, cross-compile |
| eBPF library | cilium/ebpf | Widely used, active maintenance |
| eBPF programs | C, built with clang against the host's BTF | Required by the eBPF toolchain |
| Observability | Grafana + Loki + Prometheus + Alertmanager | Standard stack, no custom UI needed for the published path |
| Fleet health | Pushgateway + hookmon-collector | Checks each bus from outside the host |
| Wire protocol | gRPC, with mutual TLS when configured | Streaming, binary encoding; TLS by default is step 7b |
| Database | PostgreSQL | JSON support, enterprise-accepted |

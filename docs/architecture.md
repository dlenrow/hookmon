# HookMon Architecture

## System Overview

HookMon has three tiers: **sensor buses** on monitored hosts, an **appliance** running the observability stack, and (future) a **central server** for policy enforcement.

```
  Monitored Host (Linux)                    HookMon Appliance
 ┌────────────────────────────────┐       ┌──────────────────────────────────┐
 │  hookmon-bus (root)            │       │  Grafana :3000                   │
 │  ┌────────────────────────┐   │       │    └─ HookMon dashboard          │
 │  │ Sensors                │   │       │    └─ Grafana alert rules         │
 │  │  bpf_syscall           │   │       │         (dead sensor, unreachable │
 │  │  exec_injection        │   │       │          host, fleet degradation) │
 │  │  shm_monitor           │   │       │                                  │
 │  │  dlopen_monitor        │   │       │  Loki :3100                      │
 │  │  linker_config         │   │       │    └─ event log store            │
 │  │  ptrace_monitor        │   │       │                                  │
 │  │  lib_integrity         │   │       │  Prometheus :9090                │
 │  │                        │   │       │    └─ metrics store              │
 │  │  Heartbeat BPF maps    │   │       │    └─ scrapes sensor bus /metrics│
 │  │  (per-sensor timestamp)│   │       │    └─ scrapes Pushgateway        │
 │  └───────┬────────────────┘   │       │                                  │
 │          │ events             │       │  Pushgateway :9091               │
 │  ┌───────▼────────────────┐   │       │    └─ fleet health metrics       │
 │  │ Enrichment             │   │       │                                  │
 │  │  pid → cmdline         │   │       │  hookmon-collector               │
 │  │  binary SHA256         │   │       │    └─ polls /status on all hosts │
 │  │  container ID          │   │       │    └─ pushes to Pushgateway      │
 │  │  elf_rpath audit       │   │       │                                  │
 │  └───────┬────────────────┘   │       │  (Future: hookmon-server         │
 │          │                    │       │   PostgreSQL, policy             │
 │  ┌───────▼────────────────┐   │       │   engine, SIEM outputs)         │
 │  │ Loki Pusher ───────────│───│───┐   └──────────▲───────▲──────────────┘
 │  └────────────────────────┘   │   │              │       │
 │  ┌────────────────────────┐   │   │  POST JSON   │       │
 │  │ Prometheus :2112 ◀─────│───│───│──────────────┘       │
 │  └────────────────────────┘   │   │  GET /metrics        │
 │  ┌────────────────────────┐   │   │                      │
 │  │ /status HTTP :2113     │◀──│───│──────────────────────┘
 │  │  (sensor health JSON)  │   │   │  GET /status (collector)
 │  └────────────────────────┘   │   │
 │  ┌────────────────────────┐   │   └──────────────────────┘
 │  │ Console (stdout)       │   │    JSON lines
 │  └────────────────────────┘   │
 └────────────────────────────────┘
```

## Sensor Bus Components

### Sensors

Each sensor monitors a specific code injection vector. eBPF-based sensors use tracepoints or uprobes; filesystem-based sensors use fanotify. Events flow to the sensor bus pipeline for enrichment and forwarding.

| Sensor | Hook Point | Type | What It Captures |
|--------|-----------|------|-----------------|
| `bpf_syscall` | `tracepoint/syscalls/sys_enter_bpf` | eBPF tracepoint | BPF_PROG_LOAD, BPF_PROG_ATTACH, BPF_MAP_CREATE commands with program name, type, instruction count, bytecode hash |
| `exec_injection` | `tracepoint/syscalls/sys_enter_execve` | eBPF tracepoint | LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, LD_DEBUG in process environment |
| `shm_monitor` | `tracepoint/syscalls/sys_enter_openat` | eBPF tracepoint | Shared memory creation matching bpftime patterns in /dev/shm |
| `dlopen_monitor` | `dlopen()` in libc | eBPF uprobe | Runtime library loading with path and flags |
| `linker_config` | `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` | fanotify | Write/create/delete/rename of linker configuration files |
| `ptrace_monitor` | `tracepoint/syscalls/sys_enter_ptrace` | eBPF tracepoint | PTRACE_ATTACH, PTRACE_SEIZE, PTRACE_POKETEXT, PTRACE_POKEDATA with target PID and address |
| `lib_integrity` | `/usr/lib`, `/usr/lib64`, `/lib`, `/lib64` | fanotify | Write/rename/delete of shared library (.so) files with before/after hashes |
| `elf_rpath` | post-enrichment audit on execve events | audit (pure Go) | DT_RPATH/DT_RUNPATH entries in ELF binaries with per-entry risk classification |

All sensors implement the `Sensor` interface:

```go
type SensorType string
const (
    SensorTypeBPF      SensorType = "bpf"
    SensorTypeFanotify SensorType = "fanotify"
    SensorTypeAudit    SensorType = "audit"
)

type Sensor interface {
    Name() string
    Type() SensorType
    Start() error
    Stop() error
    Events() <-chan *event.HookEvent
}
```

Build tags (`//go:build linux`) ensure eBPF code only compiles on Linux. Stub implementations allow the Go code to build on macOS for development.

### Enrichment

After a sensor emits a raw event, the sensor bus enriches it with process context:

- **Process info:** cmdline, exe path, ppid, uid/gid from `/proc/<pid>/`
- **Container detection:** container ID and runtime from cgroup path
- **Binary hashing:** SHA256 of the executable that triggered the event
- **BPF bytecode hashing:** SHA256 of BPF program instructions (for bpf_syscall sensor)

### Transports

The sensor bus supports multiple output modes, selectable at startup:

- **Console** (`--console`): JSON lines to stdout for development and testing
- **gRPC** (default): mTLS streaming to the central server (future)
- **Loki** (`--loki-url`): Batched HTTP POST to Loki's push API. Events are labeled with `service`, `event_type`, `severity`, `hostname`, `sensor`. Flushes every 1s or 10 events.
- **Prometheus** (`--prometheus-port`): Exposes `/metrics` endpoint with counters, gauges, and histograms.

### Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `hookmon_events_total` | Counter | `event_type`, `severity`, `comm` | Total events detected |
| `hookmon_sensor_errors_total` | Counter | `sensor` | Sensor start failures |
| `hookmon_sensors_active` | Gauge | -- | Number of running sensors |
| `hookmon_bpf_insn_count` | Histogram | `prog_name` | BPF instruction count distribution |
| `hookmon_sensor_alive` | Gauge | `sensor` | Whether sensor is alive (1/0) |
| `hookmon_sensor_last_beat_seconds` | Gauge | `sensor` | Unix timestamp of last heartbeat |
| `hookmon_sensor_last_beat_age_seconds` | Gauge | `sensor` | Seconds since last heartbeat |
| `hookmon_bus_overall` | Gauge | `status` | Overall sensor bus status |
| `hookmon_fleet_sensor_alive` | Gauge | `host`, `sensor` | Per-host per-sensor alive (from collector) |
| `hookmon_fleet_host_reachable` | Gauge | `host` | Host reachable (from collector) |
| `hookmon_fleet_host_status` | Gauge | `host`, `status` | Host status (from collector) |
| `hookmon_fleet_hosts_total` | Gauge | -- | Fleet rollup: total hosts |
| `hookmon_fleet_hosts_alive` | Gauge | -- | Fleet rollup: alive hosts |
| `hookmon_fleet_hosts_degraded` | Gauge | -- | Fleet rollup: degraded hosts |
| `hookmon_fleet_hosts_unreachable` | Gauge | -- | Fleet rollup: unreachable hosts |

Note: `hookmon_fleet_*` metrics are pushed by hookmon-collector to Pushgateway and scraped by Prometheus from there.

## Sensor Health Architecture

Each eBPF sensor maintains a per-sensor heartbeat BPF map. The sensor bus userspace reads these maps and exposes health state via an HTTP endpoint. A server-side collector aggregates fleet-wide health into Prometheus via Pushgateway.

```
Each eBPF sensor:
  tracepoint/uprobe handler
       |
       +-- emits HookEvent to pipeline (existing)
       |
       +-- writes bpf_ktime_get_ns() to hookmon_heartbeat_{name} BPF map
           (throttled: at most once per 10s)

Sensor bus (userspace):
  BPF map reader goroutine (every 5s)
       +-- reads each sensor's heartbeat map
           +-- calls registry.Beat(sensorName) if timestamp is fresh

  Registry evaluator (every 15s)
       +-- marks sensors "dead" if last beat > 35s ago

  /status HTTP endpoint
       +-- returns JSON snapshot of registry state

Server-side collector (appliance):
  Poll loop (every 30s, per host)
       +-- HTTP GET /status on each enrolled host
           +-- success: push per-sensor metrics to Pushgateway
           +-- failure: push "unreachable" metric to Pushgateway

  Grafana alert rules
       +-- fire on unreachable host, dead sensor, or fleet degradation
```

### Data Flow

```
Sensor (eBPF)                    Sensor Bus                  Appliance
 heartbeat map   --[5s read]-->  Registry    --[/status]--> hookmon-collector
                                   |                              |
                                   +-- /metrics -----> Prometheus |
                                                           ^      |
                                                           |      v
                                                       Pushgateway
                                                           ^
                                                           |
                                                       Prometheus --> Grafana alerts
```

## Event Data Model

Every detection produces a `HookEvent` with:

- **Identity:** UUID, nanosecond timestamp, host ID, hostname
- **Classification:** event type (BPF_LOAD, BPF_ATTACH, EXEC_INJECTION, SHM_CREATE, DLOPEN, LINKER_CONFIG, PTRACE_INJECT, LIB_INTEGRITY), severity
- **Process context:** PID, PPID, UID, GID, comm, cmdline, exe path, exe hash, cgroup, container ID
- **Type-specific detail:** one of `BPFDetail`, `ExecInjectionDetail`, `SHMDetail`, `DlopenDetail`, `LinkerConfigDetail`, `PtraceDetail`, `LibIntegrityDetail`

See `pkg/event/event.go` for the full struct definition.

## Appliance Components

The appliance runs containers via Docker Compose (`deploy/docker/docker-compose.grafana.yml`), all using host networking:

| Service | Port | Purpose |
|---------|------|---------|
| Grafana | 3000 | Dashboard with pre-provisioned HookMon panels |
| Loki | 3100 | Log aggregation -- receives event pushes from sensor buses |
| Prometheus | 9090 | Metrics -- scrapes sensor bus `/metrics` endpoints and Pushgateway |
| Pushgateway | 9091 | Receives fleet health metrics from hookmon-collector |
| hookmon-collector | -- | Polls sensor bus `/status` endpoints, pushes to Pushgateway |

### Grafana Dashboard

The pre-built dashboard (`deploy/docker/grafana/dashboards/hookmon.json`) includes:

- **Active Sensors** -- stat panel showing running sensor count
- **Total Events** -- cumulative event counter
- **Event Rate** -- time-series graph of events per second by type
- **Events by Type** -- bar chart breakdown
- **Events by Severity** -- donut chart (color-coded INFO/WARN/ALERT/CRITICAL)
- **Event Timeline** -- Loki log panel with full event JSON
- **Recent BPF Loads** -- table with prog_name, prog_hash, comm
- **Exec Injection Detections** -- table with library_path, target_binary, env_var
- **BPF Instruction Count** -- histogram of program complexity

## Directory Structure

```
hookmon/
├── cmd/
│   ├── hookmon-bus/main.go        # Sensor bus binary entry point
│   ├── hookmon-collector/main.go  # Fleet health collector binary
│   ├── hookmon-server/main.go     # Server binary (future)
│   └── hookmon-cli/main.go        # CLI tool (future)
├── agent/
│   ├── agent.go                   # Sensor bus lifecycle, event pipeline
│   ├── config/config.go           # YAML config + CLI flag overrides
│   ├── sensors/                   # eBPF sensors (.c + .go pairs)
│   ├── enrichment/                # Process context, hashing
│   ├── transport/                 # Console, gRPC, retry logic
│   ├── registry/                  # Sensor health registry
│   └── observability/
│       ├── loki.go                # Loki pusher
│       ├── metrics.go             # Prometheus metrics
│       └── status.go              # /status HTTP endpoint
├── server/                        # Central server (future)
├── pkg/event/event.go             # Canonical event types (shared)
├── deploy/docker/                 # Docker Compose + Grafana provisioning
├── test/e2e/                      # End-to-end test suite
└── docs/                          # This documentation
```

## Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Sensor bus language | Go | cilium/ebpf ecosystem, static linking, cross-compile |
| eBPF library | cilium/ebpf | Industry standard, bpf2go codegen, active maintenance |
| eBPF programs | C | Required by the eBPF verifier toolchain |
| Observability | Grafana + Loki + Prometheus | Standard stack, no custom UI needed for MVP |
| Fleet health | Pushgateway + hookmon-collector | Decouples sensor bus from server-side aggregation |
| Wire protocol | gRPC + mTLS | Streaming, binary encoding, mutual auth (future) |
| Database | PostgreSQL | JSON support, enterprise-accepted (future) |

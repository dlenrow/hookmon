# HookMon Architecture

## System Overview

HookMon has three tiers: **agents** on monitored hosts, an **appliance** running the observability stack, and (future) a **central server** for policy enforcement.

```
  Monitored Host (Linux)                    HookMon Appliance
 ┌────────────────────────────┐           ┌──────────────────────────┐
 │  hookmon-agent (root)      │           │  Grafana :3000           │
 │  ┌────────────────────┐    │           │    └─ HookMon dashboard  │
 │  │ Sensors (eBPF)     │    │           │                          │
 │  │  bpf_syscall        │    │           │  Loki :3100              │
 │  │  execve_preload     │    │           │    └─ event log store    │
 │  │  shm_monitor        │    │           │                          │
 │  │  dlopen_monitor     │    │           │  Prometheus :9090        │
 │  └───────┬────────────┘    │           │    └─ metrics store      │
 │          │ events          │           │                          │
 │  ┌───────▼────────────┐    │           │  (Future: hookmon-server │
 │  │ Enrichment         │    │           │   PostgreSQL, policy     │
 │  │  pid → cmdline      │    │           │   engine, SIEM outputs) │
 │  │  binary SHA256      │    │           └────────────▲─────────────┘
 │  │  container ID       │    │                        │
 │  └───────┬────────────┘    │                        │
 │          │                 │                        │
 │  ┌───────▼────────────┐    │    POST JSON           │
 │  │ Loki Pusher ───────│────│────────────────────────┘
 │  └────────────────────┘    │
 │  ┌────────────────────┐    │    GET /metrics
 │  │ Prometheus :2112 ◀─│────│──── scraped by Prometheus
 │  └────────────────────┘    │
 │  ┌────────────────────┐    │
 │  │ Console (stdout)   │    │    JSON lines
 │  └────────────────────┘    │
 └────────────────────────────┘
```

## Agent Components

### Sensors

Each sensor is an eBPF program compiled from C, loaded at agent startup, and attached to a kernel hook point. Events flow through a ring buffer to userspace.

| Sensor | Hook Point | eBPF Type | What It Captures |
|--------|-----------|-----------|-----------------|
| `bpf_syscall` | `tracepoint/syscalls/sys_enter_bpf` | Tracepoint | BPF_PROG_LOAD, BPF_PROG_ATTACH, BPF_MAP_CREATE commands with program name, type, instruction count, bytecode hash |
| `execve_preload` | `tracepoint/syscalls/sys_enter_execve` | Tracepoint | LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH in process environment |
| `shm_monitor` | `shm_open()` in libc | Uprobe | Shared memory creation matching bpftime patterns |
| `dlopen_monitor` | `dlopen()` in libc | Uprobe | Runtime library loading with path and flags |

All sensors implement the `Sensor` interface:

```go
type Sensor interface {
    Name() string
    Start() error
    Stop() error
    Events() <-chan *event.HookEvent
}
```

Build tags (`//go:build linux`) ensure eBPF code only compiles on Linux. Stub implementations allow the Go code to build on macOS for development.

### Enrichment

After a sensor emits a raw event, the agent enriches it with process context:

- **Process info:** cmdline, exe path, ppid, uid/gid from `/proc/<pid>/`
- **Container detection:** container ID and runtime from cgroup path
- **Binary hashing:** SHA256 of the executable that triggered the event
- **BPF bytecode hashing:** SHA256 of BPF program instructions (for bpf_syscall sensor)

### Transports

The agent supports multiple output modes, selectable at startup:

- **Console** (`--console`): JSON lines to stdout for development and testing
- **gRPC** (default): mTLS streaming to the central server (future)
- **Loki** (`--loki-url`): Batched HTTP POST to Loki's push API. Events are labeled with `service`, `event_type`, `severity`, `hostname`, `sensor`. Flushes every 1s or 10 events.
- **Prometheus** (`--prometheus-port`): Exposes `/metrics` endpoint with counters, gauges, and histograms.

### Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `hookmon_events_total` | Counter | `event_type`, `severity`, `comm` | Total events detected |
| `hookmon_sensor_errors_total` | Counter | `sensor` | Sensor start failures |
| `hookmon_sensors_active` | Gauge | — | Number of running sensors |
| `hookmon_bpf_insn_count` | Histogram | `prog_name` | BPF instruction count distribution |

## Event Data Model

Every detection produces a `HookEvent` with:

- **Identity:** UUID, nanosecond timestamp, host ID, hostname
- **Classification:** event type (BPF_LOAD, LD_PRELOAD, SHM_CREATE, DLOPEN), severity
- **Process context:** PID, PPID, UID, GID, comm, cmdline, exe path, exe hash, cgroup, container ID
- **Type-specific detail:** one of `BPFDetail`, `PreloadDetail`, `SHMDetail`, `DlopenDetail`

See `pkg/event/event.go` for the full struct definition.

## Appliance Components

The appliance runs three containers via Docker Compose (`deploy/docker/docker-compose.grafana.yml`), all using host networking:

| Service | Port | Purpose |
|---------|------|---------|
| Grafana | 3000 | Dashboard with pre-provisioned HookMon panels |
| Loki | 3100 | Log aggregation — receives event pushes from agents |
| Prometheus | 9090 | Metrics — scrapes agent `/metrics` endpoints |

### Grafana Dashboard

The pre-built dashboard (`deploy/docker/grafana/dashboards/hookmon.json`) includes:

- **Active Sensors** — stat panel showing running sensor count
- **Total Events** — cumulative event counter
- **Event Rate** — time-series graph of events per second by type
- **Events by Type** — bar chart breakdown
- **Events by Severity** — donut chart (color-coded INFO/WARN/ALERT/CRITICAL)
- **Event Timeline** — Loki log panel with full event JSON
- **Recent BPF Loads** — table with prog_name, prog_hash, comm
- **LD_PRELOAD Detections** — table with library_path, target_binary
- **BPF Instruction Count** — histogram of program complexity

## Directory Structure

```
hookmon/
├── cmd/
│   ├── hookmon-agent/main.go     # Agent binary entry point
│   ├── hookmon-server/main.go    # Server binary (future)
│   └── hookmon-cli/main.go       # CLI tool (future)
├── agent/
│   ├── agent.go                  # Agent lifecycle, event pipeline
│   ├── config/config.go          # YAML config + CLI flag overrides
│   ├── sensors/                  # eBPF sensors (.c + .go pairs)
│   ├── enrichment/               # Process context, hashing
│   ├── transport/                # Console, gRPC, retry logic
│   └── observability/            # Loki pusher, Prometheus metrics
├── server/                       # Central server (future)
├── pkg/event/event.go            # Canonical event types (shared)
├── deploy/docker/                # Docker Compose + Grafana provisioning
├── test/e2e/                     # End-to-end test suite
└── docs/                         # This documentation
```

## Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Agent language | Go | cilium/ebpf ecosystem, static linking, cross-compile |
| eBPF library | cilium/ebpf | Industry standard, bpf2go codegen, active maintenance |
| eBPF programs | C | Required by the eBPF verifier toolchain |
| Observability | Grafana + Loki + Prometheus | Standard stack, no custom UI needed for MVP |
| Wire protocol | gRPC + mTLS | Streaming, binary encoding, mutual auth (future) |
| Database | PostgreSQL | JSON support, enterprise-accepted (future) |

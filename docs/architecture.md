# HookMon Architecture

## System Overview

HookMon has three parts:

- **Sensor buses** (`hookmon-bus`) on monitored hosts.
- An **observability stack** (Loki, Prometheus, Pushgateway, Alertmanager, Grafana) run with Docker Compose, plus `hookmon-collector`.
- A **central server** (`hookmon-server`, PostgreSQL, `hookmon-cli`, the React dashboard).

Events reach people by two paths:

- **Observability path:** bus → Loki and Prometheus; collector → Pushgateway → Prometheus → Alertmanager and Grafana. This path works and has end-to-end tests (see [claims.md](claims.md)).
- **Server path:** bus → enrollment → mutual-TLS gRPC → `hookmon-server` → policy → PostgreSQL → REST, WebSocket, dashboard and SIEM connectors. Enrollment, mutual TLS, the REST API over HTTPS and the dashboard work. Other parts don't work yet; the [Server](#server) section lists them with the fix plan step for each.

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
 │  ┌─────────────────────────┐   │  gRPC (mutual TLS)  ┌─────────────────────────┐
 │  │ gRPC transport          │───│────────────────────▶│ hookmon-server          │
 │  │  or console (stdout)    │   │                     │  PostgreSQL, HTTPS :8443│
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
- **gRPC** (default when `--console` is not given): streams events and heartbeats to `hookmon-server` at `server_addr` over mutual TLS. Each heartbeat carries the sensor-registry snapshot. The client certificate comes from `tls.cert_file`, or from enrollment (see [Enrollment](#enrollment)). A bus with neither refuses to start; `--insecure` (or `tls.insecure: true`) connects in plaintext instead, for development. Events the server did not acknowledge go to `fallback_log_path`. Nothing replays them.
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

- **Identity:** UUID, nanosecond timestamp, host ID, hostname. On the server path the host ID is the CN of the bus's certificate and the hostname is the one the host enrolled with; the values the bus puts in the event are not stored.
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

`hookmon-collector` is not in this monitoring-only compose file. Run it on the same host (see the [deployment guide](deployment-guide.md)). The compose appliance (`deploy/appliance/docker-compose.yml`) runs everything: the server, PostgreSQL, the collector and the monitoring stack, configured by `deploy/appliance/hookmon-init.sh`.

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

`hookmon-server` reads `/etc/hookmon/server.yaml` if it exists, or the file given with `--config` (example: `deploy/server.example.yaml`). Unknown keys are an error. Command-line flags override the file. It runs:

- **Ingestion** (`server/ingestion`): the `AgentService` gRPC service on `--grpc-addr` (default `:9443`), with the `StreamEvents` RPC, schema validation and a per-host rate limit. The TLS handshake requires a client certificate signed by `tls.ca_file`. The host ID of every event and heartbeat is the CN of that certificate; the host ID in the message is ignored. The hostname stored with each event is the one the host enrolled with, looked up when the stream opens; a bus that reports a different one is logged once per stream, and its value is not kept, since only the enrolled name is tied to the certificate (re-enroll a renamed host to rename it). Validation refuses an event without a type, a type the server does not know, and AGENT_OFFLINE or AGENT_RECOVERED, which only the server raises. The rate limit (100 events/s, burst 200) is keyed by the certificate's host ID (in insecure mode, the peer's IP address), never by a message field, and keeps at most 10,000 hosts, evicting the one seen least recently. Heartbeats update the host's record and its sensor-health snapshot; the first heartbeat from a host the watchdog marked UNRESPONSIVE also raises AGENT_RECOVERED (see Watchdog). Both gRPC listeners have recovery interceptors: a panic in a handler fails that call or stream with `Internal`, is logged with its stack, and the server keeps running.
- **Enrollment** (`server/ingestion/enroll.go`) on `--enroll-addr` (default `:9444`); see [Enrollment](#enrollment).
- **Policy** (`server/policy`): matches events against the allowlist, sets severity, and in learning mode records unmatched events as PENDING entries; see [Policy and Learning Mode](#policy-and-learning-mode).
- **Store** (`server/store`): PostgreSQL (`database.url` or `--db`), with `events`, `allowlist`, `learning_mode`, `hosts`, `enrollment_token_uses` and `audit_log` tables. Migrations are in `server/store/migrations/` and run at every start. PID, PPID, UID, GID and BPF program type are stored as BIGINT, so the bus's "unknown" UID (4294967295) is stored like any other.
- **REST API, WebSocket and dashboard** (`server/api`) on `--http-addr` (default `:8443`), over HTTPS with the server certificate (TLS 1.2 or newer). Events, policies, hosts, settings and health are under `/api/v1/`, and a live event feed is at `/api/v1/ws/events` (see [Live Event Feed](#live-event-feed)). API tokens come from `api.tokens` or `--api-tokens`; `/api/v1/health` needs none. List endpoints answer `[]`, never `null`, when empty. Every write takes a JSON body of at most 64 KiB (413 above that) and refuses unknown fields. A missing event, host or policy is 404; a database failure is 500. Request headers must arrive within 10 s and the whole request within 30 s, and idle connections close after 120 s; there is no write timeout, because the WebSocket feed is one long response. Paths outside `/api` serve the dashboard (see [Dashboard](#dashboard)). The API reference is written after fix plan step 7.
- **Connectors** (`server/connectors`): Syslog/CEF, Splunk HEC, Elasticsearch, webhook and Kafka, configured under `connectors:`. Each has its own queue and worker; see [SIEM Connectors](#siem-connectors).
- **Watchdog**: every `watchdog.check_interval` (default 15 s) it marks an ONLINE host UNRESPONSIVE once it has gone `watchdog.heartbeat_timeout` (default 60 s) without a heartbeat, stores an AGENT_OFFLINE event (CRITICAL, policy action ALERT), and sends it to every connector and to the WebSocket feed. The next heartbeat sets the host ONLINE again and raises AGENT_RECOVERED (INFO, policy action ALERT, with how long the host was silent as the reason), stored and sent the same way. The heartbeat reads the old status in the same statement that sets ONLINE, so each outage gets exactly one AGENT_RECOVERED, even with several heartbeats at once. A bus restarted within the timeout raises neither.

TLS is the default. The server refuses to start without a certificate (`tls.cert_file` or `--tls-cert`) unless `--insecure` (or `tls.insecure: true`) is given. It logs "refusing to start without TLS" with the error:

```
no TLS certificate configured: set tls.cert_file, tls.key_file and tls.ca_file (or --tls-cert, --tls-key and --tls-ca), or pass --insecure to run gRPC and REST in plaintext (development only)
```

and exits with status 1, before it connects to the database.

Insecure mode runs gRPC and REST in plaintext and takes each host ID from the message, so any host can report as any other. Enrollment needs TLS, so insecure mode with enrollment tokens configured is a config error. It is for development only.

`hookmon-cli` is a REST client: `events`, `hosts`, `policies` (list, `pending`, `create` from JSON on stdin, `delete <id>`, `approve` and `reject <id> --fleet|--host <id>`), `learning` (status, `start --fleet|--host <id> --for <duration>|--until <time>`, `stop`) and `health`. Its `--server` default is `https://localhost:8443`; `--ca-file` (or `HOOKMON_CA_FILE`) names the CA that signed the server certificate.

Not working yet:

| Gap | Fix plan step |
|-----|---------------|
| Only `TestSIEM_RealStackCanaryReachesSyslogAndWebhook` (step 7d) covers this path end to end with a root bus, and it skips without `HOOKMON_TEST_PG_DSN` and `HOOKMON_SERVER_BIN`. The WebSocket is covered by `TestIntegration_WebSocketFanOut` (in-process server, test bus) and the dashboard's Playwright smoke test, not by an e2e test from a BPF canary. | 7h |

### Policy and Learning Mode

**Matching.** One matcher, `pkg/allowlist`, is used by the server and by the e2e policy tests. An entry matches when it is enabled, not expired, not PENDING, and every criterion it sets matches (AND; an empty criterion matches anything): event types, `exe_hash` and `library_hash` (`sha256:<hex>`; bare hex and any letter case are accepted), `exe_path`, `library_path`, `prog_name` and `host_pattern` (globs), `prog_type`, `prog_hash` (the kernel's BPF program tag, 16 hex digits), `uid_range`, `container_image` (matched against the container ID; the bus reports no image name), `allowed_rpaths`, and `host_id` (one enrolled host; empty for the fleet). Identical instructions of different program types share a tag, so an entry with `prog_hash` should also pin `prog_type`. When several entries match, the most restrictive action wins (DENY, then ALERT, then ALLOW); among equal actions an entry for the host wins over a fleet entry. `POST /api/v1/policies` rejects a hash in any other format, since it could never match.

**Reload.** The engine holds the allowlist and the learning windows in memory. It rereads both from PostgreSQL at startup, after every write through the API (before the API answers, so the next event sees the change), and on `SIGHUP` (for changes made in the database directly). A failed reload keeps the previous policy. SIGHUP does not reread the config file.

**Learning mode.** A learning window is open for the fleet or for one host until its end time; there is always an end time. Windows are rows in `learning_mode`, so they survive a restart. While a window covers an event's host, every event no entry matches is recorded as a PENDING allowlist entry for its key:

| Key part | Value |
|----------|-------|
| Event type | as reported |
| Executable | the acting binary's `sha256:<hex>`, or empty if the bus could not hash it (BPF_INVENTORY has no process) |
| Subject | BPF events: the program tag and program type (the program name if the kernel gave no tag). EXEC_INJECTION, DLOPEN: the library hash, or its path if it has none. LIB_INTEGRITY: the library path. LINKER_CONFIG: the file path. SHM_CREATE: the pattern the bus gave the segment name (`bpftime`, `bpf_related` or `unknown`), not the name, since browsers name every segment randomly. PTRACE_INJECT, ELF_RPATH: none |
| Container | whether the process ran in a container. The bus reports a container ID, not an image, and a container ID changes with every container, so it is not used; the exe hash, taken inside the container, identifies the binary |

Each PENDING entry has an occurrence count, first and last seen times, and the IDs of the hosts that saw it. Learning mode records; it does not change severity or suppress alerts. AGENT_OFFLINE and the BPF inventory summary are never recorded.

A PENDING entry matches nothing. Approving it for the fleet makes it APPROVED with action ALLOW; rejecting it makes it REJECTED with action ALERT, so the event keeps alerting and is not proposed again. Approving or rejecting for one host creates a separate entry for that host and takes the host off the PENDING entry, which is deleted when no host is left. A learned entry matches exactly its key: an empty executable hash or "not in a container" is not a wildcard.

REST endpoints (all need an API token): `GET /api/v1/policies` (entries in force; `?status=PENDING`, `REJECTED`, `APPROVED` or `ALL`), `POST /api/v1/policies`, `PUT /api/v1/policies/{id}` (replaces the criteria, action, expiry, description and `enabled`; `id`, `created_at`, `created_by` and `learned` are kept, and `status` cannot change), `PATCH /api/v1/policies/{id}` (sets only the fields given, such as `{"enabled": false}`; `null` clears one), `DELETE /api/v1/policies/{id}`, `POST /api/v1/policies/{id}/approve` and `/reject` with `{"scope": "fleet"}` or `{"scope": "host", "host_id": "..."}`, `POST /api/v1/events/{id}/allowlist` with `{"scope": "fleet"}` or `{"scope": "host"}`, `GET /api/v1/learning`, and `PUT` / `DELETE` on `/api/v1/learning/fleet` and `/api/v1/learning/hosts/{host_id}`, where PUT takes `{"duration": "7d"}` or `{"ends_at": "<RFC 3339>"}`.

Writes check `action` (ALLOW, ALERT or DENY; anything else, or none, is a 400) and the hash formats. A PENDING entry cannot be edited (409): it is approved or rejected. A REJECTED entry keeps action ALERT. `POST /api/v1/events/{id}/allowlist` is "Allowlist this event": it creates an APPROVED ALLOW entry whose `learned.key` is the event's key from the table above, for the fleet or for the event's host, so it matches exactly the events learning mode would have grouped with it. Field criteria cannot express some subjects (a shared memory pattern, a linker config file), and an empty executable hash would match any binary, so the key is the criterion. It answers 409 with the existing entry's ID if an ALLOW entry for that key and scope is already in force, and 400 for AGENT_OFFLINE and AGENT_RECOVERED.

**Severity.** The bus rates each event with context the server lacks (a package manager wrote the file, the shared memory name, who can write an RPATH directory). The server keeps that rating and adds the allowlist and two escalations: an unmatched event from root is CRITICAL, and a WARN event from a binary the bus could not hash is ALERT. Neither escalation applies to an event the bus rated INFO or to ELF_RPATH. The full table is in `CLAUDE.md` ("Severity Classification") and [theory-of-operations.md](theory-of-operations.md#severity).

### SIEM Connectors

Each connector runs when its block is present under `connectors:` in the server config (`syslog`, `splunk`, `elasticsearch`, `webhook`, `kafka`; see `deploy/server.example.yaml`). The server checks the settings when it loads the file. It then starts each connector before it connects to the database: it dials the syslog receiver, connects the Kafka producer, and installs the Elasticsearch ILM policy. If any of these fails, the server exits with status 1.

**What each connector gets.** It depends on the connector's `min_severity`:

| `min_severity` | Kind | Receives |
|----------------|------|----------|
| `ALERT` (default), `CRITICAL` | Alert connector | Events at or above that severity whose policy action is not ALLOW: unmatched events, and events that matched an ALERT or DENY entry. An ALLOW match is INFO, so it never reaches an alert connector. Repeats are dropped: the alert manager (`server/policy/alert.go`) admits an alert once per 5 minutes per host, binary path and learning-mode key (event type, exe hash, subject such as the BPF tag or library, in a container or not). Two different BPF programs from the same loader are two alerts. |
| `INFO`, `WARN` | Event feed | Every stored event at or above that severity, allowed or not, repeats included. |

Both kinds also get every AGENT_OFFLINE (CRITICAL) and AGENT_RECOVERED (INFO), whatever their `min_severity`, so an alert connector that was sent an outage is also sent its end. Neither is ever dropped as a repeat, since each one marks a separate outage.

This settles a difference between two earlier descriptions. The fix plan sends unmatched ALERT-and-above events to connectors. The pipeline in CLAUDE.md sends every event. The default connector follows the plan, and `min_severity: INFO` gives the full feed.

**Delivery.** Ingestion calls the dispatcher (`server/connectors/dispatch.go`), and so does the watchdog. Each connector has a bounded queue (`queue_size`, default 1024) and one worker goroutine (`queue.go`). Enqueueing never blocks, so a slow or unreachable sink never holds up a bus's stream. When a queue is full, the event is dropped for that connector only. The drop is counted, and the first drop and every 1000th after it are logged ("connector queue full; dropping events"). The worker sends batches of up to `batch_size` events, or whatever it has after `flush_interval` (default 1 s). A failure marked transient (network error, timeout, HTTP 429 or 5xx, a Kafka produce error) is retried twice, after 0.5 s and 1 s. Other failures (any other 4xx) are not retried. Delivery is at least once, so a retried batch can arrive twice; Elasticsearch documents use the event ID as `_id`, so a retry overwrites them. On shutdown the server stops the streams and the watchdog first. The workers then get 5 s to drain their queues before in-flight requests are cancelled. Each connector logs its sent, dropped and failed counts when it stops. The server has no Prometheus endpoint, so these counts are only in the log.

**Formats.**

- **Syslog** (`syslog.go`, `cef.go`). RFC 5424: `<PRI>1 TIMESTAMP HOSTNAME hookmon - MSGID - CEF:0|HookMon|HookMon|1.0|<event type>|<name>|<0-10>|<extension>`. PRI is facility (default `local0`) × 8 plus the syslog severity (CRITICAL 2, ALERT 3, WARN 4, INFO 6). TIMESTAMP is the detection time in UTC, to the microsecond. HOSTNAME is the monitored host's name, or the server's name for an event without one. MSGID is the event type. Over TCP each message is framed by octet counting (RFC 6587, `<length> <message>`) unless `framing: lf`. Over UDP each message is one datagram. Before each TCP write the connector checks whether the receiver has closed the connection, and redials if so. A failed write is retried once on a new connection.
- **Splunk HEC** (`splunk.go`). One POST per batch to `url`, holding one envelope per event (`time`, `host`, `source: hookmon`, `sourcetype`, `index`, `event`), with `Authorization: Splunk <token>`.
- **Elasticsearch** (`elastic.go`). One `_bulk` request per batch. Each event goes to `<index_prefix>-YYYY.MM.DD` for its UTC date, with `_id` set to the event ID. Authentication is basic (`username`, `password`) or `api_key`. A 200 response with failed items is an error, retried only if an item failed with 429 or 5xx. At startup, unless `ilm.setup: false`, the connector PUTs the ILM policy `ilm.policy` (default `hookmon-events`). The policy has one delete phase at `min_age: ilm.delete_after` (default `90d`), counted from each daily index's creation. The connector also PUTs an index template of the same name for `<index_prefix>-*` at priority 200. The template sets `index.lifecycle.name` and maps `timestamp` as a date and `id`, `host_id`, `event_type` and `severity` as keywords. Both PUTs replace what is there, so any changes made in Kibana are lost at the next start; set `ilm.setup: false` to keep them. No rollover is configured, because the indices are daily.
- **Webhook** (`webhook.go`). POSTs `application/json` to `url` with the configured `headers`. With `batch_size` 1 (the default) the body is one event object. With a larger `batch_size` it is a JSON array.
- **Kafka** (`kafka.go`). A synchronous producer that waits for every in-sync replica, `ClientID` `hookmon-server`. Each event is a JSON message keyed by host ID.

`ca_file` on the Splunk, Elasticsearch and webhook connectors names a CA for sinks whose certificate a system root does not sign.

**CEF fields.** Every event carries `rt` (detection time, in milliseconds), `externalId` (event ID), `deviceExternalId` (host ID) and `shost` (hostname). It also carries `cs3` ExeHash, `cs4` PolicyResult and `reason` when set. Events with a process also carry `suid`, `spid`, `sproc` (exe path), `flexString1` Cmdline (up to 1023 characters) and `flexString2` ContainerID. Events with no process, such as AGENT_OFFLINE and BPF_INVENTORY, carry no `suid`, so they can't be mistaken for root. Each custom field comes with its `…Label`.

| Event type | Fields |
|------------|--------|
| BPF_LOAD, BPF_ATTACH | `cs1` ProgType (number), `cs2` ProgName, `cs5` ProgTag, `cs6` AttachTarget, `cn1` InsnCount, `cn2` ProgID, `cn3` BPFCommand |
| BPF_INVENTORY | `cs1` ProgType, `cs2` ProgName, `cs5` ProgTag, `cs6` ScanID, `cn2` ProgID, `cn3` ProgCount (summary) |
| EXEC_INJECTION | `cs1` LibraryPath, `cs2` SetBy, `cs5` EnvVar, `cs6` TargetBinary, `fileHash` (library), `cn1` ScanTruncated, `cn2` ValueTruncated |
| SHM_CREATE | `cs1` SHMName, `cs2` Pattern, `fsize` |
| DLOPEN | `cs1` LibraryPath, `fileHash` (library), `cn1` Flags |
| LINKER_CONFIG | `cs1` FilePath, `cs2` Operation, `oldFileHash`, `fileHash` |
| LIB_INTEGRITY | `cs1` LibraryPath, `cs2` Operation, `oldFileHash`, `fileHash`, `cn1` InLdCache (0 or 1) |
| PTRACE_INJECT | `cs1` Request (name), `cs2` TargetComm, `cs5` Addr (hex), `dpid`, `dproc`, `cn1` RequestNum |
| ELF_RPATH | `cs1` RpathRaw, `cs2` RunpathRaw, `cs5` HighestRisk, `cn1` Setuid (0 or 1) |
| AGENT_OFFLINE | the common fields; name "Sensor Bus Offline" |

Header fields escape `\` and `|`. Extension values escape `\` and `=`, and CR and LF become `\r` and `\n`, so each message is one line. Only CEF dictionary keys are used: custom strings are `cs1` to `cs6`.

### Enrollment

A bus gets its identity once, with a token from the server config:

1. The operator adds tokens to `enrollment.tokens` in the server config. Each has a `name`, a `secret` of at least 32 characters, an `expires` time, and optionally `single_use`. The server checks secrets in constant time. A single-use token is recorded in PostgreSQL (`enrollment_token_uses`) when it is used, so it stays used across restarts. Enrollment also needs `tls.ca_key_file`, the key of the CA that signs bus certificates. With no tokens, the enrollment listener does not run.
2. On first start, `hookmon-bus --enroll-token-file <file> --ca-file <ca.crt>` generates an ECDSA key and sends a certificate request to the enrollment address (`--enroll-addr`, default: the `--server-addr` host on port 9444). The token can also come from `HOOKMON_ENROLL_TOKEN` or `--enroll-token`; the file (mode 0600) is preferred, because a token on the command line is visible to every user in the process list. The bus removes `HOOKMON_ENROLL_TOKEN` from its environment once read, so the helpers it runs do not inherit it. That listener uses TLS that authenticates the server only, since the bus has no certificate yet, and serves only the `Enroll` RPC. The bus verifies the server against `--ca-file`; if the server's certificate does not verify (a wrong `--ca-file`, or an address the certificate does not name), the bus exits with an error saying so instead of retrying. Other failures, such as the server being unreachable, are retried with backoff.
3. The server checks the token, assigns a host ID (a UUID), and signs a client certificate with that ID as its CN. Nothing in the request chooses the ID. It creates the host record in the same transaction that records a single-use token, and returns the certificate and the CA certificate.
4. The bus checks that the certificate matches its key, chains to the CA it was given, and names the host ID in the response. It stores `bus.key`, `bus.crt` and `ca.crt` in `--state-dir` (default `/var/lib/hookmon`), each with mode 0600, then connects to `--server-addr` with mutual TLS.

Later starts use the stored identity and ignore the token. A certificate configured with `tls.cert_file` takes precedence over both. Certificates last `enrollment.cert_validity` (default one year); there is no renewal. A server certificate that does not verify against the CA file also stops the bus at its first connection; once the bus has connected, such a failure is retried like any other.

## Dashboard

`dashboard/` is a React and TypeScript app built with Vite (`make build-dashboard` writes `dashboard/dist`). It talks to the server's REST API and WebSocket with relative URLs (`/api/v1`), using `wss:` when the page is loaded over HTTPS. The API token is entered on the Settings page and kept in the browser's local storage. Pages:

| Page | What it shows and does |
|------|------------------------|
| Event Feed (`/events`) | Recent events from REST plus live ones from the WebSocket, with filters. Each event that is not ALLOWed has an "Allowlist" button. Every event type renders, BPF_INVENTORY included, with the BPF program tag and attach target, a truncated environment scan or value, the shared memory pattern, and each ptrace request. History reloads whenever the feed reconnects, to cover the gap |
| Investigation (`/events/{id}`) | One event in full, with the same "Allowlist this event" action, and the host's recent events |
| Host Inventory (`/hosts`) | Each host's status, heartbeat, and the health of each sensor from its latest heartbeat (alive, dead, failed, unverifiable or unknown, with the registry's reason) |
| Policy Manager (`/policies`) | Entries in force, with scope, status and what each matches. Create, edit (PUT), enable or disable (PATCH) and delete |
| Pending Approval (`/pending`) | Learning-mode candidates with counts, first and last seen and hosts; approve or reject each for the fleet or one of the hosts that saw it. Shows whether learning mode is on |
| Settings (`/settings`) | The API token; the enrollment command built from the server's bound ports (`--enroll-token-file`, `--server-addr`, `--enroll-addr`, `--ca-file`, `--state-dir`) and the enrollment tokens by name and expiry; the listener addresses; connector counts (sent, failed, dropped, queued) and the live feed's clients. Read from `GET /api/v1/settings`, which never returns a token secret, a connector URL or a credential |

`hookmon-server` serves the built files from `dashboard_dir` (`--dashboard-dir`, default `/usr/share/hookmon/dashboard`) on the same HTTPS listener as the API. A request for a file in that directory gets the file. Any other path outside `/api` gets `index.html`, so the dashboard's own routes (such as `/hosts`) load directly. An unknown `/api` path gets a JSON 404, never `index.html`. If the directory has no `index.html`, the server logs a warning and serves the API only; an empty `dashboard_dir` turns the dashboard off. `deploy/docker/Dockerfile.server` copies the build to `/usr/share/hookmon/dashboard`.

**Development.** `npm run dev` serves the dashboard on `http://localhost:5173` and proxies `/api`, WebSocket included (`ws: true`), to `HOOKMON_API_URL` (default `https://localhost:8443`). With `HOOKMON_CA_FILE` the proxy verifies the server certificate; without it, it does not. The proxy passes the browser's Origin through, so add `http://localhost:5173` to `api.allowed_origins` for the live feed.

**Smoke test.** `dashboard/e2e/smoke.spec.ts` (Playwright, `npm run test:e2e`) runs against a running, seeded server: it opens all six pages and checks each shows what the API holds, allowlists an event from Investigation (and deletes the entry again), toggles a policy off and on, and checks that two tabs receive the same live events in the same order. It needs `HOOKMON_E2E_URL`, `HOOKMON_E2E_CA` and `HOOKMON_E2E_TOKEN`, and skips without them. Node verifies the server certificate against the CA; the browser then trusts only that certificate's key.

### Live Event Feed

`GET /api/v1/ws/events` upgrades to a WebSocket that sends every event the server stores, as JSON text messages, from the moment the handshake completes.

- **Token.** The same API tokens and the same check as REST. A browser cannot set an Authorization header on a WebSocket, and a token in the URL is written to access and proxy logs, so the dashboard offers two subprotocols: `hookmon.v1` and `hookmon.bearer.<token as unpadded base64url>`. The server selects `hookmon.v1`, so the token is never echoed back. Clients that can set headers send `Authorization: Bearer <token>` instead. A `?token=` in the URL is refused. A missing or wrong token gets 401 before the upgrade.
- **Origin.** A browser always sends Origin. The handshake is refused with 403 unless the Origin's host is the host the request was sent to (the server's own origin) or the origin is listed in `api.allowed_origins` (`scheme://host[:port]`). `null` is refused. A handshake with no Origin is not from a browser and is allowed; it still needs the token.
- **Fan-out.** Ingestion hands each stored event to the hub through a buffer of 256 events; if the hub falls that far behind, the event is left out of the live feed (it is still stored and sent to the connectors), counted, and logged at most once every 10 s. A hub gives every client its own buffer of 256 events. Every client gets every event, in order. Ingestion never waits for a client: when a client's buffer is full the hub drops it, and the server closes it with code 1013 (try again later). The dashboard then reconnects and reloads recent events over REST. The event feed loads recent events once the live feed has connected (or failed to), and again after each reconnect, so a first visit fetches them once. `GET /api/v1/settings` reports the number of clients, the events sent and the clients dropped.

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
├── deploy/docker/                 # Compose stack, Prometheus, Alertmanager, Grafana provisioning, Dockerfiles
├── deploy/server.example.yaml     # hookmon-server config example
├── test/e2e/                      # End-to-end tests (Linux, root, -tags e2e)
├── test/canary/                   # Programs the e2e tests run
├── test/smoketest/                # Unprivileged smoketests
├── test/transport/                # Wire, transport and enrollment tests
├── test/integration/              # Server + PostgreSQL tests (need HOOKMON_TEST_PG_DSN)
├── test/enrpki/                   # Throwaway CA and certificates for tests
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
| Wire protocol | gRPC with mutual TLS | Streaming, binary encoding, mutual authentication; plaintext only with `--insecure` |
| Database | PostgreSQL | JSON support, enterprise-accepted |

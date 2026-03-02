# CLAUDE.md — HookMon Project Specification

## Project Identity

**Name:** HookMon
**Repo:** github.com/dlenrow/hookmon
**Local path:** ~/hookmon
**License:** Apache 2.0
**Language:** Go (primary), C (eBPF programs), TypeScript (dashboard)
**Author:** Dave Lenrow <drl@clevercraft.energy>

## What This Is

HookMon is an enterprise security appliance that detects, logs, and enforces policy on two of the most dangerous instrumentation vectors in Linux: **eBPF program loading** and **LD_PRELOAD library injection**. Both mechanisms allow an attacker with even unprivileged access to intercept function calls, exfiltrate data, and install persistent backdoors that are invisible to traditional security tooling (ps, /proc, lsof, bpftool for the userspace case).

### The Threat Model

**Kernel eBPF abuse:** An attacker with brief root access (or CAP_BPF) loads an eBPF program that hooks syscalls, network functions, or file operations. The program persists in kernel space. Nothing in userland shows its presence to standard tools. Traditional detection requires hooking the `bpf()` syscall itself.

**Userspace eBPF abuse (bpftime et al.):** An attacker *without* root loads a userspace eBPF runtime (e.g., bpftime) that emulates eBPF in a userspace VM. Programs attach to target processes via `LD_PRELOAD` and shared memory. The kernel BPF subsystem is never invoked. No `bpf()` syscall occurs. No audit log entry. No bpftool visibility. The only signals are the `LD_PRELOAD` environment variable, shared memory segments in `/dev/shm`, and the runtime binary itself.

**LD_PRELOAD injection:** Even without eBPF, `LD_PRELOAD` alone allows function interposition — replacing malloc, SSL_read, open, or any dynamically-linked function with attacker-controlled code. This is both a legitimate tool (debugging, instrumentation) and a potent attack vector.

### The Core Insight

Loading an eBPF program or setting up an LD_PRELOAD harness is a **vanishingly rare event** in production. Legitimate uses (observability agents like Cilium, Falco, Datadog; debugging tools) are known, enumerable, and should be whitelisted. *Any* new, unwhitelisted event is worth investigation. This is a perfect application for an allowlist-based security model: the signal-to-noise ratio is inherently excellent because the base rate of legitimate new installations is near zero.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MONITORED HOSTS                              │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  hookmon-agent (per host)                                    │   │
│  │                                                              │   │
│  │  eBPF sensors:                                               │   │
│  │    ├── bpf_syscall_monitor   — hooks bpf() syscall           │   │
│  │    ├── execve_preload_monitor — hooks execve(), checks env   │   │
│  │    ├── shm_monitor           — hooks shm_open/mmap for       │   │
│  │    │                           bpftime-pattern detection      │   │
│  │    └── dlopen_monitor        — hooks dlopen() for runtime    │   │
│  │                                library injection              │   │
│  │                                                              │   │
│  │  Userspace daemon:                                           │   │
│  │    ├── event enrichment (pid → cmdline, cgroup, container)   │   │
│  │    ├── local cache + dedup                                   │   │
│  │    ├── mTLS gRPC stream to central server                    │   │
│  │    └── local fallback log (if server unreachable)            │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Deployed via: DEB/RPM package, container sidecar, or Ansible role  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ mTLS gRPC (port 9443)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     HOOKMON APPLIANCE                                │
│                     (virtual appliance / bare metal ISO)             │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐    │
│  │ Ingestion    │  │ Policy       │  │ Dashboard              │    │
│  │ Service      │  │ Engine       │  │ (web UI)               │    │
│  │              │  │              │  │                        │    │
│  │ gRPC server  │  │ allowlist DB │  │ React + TypeScript     │    │
│  │ event        │  │ rule eval    │  │ event feed             │    │
│  │ validation   │  │ auto-approve │  │ policy management      │    │
│  │ rate limit   │  │ alert gen    │  │ host inventory         │    │
│  └──────┬───────┘  └──────┬───────┘  │ investigation workflow │    │
│         │                 │          └────────────────────────┘    │
│         ▼                 ▼                                        │
│  ┌─────────────────────────────┐  ┌────────────────────────────┐  │
│  │ Event Store                 │  │ SIEM Connectors            │  │
│  │ PostgreSQL                  │  │                            │  │
│  │                             │  │ ├── Syslog/CEF (RFC 5424) │  │
│  │ events table                │  │ ├── Splunk HEC             │  │
│  │ policies table              │  │ ├── Elastic (bulk API)     │  │
│  │ allowlist table             │  │ ├── Webhook (generic JSON) │  │
│  │ hosts table                 │  │ └── Kafka (optional)       │  │
│  │ audit_log table             │  │                            │  │
│  └─────────────────────────────┘  └────────────────────────────┘  │
│                                                                     │
│  System services: nginx (TLS termination), systemd, auto-update     │
└─────────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
hookmon/
├── CLAUDE.md                  # This file — project specification
├── README.md                  # Public-facing project description
├── LICENSE                    # Apache 2.0
├── Makefile                   # Top-level build orchestration
├── go.mod
├── go.sum
│
├── cmd/
│   ├── hookmon-agent/         # Agent binary (runs on monitored hosts)
│   │   └── main.go
│   ├── hookmon-server/        # Central server binary
│   │   └── main.go
│   └── hookmon-cli/           # CLI for policy management & diagnostics
│       └── main.go
│
├── agent/                     # Agent package
│   ├── agent.go               # Agent lifecycle (start, stop, reconnect)
│   ├── sensors/
│   │   ├── bpf_syscall.go     # bpf() syscall hook sensor
│   │   ├── bpf_syscall.c      # eBPF C program for bpf() hook
│   │   ├── execve_preload.go  # execve() + LD_PRELOAD detection
│   │   ├── execve_preload.c   # eBPF C program for execve() hook
│   │   ├── shm_monitor.go     # /dev/shm + mmap pattern detection
│   │   ├── shm_monitor.c      # eBPF C for shm_open/mmap hooks
│   │   ├── dlopen_monitor.go  # dlopen() interception
│   │   ├── dlopen_monitor.c   # eBPF C for dlopen uprobe
│   │   └── sensor.go          # Common sensor interface
│   ├── enrichment/
│   │   ├── process.go         # pid → cmdline, exe, cgroup, container ID
│   │   ├── container.go       # Container runtime detection
│   │   └── hash.go            # Binary/library SHA256 hashing
│   ├── transport/
│   │   ├── grpc.go            # mTLS gRPC client stream
│   │   ├── fallback.go        # Local file fallback when server down
│   │   └── retry.go           # Reconnection with exponential backoff
│   └── config/
│       └── config.go          # Agent configuration (YAML)
│
├── server/                    # Central server package
│   ├── server.go              # Server lifecycle
│   ├── ingestion/
│   │   ├── grpc.go            # gRPC server for agent connections
│   │   ├── validation.go      # Event schema validation
│   │   └── ratelimit.go       # Per-host rate limiting
│   ├── policy/
│   │   ├── engine.go          # Policy evaluation engine
│   │   ├── allowlist.go       # Allowlist CRUD + matching logic
│   │   ├── rules.go           # Rule definitions and evaluation
│   │   └── alert.go           # Alert generation and dedup
│   ├── store/
│   │   ├── postgres.go        # PostgreSQL event/policy store
│   │   ├── migrations/        # SQL migration files
│   │   │   ├── 001_initial.sql
│   │   │   └── ...
│   │   └── queries/           # SQL query files (sqlc or raw)
│   │       └── ...
│   ├── connectors/
│   │   ├── syslog.go          # Syslog/CEF output
│   │   ├── splunk.go          # Splunk HTTP Event Collector
│   │   ├── elastic.go         # Elasticsearch bulk API
│   │   ├── webhook.go         # Generic JSON webhook
│   │   ├── kafka.go           # Kafka producer (optional)
│   │   └── connector.go       # Common connector interface
│   └── api/
│       ├── router.go          # HTTP API router (REST)
│       ├── events.go          # Event query endpoints
│       ├── policies.go        # Policy CRUD endpoints
│       ├── hosts.go           # Host inventory endpoints
│       └── auth.go            # API authentication (token-based)
│
├── dashboard/                 # Web dashboard (React + TypeScript)
│   ├── package.json
│   ├── tsconfig.json
│   ├── src/
│   │   ├── App.tsx
│   │   ├── pages/
│   │   │   ├── EventFeed.tsx       # Real-time event stream
│   │   │   ├── PolicyManager.tsx   # Allowlist / rule management
│   │   │   ├── HostInventory.tsx   # Monitored host status
│   │   │   ├── Investigation.tsx   # Event detail + investigation
│   │   │   └── Settings.tsx        # Connector config, users
│   │   ├── components/
│   │   │   ├── EventCard.tsx
│   │   │   ├── SeverityBadge.tsx
│   │   │   ├── HostStatus.tsx
│   │   │   ├── AllowlistEditor.tsx
│   │   │   └── TimelineView.tsx
│   │   └── api/
│   │       └── client.ts           # API client
│   └── public/
│       └── index.html
│
├── proto/                     # Protobuf definitions
│   ├── hookmon/
│   │   ├── v1/
│   │   │   ├── events.proto   # Event message types
│   │   │   ├── agent.proto    # Agent ↔ server RPC service
│   │   │   └── policy.proto   # Policy message types
│   │   └── buf.yaml
│   └── buf.gen.yaml
│
├── appliance/                 # Virtual appliance / ISO build
│   ├── packer/
│   │   ├── hookmon.pkr.hcl    # Packer template (VMware, VirtualBox, QEMU)
│   │   └── scripts/
│   │       ├── base.sh        # OS hardening, package install
│   │       ├── hookmon.sh     # Server install + systemd units
│   │       ├── postgres.sh    # PostgreSQL setup
│   │       ├── nginx.sh       # TLS termination
│   │       └── firstboot.sh   # First-boot configuration wizard
│   ├── iso/
│   │   ├── build-iso.sh       # ISO builder (cloud-init + autoinstall)
│   │   └── user-data.yaml     # cloud-init configuration
│   └── ansible/
│       ├── playbook.yml       # Alternative: deploy to existing server
│       └── roles/
│           └── hookmon/
│
├── deploy/                    # Agent deployment artifacts
│   ├── deb/                   # Debian package build
│   ├── rpm/                   # RPM package build
│   ├── docker/
│   │   ├── Dockerfile.agent   # Agent container image
│   │   └── Dockerfile.server  # Server container image (alt to appliance)
│   └── ansible/
│       └── roles/
│           └── hookmon-agent/ # Agent deployment role
│
├── pkg/                       # Shared packages
│   ├── event/
│   │   └── event.go           # Canonical event types (shared agent+server)
│   ├── crypto/
│   │   ├── mtls.go            # mTLS certificate utilities
│   │   └── enroll.go          # Agent enrollment protocol
│   └── version/
│       └── version.go         # Build version injection
│
├── test/
│   ├── integration/           # Integration tests (agent + server)
│   ├── e2e/                   # End-to-end with real eBPF
│   └── fixtures/              # Test event data, policies
│
├── docs/
│   ├── architecture.md        # Detailed architecture document
│   ├── threat-model.md        # Threat model for hookmon itself
│   ├── deployment-guide.md    # Appliance + agent deployment
│   ├── api-reference.md       # REST API docs
│   └── allowlist-guide.md     # How to build allowlists
│
└── scripts/
    ├── generate.sh            # go generate for eBPF + protobuf
    ├── build-agent.sh
    ├── build-server.sh
    └── dev-setup.sh           # Local dev environment
```

## Core Data Model

### Event

Every detected hook installation produces a canonical event:

```go
type HookEvent struct {
    // Identity
    ID        string    `json:"id"`         // UUID
    Timestamp time.Time `json:"timestamp"`  // nanosecond precision
    HostID    string    `json:"host_id"`    // enrolled agent ID
    Hostname  string    `json:"hostname"`

    // What was detected
    EventType   EventType `json:"event_type"`    // BPF_LOAD, LD_PRELOAD, SHM_CREATE, DLOPEN
    Severity    Severity  `json:"severity"`      // INFO, WARN, ALERT, CRITICAL

    // Process context
    PID         uint32   `json:"pid"`
    PPID        uint32   `json:"ppid"`
    UID         uint32   `json:"uid"`
    GID         uint32   `json:"gid"`
    Comm        string   `json:"comm"`          // task comm (16 chars)
    Cmdline     string   `json:"cmdline"`       // full /proc/pid/cmdline
    ExePath     string   `json:"exe_path"`      // /proc/pid/exe resolved
    ExeHash     string   `json:"exe_hash"`      // SHA256 of binary
    CgroupPath  string   `json:"cgroup_path"`   // cgroup v2 path
    ContainerID string   `json:"container_id"`  // if in container
    Namespace   string   `json:"namespace"`     // k8s namespace if applicable

    // Event-type-specific payload
    BPFDetail      *BPFDetail      `json:"bpf_detail,omitempty"`
    PreloadDetail  *PreloadDetail  `json:"preload_detail,omitempty"`
    SHMDetail      *SHMDetail      `json:"shm_detail,omitempty"`
    DlopenDetail   *DlopenDetail   `json:"dlopen_detail,omitempty"`

    // Policy evaluation result (filled by server)
    PolicyResult   *PolicyResult   `json:"policy_result,omitempty"`
}

type EventType string
const (
    EventBPFLoad    EventType = "BPF_LOAD"      // bpf() syscall with BPF_PROG_LOAD
    EventBPFAttach  EventType = "BPF_ATTACH"     // bpf() with attach commands
    EventLDPreload  EventType = "LD_PRELOAD"     // LD_PRELOAD detected in execve()
    EventSHMCreate  EventType = "SHM_CREATE"     // suspicious shared memory pattern
    EventDlopen     EventType = "DLOPEN"         // dlopen() of non-standard library
)

type BPFDetail struct {
    BPFCommand   uint32 `json:"bpf_cmd"`         // BPF_PROG_LOAD, BPF_PROG_ATTACH, etc.
    ProgType     uint32 `json:"prog_type"`        // BPF_PROG_TYPE_KPROBE, etc.
    ProgName     string `json:"prog_name"`        // program name from attr
    AttachType   uint32 `json:"attach_type"`
    TargetFD     int32  `json:"target_fd"`
    InsnCount    uint32 `json:"insn_count"`       // instruction count (complexity signal)
    ProgHash     string `json:"prog_hash"`        // SHA256 of BPF bytecode if capturable
}

type PreloadDetail struct {
    LibraryPath  string `json:"library_path"`     // value of LD_PRELOAD
    LibraryHash  string `json:"library_hash"`     // SHA256 of preloaded library
    TargetBinary string `json:"target_binary"`    // binary being exec'd with preload
    SetBy        string `json:"set_by"`           // "env", "ld.so.preload", "/etc/ld.so.preload"
}

type SHMDetail struct {
    SHMName      string `json:"shm_name"`         // /dev/shm segment name
    Size         uint64 `json:"size"`
    Pattern      string `json:"pattern"`          // "bpftime", "generic", "unknown"
}

type DlopenDetail struct {
    LibraryPath  string `json:"library_path"`
    LibraryHash  string `json:"library_hash"`
    Flags        int    `json:"flags"`            // RTLD_NOW, RTLD_LAZY, etc.
}
```

### Policy / Allowlist

```go
type AllowlistEntry struct {
    ID          string    `json:"id"`
    CreatedAt   time.Time `json:"created_at"`
    CreatedBy   string    `json:"created_by"`     // who approved this
    Description string    `json:"description"`    // human-readable reason

    // Match criteria (all non-empty fields must match; AND logic)
    EventTypes  []EventType `json:"event_types"`  // which event types this covers
    ExeHash     string      `json:"exe_hash"`     // exact binary hash
    ExePath     string      `json:"exe_path"`     // glob pattern ("/usr/bin/cilium*")
    LibraryHash string      `json:"library_hash"` // for preload: exact library hash
    LibraryPath string      `json:"library_path"` // glob pattern
    ProgName    string      `json:"prog_name"`    // BPF program name pattern
    ProgType    *uint32     `json:"prog_type"`    // BPF program type
    HostPattern string      `json:"host_pattern"` // hostname glob
    UIDRange    *UIDRange   `json:"uid_range"`    // allowed UID range
    ContainerImage string   `json:"container_image"` // container image pattern

    // Policy
    Action      PolicyAction `json:"action"`       // ALLOW, ALERT, DENY
    Expires     *time.Time   `json:"expires"`       // optional TTL
    Enabled     bool         `json:"enabled"`
}

type PolicyAction string
const (
    ActionAllow PolicyAction = "ALLOW"   // known good, log at INFO
    ActionAlert PolicyAction = "ALERT"   // suspicious, alert SOC
    ActionDeny  PolicyAction = "DENY"    // block if enforcement mode enabled
)
```

## Sensor Implementation Details

### Sensor 1: bpf() Syscall Monitor

Hooks the `bpf()` syscall via tracepoint `sys_enter_bpf`. Captures:
- `cmd` argument (BPF_PROG_LOAD, BPF_PROG_ATTACH, BPF_MAP_CREATE, etc.)
- `attr` contents (program type, name, attach type, instruction count)
- Calling process context (pid, uid, comm)

This catches all kernel-space eBPF activity. It requires the agent itself to have CAP_BPF (or root) — which is acceptable because the agent is a privileged security tool.

```c
// Pseudo-code for the eBPF program
SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 cmd = (u32)ctx->args[0];

    // Filter: only care about PROG_LOAD, PROG_ATTACH, MAP_CREATE
    if (cmd != BPF_PROG_LOAD && cmd != BPF_PROG_ATTACH && cmd != BPF_MAP_CREATE)
        return 0;

    struct hook_event_t event = {};
    event.event_type = EVENT_BPF_LOAD;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.bpf_cmd = cmd;

    // Read attr struct for program details
    union bpf_attr *attr = (void *)ctx->args[1];
    bpf_probe_read_user(&event.prog_type, sizeof(u32), &attr->prog_type);
    bpf_probe_read_user_str(&event.prog_name, sizeof(event.prog_name),
                            attr->prog_name);

    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}
```

### Sensor 2: execve() + LD_PRELOAD Monitor

Hooks `sys_enter_execve` (or the `sched_process_exec` tracepoint for post-exec context). For every exec:
1. Read the environment block from the new process
2. Scan for `LD_PRELOAD=` entries
3. Also check `/etc/ld.so.preload` inode for modifications (via inotify or periodic check)

Key challenge: reading the envp array from eBPF is bounded by BPF stack/instruction limits. Strategy:
- Read first N environment variables (N=64 should cover all realistic cases)
- String-match on "LD_PRELOAD" prefix
- If found, emit event with the library path

Additionally monitor for:
- `LD_LIBRARY_PATH` manipulation (less dangerous but related)
- `LD_AUDIT` (another library injection vector)
- `/etc/ld.so.preload` file changes

### Sensor 3: Shared Memory Monitor

Detect bpftime-style userspace eBPF by monitoring shared memory creation:
- Hook `shm_open()` via uprobe on libc
- Hook `mmap()` with `MAP_SHARED` flag
- Pattern match on known bpftime shared memory naming conventions
- Alert on any `/dev/shm` segment creation from non-whitelisted processes

This is the only way to detect userspace eBPF runtimes that never invoke the kernel `bpf()` syscall.

### Sensor 4: dlopen() Monitor

Hook `dlopen()` via uprobe on libc/libdl. Captures:
- Library path being loaded
- Calling process context
- RTLD flags

This catches runtime library injection that doesn't use `LD_PRELOAD` — the attacker manually calls `dlopen()` on a malicious shared object after process startup.

## Server Design Principles

### Event Processing Pipeline

```
Agent gRPC stream
    → validate schema
    → enrich (reverse DNS, asset DB lookup)
    → evaluate against allowlist
    → classify severity
    → store in PostgreSQL
    → fan out to:
        ├── WebSocket feed (dashboard real-time)
        ├── SIEM connectors (Syslog, Splunk, Elastic, webhook)
        └── Alert queue (if ALERT or CRITICAL)
```

### Severity Classification

Events are auto-classified based on allowlist evaluation:

| Condition | Severity | Action |
|-----------|----------|--------|
| Matches allowlist entry with ALLOW | INFO | Log only |
| No allowlist match, known program type (e.g., BPF_PROG_TYPE_CGROUP_SKB) | WARN | Alert SOC |
| No allowlist match, unknown binary hash | ALERT | Alert SOC, priority investigation |
| LD_PRELOAD from non-root, non-whitelisted library | ALERT | Alert SOC |
| bpftime-pattern shared memory from non-whitelisted process | CRITICAL | Alert SOC, possible active attack |
| /etc/ld.so.preload modified | CRITICAL | Alert SOC, host may be compromised |
| Any event from process with no matching allowlist AND running as root | CRITICAL | Alert SOC, priority |

### Allowlist Bootstrapping

First deployment challenge: you don't know what's "normal" yet. Strategy:

1. **Learning mode** (first 7-30 days): Agent reports all events. Server auto-creates PENDING allowlist entries for everything observed. SOC reviews and approves/rejects.
2. **Monitoring mode** (steady state): All new events evaluated against approved allowlist. Unknowns generate alerts. No blocking.
3. **Enforcement mode** (optional, advanced): Agent can actually prevent BPF program loading or process execution with LD_PRELOAD. Requires careful rollout — misconfiguration breaks legitimate tools.

## SIEM Connector Specifications

### Syslog/CEF (RFC 5424 + ArcSight CEF)

Standard syslog output for any SIEM that accepts syslog:

```
CEF:0|HookMon|HookMon|1.0|BPF_LOAD|BPF Program Loaded|7|
  src=10.1.2.3 shost=web-prod-01 suid=0 sproc=/usr/bin/cilium-agent
  cs1Label=ProgType cs1=BPF_PROG_TYPE_KPROBE
  cs2Label=ProgName cs2=trace_tcp_connect
  cs3Label=ExeHash cs3=sha256:abcdef...
  cs4Label=PolicyResult cs4=ALLOW
  cn1Label=InsnCount cn1=142
```

### Splunk HEC (HTTP Event Collector)

POST JSON events directly to Splunk's HEC endpoint. Configuration:
- HEC token
- Splunk URL
- Index name
- Source type: `hookmon:event`

### Elasticsearch

Bulk API to push events. Configuration:
- Elasticsearch URL
- Index pattern: `hookmon-events-YYYY.MM.DD`
- ILM policy for retention
- Optional: ship via Logstash instead

### Generic Webhook

POST JSON event to any URL. Supports:
- Custom headers (for auth tokens)
- Retry with exponential backoff
- Batching (configurable batch size / flush interval)

## Virtual Appliance Build

### Target Formats
- OVA (VMware vSphere / ESXi)
- QCOW2 (KVM / Proxmox / OpenStack)
- VHD (Hyper-V / Azure)
- ISO (bare-metal install)

### Base OS
Ubuntu Server 24.04 LTS (minimal). Rationale: widest enterprise acceptance, long-term support, straightforward security patching.

### Appliance Components

Bundled and configured automatically:
- **hookmon-server** binary (Go, statically linked)
- **PostgreSQL 16** (local, dedicated DB)
- **nginx** (TLS termination, static dashboard serving, reverse proxy to API)
- **systemd** units for all services
- **certbot** or self-signed TLS cert generation
- **unattended-upgrades** for security patches

### First-Boot Configuration

Console-based setup wizard on first boot:
1. Network configuration (static IP recommended for appliance)
2. Admin password
3. TLS certificate (self-signed, provide own, or Let's Encrypt)
4. SIEM connector configuration (optional, can defer to web UI)
5. Generate agent enrollment token
6. Display enrollment command for agents:
   ```
   curl -sSL https://hookmon.internal:9443/enroll | \
     sudo bash -s -- --token <enrollment-token>
   ```

### Agent Enrollment Protocol

1. Agent downloads enrollment script from server
2. Script installs hookmon-agent package
3. Agent generates keypair, sends CSR to server with enrollment token
4. Server signs cert, returns signed cert + CA cert
5. Agent configures mTLS and connects
6. Server registers host in inventory

## Build System

### Prerequisites
- Go 1.22+
- clang/llvm (for eBPF C compilation)
- bpf2go (cilium/ebpf code generator)
- buf (protobuf code generator)
- Node.js 20+ (dashboard build)
- Docker (appliance build)
- Packer (appliance image build)

### Key Make Targets

```makefile
make generate          # eBPF codegen + protobuf codegen
make build-agent       # Build agent binary
make build-server      # Build server binary
make build-cli         # Build CLI tool
make build-dashboard   # Build dashboard static assets
make build-all         # All of the above

make test              # Unit tests
make test-integration  # Integration tests (requires privileged container)
make test-e2e          # End-to-end tests

make package-deb       # Build .deb for agent
make package-rpm       # Build .rpm for agent
make docker-agent      # Build agent container image
make docker-server     # Build server container image

make appliance-ova     # Build OVA virtual appliance
make appliance-qcow2   # Build QCOW2 image
make appliance-iso     # Build install ISO
```

## Development Workflow

### Phase 1: Agent Core (MVP)

Build order:
1. `bpf_syscall.c` + `bpf_syscall.go` — the bpf() syscall hook sensor
2. `execve_preload.c` + `execve_preload.go` — LD_PRELOAD detection
3. `enrichment/process.go` — pid-to-context resolution
4. `event.go` — canonical event types
5. `cmd/hookmon-agent/main.go` — agent binary that loads sensors, prints events to stdout

At this point you have a working standalone agent that detects BPF loads and LD_PRELOAD usage on a single host.

### Phase 2: Central Server (MVP)

1. `proto/` — define protobuf messages and gRPC service
2. `server/ingestion/grpc.go` — accept agent streams
3. `server/store/postgres.go` — persist events
4. `server/policy/allowlist.go` — basic allowlist matching
5. `server/api/` — REST API for events and policies
6. `agent/transport/grpc.go` — agent-side gRPC client
7. `cmd/hookmon-server/main.go` — server binary

### Phase 3: Dashboard

1. Event feed page (WebSocket real-time)
2. Host inventory page
3. Allowlist/policy management page
4. Investigation detail page

### Phase 4: SIEM Connectors

1. Syslog/CEF
2. Splunk HEC
3. Generic webhook
4. Elasticsearch

### Phase 5: Virtual Appliance

1. Packer template
2. First-boot wizard
3. Agent enrollment flow
4. ISO builder

### Phase 6: Advanced Sensors

1. `shm_monitor` — bpftime-style detection
2. `dlopen_monitor` — runtime library injection
3. Enforcement mode (optional, careful)

## Security of HookMon Itself

The agent runs with elevated privileges (CAP_BPF, CAP_SYS_ADMIN for some hooks). This makes the agent itself a high-value target.

Mitigations:
- Agent binary is statically compiled, minimal attack surface
- Agent communicates only with the central server via mTLS (no other network)
- Agent config file is root-readable only
- Agent private key is root-readable only
- Server API requires authentication for all endpoints
- Appliance runs with firewall rules (only ports 9443 gRPC, 443 HTTPS)
- All inter-component communication is TLS-encrypted
- PostgreSQL listens only on localhost
- Agent binary integrity: server can verify agent binary hash at enrollment

## Key Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Agent language | Go | cilium/ebpf ecosystem, static linking, cross-compile |
| eBPF library | cilium/ebpf | Industry standard, bpf2go codegen, active maintenance |
| Server language | Go | Same binary ecosystem as agent, excellent gRPC support |
| Wire protocol | gRPC + mTLS | Streaming, efficient binary encoding, mutual auth |
| Database | PostgreSQL | Reliable, JSON support for flexible event payloads, enterprise-accepted |
| Dashboard | React + TypeScript | Standard, large component ecosystem |
| Appliance base | Ubuntu Server 24.04 LTS | Enterprise acceptance, 10-year support window |
| Image build | Packer | Multi-format output (OVA, QCOW2, VHD, ISO) from single template |
| Agent deployment | DEB/RPM + Ansible | Standard enterprise Linux deployment patterns |

## Non-Goals (Explicitly Out of Scope)

- **Runtime BPF program analysis/decompilation.** HookMon detects and logs BPF program loading; it does not attempt to disassemble or analyze the BPF bytecode for malicious behavior. That is a different (and much harder) problem.
- **Host-based prevention/blocking in v1.** Enforcement mode is Phase 6 and optional. The core value proposition is visibility and alerting, not inline blocking.
- **Windows support.** eBPF on Windows (eBPF for Windows project) exists but is architecturally different. Future consideration only.
- **Replacing existing eBPF security tools.** HookMon complements Falco, Tetragon, Tracee — it monitors the monitors. It answers "who loaded that Falco BPF program and was it authorized?" rather than "what syscalls is this container making?"

## Naming

- **HookMon** — the project, the product, the appliance
- **hookmon-agent** — the per-host agent binary
- **hookmon-server** — the central server binary
- **hookmon-cli** — the command-line policy management tool
- **HookMon Dashboard** — the web UI

## References

- [bpftime](https://github.com/eunomia-bpf/bpftime) — userspace eBPF runtime that motivated the SHM sensor
- [bpftime-go](https://github.com/tylerflint/bpftime-go) — Go bindings demonstrating unprivileged eBPF, the specific threat catalyst
- [cilium/ebpf](https://github.com/cilium/ebpf) — Go eBPF library used by the agent
- [Falco](https://falco.org/) — runtime security tool (complementary, not competitive)
- [Tetragon](https://github.com/cilium/tetragon) — eBPF-based security observability (complementary)
- [Tracee](https://github.com/aquasecurity/tracee) — eBPF-based runtime security (complementary)

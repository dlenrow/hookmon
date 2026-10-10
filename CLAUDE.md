# CLAUDE.md — HookMon Project Specification

## Project Identity

**Name:** HookMon
**Repo:** github.com/dlenrow/hookmon
**Local path:** ~/hookmon
**License:** Apache 2.0
**Language:** Go (primary), C (eBPF programs), TypeScript (dashboard)
**Author:** Dave Lenrow <david.lenrow@illumio.com>

## What This Is

HookMon is a security monitor that detects and logs the main mechanisms by which code enters a Linux process: **eBPF program loading**, **environment-based library injection** (LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH/LD_DEBUG), **shared memory exploitation**, **runtime dlopen() injection**, **linker configuration tampering**, **ptrace code injection**, **shared library replacement**, and **risky ELF RPATH/RUNPATH entries**. These mechanisms allow an attacker to intercept function calls, exfiltrate data, and install persistent backdoors that traditional security tooling rarely watches. It does not cover every mechanism; `docs/threat-model.md` lists what is and isn't covered. It does not enforce or block anything: there is no enforcement mode. `docs/claims.md` records what has been tested.

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
│  │  hookmon-bus (per host, formerly hookmon-agent)              │   │
│  │                                                              │   │
│  │  Sensors (8):                                                 │   │
│  │    ├── bpf_syscall      — hooks bpf() syscall (eBPF)         │   │
│  │    ├── exec_injection   — env scan at exec (eBPF)            │   │
│  │    ├── shm_monitor      — detects /dev/shm patterns (eBPF)   │   │
│  │    ├── dlopen_monitor   — hooks dlopen() (eBPF uprobe)       │   │
│  │    ├── linker_config    — watches ld.so config (fanotify)    │   │
│  │    ├── ptrace_monitor   — hooks ptrace() inject (eBPF)       │   │
│  │    ├── lib_integrity    — watches .so files (fanotify)       │   │
│  │    └── elf_rpath        — RPATH at exec (eBPF + Go)          │   │
│  │                                                              │   │
│  │  Every 10 s: bus fires each eBPF hook (active probe)         │   │
│  │                                                              │   │
│  │  Sensor bus:                                                 │   │
│  │    ├── event enrichment (pid → cmdline, cgroup, container)   │   │
│  │    ├── sensor health registry (heartbeat maps + links)       │   │
│  │    ├── /status HTTP endpoint + Prometheus /metrics           │   │
│  │    ├── mTLS gRPC to server (enrolled cert)                   │   │
│  │    └── local fallback log (if server unreachable)            │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Deployed today: built from source. DEB/RPM/Ansible: step 7g        │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ gRPC (port 9443, mutual TLS; enrollment on 9444)
                           │ HTTP /status (port 2112) ← polled by collector
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     HOOKMON APPLIANCE                                │
│                     (today: compose stack; images: step 7g)          │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐    │
│  │ Ingestion    │  │ Policy       │  │ Dashboard              │    │
│  │ Service      │  │ Engine       │  │ (web UI)               │    │
│  │              │  │              │  │                        │    │
│  │ gRPC server  │  │ allowlist DB │  │ React + TypeScript     │    │
│  │ event        │  │ rule eval    │  │ event feed             │    │
│  │ validation   │  │ learning: 7c │  │ policy management      │    │
│  │ rate limit   │  │ alert gen    │  │ host inventory         │    │
│  └──────┬───────┘  └──────┬───────┘  │ investigation workflow │    │
│         │                 │          └────────────────────────┘    │
│         ▼                 ▼                                        │
│  ┌─────────────────────────────┐  ┌────────────────────────────┐  │
│  │ Event Store                 │  │ SIEM Connectors            │  │
│  │ PostgreSQL                  │  │                            │  │
│  │                             │  │ ├── Syslog/CEF (RFC 5424) │  │
│  │ events table                │  │ ├── Splunk HEC             │  │
│  │ allowlist table             │  │ ├── Elastic (bulk API)     │  │
│  │ hosts table                 │  │ ├── Webhook (generic JSON) │  │
│  │ audit_log table             │  │ └── Kafka (optional)       │  │
│  │                             │  │                            │  │
│  └─────────────────────────────┘  └────────────────────────────┘  │
│                                                                     │
│  ┌────────────────────────────┐  ┌────────────────────────────┐  │
│  │ hookmon-collector          │  │ Prometheus Pushgateway     │  │
│  │  polls /status on all     │──▶│  :9091                     │  │
│  │  enrolled hosts (30s)     │  └────────────┬───────────────┘  │
│  └────────────────────────────┘               │ scraped by       │
│                                               ▼ Prometheus       │
│  Planned (step 7g): nginx, systemd units, auto-update               │
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
│   ├── hookmon-bus/           # Sensor bus binary (runs on monitored hosts)
│   │   └── main.go
│   ├── hookmon-agent/         # Deprecated alias for hookmon-bus
│   │   └── main.go
│   ├── hookmon-collector/     # Server-side fleet health poller
│   │   └── main.go
│   ├── hookmon-server/        # Central server binary
│   │   └── main.go
│   └── hookmon-cli/           # CLI for policy management & diagnostics
│       └── main.go
│
├── agent/                     # Sensor bus package
│   ├── agent.go               # Sensor bus lifecycle (start, stop, reconnect), self-filter
│   ├── health.go              # Probe, read heartbeat maps, check attachments, evaluate
│   ├── probe_linux.go         # The harmless calls that fire each eBPF hook
│   ├── probe/
│   │   └── dlopen_probe.c     # hookmon-dlopen-probe helper (fires the dlopen uprobe)
│   ├── registry/
│   │   ├── registry.go        # SensorRegistry — heartbeat tracking, liveness
│   │   └── registry_test.go   # Unit tests for registry
│   ├── sensors/
│   │   ├── sensor.go          # Common sensor interface (Sensor, SensorType)
│   │   ├── bpf_syscall.go     # bpf() syscall hook sensor
│   │   ├── bpf_syscall.c      # eBPF C for sys_enter_bpf / sys_exit_bpf
│   │   ├── bpf_inventory.go   # BPF_INVENTORY: list every loaded program (startup, every 5 min)
│   │   ├── bpf_health.go      # Heartbeat map read and attachment check (BPFHealth)
│   │   ├── exec_injection.go  # LD_* env var injection detection
│   │   ├── exec_injection.c   # eBPF C for sched_process_exec env scan
│   │   ├── shm_monitor.go     # /dev/shm creation detection
│   │   ├── shm_monitor.c      # eBPF C for sys_enter_openat / openat2
│   │   ├── shm_classify.go    # bpftime / bpf_related / unknown classification
│   │   ├── dlopen_monitor.go  # dlopen() interception
│   │   ├── dlopen_monitor.c   # eBPF C for dlopen uprobe
│   │   ├── dlopen_libc.go     # Finds every mapped glibc, host and containers
│   │   ├── linker_config.go   # ld.so config file monitoring (fanotify)
│   │   ├── lib_integrity.go   # shared library file monitoring (fanotify)
│   │   ├── fanotify_linux.go  # fanotify directory-entry watcher shared by both
│   │   ├── ldcache.go         # ld.so.cache parser (InLdCache)
│   │   ├── pkgmgr.go          # Package-manager ancestry check (INFO severity)
│   │   ├── ptrace_monitor.go  # ptrace() injection detection
│   │   ├── ptrace_monitor.c   # eBPF C for ptrace tracepoint
│   │   ├── elf_rpath.go       # ELF RPATH/RUNPATH analysis (pure Go, cross-platform)
│   │   ├── elf_rpath.c        # eBPF C for sched_process_exec
│   │   ├── elf_rpath_sensor.go # elf_rpath sensor: exec events → cached analysis
│   │   ├── elf_rpath_test.go  # Unit tests for RPATH classification
│   │   ├── embed.go           # eBPF .o file embeds (built by `make bpf`)
│   │   └── sensor_stub.go     # macOS build stubs
│   ├── observability/
│   │   ├── prometheus.go      # Prometheus metrics + HTTP server (/metrics + /status)
│   │   ├── status.go          # /status HTTP handler (sensor health JSON)
│   │   ├── status_test.go     # Unit tests for /status handler
│   │   └── loki.go            # Loki log pusher
│   ├── enrichment/
│   │   ├── process.go         # pid → cmdline, exe, cgroup, container ID
│   │   ├── container.go       # Container runtime detection
│   │   └── hash.go            # Binary/library SHA256 hashing
│   ├── transport/
│   │   ├── grpc.go            # mutual-TLS gRPC client stream (plaintext only with --insecure)
│   │   ├── enroll.go          # Enrollment: keypair, Enroll RPC, identity in state_dir
│   │   ├── console.go         # --console: JSON lines on stdout
│   │   ├── fallback.go        # Local file fallback when server down
│   │   └── retry.go           # Reconnection with exponential backoff
│   └── config/
│       └── config.go          # Agent configuration (YAML)
│
├── server/                    # Central server package
│   ├── server.go              # Server lifecycle; refuses to start without TLS unless --insecure
│   ├── config.go              # YAML config (/etc/hookmon/server.yaml; example in deploy/)
│   ├── watchdog.go            # Marks hosts UNRESPONSIVE (AGENT_OFFLINE)
│   ├── ingestion/
│   │   ├── grpc.go            # gRPC server for agent connections; host ID from the client cert
│   │   ├── enroll.go          # Enroll RPC: token check, CSR signing, host ID assignment
│   │   ├── validation.go      # Event schema validation
│   │   └── ratelimit.go       # Per-host rate limiting
│   ├── policy/
│   │   ├── engine.go          # Policy evaluation engine
│   │   ├── allowlist.go       # Allowlist CRUD + matching logic
│   │   ├── rules.go           # Rule definitions and evaluation
│   │   └── alert.go           # Alert generation and dedup
│   ├── store/
│   │   ├── postgres.go        # PostgreSQL event/policy store (queries live here)
│   │   └── migrations/        # SQL migration files
│   │       ├── 001_initial.sql
│   │       ├── ...
│   │       └── 005_uint32_bigint.sql  # pid, ppid, uid, gid, prog_type to BIGINT
│   ├── connectors/
│   │   ├── syslog.go          # Syslog/CEF output
│   │   ├── splunk.go          # Splunk HTTP Event Collector
│   │   ├── elastic.go         # Elasticsearch bulk API
│   │   ├── webhook.go         # Generic JSON webhook
│   │   ├── kafka.go           # Kafka producer (optional)
│   │   └── connector.go       # Common connector interface
│   └── api/
│       ├── router.go          # HTTPS router: REST API, then the dashboard for non-API paths
│       ├── dashboard.go       # Serves dashboard_dir, index.html fallback for client routes
│       ├── events.go          # Event query endpoints
│       ├── policies.go        # Policy CRUD endpoints
│       ├── hosts.go           # Host inventory endpoints
│       ├── websocket.go       # Live event feed
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
│   ├── buf.yaml
│   ├── buf.gen.yaml
│   └── hookmon/
│       └── v1/
│           ├── events.proto   # Event message types
│           ├── agent.proto    # Agent ↔ server RPC service
│           └── policy.proto   # Policy message types
│
├── gen/hookmon/v1/            # Generated protobuf + gRPC code (`cd proto && buf generate`)
│
├── appliance/                 # Virtual appliance / ISO build — none works yet (step 7g)
│   ├── packer/
│   │   ├── hookmon.pkr.hcl    # Packer template (only a QEMU/qcow2 source today)
│   │   └── scripts/
│   │       ├── base.sh        # OS hardening, package install
│   │       ├── hookmon.sh     # Server install + systemd units
│   │       ├── postgres.sh    # PostgreSQL setup
│   │       ├── nginx.sh       # TLS termination
│   │       └── firstboot.sh   # First-boot configuration wizard
│   ├── iso/
│   │   ├── build-iso.sh       # ISO builder (cloud-init + autoinstall)
│   │   └── user-data.yaml     # cloud-init configuration — missing (step 7g)
│   └── ansible/
│       ├── playbook.yml       # Alternative: deploy to existing server
│       └── roles/hookmon/     # Referenced roles and templates — missing (step 7g)
│
├── deploy/                    # Agent deployment artifacts
│   ├── deb/                   # Debian package build (ships hookmon-agent; step 7g)
│   ├── rpm/                   # RPM package build (ships hookmon-agent; step 7g)
│   ├── docker/
│   │   ├── docker-compose.grafana.yml  # Observability stack (Loki, Prometheus, Pushgateway, Alertmanager, Grafana)
│   │   ├── prometheus.yml, alertmanager.yml
│   │   ├── grafana/           # Dashboard, datasources, alert rules and their promtool tests
│   │   ├── Dockerfile.agent   # Agent container image
│   │   └── Dockerfile.server  # Server container image; dashboard in /usr/share/hookmon/dashboard
│   ├── server.example.yaml    # hookmon-server config example
│   └── ansible/
│       └── roles/
│           └── hookmon-agent/ # Agent deployment role (tasks only; its files and templates are missing; step 7g)
│
├── pkg/                       # Shared packages
│   ├── event/
│   │   └── event.go           # Canonical event types (shared agent+server)
│   ├── crypto/
│   │   ├── mtls.go            # TLS configs: mTLS gRPC, enrollment, REST
│   │   ├── enroll.go          # Keypair, CA loading, CSR signing
│   │   ├── identity.go        # Host ID from a verified client certificate
│   │   └── token.go           # Enrollment tokens: expiry, constant-time compare, single use
│   └── version/
│       └── version.go         # Build version injection
│
├── test/
│   ├── e2e/                   # End-to-end with real eBPF (Linux, root, -tags e2e)
│   ├── canary/                # Programs the e2e tests run (BPF canaries, bpftime_sim, ...)
│   ├── smoketest/             # Unprivileged pre-push smoketests
│   ├── transport/             # Wire-format, transport and enrollment tests
│   ├── integration/           # Real server + PostgreSQL (skips without HOOKMON_TEST_PG_DSN)
│   └── enrpki/                # Throwaway CA and certificates for tests
│
├── docs/
│   ├── architecture.md        # Detailed architecture document
│   ├── threat-model.md        # Ways code enters a process, coverage, what HookMon trusts
│   ├── theory-of-operations.md # Attack classes, allowlist model, tests
│   ├── deployment-guide.md    # Observability stack, sensor bus, server path and enrollment
│   ├── claims.md              # Claims ledger: what was tested, and how
│   ├── api-reference.md       # REST API docs — written after step 7
│   └── allowlist-guide.md     # How to build allowlists — written after step 7
│
└── scripts/
    ├── generate.sh            # buf generate + make bpf
    ├── build-agent.sh         # Agent binary, .deb and .rpm
    ├── build-server.sh
    ├── dev-setup.sh           # Local dev environment
    ├── pre-push               # Git hook: runs the smoketests
    └── ...                    # build-linux.sh, build-on-linux.sh, deploy-test.sh, run-e2e.sh, smoke-test.sh
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
    EventType   EventType `json:"event_type"`    // see the EventType constants below
    Severity    Severity  `json:"severity"`      // INFO, WARN, ALERT, CRITICAL

    // Process context
    PID         uint32   `json:"pid"`
    PPID        uint32   `json:"ppid"`
    UID         uint32   `json:"uid"`
    GID         uint32   `json:"gid"`
    Comm        string   `json:"comm"`          // task comm (16 chars)
    Cmdline     string   `json:"cmdline"`       // full /proc/pid/cmdline
    ExePath     string   `json:"exe_path"`      // /proc/pid/exe resolved
    ExeHash     string   `json:"exe_hash"`      // "sha256:<hex>" of the binary
    CgroupPath  string   `json:"cgroup_path"`   // cgroup path (v1 or v2)
    ContainerID string   `json:"container_id"`  // if in container
    Namespace   string   `json:"namespace"`     // k8s namespace; never filled today

    // Event-type-specific payload
    BPFDetail            *BPFDetail            `json:"bpf_detail,omitempty"`
    ExecInjectionDetail  *ExecInjectionDetail  `json:"exec_injection_detail,omitempty"`
    SHMDetail            *SHMDetail            `json:"shm_detail,omitempty"`
    DlopenDetail         *DlopenDetail         `json:"dlopen_detail,omitempty"`
    LinkerConfigDetail   *LinkerConfigDetail   `json:"linker_config_detail,omitempty"`
    PtraceDetail         *PtraceDetail         `json:"ptrace_detail,omitempty"`
    LibIntegrityDetail   *LibIntegrityDetail   `json:"lib_integrity_detail,omitempty"`
    ElfRpathDetail       *ElfRpathDetail       `json:"elf_rpath_detail,omitempty"`
    BPFInventoryDetail   *BPFInventoryDetail   `json:"bpf_inventory_detail,omitempty"`

    // Policy evaluation result (filled by server)
    PolicyResult   *PolicyResult   `json:"policy_result,omitempty"`
}

type EventType string
const (
    EventBPFLoad      EventType = "BPF_LOAD"        // bpf() syscall with BPF_PROG_LOAD
    EventBPFAttach    EventType = "BPF_ATTACH"       // bpf() PROG_ATTACH, LINK_CREATE, RAW_TRACEPOINT_OPEN
    EventBPFInventory EventType = "BPF_INVENTORY"    // one per loaded program at startup and every 5 min, then a host summary
    EventExecInjection EventType = "EXEC_INJECTION"  // LD_PRELOAD/LD_AUDIT/etc. in a new process's environment
    EventSHMCreate    EventType = "SHM_CREATE"       // /dev/shm segment created
    EventDlopen       EventType = "DLOPEN"           // glibc dlopen() call
    EventLinkerConfig EventType = "LINKER_CONFIG"    // /etc/ld.so.preload, ld.so.conf(.d) or ld.so.cache modified
    EventPtraceInject EventType = "PTRACE_INJECT"    // ptrace attach, memory, USER-area or register write
    EventLibIntegrity EventType = "LIB_INTEGRITY"    // shared library modified on disk
    EventElfRpath     EventType = "ELF_RPATH"       // suspicious RPATH/RUNPATH in ELF binary
    EventAgentOffline   EventType = "AGENT_OFFLINE"   // server watchdog: host stopped heartbeating
    EventAgentRecovered EventType = "AGENT_RECOVERED"
)

type BPFDetail struct {
    BPFCommand   uint32 `json:"bpf_cmd"`         // BPF_PROG_LOAD, BPF_PROG_ATTACH, etc.
    ProgType     uint32 `json:"prog_type"`        // BPF_PROG_TYPE_KPROBE, etc.
    ProgName     string `json:"prog_name"`        // program name from attr
    AttachType   uint32 `json:"attach_type"`
    TargetFD     int32  `json:"target_fd"`
    InsnCount    uint32 `json:"insn_count"`       // instruction count (complexity signal)
    // ProgHash is the kernel's program tag in hex (16 digits, as bpftool
    // prints it): the first 8 bytes of a SHA-1 over the instructions with
    // map references zeroed. Stable across loads on one kernel. Not a SHA-256.
    ProgHash     string `json:"prog_hash"`
    ProgID       uint32     `json:"prog_id,omitempty"`
    LoadTime     *time.Time `json:"load_time,omitempty"`
    CreatedByUID *uint32    `json:"created_by_uid,omitempty"`
    AttachTarget string     `json:"attach_target,omitempty"` // tracepoint of a RAW_TRACEPOINT_OPEN
}

type BPFInventoryDetail struct {
    ScanID    string            `json:"scan_id"`
    Summary   bool              `json:"summary"`              // true for the host summary event
    ProgCount uint32            `json:"prog_count,omitempty"` // summary only
    ByType    map[string]uint32 `json:"by_type,omitempty"`    // summary only
}

type ExecInjectionDetail struct {
    LibraryPath    string `json:"library_path"`     // value of the env var
    LibraryHash    string `json:"library_hash"`     // "sha256:<hex>" for an absolute LD_PRELOAD/LD_AUDIT path
    TargetBinary   string `json:"target_binary"`    // binary being exec'd
    SetBy          string `json:"set_by"`           // always "env" today
    EnvVar         string `json:"env_var"`          // which env var: LD_PRELOAD, LD_AUDIT, etc.
    ScanTruncated  bool   `json:"scan_truncated,omitempty"`  // scan stopped before the end of the environment
    ValueTruncated bool   `json:"value_truncated,omitempty"` // value longer than the sensor captures
}

type SHMDetail struct {
    SHMName      string `json:"shm_name"`         // /dev/shm segment name
    Size         uint64 `json:"size"`
    Pattern      string `json:"pattern"`          // "bpftime", "bpf_related", "unknown"
}

type DlopenDetail struct {
    LibraryPath  string `json:"library_path"`
    LibraryHash  string `json:"library_hash"`
    Flags        int    `json:"flags"`            // RTLD_NOW, RTLD_LAZY, etc.
}

type LinkerConfigDetail struct {
    FilePath    string `json:"file_path"`     // which config file was modified
    Operation   string `json:"operation"`     // "write", "create", "delete", "rename"
    OldHash     string `json:"old_hash"`      // "sha256:<hex>" before (startup baseline or last event)
    NewHash     string `json:"new_hash"`      // "sha256:<hex>" after
}

type PtraceDetail struct {
    Request     uint32 `json:"request"`       // PTRACE_ATTACH, PTRACE_POKETEXT, etc.
    RequestName string `json:"request_name"`  // human-readable
    TargetPID   uint32 `json:"target_pid"`
    TargetComm  string `json:"target_comm"`
    Addr        uint64 `json:"addr"`          // for POKETEXT/POKEDATA/POKEUSER
}

type LibIntegrityDetail struct {
    LibraryPath string `json:"library_path"`
    Operation   string `json:"operation"`     // "write", "create", "rename", "delete"
    OldHash     string `json:"old_hash"`
    NewHash     string `json:"new_hash"`
    InLdCache   bool   `json:"in_ld_cache"`   // whether /etc/ld.so.cache lists this lib
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
    ProgHash    string      `json:"prog_hash"`    // kernel program tag; pin ProgType too
    HostPattern string      `json:"host_pattern"` // hostname glob
    UIDRange    *UIDRange   `json:"uid_range"`    // allowed UID range
    ContainerImage string   `json:"container_image"` // container image pattern
    AllowedRpaths []string  `json:"allowed_rpaths,omitempty"`

    // Policy
    Action      PolicyAction `json:"action"`       // ALLOW, ALERT, DENY
    Expires     *time.Time   `json:"expires"`       // optional TTL
    Enabled     bool         `json:"enabled"`
}

type PolicyAction string
const (
    ActionAllow PolicyAction = "ALLOW"   // known good, log at INFO
    ActionAlert PolicyAction = "ALERT"   // suspicious, alert SOC
    ActionDeny  PolicyAction = "DENY"    // recorded only: there is no enforcement mode
)
```

There is no PENDING state yet; learning mode is fix plan step 7c.

## Sensor Implementation Details

### Sensor 1: bpf() Syscall Monitor

Hooks the `bpf()` syscall via tracepoints `sys_enter_bpf` and `sys_exit_bpf`. Captures:
- `cmd` argument: `BPF_PROG_LOAD` (BPF_LOAD event), and `BPF_PROG_ATTACH`, `BPF_LINK_CREATE` and `BPF_RAW_TRACEPOINT_OPEN` (BPF_ATTACH event). `BPF_MAP_CREATE` is not reported: a map runs no code, and any program that uses one is reported when it loads.
- `attr` contents (program type, name, attach type, instruction count, raw tracepoint name)
- For `PROG_LOAD`, the kernel's view of the new program, read in `sys_exit_bpf` from the returned fd: program ID and the kernel's program tag (`ProgHash`). For the attach commands, the program behind the fd the caller passed.
- Calling process context (pid, ppid, uid, gid, comm)

At startup and every 5 minutes the sensor also lists every loaded program and emits one BPF_INVENTORY event per program, then a host summary. That catches programs loaded before the bus started.

Not covered: `BPF_LINK_UPDATE`, and attaches that don't go through `bpf()` (perf `SET_BPF` ioctl, netlink XDP/tc, `SO_ATTACH_BPF`). The sensor requires the bus to run as root, which is acceptable because the bus is a privileged security tool.

```c
// Simplified from agent/sensors/bpf_syscall.c
SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 cmd = (u32)ctx->args[0];
    if (cmd != BPF_PROG_LOAD && cmd != BPF_PROG_ATTACH &&
        cmd != BPF_LINK_CREATE && cmd != BPF_RAW_TRACEPOINT_OPEN)
        return 0;
    // Fill pid, uid, comm and the attr fields. For the attach commands, read
    // the attached program's ID and tag through the fd the caller passed.
    // Store the record per thread until the syscall returns.
}

SEC("tracepoint/syscalls/sys_exit_bpf")
int trace_bpf_exit(struct trace_event_raw_sys_exit *ctx) {
    // For a stored PROG_LOAD with ret >= 0, read the new program's ID and
    // bpf_prog->tag through the returned fd. Emit every stored record.
}
```

### Sensor 2: Exec Injection Monitor

Hooks `tracepoint/sched/sched_process_exec`, which fires after every successful `execve` and `execveat`, once the new image is installed and before it runs. For every exec:
1. Read the new process's environment from the kernel's copy (`mm->env_start` to `mm->env_end`), the strings `ld.so` will read
2. Scan the start of each variable for `LD_PRELOAD=`, `LD_AUDIT=`, `LD_LIBRARY_PATH=`, and `LD_DEBUG=`
3. Emit one event per match with the env var name, its value, and the target binary. For an absolute `LD_PRELOAD`/`LD_AUDIT` path, Go adds the library's `sha256:` hash.

Limits: the scan reads the environment 256 bytes at a time. With `bpf_loop` (kernel 5.17+) it does up to 8192 reads; on older kernels a bounded loop does 512. If the scan stops before `env_end` (out of reads, a failed read, or more than 16 matches), one more event goes out flagged `scan_truncated`, so a variable past the limit is never missed silently. A value longer than the sensor captures is flagged `value_truncated`.

### Sensor 3: Shared Memory Monitor

Detect bpftime-style userspace eBPF by monitoring shared memory creation:
- Hook the `sys_enter_openat` and `sys_enter_openat2` tracepoints, filter for `/dev/shm/` paths opened with `O_CREAT` (what glibc's `shm_open` does)
- Classify the name: `bpftime` (CRITICAL) if it contains "bpftime" (bpftime's default is `bpftime_maps_shm`) or the creator's environment sets `BPFTIME_GLOBAL_SHM_NAME` to it; `bpf_related` (ALERT) if it contains "bpf"; `unknown` (INFO) otherwise

Together with `exec_injection` (bpftime injects via `LD_PRELOAD`), this is how HookMon sees userspace eBPF runtimes that never invoke the kernel `bpf()` syscall. Tested with a simulator only, not the real bpftime runtime. Not covered: relative or dirfd-relative opens, `/run/shm`, `creat()`, `O_TMPFILE`+`linkat`, renames into `/dev/shm`, io_uring opens, System V shm.

### Sensor 4: dlopen() Monitor

Hook `dlopen()` via uprobe on every distinct glibc object (`libc.so.6`, or `libdl.so.2` before glibc 2.34) that any process has mapped, found in `/proc/*/maps` at startup and every 5 minutes, including containers' own glibc. Captures:
- Library path being loaded, and its `sha256:` hash
- Calling process context
- RTLD flags

Events are deduplicated: one per (exe hash, library path) per hour. Attachments are capped at 256.

This catches runtime library injection that doesn't use `LD_PRELOAD` — the attacker manually calls `dlopen()` on a malicious shared object after process startup. Not covered: musl and static binaries, `dlmopen`, a libc mapped since the last scan, and loaders that map code without `dlopen`.

### Sensor 5: Linker Config Monitor

Pure Go, no eBPF. Uses fanotify directory-entry events (`FAN_REPORT_DFID_NAME`, Linux 5.9+; marks on `/etc` and `/etc/ld.so.conf.d`) to watch:
- `/etc/ld.so.preload` — system-wide library preload
- `/etc/ld.so.conf` — linker configuration
- `/etc/ld.so.conf.d/` — linker configuration drop-in directory
- `/etc/ld.so.cache` — the linker's library cache

Any write, create, delete, or rename of these files (including `sed -i`, `mv`, `ln -sf`) produces a LINKER_CONFIG event. Each watched file is hashed at startup, so events carry the old and new `sha256:` hashes. A change is CRITICAL — it affects every dynamically-linked process on the system — or INFO when a package manager is in the writer's process ancestry. If no fanotify mark succeeds, the sensor fails to start. Only the host's `/etc` is watched, not containers'.

### Sensor 6: Ptrace Monitor

eBPF tracepoint on `sys_enter_ptrace`. Filters for dangerous requests:
- `PTRACE_ATTACH` (16) — attach to a running process
- `PTRACE_SEIZE` (0x4206) — modern attach variant
- `PTRACE_POKETEXT` (4) — write to process text segment
- `PTRACE_POKEDATA` (5) — write to process data segment
- `PTRACE_POKEUSER` (6) — write to the USER area (debug registers, for example)
- `PTRACE_SETREGS` (13; x86 and arm, not arm64) — overwrite registers
- `PTRACE_SETREGSET` (0x4205) — overwrite a register set

Events include the ptrace request type, target PID, target process comm (resolved in the caller's PID namespace; empty when the target is in a nested namespace below it), and memory address (for POKE operations). Legitimate debugger use (gdb, strace) should be allowlisted.

### Sensor 7: Library Integrity Monitor

Pure Go, fanotify directory-entry events, with a mark on every directory under the standard library directories:
- `/usr/lib/`, `/usr/lib64/`, `/lib/`, `/lib64/`

Filters for `*.so` and `*.so.*` files. On write, create, rename, or delete, produces a LIB_INTEGRITY event with the library path, operation, before/after `sha256:` hashes, and whether `/etc/ld.so.cache` lists the library (parsed by the sensor). Every library is hashed at startup, in the background, to fill the first event's old hash. A change is ALERT, or INFO when a package manager is in the writer's process ancestry. This detects trojanized library replacement attacks in those directories; `/usr/local/lib`, `/opt` and other paths are not watched.

### Sensor 8: ELF RPATH Monitor

An eBPF sensor (`SensorTypeBPF`) since step 4. A `tracepoint/sched/sched_process_exec` program fires after every successful exec (`execve` and `execveat`) and sends the filename and the kernel's identity of the loaded binary (device, inode, mtime, mode) to Go over a ring buffer. Go uses `debug/elf` to inspect DT_RPATH and DT_RUNPATH entries. It is no longer a post-enrichment hook, and no sensor uses `SensorTypeAudit` now.

For each exec event, when `cfg.Sensors.ElfRpath` is enabled, the bus:
1. Checks an LRU cache keyed by the binary's (device, inode, mtime, mode), max 10k entries, which also remembers binaries with no RPATH
2. If uncached, opens the binary with `debug/elf` and reads `DT_RPATH`/`DT_RUNPATH` via `f.DynString()`
3. Classifies each path entry by risk (CRITICAL/HIGH/MEDIUM/LOW/NONE)
4. If highest risk >= MEDIUM, emits a supplementary `ELF_RPATH` event with full process context, once per binary version (device, inode, mtime, mode), on its first exec, not on every exec

Risk classification (`$ORIGIN`, `$LIB` and `$PLATFORM`, also written `${NAME}`, are expanded first, as ld.so expands them):
- CRITICAL: relative paths; `/tmp`, `/var/tmp`, `/dev/shm`, `/home` and anything under them; `$ORIGIN` in SUID binary; `$ORIGIN` resolving into one of those directories
- HIGH: empty entries (`::`), non-existent directories, world-writable directories, directories below a world-writable parent that has no sticky bit
- MEDIUM: non-standard existing directory owned by a non-root user or writable by its group, or below a parent directory a non-root user owns or its group can write (a sticky parent only counts through its owner)
- LOW (no event): non-standard existing directory that only root can write, itself and every parent; `$ORIGIN` in a non-SUID binary resolving to such a directory
- NONE: standard system library paths (`/usr/lib`, `/lib`, etc.)

DT_RPATH (deprecated) bumps severity one level vs DT_RUNPATH, except that it never lifts LOW to MEDIUM: a directory only root can write produces no event whichever tag names it.

```go
type ElfRpathDetail struct {
    HasRpath       bool         `json:"has_rpath"`
    HasRunpath     bool         `json:"has_runpath"`
    RpathRaw       string       `json:"rpath_raw,omitempty"`
    RunpathRaw     string       `json:"runpath_raw,omitempty"`
    Entries        []RpathEntry `json:"entries"`
    HighestRisk    RpathRisk    `json:"highest_risk"`
    UsesOrigin     bool         `json:"uses_origin"`
    UsesDeprecated bool         `json:"uses_deprecated"`
    IsSetuid       bool         `json:"is_setuid"`
}
```

CLI batch scan: `hookmon-bus --scan-rpath /usr/bin` (also accepted by the deprecated `hookmon-agent`) analyzes all ELF binaries in a directory and outputs JSON.

Not analyzed: the libraries a binary loads (only the executable), and a binary whose process exited before its path could be resolved (relative paths outside the cwd, `/dev/fd/N`, scripts, other mount namespaces, names of 255 bytes or more).

## Server Design Principles

### Event Processing Pipeline

```
Agent gRPC stream
    → validate schema
    → evaluate against allowlist and built-in rules
    → classify severity (replaces the bus's severity; fix plan step 7c)
    → store in PostgreSQL
    → fan out to:
        ├── WebSocket feed (dashboard real-time; one shared channel, step 7e)
        ├── SIEM connectors (Syslog, Splunk, Elastic, webhook, Kafka; none configurable yet, step 7d)
        └── Alert queue (if ALERT or CRITICAL; created but never called, step 7d)
```

Server-side enrichment (reverse DNS, asset DB lookup) is not built.

### Severity Classification

This table is the server's intended classification. Today the server replaces the bus's per-sensor severity with its own, so the bus's INFO downgrades (package-manager writes, ordinary shared memory) are lost on the server path, and the root-UID check runs before RPATH classification. Both are fix plan step 7c. On the bus (console, Loki, Prometheus), severity is set per sensor; see `docs/theory-of-operations.md`.

Events are auto-classified based on allowlist evaluation:

| Condition | Severity | Action |
|-----------|----------|--------|
| Matches allowlist entry with ALLOW | INFO | Log only |
| No allowlist match, known program type (e.g., BPF_PROG_TYPE_CGROUP_SKB) | WARN | Alert SOC |
| No allowlist match, unknown binary hash | ALERT | Alert SOC, priority investigation |
| Exec injection from non-root, non-whitelisted library | ALERT | Alert SOC |
| Ptrace injection detected | ALERT | Alert SOC, process memory manipulation |
| Shared library modified on disk | ALERT | Alert SOC, possible trojanized library |
| ELF RPATH with CRITICAL risk entries | CRITICAL | Attacker-controlled library search path |
| ELF RPATH with HIGH risk entries | ALERT | Suspicious library search path |
| ELF RPATH with MEDIUM risk entries | WARN | Library search path a non-root user or group can write |
| ELF RPATH with only LOW or NONE entries | — | No event (root-only-writable or standard library path) |
| bpftime-pattern shared memory from non-whitelisted process | CRITICAL | Alert SOC, possible active attack |
| Linker configuration modified | CRITICAL | Alert SOC, system-wide injection vector |
| Any event from process with no matching allowlist AND running as root | CRITICAL | Alert SOC, priority |

### Allowlist Bootstrapping

First deployment challenge: you don't know what's "normal" yet. Strategy:

1. **Learning mode** (first 7-30 days) — **not built; fix plan step 7c.** Agent reports all events. Server auto-creates PENDING allowlist entries for everything observed. SOC reviews and approves/rejects.
2. **Monitoring mode** (steady state): All new events evaluated against approved allowlist. Unknowns generate alerts. No blocking. Today allowlist entries are added by hand (REST API or `hookmon-cli policies create`), and the server reads them only at startup (step 7c).
3. **Enforcement mode** (optional, advanced) — **does not exist; not in the fix plan.** Agent would prevent BPF program loading or process execution with LD_PRELOAD.

## SIEM Connector Specifications

**Status:** connector code exists for all five (`server/connectors/`), but `hookmon-server` has no flag or config file that turns one on, so none runs today (fix plan step 7d).

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
- ILM policy for retention — not implemented (step 7d)
- Optional: ship via Logstash instead

### Generic Webhook

POST JSON event to any URL. Supports:
- Custom headers (for auth tokens)
- Retry with exponential backoff
- Batching (configurable batch size / flush interval) — not implemented; one POST per event

### Kafka

Producer to a configured topic (`server/connectors/kafka.go`).

## Virtual Appliance Build

**Status: none of this works yet (fix plan step 7g).** Today the only appliance is the observability compose stack (`deploy/docker/docker-compose.grafana.yml`). The Packer template defines only a QEMU (qcow2) source; `make appliance-ova` names a VMware source that does not exist; `appliance/iso/user-data.yaml` is missing; `firstboot.sh` writes a config file nothing reads; the server binary is not uploaded. Step 7g makes qcow2 work and either fixes OVA, VHD and ISO or removes them.

### Target Formats
- OVA (VMware vSphere / ESXi) — not built
- QCOW2 (KVM / Proxmox / OpenStack) — template exists, not working
- VHD (Hyper-V / Azure) — not built
- ISO (bare-metal install) — not working

### Base OS
Ubuntu Server 24.04 LTS (minimal). Rationale: widest enterprise acceptance, long-term support, straightforward security patching.

### Appliance Components

Bundled and configured automatically:
- **hookmon-server** binary (Go, statically linked)
- **PostgreSQL 16** (local, dedicated DB)
- **nginx** (TLS termination, static dashboard serving, reverse proxy to API). `hookmon-server` now terminates TLS and serves the dashboard itself, and `nginx.sh` still proxies to plain `http://127.0.0.1:8443` (step 7g)
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

The `/enroll` script and `curl` command above do not exist (fix plan step 7g). A bus enrolls with `hookmon-bus --enroll-token` instead.

### Agent Enrollment Protocol

**Status: working (fix plan step 7a).** There is no enrollment script or package install yet (step 7g); the operator installs the bus and runs it once with a token.

1. The server config (`/etc/hookmon/server.yaml`) lists enrollment tokens: name, secret (at least 32 characters), expiry, optional `single_use`. With tokens configured, the server listens for enrollment on 9444 (TLS, server authentication only, `Enroll` RPC only).
2. On first start, `hookmon-bus --enroll-token <secret> --server-addr <host>:9443 --ca-file ca.crt` generates an ECDSA P-256 keypair and sends a CSR to `--enroll-addr` (default: the server host on 9444), verifying the server against `--ca-file`.
3. The server checks the token in constant time, rejects it if expired or already used (single-use tokens are recorded in PostgreSQL), assigns a UUID host ID, and signs a client certificate with that ID as CN. It creates the host in the inventory and returns the certificate and the CA certificate.
4. The bus checks the certificate against its key and its CA, stores `bus.key`, `bus.crt` and `ca.crt` in `/var/lib/hookmon` (`--state-dir`) with mode 0600, and connects to 9443 with mutual TLS.
5. On every later RPC the server takes the host ID from the client certificate and ignores the one in the message. Heartbeats carry the sensor-registry snapshot. Later starts reuse the stored identity.

Gaps: the token is visible in the process list during the first start; certificates are not renewed; no AGENT_RECOVERED event is sent when a host comes back.

## Build System

### Prerequisites
- Go 1.23+ (`go.mod`)
- make and a C compiler (for `hookmon-dlopen-probe`)
- On Linux: clang, llvm-strip, libbpf headers, bpftool, and a kernel with BTF. `make bpf` builds the eBPF objects from the running kernel's BTF; `embed.go` embeds them, so on Linux no Go package that imports `agent/sensors` builds until `make bpf` has run. There is no bpf2go step.
- buf (protobuf code generator)
- Node.js 20+ (dashboard build)
- Docker (images, compose stack)
- Packer (appliance image build; not working yet, step 7g)

### Key Make Targets

```makefile
make generate          # buf generate (proto/) + make bpf (Linux only)
make bpf               # vmlinux.h from kernel BTF, then the eBPF objects (Linux)
make build-bus         # Build sensor bus binary (hookmon-bus)
make build-agent       # Build deprecated agent binary (alias for hookmon-bus)
make build-collector   # Build collector binary (hookmon-collector)
make build-server      # Build server binary
make build-cli         # Build CLI tool
make build-dlopen-probe # Build the hookmon-dlopen-probe helper
make build-dashboard   # Build dashboard static assets
make build-all         # bus, agent, server, cli, collector, dlopen-probe (not dashboard)
make build-canaries    # e2e canary programs (test/canary)

make test              # go test ./...
make test-unit         # Unit tests with -race
make smoketest         # Unprivileged smoketests (test/smoketest)
make test-e2e          # End-to-end tests (Linux, sudo; deploys to /tmp)
make ci                # build-all + test-unit + go vet
make test-integration  # Broken: test/integration does not exist

make package-deb       # Build .deb for agent (ships hookmon-agent; step 7g)
make package-rpm       # Build .rpm for agent (ships hookmon-agent; step 7g)
make docker-agent      # Build agent container image
make docker-server     # Build server container image

make appliance-ova     # Broken: the Packer template has no VMware source (step 7g)
make appliance-qcow2   # Build QCOW2 image (not working yet; step 7g)
make appliance-iso     # Build install ISO (user-data.yaml missing; step 7g)
```

## Development Workflow

### Phase 1: Agent Core (MVP)

Build order:
1. `bpf_syscall.c` + `bpf_syscall.go` — the bpf() syscall hook sensor
2. `exec_injection.c` + `exec_injection.go` — LD_PRELOAD detection
3. `enrichment/process.go` — pid-to-context resolution
4. `event.go` — canonical event types
5. `cmd/hookmon-bus/main.go` — sensor bus binary that loads sensors, prints events to stdout (`--console`)

At this point you have a working standalone agent that detects BPF loads and exec injection on a single host.

### Phase 2: Central Server (MVP)

1. `proto/` — define protobuf messages and gRPC service
2. `server/ingestion/grpc.go` — accept agent streams
3. `server/store/postgres.go` — persist events
4. `server/policy/allowlist.go` — basic allowlist matching
5. `server/api/` — REST API for events and policies
6. `agent/transport/grpc.go` — agent-side gRPC client
7. `cmd/hookmon-server/main.go` — server binary

Status: built, with gaps. Enrollment (7a) and TLS by default (7b) work. The allowlist loads once at startup (7c), connectors can't be configured (7d), and no e2e test covers this path (7h).

### Phase 3: Dashboard

Status: the five pages build, and `hookmon-server` serves them from `dashboard_dir` over HTTPS (step 7b). The WebSocket, the Settings page and the dev proxy have known bugs (step 7e).

1. Event feed page (WebSocket real-time)
2. Host inventory page
3. Allowlist/policy management page
4. Investigation detail page

### Phase 4: SIEM Connectors

Status: code exists; nothing configures it (step 7d).

1. Syslog/CEF
2. Splunk HEC
3. Generic webhook
4. Elasticsearch

### Phase 5: Virtual Appliance

Status: not working (step 7g). Enrollment itself works (7a); the appliance does not set it up.

1. Packer template
2. First-boot wizard
3. Agent enrollment flow
4. ISO builder

### Phase 6: Advanced Sensors (Complete)

All 8 sensors implemented:
1. `bpf_syscall` — kernel eBPF detection (eBPF tracepoints `sys_enter_bpf`/`sys_exit_bpf`, plus BPF_INVENTORY)
2. `exec_injection` — LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH/LD_DEBUG detection (eBPF tracepoint `sched_process_exec`)
3. `shm_monitor` — bpftime-style shared memory detection (eBPF tracepoints `sys_enter_openat`/`openat2`)
4. `dlopen_monitor` — runtime library injection (eBPF uprobe on every mapped glibc)
5. `linker_config` — ld.so config file monitoring (fanotify)
6. `ptrace_monitor` — ptrace code injection detection (eBPF tracepoint)
7. `lib_integrity` — shared library file integrity (fanotify)
8. `elf_rpath` — ELF RPATH/RUNPATH binary audit (eBPF tracepoint `sched_process_exec` + Go analysis)

Enforcement mode: does not exist, and the fix plan does not add it.

### Phase 7: Sensor Bus Heartbeat and Anti-Tampering

1. Per-sensor heartbeat BPF maps (all six eBPF sensors write a kernel timestamp each time their hook runs, before any filter). Every 10 s the bus fires each hook itself with a harmless call (active probe: its own `bpf()` map reads, `openat`/`openat2` of `/dev/null`, an invalid `ptrace`, `/bin/true`, and `hookmon-dlopen-probe`), then reads the maps; a sensor is alive only if its value moved forward. It also checks that each program and link are still attached (`CheckAttached`). Default `dead_threshold` is 15 s.
2. Go-side heartbeat tickers for the fanotify sensors (they prove the bus runs, not that the watch fires)
3. `SensorRegistry` with Beat/Evaluate/Overall/Snapshot; statuses `alive`, `dead`, `failed`, `unverifiable`, `unknown`
4. `/status` HTTP endpoint on sensor bus (alongside `/metrics`)
5. Per-sensor Prometheus metrics (`hookmon_sensor_alive`, etc.)
6. Binary rename: `hookmon-bus` (formerly `hookmon-agent`)
7. `hookmon-collector` — server-side fleet health poller
8. SSH transport option for collector (runs `curl` on the host; same `/status` answer)
9. Pushgateway integration + Prometheus alert rules routed to Alertmanager (`HookMonHostUnreachable`, `HookMonSensorDead`, `HookMonFleetDegraded`, `HookMonCollectorSilent`, `HookMonNoEvents24h`)
10. Fleet health banner + sensor grid panels in Grafana dashboard

## Security of HookMon Itself

The sensor bus runs as root (eBPF, fanotify). This makes it a high-value target. `SECURITY.md` lists the trust boundaries and known limitations; `docs/threat-model.md` lists what HookMon trusts.

Mitigations, with their status today:
- Sensor bus binary is statically compiled Go. It runs two helpers every 10 s (`/bin/true`, `hookmon-dlopen-probe`), which must be root-owned.
- Sensor bus talks to the central server over mutual-TLS gRPC. Without a certificate or enrollment token it refuses to connect; `--insecure` allows plaintext for development. It also pushes to Loki (plain HTTP) and serves `/status` and `/metrics` (unauthenticated HTTP; `status_addr` limits the bind address).
- Config file is root-readable only (operator's job; no package sets it yet).
- Private key is root-readable only: enrollment writes `bus.key`, `bus.crt` and `ca.crt` with mode 0600.
- The server refuses to start without a TLS certificate unless `--insecure`. REST, the WebSocket and the dashboard are served over HTTPS on 8443.
- Server API requires a token on every endpoint except `/api/v1/health`. The WebSocket accepts any non-empty token (step 7e).
- Appliance firewall rules (only ports 9443 gRPC, 443 HTTPS, 2112 status) — not built (step 7g).
- All inter-component communication TLS-encrypted — bus to server and REST, yes; Loki pushes, `/status`, `/metrics` and the default PostgreSQL connection (`sslmode=disable`) are not.
- PostgreSQL listens only on localhost — the default connection string, not enforced.
- Binary integrity: server verifies the sensor bus binary hash at enrollment — not built.

### Tamper Detection

A sophisticated attacker will attempt to disable HookMon before proceeding. The heartbeat and polling design provides layered tamper detection:

- **Active probes and heartbeat maps:** Every 10 seconds the bus fires each eBPF sensor's hook itself, and the hook writes a kernel timestamp to its heartbeat map. A sensor is alive only if its map moved forward and its program and link are still attached. A hook that stops running is marked dead after `dead_threshold` (15 s), about 20 s in the worst case. On kernel 5.19, `bpftool link detach` is refused for these links, so the dead path is covered by unit tests only.
- **Server-side polling:** The `hookmon-collector` polls each host's `/status` endpoint every 30 seconds. If the sensor bus process is killed, the endpoint becomes unreachable — the collector detects this within one poll interval.
- **Out-of-band verification:** not built, and not in the fix plan. The collector's SSH mode runs `curl -s http://localhost:2112/status` on the host, so it sees the same answer as HTTP mode. It does not run `bpftool`, and it does not verify SSH host keys.
- **Prometheus alerting:** rules in `deploy/docker/grafana/alerts/hookmon-alerts.yaml` route to Alertmanager. `HookMonSensorDead` and `HookMonFleetDegraded` fire after 1 minute, `HookMonHostUnreachable` after 2 minutes, and `HookMonCollectorSilent` when the collector has not pushed for 90 s. The Grafana Fleet Health panel shows the state.
- **Limit:** root on the host can kill the bus and serve a fake `/status`, or write fresh timestamps into a heartbeat map. HookMon does not detect either.

## Key Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Agent language | Go | cilium/ebpf ecosystem, static linking, cross-compile |
| eBPF library | cilium/ebpf | Industry standard, active maintenance. Objects are built with clang by `make bpf` and embedded with `go:embed`; no bpf2go |
| Server language | Go | Same binary ecosystem as agent, excellent gRPC support |
| Wire protocol | gRPC + mTLS | Streaming, efficient binary encoding, mutual auth (plaintext only with `--insecure`) |
| Database | PostgreSQL | Reliable, JSON support for flexible event payloads, enterprise-accepted |
| Dashboard | React + TypeScript | Standard, large component ecosystem |
| Appliance base | Ubuntu Server 24.04 LTS | Enterprise acceptance, 10-year support window |
| Image build | Packer | Multi-format output (OVA, QCOW2, VHD, ISO) from single template (only a qcow2 source exists; step 7g) |
| Agent deployment | DEB/RPM + Ansible | Standard enterprise Linux deployment patterns (not working; step 7g) |

## Non-Goals (Explicitly Out of Scope)

- **Runtime BPF program analysis/decompilation.** HookMon detects and logs BPF program loading; it does not attempt to disassemble or analyze the BPF bytecode for malicious behavior. That is a different (and much harder) problem.
- **Host-based prevention/blocking.** Enforcement mode does not exist and the fix plan does not add it. The core value proposition is visibility and alerting, not inline blocking.
- **Windows support.** eBPF on Windows (eBPF for Windows project) exists but is architecturally different. Future consideration only.
- **Replacing existing eBPF security tools.** HookMon complements Falco, Tetragon, Tracee — it monitors the monitors. It answers "who loaded that Falco BPF program and was it authorized?" rather than "what syscalls is this container making?"

## Naming

- **HookMon** — the project, the product, the appliance
- **Sensors** — the eBPF programs and fanotify watchers. Read-only observation hooks. Cannot block, modify, or enforce anything.
- **Sensor bus** (`hookmon-bus`) — the lightweight per-host userspace process. Receives events from sensors, maintains the sensor health registry, exposes a local /status endpoint. Not a general-purpose agent. No policy engine, no enforcement capability.
- **hookmon-bus** — the per-host sensor bus binary (formerly `hookmon-agent` in early releases)
- **hookmon-collector** — the server-side polling binary. Polls sensor bus /status endpoints, pushes fleet health metrics to Pushgateway.
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

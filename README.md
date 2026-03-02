# HookMon

**Enterprise monitoring and policy enforcement for eBPF program loading and library injection.**

HookMon is a security appliance that detects every eBPF program load and every `LD_PRELOAD` library injection across your fleet, evaluates each against an allowlist, and alerts your SOC when something unauthorized appears. Deploy as a virtual appliance (ISO/OVA/QCOW2), enroll agents on your hosts, and get visibility into an attack surface that no existing tool monitors.

## Why This Exists

Loading an eBPF program or injecting a library via `LD_PRELOAD` are two of the most powerful instrumentation capabilities in Linux — and two of the most dangerous. An attacker who can do either one can intercept any function call, exfiltrate any data, and install backdoors that are invisible to `ps`, `lsof`, `/proc`, and every traditional detection tool.

The conventional threat model assumes this requires root (or `CAP_BPF`). That assumption is now wrong.

### The bpftime Problem

[bpftime-go](https://github.com/tylerflint/bpftime-go) is a Go module that runs eBPF programs **entirely in userspace** — no root, no `CAP_BPF`, no kernel eBPF subsystem involved. It works by emulating the eBPF VM in a userspace runtime and attaching to target processes via `LD_PRELOAD` and shared memory.

This means:

- **An unprivileged user** can hook `malloc`, `open`, `SSL_read`, `SSL_write`, or any dynamically-linked function in any process they can launch.
- **The kernel `bpf()` syscall is never called.** No audit log entry. No `bpftool` visibility. No kernel BPF program list.
- **No artifacts in `/proc`.** The instrumentation lives in userspace memory and shared memory segments. Standard forensic tools see nothing.
- **Every process the attacker launches inherits the hooks** via `LD_PRELOAD`. Reverse shells, SSH sessions, curl commands — all instrumented silently.

The only detection signals are the `LD_PRELOAD` environment variable being set (which legitimate tools also use), shared memory segments in `/dev/shm`, and the runtime binary itself.

If you were monitoring the `bpf()` syscall to detect eBPF abuse, you are now blind to an entire class of attacks that achieves the same outcome without ever invoking that syscall.

### The Broader Problem

Even before userspace eBPF, the detection story for kernel eBPF abuse was poor. An attacker with brief root access loads an eBPF program that hooks syscalls or network functions. The program persists in kernel space. Traditional security tooling doesn't track what BPF programs are loaded, who loaded them, or whether they're authorized.

Meanwhile, legitimate eBPF usage is exploding — Cilium, Falco, Datadog, Tetragon, Tracee, and dozens of other tools load eBPF programs as part of normal operations. Nobody is tracking whether those programs are the *authorized versions* or whether something has been tampered with.

### The Insight

**eBPF program loading and `LD_PRELOAD` injection are vanishingly rare events in production.** A typical server might see a handful of BPF program loads at boot (from its observability stack) and then zero for months. Any new load that doesn't match a known, approved program is worth investigation.

This makes allowlist-based monitoring extremely effective. The signal-to-noise ratio is inherently excellent because the base rate of legitimate new installations is near zero.

## What HookMon Does

**On every monitored host**, the HookMon agent runs four sensors:

| Sensor | Hooks | Detects |
|--------|-------|---------|
| `bpf_syscall` | `bpf()` syscall tracepoint | Kernel eBPF program loads and attachments |
| `execve_preload` | `execve()` tracepoint | `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` injection |
| `shm_monitor` | `shm_open()` / `mmap()` uprobes | Userspace eBPF runtimes (bpftime pattern detection) |
| `dlopen_monitor` | `dlopen()` uprobe | Runtime library injection without `LD_PRELOAD` |

Every detected event is enriched with full process context (pid, uid, cmdline, binary hash, container ID, cgroup path) and streamed over mTLS gRPC to the central HookMon server.

**On the central server**, each event is:

1. Evaluated against an allowlist of known, approved programs
2. Classified by severity (INFO → CRITICAL)
3. Stored for investigation and audit
4. Forwarded to your SIEM (Splunk, Elastic, Syslog/CEF, or generic webhook)
5. Displayed on the real-time dashboard

## Architecture

```
  Monitored Hosts                          HookMon Appliance
 ┌──────────────┐                        ┌──────────────────────┐
 │ hookmon-agent │──── mTLS gRPC ────▶  │ Ingestion Service    │
 │  4 eBPF       │                       │         │            │
 │  sensors      │                       │    Policy Engine     │
 └──────────────┘                        │    (allowlist eval)  │
 ┌──────────────┐                        │         │            │
 │ hookmon-agent │──── mTLS gRPC ────▶  │    PostgreSQL        │
 └──────────────┘                        │         │            │
 ┌──────────────┐                        │  ┌──────┴─────────┐  │
 │ hookmon-agent │──── mTLS gRPC ────▶  │  │  Dashboard     │  │
 └──────────────┘                        │  │  SIEM outputs  │  │
       ...                               │  │  Alert queue   │  │
                                         │  └────────────────┘  │
                                         └──────────────────────┘
```

## Deployment

### Central Server (Virtual Appliance)

Download the ISO/OVA/QCOW2 image, boot it, and run the first-boot wizard:

```bash
# First boot walks you through:
# 1. Network configuration
# 2. Admin credentials
# 3. TLS certificate
# 4. SIEM connector setup (optional)
# 5. Agent enrollment token generation
```

### Agent Enrollment

On each monitored host:

```bash
curl -sSL https://hookmon.internal:9443/enroll | \
  sudo bash -s -- --token <enrollment-token>
```

This installs the agent package, establishes mTLS, and begins streaming events.

### Agent Deployment at Scale

For fleet deployment, use the provided Ansible role, or install the DEB/RPM package directly:

```bash
# Debian/Ubuntu
sudo apt install ./hookmon-agent_1.0.0_amd64.deb

# RHEL/CentOS
sudo rpm -i hookmon-agent-1.0.0.x86_64.rpm
```

## Allowlist Workflow

1. **Learning mode** — Deploy agents, observe all events for 7-30 days. The server auto-creates pending allowlist entries for everything observed.
2. **Review** — SOC reviews pending entries in the dashboard. Approve known-good tools (Cilium, Datadog, Falco, etc.), flag unknowns for investigation.
3. **Monitoring mode** — Approved allowlist is active. Any new, unrecognized event generates an alert. No blocking.
4. **Enforcement mode** *(optional)* — Agent can block unauthorized BPF loads or LD_PRELOAD usage inline. Requires careful rollout.

## SIEM Integration

HookMon forwards events to your existing security infrastructure:

- **Syslog/CEF** (RFC 5424 + ArcSight Common Event Format) — any SIEM that accepts syslog
- **Splunk** — HTTP Event Collector (HEC) direct integration
- **Elasticsearch** — Bulk API, with ILM-managed index lifecycle
- **Webhook** — Generic JSON POST to any endpoint (PagerDuty, Opsgenie, custom)
- **Kafka** — For high-volume environments or custom processing pipelines

## What HookMon Is Not

HookMon **complements** runtime security tools — it doesn't replace them.

- **Falco/Tetragon/Tracee** answer: "What syscalls is this container making?"
- **HookMon** answers: "Who loaded that Falco eBPF program, when, was it the authorized binary, and has anything changed since last deployment?"

HookMon monitors the monitors. It provides the authorization and inventory layer that sits underneath the runtime security layer.

## Building from Source

```bash
# Prerequisites: Go 1.22+, clang/llvm, buf, Node.js 20+
make generate      # eBPF codegen + protobuf codegen
make build-all     # Agent, server, CLI, dashboard
make test          # Run tests
```

See [CLAUDE.md](CLAUDE.md) for full project specification, architecture details, and development workflow.

## License

Apache 2.0

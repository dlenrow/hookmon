# HookMon

**Enterprise monitoring and policy enforcement for every mechanism by which code enters a Linux process.**

HookMon is a security appliance that detects eBPF program loading, library injection, shared memory exploitation, runtime dlopen, linker configuration tampering, ptrace code injection, shared library replacement, and suspicious ELF RPATH entries across your fleet. Each event is evaluated against an allowlist and surfaced to your SOC when something unauthorized appears. Deploy as a virtual appliance (ISO/OVA/QCOW2), enroll sensor buses on your hosts, and get visibility into attack surfaces that no existing tool monitors.

## Eight Read-Only Kernel Sensors

HookMon's detection layer is eight purpose-built sensors that passively observe code injection vectors. They cannot block, modify, or interfere with any operation — they produce events, nothing more.

| Sensor | Mechanism | Detects |
|--------|-----------|---------|
| `bpf_syscall` | `bpf()` syscall tracepoint (eBPF) | Kernel eBPF program loads and attachments |
| `exec_injection` | `execve()` tracepoint (eBPF) | `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `LD_DEBUG` injection |
| `shm_monitor` | `openat()` tracepoint (eBPF) | Userspace eBPF runtimes (bpftime shared memory patterns) |
| `dlopen_monitor` | `dlopen()` uprobe (eBPF) | Runtime library injection without `LD_PRELOAD` |
| `linker_config` | fanotify (Go) | Writes to `/etc/ld.so.preload`, `ld.so.conf`, `ld.so.conf.d/` |
| `ptrace_monitor` | `ptrace()` tracepoint (eBPF) | `PTRACE_ATTACH`, `PTRACE_POKETEXT`, `PTRACE_POKEDATA` injection |
| `lib_integrity` | fanotify (Go) | Shared library modification/replacement in `/usr/lib`, `/lib`, etc. |
| `elf_rpath` | `debug/elf` audit (Go) | Suspicious `DT_RPATH`/`DT_RUNPATH` entries in executed binaries |

Every detected event is enriched with full process context (pid, uid, cmdline, binary hash, container ID, cgroup path) and streamed over mTLS gRPC to the central HookMon server.

**On the central server**, each event is:

1. Evaluated against an allowlist of known, approved programs
2. Classified by severity (INFO, WARN, ALERT, CRITICAL)
3. Stored for investigation and audit
4. Forwarded to your SIEM (Splunk, Elastic, Syslog/CEF, or generic webhook)
5. Displayed on the real-time dashboard

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

**Code injection events are vanishingly rare in production.** A typical server might see a handful of BPF program loads at boot and then zero for months. Shared libraries don't change between OS updates. `/etc/ld.so.preload` essentially never exists on a production host. Any new event that doesn't match a known, approved pattern is worth investigation.

This makes allowlist-based monitoring extremely effective. The signal-to-noise ratio is inherently excellent because the base rate of legitimate new activity is near zero.

## Architecture

```
  Monitored Hosts                          HookMon Appliance
 ┌──────────────────┐                    ┌──────────────────────────┐
 │ hookmon-bus       │── mTLS gRPC ──▶  │ Ingestion Service        │
 │  8 sensors        │                   │         │                │
 │  /status endpoint │◀── poll 30s ────│── hookmon-collector      │
 │  Prometheus :2112 │◀── scrape ──────│── Prometheus             │
 │  Loki push ──────│── POST ────────▶│── Loki                   │
 └──────────────────┘                    │         │                │
 ┌──────────────────┐                    │    Policy Engine         │
 │ hookmon-bus       │── mTLS gRPC ──▶  │    (allowlist eval)      │
 │  /status endpoint │◀── poll 30s ────│── hookmon-collector      │
 └──────────────────┘                    │         │                │
       ...                               │    PostgreSQL            │
                                         │    Grafana :3000         │
                                         │    SIEM connectors       │
                                         └──────────────────────────┘
```

The sensor bus exposes Prometheus metrics and pushes structured logs to Loki. The `/status` endpoint reports per-sensor health, polled independently by the server-side collector. The appliance runs Grafana with a pre-built dashboard for real-time event visualization. See [docs/architecture.md](docs/architecture.md) for details.

## How HookMon Knows It's Still Running

Detecting attacks is useless if the detector itself dies silently. HookMon has a server-initiated health model that does not depend on the sensor bus reporting its own status:

1. **Sensor heartbeats.** Each eBPF sensor writes a timestamp to a BPF map every 10 seconds. The fanotify and audit sensors update an in-process heartbeat at the same interval.
2. **The sensor bus aggregates.** The bus reads every sensor's heartbeat and exposes the result on its `/status` HTTP endpoint — one JSON object listing each sensor, its last heartbeat, and whether it considers itself healthy.
3. **The collector polls.** `hookmon-collector`, running on the appliance, polls `/status` on every enrolled host every 30 seconds. It writes the results to the event store.
4. **Grafana fires on silence.** If the collector cannot reach a bus, or if any sensor's heartbeat is stale, a Grafana alerting rule fires and the dashboard banner turns red.

The key property: the server reaches out to the bus. The bus does not phone home. If the bus process is killed, the collector notices within 30 seconds because `/status` stops responding. If a single sensor crashes but the bus keeps running, the collector sees the stale heartbeat in the `/status` response. There is no case where silent failure goes undetected.

## Why This Generates Almost No Alert Noise

HookMon monitors events that almost never happen. This is not a heuristic system that scores probabilities — it watches concrete, discrete operations that have a near-zero base rate in production:

- **BPF programs** load at boot and don't change until a tool is updated. A host might see 5-10 loads at startup, then zero for weeks or months.
- **Shared libraries** don't change between OS updates. A modified `.so` file is not a statistical signal — it is a fact that demands explanation.
- **`/etc/ld.so.preload`** essentially never exists on a production host. If it appears, that is not an anomaly to be scored. It is an event to be dispositioned.
- **`LD_PRELOAD` in an execve** is weekly or monthly per host in steady state, and every instance maps to a specific tool (e.g., `jemalloc`, `libfaketime`).
- **Ptrace injection** outside of debugger sessions is vanishingly rare. `PTRACE_POKETEXT` from a non-debugger process is not noise.

Every unallowlisted event is individually significant. It is not a statistical anomaly that might be a false positive — it is a concrete fact that requires disposition. The allowlist is built from observed reality during learning mode. The operational question for the SOC is "do we approve this new entry?" not "is this a real threat among thousands of alerts?"

In steady state, most hosts generate zero alerts per week. When an alert fires, it means something new and specific happened. That is the entire point.

## Quick Start

### 1. Deploy the Grafana Stack (Appliance)

On your appliance host (any Linux box with Docker):

```bash
git clone https://github.com/dlenrow/hookmon.git
cd hookmon
docker compose -f deploy/docker/docker-compose.grafana.yml up -d
```

This starts Grafana (:3000), Loki (:3100), Prometheus (:9090), and the hookmon-collector with the HookMon dashboard pre-provisioned. Default login: `admin` / `hookmon`.

### 2. Build and Run the Sensor Bus

On each monitored Linux host:

```bash
# Install build deps
sudo apt install -y clang llvm libbpf-dev  # + Go 1.22+

# Clone and build
git clone https://github.com/dlenrow/hookmon.git
cd hookmon/agent/sensors
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
for f in *.c; do clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c $f -o ${f%.c}.o; done
cd ../..
go build -o bin/hookmon-bus ./cmd/hookmon-bus/

# Run with observability
sudo bin/hookmon-bus --console \
  --loki-url http://<appliance>:3100 \
  --prometheus-port 2112 \
  --status-port 8080
```

### 3. Configure the Collector

On the appliance, register each enrolled host so the collector knows where to poll:

```bash
hookmon-cli host add --name web-prod-01 --address 10.1.2.3:8080
```

The collector begins polling `/status` on the registered host every 30 seconds.

### 4. View the Dashboard

Open `http://<appliance>:3000/d/hookmon-main/hookmon` in your browser.

### Future: Virtual Appliance

The appliance will ship as an ISO/OVA/QCOW2 with a first-boot wizard for network, TLS, SIEM connectors, and sensor bus enrollment. Sensor buses will enroll via:

```bash
curl -sSL https://hookmon.internal:9443/enroll | \
  sudo bash -s -- --token <enrollment-token>
```

For fleet deployment, use the provided Ansible role or DEB/RPM packages.

## Allowlist Workflow

1. **Learning mode** — Deploy sensor buses, observe all events for 7-30 days. The server auto-creates pending allowlist entries for everything observed.
2. **Review** — SOC reviews pending entries in the dashboard. Approve known-good tools (Cilium, Datadog, Falco, etc.), flag unknowns for investigation.
3. **Monitoring mode** — Approved allowlist is active. Any new, unrecognized event generates an alert. No blocking.
4. **Enforcement mode** *(optional, off by default)* — The sensor bus can optionally block unauthorized BPF loads or LD_PRELOAD usage inline. Requires explicit opt-in and careful rollout.

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

**HookMon is read-only by default.** In the default monitoring mode, the sensor bus cannot block, modify, or prevent any operation on the host. It observes kernel and filesystem events and reports them to the central server. It does not inject code, modify process memory, alter environment variables, or interfere with any syscall. Enforcement mode — where the bus can block unauthorized BPF loads or library injection — is explicitly opt-in, off by default, and requires deliberate configuration by the operator. If you never enable enforcement mode, the sensor bus is purely passive.

## Documentation

- [Architecture](docs/architecture.md) — system design, data flow, component overview
- [Deployment Guide](docs/deployment-guide.md) — appliance setup, sensor bus build, Grafana stack
- [Theory of Operations](docs/theory-of-operations.md) — threat model, detection approach, allowlist strategy

## Building from Source

```bash
# Prerequisites: Go 1.22+, clang/llvm, libbpf-dev, Node.js 20+
# On the monitored host (Linux with BTF-enabled kernel):
cd agent/sensors
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
for f in *.c; do clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c $f -o ${f%.c}.o; done
cd ../..
go build -o bin/hookmon-bus ./cmd/hookmon-bus/
go build -o bin/hookmon-server ./cmd/hookmon-server/
go build -o bin/hookmon-cli ./cmd/hookmon-cli/
```

## License

Apache 2.0

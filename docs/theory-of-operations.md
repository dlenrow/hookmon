# HookMon Theory of Operations

## Threat Model

HookMon defends against two classes of instrumentation abuse that are invisible to traditional security tooling.

### Class 1: Kernel eBPF Abuse

**Attack scenario:** An attacker with brief root access (or `CAP_BPF`) loads an eBPF program that hooks syscalls, network functions, or file operations. The program runs in kernel space, survives the attacker's session ending, and is invisible to `ps`, `lsof`, and standard forensic tools.

**Detection gap:** The `bpf()` syscall is the only entry point for kernel eBPF. Traditional tools don't monitor it. `bpftool prog list` shows loaded programs but doesn't track *who* loaded them, *when*, or *whether they're authorized*.

**HookMon approach:** The `bpf_syscall` sensor attaches to `tracepoint/syscalls/sys_enter_bpf` and captures every BPF_PROG_LOAD, BPF_PROG_ATTACH, and BPF_MAP_CREATE with full process context and a SHA256 hash of the program bytecode. This creates an audit trail that answers: who loaded what, when, and is it the expected binary?

### Class 2: Userspace eBPF (bpftime)

**Attack scenario:** An attacker *without root* uses a userspace eBPF runtime (bpftime, bpftime-go) to hook any dynamically-linked function in any process they can launch. The runtime works via `LD_PRELOAD` and shared memory. No kernel BPF subsystem is involved.

**Detection gap:** This is the worst-case scenario for defenders:
- No `bpf()` syscall fired — kernel BPF monitoring sees nothing
- No audit log entry generated
- No `bpftool` visibility
- No `/proc` artifacts beyond the LD_PRELOAD environment variable
- The instrumentation lives entirely in userspace memory

**HookMon approach:** Three sensors work together:
1. `execve_preload` catches the `LD_PRELOAD` being set in the environment of new processes
2. `shm_monitor` detects shared memory segments matching bpftime patterns in `/dev/shm`
3. `dlopen_monitor` catches runtime library loading via `dlopen()`

### Class 3: LD_PRELOAD Injection (Non-eBPF)

**Attack scenario:** Even without eBPF, `LD_PRELOAD` alone enables function interposition — replacing `malloc`, `SSL_read`, `open`, or any dynamically-linked function with attacker-controlled code. Used legitimately for debugging and instrumentation, but also a potent attack vector.

**HookMon approach:** The `execve_preload` sensor captures every process exec that has `LD_PRELOAD`, `LD_AUDIT`, or `LD_LIBRARY_PATH` set, along with the library path, its SHA256 hash, and the target binary being executed.

## The Allowlist Model

### Why Allowlists Work Here

The key insight is that eBPF program loading and LD_PRELOAD injection are **vanishingly rare events** in production. A typical server sees:

- A handful of BPF program loads at boot (from the observability stack — Cilium, Falco, Datadog)
- Zero new loads for weeks or months
- Occasional loads during deployments or updates

The base rate of *legitimate new installations* is near zero. This means every event that doesn't match a known, approved pattern is worth investigation. The signal-to-noise ratio is inherently excellent.

Compare this with syscall monitoring (millions of events per second) or network monitoring (enormous volume). HookMon operates in a domain where the event volume is naturally low and the significance of each event is naturally high.

### Severity Classification

Events are classified based on allowlist evaluation:

| Condition | Severity | Meaning |
|-----------|----------|---------|
| Matches allowlist entry with ALLOW action | INFO | Known good, log for audit |
| No allowlist match, known BPF program type | WARN | Unusual but possibly legitimate |
| No allowlist match, unknown binary hash | ALERT | Unknown program, investigate |
| LD_PRELOAD from non-root, non-whitelisted library | ALERT | Possible injection attack |
| bpftime-pattern shared memory from unknown process | CRITICAL | Likely active userspace eBPF attack |
| `/etc/ld.so.preload` modified | CRITICAL | Host may be compromised |
| Any unmatched event from root | CRITICAL | Privileged unauthorized activity |

### Operational Workflow

**Phase 1: Learning (Days 1-30)**
Deploy agents in console mode. Every event is logged. Operators build familiarity with what "normal" looks like on their infrastructure. The system auto-creates candidate allowlist entries for review.

**Phase 2: Monitoring (Steady State)**
The allowlist is active. Known-good events log at INFO. Anything new generates alerts. No blocking — visibility only. This is the primary operating mode for most deployments.

**Phase 3: Enforcement (Optional)**
The agent can block unauthorized BPF loads or LD_PRELOAD usage at the kernel level. This requires high confidence in the allowlist and careful rollout, since a false positive can break legitimate tooling.

## What HookMon Monitors the Monitors

A critical operational question that no existing tool answers:

> "The Falco eBPF program that's loaded on prod-web-03 — is it the *authorized version*? Was it loaded by the *authorized installer*? Has it been *replaced* since deployment?"

HookMon captures program bytecode hashes. If an attacker replaces a legitimate eBPF program with a modified one (same name, different code), HookMon detects the hash mismatch. This provides integrity monitoring for the security tools themselves.

## Event Enrichment

Raw eBPF events contain only kernel-space information (PID, UID, comm). The agent enriches each event from `/proc`:

- **cmdline:** full command line of the process
- **exe_path:** resolved symlink from `/proc/<pid>/exe`
- **exe_hash:** SHA256 of the executable binary
- **cgroup_path:** cgroup v2 path (enables container attribution)
- **container_id:** extracted from cgroup path
- **ppid:** parent PID for process tree analysis
- **prog_hash:** for BPF events, SHA256 of the program bytecode itself

This enrichment happens in userspace immediately after the event is received, while the process is still alive and `/proc/<pid>/` is accessible.

## Self-Detection

HookMon's own agent loads eBPF programs at startup. The agent detects its own BPF loads and reports them. This is expected and should be the first entry in any allowlist. It also serves as a continuous self-test: if the agent stops detecting its own programs, something is wrong.

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
1. `exec_injection` catches `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, and `LD_DEBUG` being set in the environment of new processes
2. `shm_monitor` detects shared memory segments matching bpftime patterns in `/dev/shm`
3. `dlopen_monitor` catches runtime library loading via `dlopen()`

### Class 3: LD_PRELOAD Injection (Non-eBPF)

**Attack scenario:** Even without eBPF, `LD_PRELOAD` alone enables function interposition — replacing `malloc`, `SSL_read`, `open`, or any dynamically-linked function with attacker-controlled code. Used legitimately for debugging and instrumentation, but also a potent attack vector.

**HookMon approach:** The `exec_injection` sensor captures every process exec that has `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, or `LD_DEBUG` set, along with the library path, its SHA256 hash, and the target binary being executed.

### Class 4: Linker Configuration Tampering

**Attack scenario:** An attacker modifies `/etc/ld.so.preload`, `/etc/ld.so.conf`, or files in `/etc/ld.so.conf.d/` to persistently inject libraries into every process started on the host. Unlike environment-based `LD_PRELOAD` (which affects only child processes), modifying `/etc/ld.so.preload` affects *all* dynamically-linked programs system-wide and survives reboots.

**Detection gap:** Standard file integrity monitoring (AIDE, OSSEC) can detect changes but doesn't understand the *significance* of these specific files in the context of code injection. Alert fatigue from noisy FIM rules means these changes may be overlooked.

**HookMon approach:** The `linker_config` sensor uses fanotify to watch `/etc/ld.so.preload`, `/etc/ld.so.conf`, and `/etc/ld.so.conf.d/` for any write, create, delete, or rename operations. Every modification produces an event with the file path, operation type, and before/after content hashes. These events are always classified as CRITICAL.

### Class 5: Ptrace Code Injection

**Attack scenario:** An attacker uses `ptrace()` to attach to a running process and inject code via `PTRACE_POKETEXT` or `PTRACE_POKEDATA`. This allows modifying executable code in a target process's memory without any library or file on disk. It's a classic technique for process hollowing, debugger-based injection, and anti-forensics.

**Detection gap:** While some EDR tools monitor ptrace, they often only flag `PTRACE_ATTACH` and miss the more dangerous `PTRACE_POKETEXT`/`PTRACE_POKEDATA` that actually inject code. Standard audit logging may capture the syscall but lacks context about what was injected.

**HookMon approach:** The `ptrace_monitor` sensor hooks `tracepoint/syscalls/sys_enter_ptrace` and filters for dangerous requests: `PTRACE_ATTACH`, `PTRACE_SEIZE`, `PTRACE_POKETEXT`, and `PTRACE_POKEDATA`. Each event includes the ptrace request type, target PID, target process name, and memory address (for POKE operations).

### Class 6: Shared Library Replacement

**Attack scenario:** An attacker replaces a legitimate shared library on disk (e.g., `/usr/lib/libssl.so`) with a trojanized version. Every process that loads the library subsequently executes attacker code. This is stealthy because the library path and name remain unchanged — only the contents differ.

**Detection gap:** Package managers detect tampering at verification time, but not in real-time. Between package verifications, a replaced library operates undetected. Runtime LD_PRELOAD monitoring doesn't help because no environment variable is involved.

**HookMon approach:** The `lib_integrity` sensor uses fanotify to monitor standard library directories (`/usr/lib`, `/usr/lib64`, `/lib`, `/lib64`) for write, rename, or delete operations on `.so` files. Events include the library path, operation type, before/after hashes, and whether the library is in the `ld.so.cache`.

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
| Exec injection from non-root, non-whitelisted library | ALERT | Possible injection attack |
| Ptrace injection detected | ALERT | Process memory manipulation |
| Shared library modified on disk | ALERT | Possible library replacement attack |
| bpftime-pattern shared memory from unknown process | CRITICAL | Likely active userspace eBPF attack |
| Linker configuration modified | CRITICAL | System-wide injection vector changed |
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

## Test Scenarios

The e2e test suite (`test/e2e/`) exercises the full detection pipeline: sensors fire, events are enriched, and policy evaluation produces the correct action. All tests require root (for eBPF), a built agent binary, and run on Linux.

### BPF Load Detection Tests

These tests use canary eBPF programs (`test/canary/`) to trigger the `bpf_syscall` sensor:

- **TestDetectUnknownBPFLoad** — Loads `hello_bpf.o` and verifies a `BPF_LOAD` event fires with the correct `ProgName`, a non-empty `ProgHash`, and severity `WARN` (no allowlist match).
- **TestDetectSecondApp** — Loads both `hello_bpf.o` and `net_monitor.o`, confirming different programs produce different `ProgHash` values.
- **TestVersionChangeNewHash** — Loads `hello_bpf.o` v1 and v2, confirming revised bytecode (same function, different code) produces a different hash. This validates that allowlist entries pinned to a specific `ProgHash` will correctly reject modified versions.
- **TestWhitelistByProgHash** — Captures `hello_bpf`'s hash, builds an ALLOW entry, verifies it matches. Then loads `hello_bpf_v2` against the same allowlist and confirms it gets ALERT (hash mismatch).
- **TestBlacklistByProgHash** — Creates a DENY entry for `net_monitor`'s hash and verifies the policy engine returns DENY.
- **TestWhitelistByExeHash** — Allowlists the loader binary itself (by `ExeHash`), trusting *all* programs loaded by that binary regardless of which BPF program it loads.

### bpftime-go Attack Simulation

These tests simulate the full attack chain of a userspace eBPF attack using `bpftime_sim` (`test/canary/bpftime_sim.c`):

**Attack chain reproduced:**
1. `bpftime_sim` calls `shm_open("/bpftime_agent_shm")` — this is how bpftime establishes a shared memory communication channel between its agent and the hooked target process.
2. `bpftime_sim` forks and execs `/bin/true` with `LD_PRELOAD=libfake_hook.so` — this is how bpftime injects its runtime into target processes.

**Expected detections:**
- `SHM_CREATE` event with `Pattern="bpftime"` at severity `CRITICAL` — the shm_monitor uprobe on `shm_open()` fires and classifies the segment name.
- `EXEC_INJECTION` event with `LibraryPath` containing `fake_hook` at severity `ALERT` — the exec_injection tracepoint captures the environment variable.

**Why SHM_CREATE is CRITICAL:** Shared memory with bpftime naming is the strongest signal of a userspace eBPF attack. Unlike LD_PRELOAD (which has legitimate uses), bpftime-pattern shared memory has no legitimate purpose outside of the bpftime runtime itself.

**Tests:**
- **TestDetectBpftimeExploit** — Runs the full simulation, waits for both events, asserts correct severity for each. Logs the complete event details including hashes and process context.
- **TestDenyBpftimeByPolicy** — Captures a bpftime SHM event, builds a DENY entry matching `EventTypes=[SHM_CREATE]` with `LibraryPath="bpftime"` (matched against the SHM name), verifies the policy engine returns DENY. Also confirms the same entry does *not* match a non-bpftime SHM event (e.g., PostgreSQL shared memory).

### Running the Tests

**Build canaries (on Linux test host):**
```bash
cd ~/hookmon/test/canary
make all
cp load_canary hello_bpf.o net_monitor.o hello_bpf_v2.o /tmp/
cp bpftime_sim libfake_hook.so /tmp/
```

**Build the agent:**
```bash
cd ~/hookmon
go build -o /tmp/hookmon-agent ./cmd/hookmon-agent/
```

**Run all e2e tests:**
```bash
sudo -E go test -v -timeout 120s ./test/e2e/
```

**Run with Grafana observability (Loki + Prometheus):**
```bash
sudo -E env PATH=$PATH \
  HOOKMON_LOKI_URL=http://raspberrypi:3100 \
  HOOKMON_PROMETHEUS_PORT=2112 \
  go test -v -timeout 120s ./test/e2e/
```

**Run only bpftime tests:**
```bash
sudo -E env PATH=$PATH \
  HOOKMON_BPFTIME_SIM=/tmp/bpftime_sim \
  HOOKMON_FAKE_HOOK_LIB=/tmp/libfake_hook.so \
  go test -v -run TestDetectBpftime -timeout 120s ./test/e2e/
```

**Environment variables:**
| Variable | Default | Purpose |
|----------|---------|---------|
| `HOOKMON_AGENT_BIN` | `/tmp/hookmon-agent` | Path to agent binary |
| `HOOKMON_LOADER_BIN` | `/tmp/load-canary` | Path to BPF canary loader |
| `HOOKMON_CANARY_DIR` | `/tmp` | Directory containing `.o` canary files |
| `HOOKMON_BPFTIME_SIM` | `/tmp/bpftime_sim` | Path to bpftime simulator |
| `HOOKMON_FAKE_HOOK_LIB` | `/tmp/libfake_hook.so` | Path to fake LD_PRELOAD library |
| `HOOKMON_LOKI_URL` | (disabled) | Loki push URL for test event logging |
| `HOOKMON_PROMETHEUS_PORT` | (disabled) | Prometheus metrics port |

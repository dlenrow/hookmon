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

### Class 7: RPATH/RUNPATH Abuse

**Attack scenario:** An attacker modifies an ELF binary's dynamic section to include a malicious RPATH or RUNPATH entry (e.g., `/tmp/evil` or a relative path like `lib/`). When the binary executes, the dynamic linker searches these directories for shared libraries *before* the system defaults. The attacker places a trojanized library at that path, and it gets loaded silently — no `LD_PRELOAD`, no config file modification, no environment variable.

**Detection gap:** This is a supply-chain and persistence vector that's invisible to all other HookMon sensors. The injection is baked into the binary's ELF headers. There's no runtime event to hook because the linker resolves paths at load time using the binary's own metadata. Tools like `readelf -d` can show RPATH/RUNPATH but aren't monitored in real-time.

**HookMon approach:** The `elf_rpath` sensor is an audit-type sensor that runs after event enrichment on every exec event. It opens the binary using Go's `debug/elf` package and reads `DT_RPATH` and `DT_RUNPATH` entries. Each path is classified by risk:

| Condition | Risk |
|-----------|------|
| Relative path (no `/`, not `$ORIGIN`) | CRITICAL |
| Writable directories: `/tmp/*`, `/var/tmp/*`, `/dev/shm/*`, `/home/*` | CRITICAL |
| `$ORIGIN` in SUID/SGID binary | CRITICAL |
| Empty entry (double `::` separator) | HIGH |
| Non-existent directory | HIGH |
| World-writable directory | HIGH |
| `$ORIGIN` in non-SUID binary | LOW |
| Standard system paths (`/usr/lib`, `/lib`, etc.) | NONE |
| Non-standard but root-owned, not writable | MEDIUM |

DT_RPATH (deprecated, takes precedence over `LD_LIBRARY_PATH`) is bumped one severity level vs DT_RUNPATH. Only binaries with MEDIUM risk or above produce an `ELF_RPATH` event. Results are cached by (path, inode, mtime) to avoid re-analyzing the same binary.

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
| ELF RPATH with CRITICAL risk entries | CRITICAL | Attacker-controlled library path in binary |
| ELF RPATH with HIGH risk entries | ALERT | Suspicious library search path |
| Any unmatched event from root | CRITICAL | Privileged unauthorized activity |

### Operational Workflow

**Phase 1: Learning (Days 1-30)**
Deploy sensor buses in console mode. Every event is logged. Operators build familiarity with what "normal" looks like on their infrastructure. The system auto-creates candidate allowlist entries for review.

**Phase 2: Monitoring (Steady State)**
The allowlist is active. Known-good events log at INFO. Anything new generates alerts. No blocking — visibility only. This is the primary operating mode for most deployments.

**Phase 3: Enforcement (Optional)**
The sensor bus can block unauthorized BPF loads or LD_PRELOAD usage at the kernel level. This requires high confidence in the allowlist and careful rollout, since a false positive can break legitimate tooling.

## What HookMon Monitors the Monitors

A critical operational question that no existing tool answers:

> "The Falco eBPF program that's loaded on prod-web-03 — is it the *authorized version*? Was it loaded by the *authorized installer*? Has it been *replaced* since deployment?"

HookMon captures program bytecode hashes. If an attacker replaces a legitimate eBPF program with a modified one (same name, different code), HookMon detects the hash mismatch. This provides integrity monitoring for the security tools themselves.

## Event Enrichment

Raw eBPF events contain only kernel-space information (PID, UID, comm). The sensor bus enriches each event from `/proc`:

- **cmdline:** full command line of the process
- **exe_path:** resolved symlink from `/proc/<pid>/exe`
- **exe_hash:** SHA256 of the executable binary
- **cgroup_path:** cgroup v2 path (enables container attribution)
- **container_id:** extracted from cgroup path
- **ppid:** parent PID for process tree analysis
- **prog_hash:** for BPF events, SHA256 of the program bytecode itself

This enrichment happens in userspace immediately after the event is received, while the process is still alive and `/proc/<pid>/` is accessible.

## Self-Detection

HookMon's own sensor bus loads eBPF programs at startup. The sensor bus detects its own BPF loads and reports them. This is expected and should be the first entry in any allowlist. It also serves as a continuous self-test: if the sensor bus stops detecting its own programs, something is wrong.

## Test Scenarios

The e2e test suite (`test/e2e/`) exercises the full detection pipeline: sensors fire, events are enriched, and policy evaluation produces the correct action. All tests require root (for eBPF), a built sensor bus binary, and run on Linux.

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

**Build the sensor bus:**
```bash
cd ~/hookmon
go build -o /tmp/hookmon-bus ./cmd/hookmon-bus/
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
| `HOOKMON_AGENT_BIN` | `/tmp/hookmon-bus` | Path to sensor bus binary |
| `HOOKMON_LOADER_BIN` | `/tmp/load-canary` | Path to BPF canary loader |
| `HOOKMON_CANARY_DIR` | `/tmp` | Directory containing `.o` canary files |
| `HOOKMON_BPFTIME_SIM` | `/tmp/bpftime_sim` | Path to bpftime simulator |
| `HOOKMON_FAKE_HOOK_LIB` | `/tmp/libfake_hook.so` | Path to fake LD_PRELOAD library |
| `HOOKMON_LOKI_URL` | (disabled) | Loki push URL for test event logging |
| `HOOKMON_PROMETHEUS_PORT` | (disabled) | Prometheus metrics port |

## Deterministic Low-Frequency Events

### Probabilistic vs. Deterministic Detection

Traditional security monitoring operates in probabilistic mode. Network IDS, UEBA, and EDR telemetry produce millions of events per second, and detection relies on statistical models, heuristics, anomaly scores, and machine learning classifiers to separate signal from noise. Every alert carries a confidence score. Every investigation starts with "is this real?" False positive rates dominate operational cost.

HookMon operates in a fundamentally different domain. The events it monitors — BPF program loading, library injection, linker configuration changes, ptrace code injection, shared library replacement — are **deterministic binary facts**. A BPF program was either loaded or it wasn't. An `LD_PRELOAD` variable was either present in the execve environment or it wasn't. `/etc/ld.so.preload` was either modified or it wasn't. There is no probability involved in detection. The event either matches the allowlist or it doesn't.

### Natural Sparsity

This domain is naturally sparse. On a typical production server:

- BPF programs load at boot when the observability stack starts (Cilium, Falco, Datadog) and then not again until the next tool update — weeks or months later.
- Shared libraries change only during OS package updates.
- `/etc/ld.so.preload` essentially never exists on a healthy system; its mere presence is notable.
- Ptrace activity outside of known debuggers (gdb, strace, IDE remote debug) is near-zero.
- Linker configuration files change only during package manager operations.
- ELF binaries with non-standard RPATH/RUNPATH entries are rare and change only on software deployment.

The base rate of legitimate *new* events — events not already in the allowlist — approaches zero in steady-state operation. This is not a property HookMon engineers; it is a property of the domain itself.

### Allowlist Self-Population

The allowlist does not need to be manually constructed from documentation or vendor lists. The learning mode deployment model observes the actual fleet:

1. Deploy sensor buses across the infrastructure in learning mode.
2. Over 7-30 days, every BPF load, every LD_PRELOAD exec, every library change is captured with full context (binary hash, program hash, process lineage, host identity).
3. The server auto-creates candidate allowlist entries for each unique event signature.
4. Security operations reviews and approves the candidates, adding descriptions ("Cilium CNI loads BPF programs at boot", "Datadog agent uses LD_PRELOAD for instrumentation").

By the time learning mode ends and monitoring mode activates, the complete legitimate event universe for that infrastructure is captured in the allowlist. The allowlist is not a theoretical policy — it is an empirical record of observed reality.

### Operational Consequences

Every unallowlisted event in monitoring mode is a **concrete fact**, not a statistical suspicion. The disposition question changes fundamentally:

- Traditional SIEM: "Is this alert real? What's the confidence? Should we investigate or is this another false positive?" — a **threat hunting** workflow.
- HookMon: "A new BPF program was loaded by binary X with hash Y on host Z. Do we approve this change?" — a **change management** workflow.

The investigation is not "determine whether something happened." The investigation is "determine whether this known-to-have-happened thing is authorized." This is a categorically simpler operational problem.

### No Tuning Required

There are no thresholds to adjust. No sensitivity dials. No model parameters to retrain. No baseline windows to recalibrate. No feature engineering. The allowlist is the complete policy. An event matches it or it doesn't.

Alert fatigue is structurally impossible. Every alert describes a specific new event — a specific binary loaded a specific BPF program, or a specific process was exec'd with a specific LD_PRELOAD library — that requires a specific human decision: approve it or investigate it. There is no class of "probably fine, auto-close" alerts because there is no probabilistic classification producing them.

## Sensor Health and Anti-Tampering

### Why Self-Integrity Matters

A sophisticated attacker who discovers HookMon running on a target host will attempt to disable it before proceeding with their actual objective. The most dangerous evasion scenario is **silent disabling** — the sensor bus process is killed or its eBPF programs are unloaded, but no alert fires because the component responsible for generating alerts is the one that was disabled. A monitoring tool that can be silently neutralized provides false assurance, which is worse than no monitoring at all.

### Sensor Heartbeats

Each eBPF sensor writes a kernel timestamp to a dedicated BPF map entry every 10 seconds. This heartbeat is independent of event traffic — a sensor that has detected zero events still heartbeats normally. The sensor bus userspace process reads these maps and maintains a liveness registry for every sensor. If a sensor's last heartbeat is older than 35 seconds, the sensor bus marks it dead and emits a sensor health event.

The 35-second threshold (3.5x the heartbeat interval) accommodates scheduling jitter under load while catching genuine failures within one minute.

### Server-Side Out-of-Band Polling

The sensor bus cannot be trusted to accurately report its own health if it has been compromised. An attacker who controls the sensor bus process can forge heartbeat reports and suppress health alerts. Server-side polling addresses this by inverting the trust model.

The collector (server) reaches out to the sensor bus — the sensor bus does not phone home its health. The server polls a health endpoint on each sensor bus at a configurable interval (default: 30 seconds). This is out-of-band relative to the event stream. If the sensor bus process has been killed, the poll endpoint becomes unreachable, which is itself the alert signal. The server does not need to trust any self-report; it observes reachability directly.

### Tamper Signal Hierarchy

The combination of heartbeats, polling, and event rate analysis produces a layered tamper detection model:

| Signal | Interpretation | Severity |
|--------|---------------|----------|
| Poll endpoint unreachable | Sensor bus process killed or host network severed | CRITICAL |
| Poll succeeds, but specific sensors report dead heartbeats | Targeted sensor unload (e.g., `bpftool prog detach`) | ALERT |
| Poll succeeds, all sensors alive, but event rate zero for 24h | Events being suppressed in the pipeline | WARN |

The third signal — sensors alive but no events — requires combining heartbeat liveness with event rate. A host that genuinely has zero events for 24 hours is unusual but possible (a dormant standby, for example). Context from the host inventory (role, expected activity level) disambiguates. The key point is that heartbeats alone confirm the sensor is running; they cannot confirm events are flowing end-to-end.

### Limitations of Polling

Server-side polling cannot catch attacks that happen between poll intervals where the attacking process has already exited. If an attacker loads a BPF program, kills the sensor bus, and the server's next poll is 25 seconds away, the attack completes in the blind spot. Heartbeats confirm sensor liveness at a point in time; they cannot reconstruct missed events.

However, for **persistent and state-based attacks** — kernel BPF programs that remain loaded, linker configuration changes that persist on disk, replaced shared libraries — the damage outlasts the blind spot. The combination of heartbeat monitoring and independent out-of-band verification can detect these after the fact.

### SSH-Based Independent Verification

For maximum assurance, the collector can optionally SSH to monitored hosts and run verification commands that completely bypass the sensor bus:

```bash
bpftool prog list | grep hookmon
```

This independently verifies the kernel BPF program inventory — confirming that HookMon's own eBPF programs are still loaded and that no unexpected programs have appeared. The verification uses a separate authentication path (SSH keys managed by the collector), a separate binary (`bpftool`, part of the kernel toolchain), and reads directly from the kernel's BPF subsystem. An attacker would need to compromise both the sensor bus and the SSH-based verification path to evade detection.

Similar independent checks can verify `/etc/ld.so.preload` contents, `/dev/shm` segment inventory, and loaded shared library hashes — all without relying on any HookMon component running on the target host.

# HookMon Theory of Operations

## Attack Classes

HookMon watches classes of instrumentation abuse that traditional security tooling does not track well. [threat-model.md](threat-model.md) lists every way code enters a Linux process, including the ones HookMon does not cover.

### Class 1: Kernel eBPF Abuse

**Attack scenario:** An attacker with brief root access (or `CAP_BPF`) loads an eBPF program that hooks syscalls, network functions, or file operations. The program runs in kernel space, survives the attacker's session ending, and does not show in `ps`, `lsof` or most forensic tools.

**Detection gap:** Every eBPF program is loaded through the `bpf()` syscall. Traditional tools don't monitor it. `bpftool prog list` shows loaded programs but not *who* loaded them, *when*, or *whether they're authorized*.

**HookMon approach:** The `bpf_syscall` sensor attaches to `tracepoint/syscalls/sys_enter_bpf` and `sys_exit_bpf`. It reports:
- every `BPF_PROG_LOAD` as BPF_LOAD, with process context and the kernel's program tag, read from the kernel when the load returns;
- every `BPF_PROG_ATTACH`, `BPF_LINK_CREATE` and `BPF_RAW_TRACEPOINT_OPEN` as BPF_ATTACH;
- every loaded program as BPF_INVENTORY, at startup and every 5 minutes, followed by a host summary. This catches programs loaded before HookMon started.

`BPF_MAP_CREATE` is not reported: a map runs no code. Attaches that don't go through `bpf()` (the perf `SET_BPF` ioctl, netlink XDP and tc, `SO_ATTACH_BPF`) are not seen, though the program's load is.

### Class 2: Userspace eBPF (bpftime)

**Attack scenario:** An attacker *without root* uses a userspace eBPF runtime (bpftime, bpftime-go) to hook any dynamically linked function in any process they can launch. The runtime works via `LD_PRELOAD` and shared memory. The kernel BPF subsystem is not involved.

**Detection gap:**
- No `bpf()` syscall, so kernel BPF monitoring sees nothing
- No audit log entry
- No `bpftool` visibility
- In `/proc`, only the `LD_PRELOAD` value and the runtime library in the process's memory map
- The instrumentation lives in userspace memory

**HookMon approach:** Three sensors:
1. `exec_injection` catches `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` and `LD_DEBUG` in the environment of new processes.
2. `shm_monitor` catches `/dev/shm` segments created with bpftime's names. It matches bpftime's default name (`bpftime_maps_shm`), any name containing `bpftime`, and a name set through `BPFTIME_GLOBAL_SHM_NAME` in the creator's environment.
3. `dlopen_monitor` catches runtime library loading through glibc's `dlopen()`.

These detections were tested with a simulator, not the real bpftime runtime ([claims.md](claims.md)).

### Class 3: LD_PRELOAD Injection (Non-eBPF)

**Attack scenario:** Even without eBPF, `LD_PRELOAD` alone enables function interposition: replacing `malloc`, `SSL_read`, `open`, or any dynamically linked function with attacker-controlled code. It has legitimate uses in debugging and instrumentation, and it is also a potent attack vector.

**HookMon approach:** The `exec_injection` sensor attaches to `tracepoint/sched/sched_process_exec`, which fires after every successful `execve` and `execveat`. It reads the new process's environment from the kernel's copy (`env_start` to `env_end`), the same strings `ld.so` will read. Each `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` or `LD_DEBUG` variable gives one event with the variable, its value and the target binary. For an absolute `LD_PRELOAD` or `LD_AUDIT` path, the event also carries the library's `sha256:<hex>` hash.

The scan reads up to 8192 chunks of 256 bytes on kernels with `bpf_loop` (5.17 and newer), or 512 on older kernels. If it stops before the end of the environment, it sends one more event flagged `scan_truncated`, so a variable past the limit is never missed silently. A value longer than 255 bytes is flagged `value_truncated`.

### Class 4: Linker Configuration Tampering

**Attack scenario:** An attacker modifies `/etc/ld.so.preload`, `/etc/ld.so.conf`, a file in `/etc/ld.so.conf.d/`, or `/etc/ld.so.cache` to inject libraries into every process started on the host. Unlike environment-based `LD_PRELOAD`, which affects only child processes, `/etc/ld.so.preload` affects *all* dynamically linked programs system-wide and survives reboots.

**Detection gap:** File integrity monitoring (AIDE, OSSEC) can detect changes but treats these files like any other. Noisy FIM rules can bury them.

**HookMon approach:** The `linker_config` sensor marks `/etc` and `/etc/ld.so.conf.d` with fanotify directory-entry events (`FAN_REPORT_DFID_NAME`, Linux 5.9+). It catches writes, creates, deletes and renames over the files, including `sed -i`, `mv`, `cp` and `ln -sf`. At startup it hashes each watched file, so every event carries the old hash and the new one. A change is CRITICAL, or INFO when a package manager is in the writer's process ancestry.

### Class 5: Ptrace Code Injection

**Attack scenario:** An attacker uses `ptrace()` to attach to a running process and inject code: writing memory with `PTRACE_POKETEXT` or `PTRACE_POKEDATA`, or redirecting execution by writing registers. No library or file on disk is needed.

**Detection gap:** Some EDR tools only flag `PTRACE_ATTACH` and miss the writes that inject the code.

**HookMon approach:** The `ptrace_monitor` sensor hooks `tracepoint/syscalls/sys_enter_ptrace` and reports `PTRACE_ATTACH`, `PTRACE_SEIZE`, `PTRACE_POKETEXT`, `PTRACE_POKEDATA`, `PTRACE_POKEUSER`, `PTRACE_SETREGS` and `PTRACE_SETREGSET`. Each event includes the request, the target PID, the target's comm, and the address for POKE requests. The target comm is resolved in the caller's PID namespace. It is empty when the target is in a namespace nested below the caller's.

### Class 6: Shared Library Replacement

**Attack scenario:** An attacker replaces a shared library on disk (for example `/usr/lib/libssl.so`) with a trojanized version. Every process that loads the library afterwards runs attacker code. The path and name stay the same; only the contents differ.

**Detection gap:** Package managers detect tampering when someone runs a verification, not in real time.

**HookMon approach:** The `lib_integrity` sensor marks every directory under `/usr/lib`, `/usr/lib64`, `/lib` and `/lib64` with fanotify directory-entry events. It reports writes, creates, deletes and renames of `*.so` and `*.so.*` files, with the old and new hashes and whether `ld.so.cache` lists the library. At startup it hashes every shared object in the background; a file changed before its turn has no old hash. A change is ALERT, or INFO when a package manager is in the writer's process ancestry.

### Class 7: RPATH/RUNPATH Abuse

**Attack scenario:** An attacker builds or modifies an ELF binary so its RPATH or RUNPATH names a directory they control (for example `/tmp/evil`, or a relative path like `lib/`). When the binary runs, the dynamic linker searches those directories for shared libraries before the system defaults. The attacker places a trojanized library there, and it loads with no `LD_PRELOAD`, no config file change and no environment variable.

**Detection gap:** The library search path is part of the binary. No other HookMon sensor sees it. `readelf -d` shows RPATH and RUNPATH, but nothing runs it on every exec.

**HookMon approach:** The `elf_rpath` sensor attaches to `tracepoint/sched/sched_process_exec`. For each successful exec (`execve` and `execveat`) it sends the filename and the kernel's identity of the loaded binary (device, inode, mtime) to Go. Go opens the binary with `debug/elf`, reads `DT_RPATH` and `DT_RUNPATH`, and ranks each entry. Results are cached in an LRU keyed by the binary's identity, including binaries with no RPATH. A binary version whose highest risk is MEDIUM or above produces one ELF_RPATH event, on its first exec.

`$ORIGIN`, `$LIB` and `$PLATFORM` (also written `${NAME}`) are expanded first, as ld.so expands them.

| Condition | Risk |
|-----------|------|
| Relative path; `/tmp`, `/var/tmp`, `/dev/shm`, `/home` and anything under them; `$ORIGIN` in a SUID binary; `$ORIGIN` resolving into one of those directories | CRITICAL |
| Empty entry (`::`); non-existent directory; world-writable directory; directory below a world-writable parent with no sticky bit | HIGH |
| Non-standard existing directory owned by a non-root user or writable by its group, or below a parent a non-root user owns or its group can write (a sticky parent counts only through its owner) | MEDIUM |
| Non-standard existing directory that only root can write, itself and every parent; `$ORIGIN` in a non-SUID binary resolving to such a directory | LOW (no event) |
| Standard system library paths (`/usr/lib`, `/lib`, etc.) | NONE |

DT_RPATH (deprecated; searched before `LD_LIBRARY_PATH`) is bumped one level above DT_RUNPATH, except that it never lifts LOW to MEDIUM.

Only the executed binary is analyzed, not the libraries it loads. A binary is not analyzed if the process has already exited and its path can't be resolved: relative paths outside the cwd, `/dev/fd/N` (fexecve, memfd), scripts (the interpreter is what loads), other mount namespaces, and names of 255 bytes or more.

`hookmon-bus --scan-rpath <dir>` runs the same analysis over a directory and prints JSON.

## The Allowlist Model

### Why Allowlists Work Here

eBPF program loading and LD_PRELOAD injection are **rare events** in production. A typical server sees:

- A handful of BPF program loads at boot (from the observability stack: Cilium, Falco, Datadog)
- Few or no new loads for weeks or months
- Occasional loads during deployments or updates

The base rate of *legitimate new installations* is low, so an event that doesn't match a known, approved pattern is worth a look.

Compare this with syscall monitoring (millions of events per second) or network monitoring. HookMon works in a domain where event volume is low and each event matters.

### Severity

**On the bus** (what the console, Loki and Prometheus show), by sensor:

| Event | Severity |
|-------|----------|
| BPF_LOAD, BPF_ATTACH | WARN |
| BPF_INVENTORY | INFO |
| EXEC_INJECTION (including `scan_truncated`) | ALERT |
| SHM_CREATE | CRITICAL for bpftime names, ALERT for other names containing `bpf`, INFO otherwise |
| DLOPEN | WARN |
| LINKER_CONFIG | CRITICAL; INFO when a package manager is in the writer's ancestry |
| PTRACE_INJECT | ALERT |
| LIB_INTEGRITY | ALERT; INFO when a package manager is in the writer's ancestry |
| ELF_RPATH | CRITICAL, ALERT or WARN for a highest risk of CRITICAL, HIGH or MEDIUM |

**On the server**, the policy engine keeps the bus's rating, because the bus has context the server lacks (a package manager in the writer's ancestry, the segment name, who can write an RPATH directory), and adds what the server knows: the allowlist, and two escalations. The first row that applies wins:

| Condition | Severity | Meaning |
|-----------|----------|---------|
| Host offline (AGENT_OFFLINE from the watchdog) | CRITICAL | Bus stopped or killed |
| AGENT_OFFLINE or AGENT_RECOVERED on a bus's event stream | ALERT | Lifecycle report |
| BPF_INVENTORY | INFO | Census; the policy result says whether each program is on the allowlist |
| Matches an allowlist entry with ALLOW action | INFO | Known good, log for audit |
| The bus rated it INFO (package-manager write, ordinary /dev/shm segment) | INFO | Expected change |
| bpftime-pattern shared memory | CRITICAL | Likely active userspace eBPF attack |
| Linker configuration modified (not by a package manager) | CRITICAL | System-wide injection vector changed |
| ELF RPATH, by highest risk (CRITICAL, HIGH, MEDIUM), whatever the UID | CRITICAL, ALERT, WARN | Library search path someone else can write |
| Any other unmatched event from root | CRITICAL | Privileged unauthorized activity |
| Exec injection | ALERT | Possible injection attack |
| Ptrace injection | ALERT | Process memory manipulation |
| Shared library modified on disk (not by a package manager) | ALERT | Possible library replacement attack |
| Shared memory with a BPF-related name | ALERT | Possible userspace BPF runtime |
| The bus could not hash the binary (BPF load or attach, dlopen) | ALERT | Unknown program, investigate |
| BPF load or attach, or dlopen, not on the allowlist | WARN | Unusual but possibly legitimate |

The root escalation never touches an event the bus rated INFO or an ELF_RPATH event, so a package-manager write by root stays INFO and a MEDIUM RPATH run by root stays WARN. An event that matches an ALERT or DENY entry (such as a rejected learning-mode candidate) is rated like an unmatched one. The same table, numbered, is in `CLAUDE.md`.

### Operational Workflow

**Phase 1: Learning**
Turn on learning mode for the fleet or one host, with an end time: `hookmon-cli learning start --fleet --for 7d`. Until then, each unmatched unique event becomes a PENDING allowlist entry, with its count, first and last time seen, and the hosts that saw it. Operators list them (`hookmon-cli policies pending`) and approve or reject each one for the fleet or for one host. Learning mode does not change severity or hold back alerts; it only records. [architecture.md](architecture.md#policy-and-learning-mode) gives the key and the API.

**Phase 2: Monitoring (steady state)**
The allowlist is active. Known-good events log at INFO. Anything new raises an alert. Nothing is blocked. A change through the API applies to the next event; SIGHUP rereads the allowlist from the database.

**Phase 3: Enforcement (does not exist)**
The idea was that the bus could block unauthorized BPF loads or LD_PRELOAD use. No code for this exists, and the fix plan does not add it. HookMon is read-only.

## How HookMon Monitors the Monitors

An operational question few tools answer:

> "The Falco eBPF program that's loaded on prod-web-03: is it the *authorized version*? Was it loaded by the *authorized installer*? Has it been *replaced* since deployment?"

HookMon records the kernel's program tag for every BPF load and every program in the inventory. The kernel computes the tag over the program's instructions with map references zeroed, so the same program has the same tag on every load on the same kernel, and a modified program with the same name gets a different tag. Two programs with identical instructions and different program types share a tag, so an allowlist entry should also pin the program type. The tag is the first 8 bytes of a SHA-1; it is not a SHA-256.

## Event Enrichment

Raw eBPF events carry kernel-side information: PID, PPID, UID, GID and comm. The bus adds, from `/proc`:

- **cmdline:** the full command line
- **exe_path:** `/proc/<pid>/exe`, as the process sees it
- **exe_hash:** `sha256:<hex>` of the executable, cached by (device, inode, mtime, ctime). A container process is hashed through `/proc/<pid>/root`, so the hash is of the container's binary.
- **cgroup_path:** the cgroup path
- **container_id:** from the cgroup path, for Docker, cri-containerd, CRI-O and libpod, on cgroup v1 and v2

Enrichment runs as soon as the bus receives the event. If the process has already exited, these fields are empty. File-sensor events whose writer has exited get UID 4294967295 ("unknown"). The server stores that value as is: PID, PPID, UID and GID are BIGINT columns (migration `005_uint32_bigint.sql`).

## Self-Filtering

The bus loads its own eBPF programs at startup and, every 10 seconds, runs probe processes to check its hooks. It drops every event whose PID or parent PID is its own, so neither shows up as a detection. HookMon's own programs do appear in every BPF_INVENTORY scan, because inventory events carry no PID. An allowlist should expect them there.

## Test Scenarios

The e2e suite (`test/e2e/`, build tag `e2e`) runs real attacks against a real bus. It needs Linux, root, the eBPF toolchain, and a bus binary built for the host. Every test runs the bus with `--console`, so it covers the sensors and enrichment, not the server path (fix plan step 7h). The canary programs are in `test/canary/`.

The [claims ledger](claims.md) records which tests were run, on which host, and the results.

### Tests by Sensor

| Sensor | Tests |
|--------|-------|
| `bpf_syscall` | `TestSensor1_BPFSyscall_DetectLoad`, `TestSensor1_BPFSyscall_DifferentHashPerProgram`, `TestSensor1_BPFSyscall_VersionChangeNewHash`, `TestSensor1_BPFSyscall_SameProgramSameTag`, `TestSensor1_BPFSyscall_ModifiedProgramNewTag`, `TestSensor1_BPFInventory_PreexistingProgram`, `TestSensor1_BPFSyscall_LinkCreateAttach`, `TestSensor1_BPFSyscall_RawTracepointAttach` |
| `exec_injection` | `TestSensor2_ExecInjection_LDPreload`, `TestExecInj_PreloadAt100th`, `TestExecInj_Execveat`, `TestExecInj_ScanTruncated` |
| `shm_monitor` | `TestSensor3_SHMMonitor_BpftimePattern`, `TestSensor3_SHMMonitor_BpftimeDefaultName`, `TestSensor3_SHMMonitor_EnvRenamedIsBpftime`, `TestSensor3_SHMMonitor_BpfRelatedIsAlert`, `TestSensor3_SHMMonitor_GenericIsInfo`, `TestSensor3_SHMMonitor_Openat2` |
| `dlopen_monitor` | `TestSensor4_DlopenMonitor_LoadLibrary`, `TestDlopenW_ContainerLibc`, `TestDlopenW_Dedupe` |
| `linker_config` | `TestSensor5_LinkerConfig_WriteConfD`, `TestLinkerConfig_PreloadOperations` |
| `ptrace_monitor` | `TestSensor6_PtraceMonitor_Attach`, `TestSensor6_PtraceMonitor_RegisterWrites`, `TestSensor6_PtraceMonitor_AttachTargetComm`, `TestSensor6_PtraceMonitor_TargetCommInPidNamespace` |
| `lib_integrity` | `TestSensor7_LibIntegrity_WriteToUsrLib`, `TestLibIntegrity_SoOperations`, `TestLibIntegrity_AptReinstallIsInfo` |
| `elf_rpath` | `TestSensor8_ElfRpath_SuspiciousPath`, `TestSensor8_ElfRpath_OriginTmpCleanEnv`, `TestRpathW_EmitOncePerBinaryVersion` |
| Health | `TestHeartbeat_IdleAllAlive`, `TestHeartbeat_LinkDetach`, `TestHeartbeat_KillBusCollectorUnreachable`, `TestHeartbeat_DlopenProbeMissing` |
| Combined | `TestCombined_BpftimeAttackChain` |
| Allowlist matching | `TestPolicy_AllowByProgHash`, `TestPolicy_DenyByProgHash` |

The two `TestPolicy_` tests capture a real event and run it through `pkg/allowlist`, the matcher the server uses. Learning mode, approval and reload are tested against PostgreSQL in `test/integration/policy_test.go`, with the real server and bus transport.

No e2e test sends `PTRACE_SEIZE`, `PTRACE_POKETEXT` or `PTRACE_POKEDATA`, or sets `LD_LIBRARY_PATH`. `LD_AUDIT` and `LD_DEBUG` are covered by the root-only unit test `TestExecInjScanBoundary` in `agent/sensors`.

### bpftime Attack Simulation

`TestCombined_BpftimeAttackChain` runs `bpftime_sim` (`test/canary/bpftime_sim.c`), which reproduces the observable footprint of a bpftime attack:

1. `shm_open("/bpftime_agent_shm")`, which glibc turns into an `openat` of `/dev/shm/bpftime_agent_shm` with `O_CREAT`.
2. A fork and exec of a target with `LD_PRELOAD` set to `libfake_hook.so`.

Expected detections:
- `SHM_CREATE` with `Pattern="bpftime"`, from `shm_monitor`'s `openat` tracepoint.
- `EXEC_INJECTION` with `LibraryPath` containing `fake_hook`, from `exec_injection`.

Shared memory with bpftime's names has no use outside the bpftime runtime, so it is CRITICAL on the bus. The real runtime has not been tested.

### Running the Tests

**Everything:** `make test-e2e` builds the bus, the dlopen helper and the canaries, copies them to `/tmp/hookmon-bus`, `/tmp/hookmon-dlopen-probe` and `/tmp/canary/`, and runs the suite with `sudo`:

```bash
make test-e2e
```

**One test**, after `make test-e2e` has deployed the binaries once:

```bash
sudo env "PATH=$PATH" go test -tags e2e -v -count=1 -timeout 300s \
  -run TestCombined_BpftimeAttackChain ./test/e2e/
```

**With Loki and a status port:**

```bash
sudo env "PATH=$PATH" \
  HOOKMON_LOKI_URL=http://<stack-host>:3100 \
  HOOKMON_STATUS_PORT=2112 \
  go test -tags e2e -v -count=1 -timeout 300s ./test/e2e/
```

**The 10-minute idle health test:**

```bash
sudo env "PATH=$PATH" HOOKMON_E2E_LONG=1 \
  go test -tags e2e -v -count=1 -timeout 900s -run TestHeartbeat_IdleAllAlive ./test/e2e/
```

**Environment variables:**

| Variable | Default | Purpose |
|----------|---------|---------|
| `HOOKMON_BUS_BIN` | `/tmp/hookmon-bus` | Sensor bus binary |
| `HOOKMON_AGENT_BIN` | (unset) | Older name for `HOOKMON_BUS_BIN`, read only if that is unset |
| `HOOKMON_CANARY_BIN` | `/tmp/canary/bin` | Directory of canary executables (`load_canary`, `bpftime_sim`, `libfake_hook.so`, ...) |
| `HOOKMON_CANARY_DIR` | `/tmp/canary` | Directory of canary `.o` files and scripts |
| `HOOKMON_LOKI_URL` | (unset) | Passed to the bus as `--loki-url` |
| `HOOKMON_STATUS_PORT` | (unset; the bus uses 2112) | Passed to the bus as `--status-port` |
| `HOOKMON_E2E_LONG` | (unset) | Set to `1` to run `TestHeartbeat_IdleAllAlive` |
| `HOOKMON_E2E_IDLE_DURATION` | `10m` | Length of the idle test |
| `HOOKMON_COLLECTOR_BIN` | `bin/hookmon-collector`, else built on the fly | Collector for `TestHeartbeat_KillBusCollectorUnreachable` |
| `HOOKMON_E2E_REINSTALL_PKG` | `libmnl0` | Package `TestLibIntegrity_AptReinstallIsInfo` reinstalls |

## Deterministic Low-Frequency Events

### Probabilistic vs. Deterministic Detection

Most security monitoring is probabilistic. Network IDS, UEBA and EDR telemetry produce millions of events per second, and detection relies on statistical models, heuristics, anomaly scores and classifiers to separate signal from noise. Every alert carries a confidence score. Every investigation starts with "is this real?" False positives dominate operational cost.

HookMon works in a different domain. The events it reports (BPF program loading, library injection, linker configuration changes, ptrace code injection, shared library replacement) are **discrete facts**. A BPF program was loaded or it wasn't. An `LD_PRELOAD` variable was in the new process's environment or it wasn't. `/etc/ld.so.preload` was modified or it wasn't. Detection involves no probability. The event matches the allowlist or it doesn't.

Detection is only as complete as the sensors. [threat-model.md](threat-model.md) lists what they miss.

### Natural Sparsity

On a typical production server:

- BPF programs load at boot when the observability stack starts, and then not again until the next tool update.
- Shared libraries change during OS package updates.
- `/etc/ld.so.preload` rarely exists on a healthy system; its presence is notable.
- Ptrace activity outside known debuggers (gdb, strace, IDE remote debug) is near zero.
- Linker configuration files change during package manager operations.
- ELF binaries with non-standard RPATH or RUNPATH entries are rare and change on software deployment.

The base rate of legitimate *new* events, those not already in the allowlist, should approach zero in steady state. This is a property of the domain, not something HookMon engineers. It has not yet been measured on real hosts (fix plan step 8).

### Allowlist Self-Population

The allowlist does not need to be written by hand from documentation or vendor lists. Learning mode observes the fleet:

1. Turn on learning mode for the fleet, or for some hosts, with an end time.
2. For the learning period, every event that matches no entry is recorded by its key: event type, exe hash, subject (BPF program tag and type, library hash or path, file path, or the shared memory pattern), and whether it ran in a container.
3. The server keeps one PENDING allowlist entry per key, with its count, first and last time seen, and the hosts that saw it.
4. Security operations reviews the entries and approves or rejects each one, for the fleet or for one host.

When learning ends and monitoring starts, the allowlist records what the infrastructure actually does. An approved entry allows exactly the tuple that was seen, so a new binary version, a changed library or a new BPF program is new again. Descriptions are generated ("learned: BPF_LOAD by /usr/bin/foo: BPF tag …, prog type 8"); there is no way yet to edit them (step 7e adds policy editing). The allowlist guide (`docs/allowlist-guide.md`) will be written after step 7.

### Operational Consequences

In monitoring mode, every unallowlisted event is a **concrete fact**, not a statistical suspicion. The disposition question changes:

- Traditional SIEM: "Is this alert real? What's the confidence? Should we investigate or is this another false positive?" That is a **threat hunting** workflow.
- HookMon: "A new BPF program was loaded by binary X with tag Y on host Z. Do we approve this change?" That is a **change management** workflow.

The investigation is not "did something happen?" It is "is this thing that happened authorized?" That is a simpler problem.

### Little Tuning

The allowlist is the main policy. An event matches it or it doesn't. There are no anomaly scores or models to retrain.

Every alert describes a specific new event that needs a specific decision: approve it or investigate it. That keeps alert fatigue low, as long as the allowlist covers what the hosts legitimately do. Some sensors are noisier than others: `dlopen_monitor` reports each new (binary, library) pair, at most once an hour, and `shm_monitor` reports every `/dev/shm` creation at INFO. The bus has a few settings (`heartbeat_sensor_interval`, `dead_threshold`), and the alert rules have thresholds.

## Sensor Health and Anti-Tampering

### Why Self-Integrity Matters

An attacker who finds HookMon on a host will try to disable it before going further. The most dangerous case is **silent disabling**: the bus is killed or its eBPF hooks are removed, and no alert fires because the component that would raise it is the one disabled. A monitor that can be silently neutralized gives false assurance.

### Active Probes

A heartbeat written by a timer only proves a program is loaded. It keeps ticking after an attacker detaches the hook. So the bus tests each hook by running it. Every 10 seconds (`heartbeat_sensor_interval`), the bus fires every eBPF hook with a harmless call: its own `bpf()` map reads, an `openat` and `openat2` of `/dev/null`, a `ptrace` that the kernel rejects, one `/bin/true` run, and a `dlopen` through `hookmon-dlopen-probe`. Each hook writes a kernel timestamp to its `hookmon_heartbeat_<sensor>` map before any filtering. The bus then reads the maps. A sensor is alive only if its value moved forward since the last check.

As a second, independent signal, the bus checks that each sensor's program and link still exist and that the kernel still has the program attached to its hook.

A sensor with no confirmed beat for 15 seconds (`dead_threshold`) is marked dead. With a 10-second cycle, that is two missed cycles, and the worst case is about 20 seconds. A sensor that failed to start is `failed`; one the bus cannot test (for example, the dlopen helper is missing) is `unverifiable`. Both count against the host's overall status.

The two fanotify sensors are marked alive by a timer in the bus. That proves the bus is running, not that the fanotify watch still fires.

Detaching a hook with `bpftool link detach` could not be tested on kernel 5.19, which refuses that for these links (EOPNOTSUPP). The dead path is covered by unit tests.

### Server-Side Out-of-Band Polling

The bus cannot be trusted to report its own health if it has been compromised. The collector inverts that: it reaches out to the bus. It polls each bus's `/status` endpoint every 30 seconds (`poll_interval`). If the bus has been killed, the endpoint stops answering, and that is itself the alert signal.

This does not cover an attacker with root on the host, who can stop the bus and serve a fake "alive" `/status`, or write fresh timestamps into a heartbeat map. See [SECURITY.md](../SECURITY.md).

On the server path, `hookmon-server` has a watchdog of its own. A host with no heartbeat for `watchdog.heartbeat_timeout` (default 60 s) is marked UNRESPONSIVE and an AGENT_OFFLINE event (CRITICAL) is stored. Heartbeats arrive over mutual TLS, and the server takes the host ID from the bus's certificate, so one host cannot keep another looking alive. The same root attacker can still run a fake bus with the stolen key and certificate from `/var/lib/hookmon`. AGENT_OFFLINE reaches the database and the dashboard, but no SIEM connector yet (fix plan step 7d).

### Tamper Signal Hierarchy

| Signal | Interpretation | Prometheus rule | Severity label |
|--------|---------------|-----------------|----------------|
| Poll endpoint unreachable | Bus killed, or host network cut | `HookMonHostUnreachable` (for 2m) | critical |
| Poll succeeds, but sensors report dead | A hook detached or a program unloaded | `HookMonSensorDead` (for 1m) | high |
| Any host degraded (dead, failed or unverifiable sensors) | As above, or a sensor that never started | `HookMonFleetDegraded` (for 1m) | high |
| All sensors alive, but no events for 24 h | Events being suppressed between the sensors and the bus | `HookMonNoEvents24h` (for 10m) | warning |
| Collector has not pushed to Pushgateway for 90 s | Collector killed, or Pushgateway restarted and lost its data | `HookMonCollectorSilent` (for 30s) | critical |

The rules are in `deploy/docker/grafana/alerts/hookmon-alerts.yaml`. Prometheus sends firing alerts to Alertmanager.

The "no events for 24 h" row combines heartbeat liveness with event rate. A host can genuinely have no events for 24 hours (a dormant standby, for example); the host's role decides. Heartbeats confirm the sensors run; they cannot confirm events flow end to end. `HookMonNoEvents24h` uses the bus's own `/metrics` (`hookmon_sensor_alive` and `hookmon_events_total`), so it needs each bus listed as a scrape target in `prometheus.yml`.

`hookmon_events_total` also counts BPF_INVENTORY events, which `bpf_syscall` sends every 5 minutes on its own, not from a hook. The rule leaves them out, so a host whose hooks' events are all lost can still fire `HookMonNoEvents24h`.

The collector-silence rule matters because Pushgateway keeps serving the last values it received. Without it, a dead collector would leave the fleet showing "all alive" forever.

### Limitations of Polling

Polling cannot catch an attack that completes between polls. If an attacker loads a BPF program and kills the bus, and the next poll is 25 seconds away, the attack completes in the blind spot. Heartbeats confirm sensor liveness at a point in time; they cannot reconstruct missed events.

For **persistent attacks** (kernel BPF programs that stay loaded, linker configuration changes on disk, replaced shared libraries) the damage outlasts the blind spot. When the bus restarts, the BPF inventory lists every loaded program, and the file sensors take a new baseline. A file changed while the bus was down is not reported as a change; its new hash becomes the baseline.

### Independent Verification over SSH (not built)

An earlier design had the collector SSH to each host and run checks that bypass the bus entirely, such as `bpftool prog list | grep hookmon`. That is not built, and the fix plan does not add it. The collector's SSH mode runs `curl -s http://localhost:2112/status` on the host, so it returns the same answer the bus gives over HTTP. It does not verify the SSH host key.

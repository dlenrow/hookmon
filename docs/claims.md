# HookMon claims ledger

One row per claim the blog makes. Status values:

- **Verified**: a command or test was run and the result was seen.
- **Code reading**: the code was read but nothing was run.
- **Not true**: the code does not do what the claim says.

A claim is never made true by changing its test. Rows are updated as each fix-plan step lands. The step log below records what was run.

## Claims

| Claim | Test or command | Result | Status |
| --- | --- | --- | --- |
| Eight sensors | `make test-e2e`; `/status` | Eight sensors are started and health-checked. Since step 4, `elf_rpath` is its own eBPF sensor on `sched_process_exec`. The e2e suite detects an attack for each of the eight. | Verified |
| SHA256 bytecode hashing detects a modified program with the same name | `TestSensor1_BPFSyscall_SameProgramSameTag`, `TestSensor1_BPFSyscall_ModifiedProgramNewTag` | The capability works, but not by SHA256. Since step 4 the bus records the kernel's program tag, which the kernel computes over the instructions with map references zeroed, so it is stable across loads. The same canary loaded twice gets the same tag; a modified canary gets a new one. Two programs with identical instructions and different types share a tag, so allowlist entries should also pin the program type. The blog should say "kernel program tag". | Not true |
| Enrichment with PID, UID, cmdline, exe path, exe SHA256, cgroup, container ID | `agent/enrichment` tests; container hash check on drl-nuc8i3bek | Since step 4: exe hashes are `sha256:<hex>`, cached by (device, inode, mtime, ctime). A container process is hashed through `/proc/<pid>/root`: for `sleep` in a container the new bus hashed the container's busybox, matching `sha256sum` inside it, where the old bus hashed the host's coreutils. Container IDs are recognized for docker, cri-containerd, CRI-O and libpod on cgroup v1 and v2. File-sensor writers that exit before the bus reads `/proc` are now named from a process cache fed by every exec (`agent/proccache`). Under CPU load, `TestLinkerConfig_PreloadOperations` went from 15/20 to 20/20. A writer that never exec'd while the bus was running (a forked subshell, a daemon started before the bus) and has exited still gets UID "unknown" (4294967295), never 0. | Verified |
| `lib_integrity` baselines at startup; package-manager writes are INFO | `TestLibIntegrity_AptReinstallIsInfo`, `TestLibIntegrity_SoOperations` | Since step 4, every watched file is hashed at startup and each event carries the previous hash. Package-manager writes are INFO: `apt-get install --reinstall libmnl0` produced only INFO events, and the writer was recognized by dpkg's executable path. The server still overrides bus severity (`server/policy/engine.go`) until step 7c, so INFO reaches the console, Loki and metrics but not the server path. | Verified |
| `linker_config` catches linker-cache poisoning | `TestLinkerConfig_PreloadOperations`; the apt reinstall run | Since step 4, `/etc/ld.so.cache` is watched along with `/etc/ld.so.preload` and `ld.so.conf(.d)`. Directory-entry events catch create, delete and rename. `cp`, `sed -i`, `mv`, `ln -sf` and `rm` on `/etc/ld.so.preload` each raised CRITICAL. ldconfig's rewrite of `ld.so.cache` was seen, as INFO because the writer was the package manager. No test writes `ld.so.cache` from outside a package manager. | Verified |
| `ptrace_monitor` sees register manipulation | `TestSensor6_PtraceMonitor_RegisterWrites`, `TestSensor6_PtraceMonitor_Attach`, `TestSensor6_PtraceMonitor_AttachTargetComm`, `TestSensor6_PtraceMonitor_TargetCommInPidNamespace` | Since step 4, POKEUSER, SETREGS and SETREGSET are reported, along with ATTACH, SEIZE, POKETEXT and POKEDATA. The e2e tests exercise ATTACH, SETREGS, SETREGSET and POKEUSER. SEIZE, POKETEXT and POKEDATA are in the filter but have no test. `TargetComm` is filled, including across PID namespaces; it is empty when the target is in a namespace nested below the caller's. The `Addr` field was wrong on every event before this step, because of struct padding; it is now fixed and tested. | Verified |
| `elf_rpath` audits every exec | `TestSensor8_ElfRpath_OriginTmpCleanEnv` (10/10), `TestSensor8_ElfRpath_SuspiciousPath` (10/10) | Since step 4, every successful exec (execve and execveat) runs through `sched_process_exec`. The binary is identified by the kernel's inode and mtime, with an LRU cache that also remembers binaries with no RPATH. Not analysed if the process has already exited and its path can't be resolved: relative paths outside the cwd, `/dev/fd/N` (fexecve, memfd), scripts (the interpreter is what loads), other mount namespaces, and names of 255 bytes or more. | Verified |
| Heartbeat every 10 s independent of traffic | `TestHeartbeat_IdleAllAlive` (`HOOKMON_E2E_LONG=1`); `agent/health_test.go` | Since step 3, every 10 s the bus fires each eBPF hook itself. A sensor is alive only if its kernel heartbeat map advanced and its program and link are still attached. On an idle host all sensors were alive at every one of 120 polls over 10 minutes. Detaching a hook can't be tested on kernel 5.19 (`bpftool link detach` returns EOPNOTSUPP for these links), so the dead path is covered by unit tests. A root attacker can forge the heartbeat map (see SECURITY.md). | Verified |
| `/status` plus a 30 s collector poll | `TestHeartbeat_KillBusCollectorUnreachable` | Default poll is 30 s. After `kill -9` of the bus, the collector (set to poll every 2 s for the test) reported the host unreachable 1.955 s later, within one poll. A root attacker can serve a fake `/status` (see SECURITY.md). | Verified |
| Four-row alert hierarchy, including "zero events for 24h" | `promtool test rules deploy/docker/grafana/alerts/tests/*.yml`; live run on drl-nuc8i3bek | There are five rules: HostUnreachable, SensorDead, FleetDegraded, plus CollectorSilent and NoEvents24h (new in step 3). Alertmanager now routes them to a placeholder webhook. CollectorSilent fired live after the collector was stopped and reached Alertmanager. Both new rules pass promtool unit tests; NoEvents24h has not fired on a live host. Step 5 found that the periodic `BPF_INVENTORY` events (added in step 4) kept NoEvents24h from ever firing; the rule now excludes them, and a promtool case covers a host with inventory events only. The blog's "four rows" no longer matches the count. | Verified |
| Fleet health banner | `deploy/docker/grafana/dashboards/hookmon.json` | The "Fleet Health" panel exists. | Code reading |
| Read-only in default mode | Audit of the sensors | Tracepoints, uprobes and `FAN_CLASS_NOTIF` fanotify only. No blocking path exists. | Code reading |
| Enforcement mode available | Audit of the whole repo | No enforcement code exists. | Not true |
| Learning mode auto-populates candidates | Audit of `server/` | No learning mode, PENDING state or candidates exist anywhere. | Not true |
| Every way code enters a Linux process | `docs/threat-model.md` | Since step 5, the threat model lists each way code enters a process and rates its coverage. Tested: `bpf()` load and the LINK_CREATE and RAW_TRACEPOINT_OPEN attach paths, BPF inventory, LD_PRELOAD/LD_AUDIT/LD_DEBUG, ld.so.preload and ld.so.conf.d, executable RPATH, `.so` files in the four library directories, glibc dlopen (including in containers), ptrace register writes, and /dev/shm via openat and openat2. Not covered: attaches outside `bpf()`, BPF_LINK_UPDATE, dlmopen, musl and static binaries, libraries' own RUNPATH, other library directories, process_vm_writev, writes to /proc/<pid>/mem, reflective and JIT loaders, SysV shm, io_uring opens, kernel modules, binfmt_misc, and GCONV_PATH and interpreter variables. | Not true |
| mTLS enrollment | `server/ingestion` Postgres integration tests; real `hookmon-bus` and `hookmon-server` on drl-nuc8i3bek | Since step 7a: the bus enrolls on a separate port (9444) that authenticates the server only, using a token from the server config (constant-time compare, expiry, optional single-use). The server signs the CSR and assigns the HostID as the certificate CN. Every other RPC (port 9443) requires a CA-signed client certificate, and the HostID comes from that certificate, never from the message. Since 7b, TLS is the default: the server and the bus refuse plaintext unless `--insecure` is given. | Verified |
| SIEM connectors (Syslog/CEF, Splunk HEC, Elastic, webhook, Kafka) | Audit of `server/connectors`, `cmd/hookmon-server` | The connectors exist, but `hookmon-server` cannot enable any of them, so nothing reaches a SIEM. Fixed in 7d. | Not true |
| Allowlist scopes and learning mode on the server | Audit of `server/policy` | There is no learning mode and no PENDING state, and the allowlist is read only at startup. Fixed in 7c. | Not true |
| Dashboard pages (event feed, policies, hosts, investigation, settings) | Audit of `dashboard/`; `curl` against the server on drl-nuc8i3bek | Since 7b the server serves the built dashboard over TLS, with client-side routes falling back to `index.html`. The pages call the real API. Still open until 7e: the WebSocket feed accepts any token and splits events across tabs, and Settings is static. | Not true |
| Appliance and package formats (OVA, QCOW2, VHD, ISO, DEB, RPM, Ansible, compose) | Audit of `appliance/`, `deploy/` | Only the compose monitoring stack runs. Packer targets QEMU only and would fail, the ISO builder is a stub, the RPM spec and Ansible roles are broken, and the DEB ships the old binary. Fixed in 7g. | Not true |

## Step log

Each fix-plan step adds an entry: the date, the commit, the commands run, and what they showed.

### Step 1: Build (2026-10-09)

Host: drl-nuc8i3bek, Ubuntu 22.10, kernel 5.19.0-46 x86_64, Go 1.24.4, `CC=clang` (the host has no gcc). Run against a fresh clone of `origin/main` at d961b69 with the step 1 changes applied.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| eBPF objects build from a clean tree | `make bpf` | `vmlinux.h` generated from `/sys/kernel/btf/vmlinux`. Five objects built, each with its expected hook section. A second run does nothing. | Verified |
| Every binary builds | `make build-all` | `bpf` runs first, then hookmon-bus, -agent, -server, -cli and -collector. | Verified |
| Vet | `go vet ./...` | Clean. | Verified |
| Unit tests as CI runs them (non-root) | `go test -race -count=1 ./...` | All packages ok. e2e is excluded by the `linux && e2e` tag. | Verified |
| Smoketests | `make smoketest` | Pass. One test skips by design (`TestStatusEndpointUnreachableSimulation`). | Verified |
| e2e (root) | `make test-e2e` | Each run: 12/13 pass, but a different test fails each time. Run 1: `TestSensor8_ElfRpath_SuspiciousPath` timed out; it passes alone. Likely cause: the canary exits before the bus reads `/proc/<pid>/exe`, so no RPATH analysis runs. This is a product race, fixed by the step 4 `sched_process_exec` hook. Run 2: `TestCombined_BpftimeAttackChain` missed EXEC_INJECTION. Cause: the harness's `WaitForEvent` discards events that don't match, so the result depends on order. Fixed in a separate commit. | Verified |
| `Dockerfile.agent` builds hookmon-bus | `make docker-agent` | Not run: the test host's disk is full (3 GB free). | Code reading |
| CI Go job passes | GitHub Actions run 37999808472 at `95e2108` | Go Build & Test and Dashboard both pass. The first run, at `fa1150f`, failed because Ubuntu's kernel-matched bpftool wrapper has no binary for the runner's 6.17 kernel. `95e2108` switched CI to a pinned static upstream bpftool, v7.7.0 with its sha256 checked. | Verified |

Bugs found during verification and fixed in this step:
- The smoketest constructor table did not compile on Linux.
- `test/canary/load_canary.go` broke `go vet ./...` and `go test ./...` on Linux.
- `make test-e2e` failed on hosts where root's PATH has no `go`.

### e2e harness fix (2026-10-09)

`WaitForEvent` threw away every event that didn't match the filter it was waiting on. A test that waits for two events from one attack failed whenever the second arrived first. This is what happened to `TestCombined_BpftimeAttackChain` in step 1, run 2. Each sensor has its own ring buffer, so arrival order isn't fixed.

Unmatched events are now kept for later waits. Each event still matches at most once, and no assertion changed. The harness also had a `lines` channel that was never read and would stall the parser after 10,000 lines; it is removed.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| e2e (root), on the full working tree | `make test-e2e`, run twice | 13/13 both times. `TestSensor8` passed both times, but the exit race noted in step 1 is still in the code until step 4. | Verified |

### Step 2: Wire format (2026-10-09)

Run on the same host, against the full working tree. Codegen was done on macOS.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| Real protobuf code generation | `cd proto && buf generate` (buf v1.50.0; protocolbuffers/go v1.36.8 and grpc/go v1.5.1, pinned to the runtimes in go.mod) | `gen/hookmon/v1` regenerated. A second run produces no diff. | Verified |
| Round trip for every RPC in `agent.proto` (StreamEvents, Enroll) | `go test -race ./server/ingestion/` (`TestWire_StreamEvents`, `TestWire_Enroll`) | Pass. Events, including ELF_RPATH entries, survive the round trip field for field. | Verified |
| One goroutine owns `stream.Send`; concurrent senders are race-free | `TestConcurrentSendersAcrossRestart`, `-race -count=3` | Pass. Every event reaches a server or the fallback log. | Verified |
| The bus reconnects after the server is killed and restarted, and events resume | `TestReconnectAfterServerRestart`: a real IngestionServer on 127.0.0.1 is stopped and restarted on the same port, `-race -count=3` | Pass. | Verified |
| Everything as CI runs it | `make build-all`, `go vet ./...`, `go test -race ./...`, `make smoketest` | Pass. | Verified |
| e2e | `make test-e2e`, run twice | 13/13. These tests run the bus with `--console`, so they do not exercise gRPC. The full-path test is step 7h. | Verified |

Limits that remain:
- Events the server did not ack go to the fallback log. Nothing replays them.
- The heartbeat's HostID is still self-asserted. Step 7a fixes that.

### Step 3: Heartbeat and tamper detection (2026-10-09)

Run on drl-nuc8i3bek (Ubuntu 22.10, kernel 5.19) against the full working tree. The ops half was tested in a separate compose project, which was torn down afterwards.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| Each probe advances its sensor's heartbeat map | `strace` of the bus, plus reading the maps with `bpftool` | All five confirmed. The ptrace map, which has no other traffic on this host, advanced exactly every 10.000 s. The dlopen map moved only when the helper ran. | Verified |
| Idle host, all sensors alive for 10 minutes | `HOOKMON_E2E_LONG=1 go test -tags e2e -run TestHeartbeat_IdleAllAlive ./test/e2e/` | All 7 sensors alive at all 120 polls. Of 1989 host events, none came from the bus or its probes. | Verified |
| Detaching a sensor's link marks it dead within 30 s | `TestHeartbeat_LinkDetach` | Not possible as written on 5.19: `bpftool link detach` returns EOPNOTSUPP for perf_event links, and the hook keeps running. The test skips with that reason. The dead path is covered by `TestHealthCycleDetachedHookGoesDead` and `TestHealthCycleAttachmentCheckBlocksBeat`; the worst case is 20 s with a 15 s threshold and a 10 s cycle. | Code reading |
| `kill -9` of the bus is reported unreachable within one poll | `TestHeartbeat_KillBusCollectorUnreachable` | Unreachable 1.955 s after the kill, with a 2 s poll. | Verified |
| A missing dlopen helper is reported, not treated as alive | `TestHeartbeat_DlopenProbeMissing` | `dlopen_monitor=unverifiable`, and the host is `degraded`. | Verified |
| Probe events are not reported or counted | `TestProbeEventsNotSentOrCounted` | They reach neither the transport nor `hookmon_events_total`. The test fails if the filter is removed. | Verified |
| Collector silence fires an alert | Live, in compose project `hookmon-s3b` | The collector was stopped at 22:32:40. The alert went pending at 22:34:01, fired at 22:34:31, and was active in Alertmanager. | Verified |
| Alert rules and Alertmanager config are valid | `promtool check rules`, `promtool test rules`, `amtool check-config` | All pass. | Verified |
| Everything as CI runs it | `make build-all`, `go vet ./...`, `go test -race ./...`, `make test-unit`, `make smoketest` | All pass. | Verified |
| Full e2e suite | `make test-e2e` | 15 pass and 2 skip (the idle test is gated, and detach is EOPNOTSUPP). `TestSensor8` passed this run but is still flaky: it fails at about the same rate at HEAD, because of the exit race noted in step 1. | Verified |
| `Dockerfile.agent` ships the dlopen helper | Code reading | Not built: the test host's disk is full. | Code reading |

Tests whose expectations changed: `TestOverallAllUnknown`, `TestStatusHandler` and the smoketest `TestBusStatusWithSensorHealthMetrics` used to expect "alive" when a sensor had never been confirmed. The plan names that behavior as the bug. They now expect "dead" or "degraded".

Deviations from the plan:
- `/bin/true` runs every cycle, not once a minute, because a once-a-minute probe can't meet a 15 s threshold.
- The default `dead_threshold` is now 15 s, down from 35 s.

### Step 4, wave 1: bpf_syscall, elf_rpath, linker_config and lib_integrity (2026-10-10)

Three branches were merged onto main and the merged tree was run on drl-nuc8i3bek. The merge caused one compile error: two Linux-only test helpers had the same name. It was fixed in a follow-up commit.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| The same program loaded twice gets the same tag | `TestSensor1_BPFSyscall_SameProgramSameTag` | Pass. | Verified |
| A modified program gets a different tag | `TestSensor1_BPFSyscall_ModifiedProgramNewTag` | Pass. | Verified |
| A program loaded before the bus starts appears in the first inventory | `TestSensor1_BPFInventory_PreexistingProgram` | Pass. `BPF_INVENTORY` events go out at startup and every 5 minutes, followed by a host summary. | Verified |
| Link-based and raw-tracepoint attaches are reported | `TestSensor1_BPFSyscall_LinkCreateAttach`, `TestSensor1_BPFSyscall_RawTracepointAttach` | Pass. | Verified |
| New event fields survive the wire | `test/transport/bpf_inventory_wire_test.go` | Pass. The test fails if a field is dropped from the converter. | Verified |
| A binary with RUNPATH `$ORIGIN/../tmp`, run with a clean environment, raises ELF_RPATH | `TestSensor8_ElfRpath_OriginTmpCleanEnv` | 10/10, CRITICAL. | Verified |
| The Sensor8 flake is gone | `TestSensor8_ElfRpath_SuspiciousPath`, 10x standalone | 10/10, against about 50% before. | Verified |
| `cp`, `sed -i`, `mv`, `ln -sf` and `rm` against `/etc/ld.so.preload` and against a `.so` in `/usr/lib` | `TestLinkerConfig_PreloadOperations`, `TestLibIntegrity_SoOperations` | Each operation raises an event. `/etc/ld.so.preload` and `/usr/lib` were restored afterwards; neither the file nor any canary was left behind. | Verified |
| An apt reinstall of a library is INFO, not ALERT | `TestLibIntegrity_AptReinstallIsInfo` (libmnl0) | INFO. | Verified |
| Everything as CI runs it, plus root-only unit tests | `make build-all`, `go vet ./...`, `go test -race ./...`, `sudo go test -race ./agent/sensors/`, `make smoketest` | Pass. | Verified |
| Full e2e suite | `make test-e2e`, run twice | 24 pass, 2 skip, 0 fail, both runs. | Verified |

Design decisions that change behavior:
- `ProgHash` now holds the kernel program tag (16 hex digits, as `bpftool` prints it), not a sha256 of the loader's buffer. Existing `prog_hash` allowlist values no longer match.
- `MAP_CREATE` is no longer reported. A map runs no code, and any program that uses it is reported when it loads.
- File hashes from `linker_config` and `lib_integrity` use `sha256:<hex>`.
- When the writer process has already exited, UID is reported as 4294967295 ("unknown"), not 0.

Not covered: attaches that don't go through `bpf()` (perf `SET_BPF` ioctl, netlink XDP/tc, `SO_ATTACH_BPF`); `BPF_LINK_UPDATE`; moving a file out of a watched directory (`FAN_MOVED_FROM` is not in the mask); writes through a hard link outside the watched directories; `/usr/local/lib` and other `ld.so.conf` directories.

### Step 4, wave 2: exec_injection, shm_monitor, ptrace_monitor, dlopen_monitor, enrichment (2026-10-10)

Four branches were merged onto main, plus follow-up fixes. The merged tree was run on drl-nuc8i3bek.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| `LD_PRELOAD` as the 100th environment variable is detected | `TestExecInj_PreloadAt100th` | Pass. The environment scan moved to `sched_process_exec` and reads the new process's `env_start..env_end`. It reads up to 8192 variables with `bpf_loop` (kernel 5.17+), or 512 on older kernels. | Verified |
| `execveat` with `LD_PRELOAD` is detected | `TestExecInj_Execveat` | Pass. | Verified |
| An environment longer than the scan raises `scan_truncated` | `TestExecInj_ScanTruncated` | Pass (ALERT). `LibraryHash` is filled with `sha256:<hex>` for an absolute LD_PRELOAD or LD_AUDIT path. | Verified |
| shm severity follows the pattern | `test/e2e/shm_ptrace_test.go` | bpftime is CRITICAL, bpf-related is ALERT, anything else is INFO. Names come from upstream bpftime (`bpftime_maps_shm`, `handler_manager.hpp:51`), including the `BPFTIME_GLOBAL_SHM_NAME` override (`handler_manager.hpp:60-66`). `openat2` is covered. | Verified |
| A real bpftime runtime is detected | — | Not run. There are no release binaries, the image is 1.6 GB, and a source build needs about 250 MB of toolchain on a host with under 3 GB free. The attack chain test uses a simulator. | Not true |
| A dlopen inside a container with its own libc is detected | `TestDlopenW_ContainerLibc` (`debian:bookworm-slim`, pinned by digest and removed afterwards) | Pass. The same test against the old bus times out. Every distinct glibc mapped by any process gets a uprobe; libcs are rediscovered every 5 minutes and links are closed when a libc is no longer mapped. Attachments are capped at 256; past the cap the sensor reports unhealthy. | Verified |
| dlopen events are deduplicated | `TestDlopenW_Dedupe` | One event per (exe hash, library path) per hour. | Verified |
| Idle host shows no RPATH noise | 2 minutes of `--console` on the idle host, running `systemctl` and `sudo` 3x each | 18 ELF_RPATH events before, 0 after. `--scan-rpath /usr/bin` went from 72 MEDIUM to 73 LOW. | Verified |
| Each binary version raises at most one ELF_RPATH event | `TestRpathW_EmitOncePerBinaryVersion` | Pass. | Verified |
| Root-only unit tests, including RPATH ranking by parent directory | `sudo go test -race ./agent/sensors/ ./agent/enrichment/ ./agent/` | Pass. | Verified |
| Idle host, all sensors alive | `HOOKMON_E2E_LONG=1 HOOKMON_E2E_IDLE_DURATION=2m` (run per branch) | 8 of 8 sensors alive at 24 of 24 polls, with 0 events from the bus or its probes. | Verified |
| Everything as CI runs it | `make build-all`, `go vet ./...`, `go test -race ./...`, `make smoketest` | Pass. | Verified |
| Full e2e suite | `make test-e2e`, run twice | 38 pass, 2 skip, 0 fail on both runs. | Verified |

RPATH ranking, as David decided on 2026-10-10:
- A non-standard directory is ranked by who can write to it.
  - LOW, no event: only root can write the directory and every parent above it.
  - MEDIUM: a non-root user owns the directory or a parent, or its group can write it.
  - A sticky parent such as `/tmp` counts only through its owner.
- DT_RPATH never lifts LOW to MEDIUM.
- `/tmp`, `/var/tmp`, `/dev/shm` and `/home` are CRITICAL as exact paths, not only as prefixes.
- `${ORIGIN}`, `$LIB` and `$PLATFORM` are expanded as ld.so expands them.

Not covered:
- dlopen:
  - musl (Alpine) and statically linked binaries, and `dlmopen`.
  - A libc mapped since the last scan, for up to 5 minutes.
  - Container libcs can't be probed by the host helper, so their only liveness signal is the attachment check.
- shm:
  - Relative or dirfd-relative opens, `/run/shm`, `creat`, O_TMPFILE+linkat, and renames into `/dev/shm`.
  - A modified bpftime that uses some other segment name.
- exec_injection: a library named without an absolute path gets no hash. Values over 255 bytes are flagged `value_truncated`.
- Out of scope per the plan: `process_vm_writev`, writes to `/proc/<pid>/mem`, and memfd or reflective loaders that bypass `dlopen`.
- Server path: until step 7c, the policy engine overrides bus severity, so the INFO and ALERT downgrades for shm, RPATH and package-manager writes reach only the console, Loki and metrics.

### Step 4, closing fix: process cache for exited file writers (2026-10-10)

The fanotify sensors receive only a PID. Short-lived writers such as `cp`, `sed -i` and `mv` often exit before the bus reads `/proc/<pid>/status`. Their events then had UID "unknown", and the package-manager check couldn't walk their parents. Now every `sched_process_exec` record that `elf_rpath` receives feeds a bounded cache in `agent/proccache`: 16384 entries, 60 s TTL. On a miss the file sensors wait up to 200 ms for a record still in flight. `elf_rpath` now starts before the other sensors, so the cache is filling before the file sensors run.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| Exited writers are named correctly | `TestLinkerConfig_PreloadOperations` x20, with every CPU busy | Before: 15/20, with 8 of 100 events at UID 4294967295. After: 20/20. On an idle host both pass 20/20. | Verified |
| Same, on the merged tree | x10, with every CPU busy | 10/10. | Verified |
| Identity from the cache alone | Root unit test running the real `elf_rpath` sensor against `linker_config` with an empty proc root | 20 of 20 `cp` writes named with uid 0, comm `cp`, and the right parent. | Verified |
| Package-manager writes are still INFO | `TestLibIntegrity_AptReinstallIsInfo` | INFO. | Verified |
| Everything as CI runs it, plus root unit tests | `make build-all`, `go vet ./...`, `go test -race ./...`, `sudo go test -race ./agent/...`, `make smoketest` | Pass. | Verified |
| Full e2e suite | `make test-e2e`, twice | 38 pass, 2 skip, 0 fail on both runs. | Verified |

Limits:
- A writer that never exec'd while `elf_rpath` was running is still "unknown" once it exits.
- With `elf_rpath` disabled, nothing feeds the cache.
- A PID reused within 60 s by a process that never exec'd inherits the old identity; this needs PID wraparound.
- Exec records dropped by a full ring buffer leave those writers unknown.

### Step 5: Docs (2026-10-10)

- **Docs fixed.** README, architecture, deployment-guide, theory-of-operations, CONTRIBUTING, SECURITY and CLAUDE.md now match the code after steps 1–4. Each command, flag, env var and test name was checked against the code or `--help`.
- **Unfinished work is labelled.** Features step 7 builds or fixes are marked "not working yet", with the step that fixes them: enrollment (7a), TLS by default and dashboard serving (7b), learning mode and allowlist reload (7c), connector configuration (7d), WebSocket auth and fan-out (7e), and appliance images, DEB/RPM and Ansible (7g).
- **`docs/threat-model.md` is new.** It covers every way code enters a process and its coverage (see the claims row above).
- **Author email** is david.lenrow@illumio.com in all docs and packaging. Illumio stays in MAINTAINERS.md. This was David's decision on 2026-10-10.
- **Deferred until after step 7.** `docs/api-reference.md` and `docs/allowlist-guide.md` will describe learning mode and the API once they exist (David's decision, 2026-10-10).
- **Bugs found while writing docs, and fixed:**
  - `HookMonNoEvents24h` could never fire. The periodic `BPF_INVENTORY` events kept `hookmon_events_total` rising, so the recording rule now excludes them. A promtool case for an inventory-only host fails against the old rule and passes against the new one (`promtool test rules`, on drl-nuc8i3bek).
  - This ledger named five e2e tests without their `TestSensor1_` prefix, and implied that ptrace SEIZE, POKETEXT and POKEDATA had tests. Both are corrected.

### Step 7a: Enrollment and host identity (2026-10-10)

Ran on drl-nuc8i3bek against a real Postgres (`postgres:16-alpine`, pinned by digest, removed afterwards) and the real binaries.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| A fresh host enrolls and appears in the inventory | Integration test, plus real `hookmon-bus --enroll-token` as root | The bus enrolled with a single-use token and stored its key and certificates with mode 0600; `openssl verify -purpose sslclient` passes. The host shows ONLINE with 8 sensors alive, and 67 events were stored under the certificate CN. | Verified |
| Expired, reused and invalid tokens are rejected | Integration test, plus the real bus | All rejected with PermissionDenied, including a single-use token reused after a server restart. | Verified |
| Host A's certificate cannot send as host B | Integration test | Events and heartbeats are recorded under A's certificate CN, whatever HostID the message carries. | Verified |
| Stopping the bus raises an offline alert within the watchdog timeout | Integration test (2 s timeout); real bus (20 s timeout, 5 s check) | AGENT_OFFLINE fired 1.97 s after stop in the test and 20.97 s after `kill -TERM` with the real bus. The host went UNRESPONSIVE, then back ONLINE when the bus restarted with its stored identity. | Verified |
| No regressions | `make build-all`, `go vet ./...`, `go test -race ./...`, root `go test -race ./agent/...`, `make test-e2e` | Pass. e2e: 38 pass, 2 skip, 0 fail. | Verified |

Design:
- A YAML server config (`deploy/server.example.yaml`) holds addresses, TLS, database, API, enrollment tokens and watchdog settings.
- Single-use tokens are recorded by fingerprint in Postgres, in the same transaction as the new host row.
- Heartbeats now carry the sensor-registry snapshot, which is stored per host.
- Plaintext mode still trusts the message HostID as an explicit development mode, with a warning. Step 7b makes TLS the default.

Known gaps:
- The bus and server can still run with TLS off (7b).
- `events.uid` is a 32-bit INTEGER, so events carrying UID 4294967295 ("unknown", since step 4) can't be stored. This is pulled forward from 7f into 7b.
- `--enroll-token` is visible in the process list during the first start.
- No AGENT_RECOVERED event is sent when a host comes back.

### Step 7b: Secure by default (2026-10-10)

Ran on drl-nuc8i3bek with a real Postgres (`postgres:16-alpine`, pinned by digest, removed afterwards).

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| The server refuses to start without TLS | `./bin/hookmon-server` with no certificates, plus `server/secure_test.go` | Exits 1 with "refusing to start without TLS: no TLS certificate configured: set tls.cert_file, tls.key_file and tls.ca_file (or --tls-cert, --tls-key and --tls-ca), or pass --insecure to run gRPC and REST in plaintext (development only)". | Verified |
| The bus refuses plaintext | `hookmon-bus` with no certificate and no token, plus `agent/transport/secure_test.go` | Exits 1 with "no client certificate and no enrollment token: refusing to connect to the server without TLS; enroll with --enroll-token and --ca-file, set tls.cert_file, or pass --insecure …". `--console` is unaffected. | Verified |
| REST over TLS | `curl --cacert` on port 8443 | `/api/v1/health` returns 200 over TLS 1.3. Without the CA the request fails; plain HTTP gets a 400. | Verified |
| The server serves the dashboard | `curl --cacert` for `/`, `/hosts`, `/events/abc`, the assets, and `/api/v1/no-such-endpoint` | Each page path returns `dist/index.html` byte for byte. The assets return 200. An unknown API path returns a JSON 404, not the page. | Verified |
| UID 4294967295 is stored (migration 005, BIGINT) | `server/store/postgres_test.go`; a synthetic event sent to the real server | Stored and read back with uid 4294967295 over REST and in Postgres. | Verified |
| Real end to end | Root `hookmon-bus` enrolls with `hookmon-server` (TLS, Postgres) | Host ONLINE with 8 sensors. 148 events stored. The host went UNRESPONSIVE after the bus stopped. | Verified |
| `hookmon-cli` works against the TLS API | `cmd/hookmon-cli/main_test.go` | The default URL is now `https://localhost:8443`, with `--ca-file` / `HOOKMON_CA_FILE`. The test passes with the CA and fails without it. | Verified |
| No regressions | `make build-all`, `go vet ./...`, `go test -race ./...`, root `go test -race ./agent/...`, `make test-e2e` | Pass. e2e: 38 pass, 2 skip, 0 fail. | Verified |
| `Dockerfile.server` serves the dashboard | Read the Dockerfile | Not built; the test host's disk is full. | Code reading |

Still open: the appliance's nginx proxies to plain HTTP and starts the server without TLS, so it will now refuse to start (7g). The dashboard shows an enrollment command that doesn't exist (7e).

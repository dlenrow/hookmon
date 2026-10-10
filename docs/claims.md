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
| SHA256 bytecode hashing detects a modified program with the same name | `TestBPFSyscall_SameProgramSameTag`, `TestBPFSyscall_ModifiedProgramNewTag` | The capability works, but not by SHA256. Since step 4 the bus records the kernel's program tag, which the kernel computes over the instructions with map references zeroed, so it is stable across loads. The same canary loaded twice gets the same tag; a modified canary gets a new one. Two programs with identical instructions and different types share a tag, so allowlist entries should also pin the program type. The blog should say "kernel program tag". | Not true |
| Enrichment with PID, UID, cmdline, exe path, exe SHA256, cgroup, container ID | Audit of `agent/enrichment/` | Partial. fanotify events default UID to 0. Container IDs are only recognized for docker/64-hex. The exe hash uses the host-namespace path for container processes. | Not true |
| `lib_integrity` baselines at startup; package-manager writes are INFO | `TestLibIntegrity_AptReinstallIsInfo`, `TestLibIntegrity_SoOperations` | Since step 4, every watched file is hashed at startup and each event carries the previous hash. Package-manager writes are INFO: `apt-get install --reinstall libmnl0` produced only INFO events, and the writer was recognized by dpkg's executable path. The server still overrides bus severity (`server/policy/engine.go`) until step 7c, so INFO reaches the console, Loki and metrics but not the server path. | Verified |
| `linker_config` catches linker-cache poisoning | `TestLinkerConfig_PreloadOperations`; the apt reinstall run | Since step 4, `/etc/ld.so.cache` is watched along with `/etc/ld.so.preload` and `ld.so.conf(.d)`. Directory-entry events catch create, delete and rename. `cp`, `sed -i`, `mv`, `ln -sf` and `rm` on `/etc/ld.so.preload` each raised CRITICAL. ldconfig's rewrite of `ld.so.cache` was seen, as INFO because the writer was the package manager. No test writes `ld.so.cache` from outside a package manager. | Verified |
| `ptrace_monitor` sees register manipulation | Audit of `agent/sensors/ptrace_monitor.c` | Filters only ATTACH, SEIZE, POKETEXT and POKEDATA. SETREGS, SETREGSET and POKEUSER are not seen. | Not true |
| `elf_rpath` audits every exec | `TestSensor8_ElfRpath_OriginTmpCleanEnv` (10/10), `TestSensor8_ElfRpath_SuspiciousPath` (10/10) | Since step 4, every successful exec (execve and execveat) runs through `sched_process_exec`. The binary is identified by the kernel's inode and mtime, with an LRU cache that also remembers binaries with no RPATH. Not analysed if the process has already exited and its path can't be resolved: relative paths outside the cwd, `/dev/fd/N` (fexecve, memfd), scripts (the interpreter is what loads), other mount namespaces, and names of 255 bytes or more. | Verified |
| Heartbeat every 10 s independent of traffic | `TestHeartbeat_IdleAllAlive` (`HOOKMON_E2E_LONG=1`); `agent/health_test.go` | Since step 3, every 10 s the bus fires each eBPF hook itself. A sensor is alive only if its kernel heartbeat map advanced and its program and link are still attached. On an idle host all sensors were alive at every one of 120 polls over 10 minutes. Detaching a hook can't be tested on kernel 5.19 (`bpftool link detach` returns EOPNOTSUPP for these links), so the dead path is covered by unit tests. A root attacker can forge the heartbeat map (see SECURITY.md). | Verified |
| `/status` plus a 30 s collector poll | `TestHeartbeat_KillBusCollectorUnreachable` | Default poll is 30 s. After `kill -9` of the bus, the collector (set to poll every 2 s for the test) reported the host unreachable 1.955 s later, within one poll. A root attacker can serve a fake `/status` (see SECURITY.md). | Verified |
| Four-row alert hierarchy, including "zero events for 24h" | `promtool test rules deploy/docker/grafana/alerts/tests/*.yml`; live run on drl-nuc8i3bek | There are five rules: HostUnreachable, SensorDead, FleetDegraded, plus CollectorSilent and NoEvents24h (new in step 3). Alertmanager now routes them to a placeholder webhook. CollectorSilent fired live after the collector was stopped and reached Alertmanager. Both new rules pass promtool unit tests; NoEvents24h has not fired on a live host. The blog's "four rows" no longer matches the count. | Verified |
| Fleet health banner | `deploy/docker/grafana/dashboards/hookmon.json` | The "Fleet Health" panel exists. | Code reading |
| Read-only in default mode | Audit of the sensors | Tracepoints, uprobes and `FAN_CLASS_NOTIF` fanotify only. No blocking path exists. | Code reading |
| Enforcement mode available | Audit of the whole repo | No enforcement code exists. | Not true |
| Learning mode auto-populates candidates | Audit of `server/` | No learning mode, PENDING state or candidates exist anywhere. | Not true |
| Every way code enters a Linux process | Audit; `docs/threat-model.md` | `process_vm_writev`, writes to `/proc/<pid>/mem`, and memfd/reflective loaders are not covered. `docs/threat-model.md` does not exist yet. | Not true |

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
| The same program loaded twice gets the same tag | `TestBPFSyscall_SameProgramSameTag` | Pass. | Verified |
| A modified program gets a different tag | `TestBPFSyscall_ModifiedProgramNewTag` | Pass. | Verified |
| A program loaded before the bus starts appears in the first inventory | `TestBPFInventory_PreexistingProgram` | Pass. `BPF_INVENTORY` events go out at startup and every 5 minutes, followed by a host summary. | Verified |
| Link-based and raw-tracepoint attaches are reported | `TestBPFSyscall_LinkCreateAttach`, `TestBPFSyscall_RawTracepointAttach` | Pass. | Verified |
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

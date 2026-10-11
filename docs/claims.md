# HookMon claims ledger

One row per claim the blog makes. Status values:

- **Verified**: a command or test was run and the result was seen.
- **Code reading**: the code was read but nothing was run.
- **Not true**: the code does not do what the claim says.

A claim is never made true by changing its test. Rows are updated as each fix-plan step lands. The step log below records what was run.

## Claims

| Claim | Test or command | Result | Status |
| --- | --- | --- | --- |
| Eight sensors | `make test-e2e`; `/status` | Eight sensors are started and health-checked. Since step 4, `elf_rpath` is its own eBPF sensor on `sched_process_exec`. The e2e suite detects an attack for each of the eight. Before 3465875, three of them did not work on a RHEL 9 kernel; since then all eight do on Rocky Linux 9.8 (see "After the release gate"). | Verified |
| SHA256 bytecode hashing detects a modified program with the same name | `TestSensor1_BPFSyscall_SameProgramSameTag`, `TestSensor1_BPFSyscall_ModifiedProgramNewTag` | The capability works, but not by SHA256. Since step 4 the bus records the kernel's program tag, which the kernel computes over the instructions with map references zeroed, so it is stable across loads. The same canary loaded twice gets the same tag; a modified canary gets a new one. Two programs with identical instructions and different types share a tag, so allowlist entries should also pin the program type. The blog should say "kernel program tag". | Not true |
| Enrichment with PID, UID, cmdline, exe path, exe SHA256, cgroup, container ID | `agent/enrichment` tests; container hash check on drl-nuc8i3bek | Since step 4: exe hashes are `sha256:<hex>`, cached by (device, inode, mtime, ctime). A container process is hashed through `/proc/<pid>/root`: for `sleep` in a container the new bus hashed the container's busybox, matching `sha256sum` inside it, where the old bus hashed the host's coreutils. Container IDs are recognized for docker, cri-containerd, CRI-O and libpod on cgroup v1 and v2. File-sensor writers that exit before the bus reads `/proc` are now named from a process cache fed by every exec (`agent/proccache`). Under CPU load, `TestLinkerConfig_PreloadOperations` went from 15/20 to 20/20. A writer that never exec'd while the bus was running (a forked subshell, a daemon started before the bus) and has exited still gets UID "unknown" (4294967295), never 0. | Verified |
| `lib_integrity` baselines at startup; package-manager writes are INFO | `TestLibIntegrity_AptReinstallIsInfo`, `TestLibIntegrity_SoOperations` | Since step 4, every watched file is hashed at startup and each event carries the previous hash. Package-manager writes are INFO: `apt-get install --reinstall libmnl0` produced only INFO events, and the writer was recognized by dpkg's executable path. The server still overrides bus severity (`server/policy/engine.go`) until step 7c, so INFO reaches the console, Loki and metrics but not the server path. | Verified |
| `linker_config` catches linker-cache poisoning | `TestLinkerConfig_PreloadOperations`; the apt reinstall run | Since step 4, `/etc/ld.so.cache` is watched along with `/etc/ld.so.preload` and `ld.so.conf(.d)`. Directory-entry events catch create, delete and rename. `cp`, `sed -i`, `mv`, `ln -sf` and `rm` on `/etc/ld.so.preload` each raised CRITICAL. ldconfig's rewrite of `ld.so.cache` was seen, as INFO because the writer was the package manager. No test writes `ld.so.cache` from outside a package manager. | Verified |
| `ptrace_monitor` sees register manipulation | `TestSensor6_PtraceMonitor_RegisterWrites`, `TestSensor6_PtraceMonitor_Attach`, `TestSensor6_PtraceMonitor_AttachTargetComm`, `TestSensor6_PtraceMonitor_TargetCommInPidNamespace` | Since step 4, POKEUSER, SETREGS and SETREGSET are reported, along with ATTACH, SEIZE, POKETEXT and POKEDATA. The e2e tests exercise ATTACH, SETREGS, SETREGSET and POKEUSER. SEIZE, POKETEXT and POKEDATA are in the filter but have no test. `TargetComm` is filled, including across PID namespaces; it is empty when the target is in a namespace nested below the caller's. The `Addr` field was wrong on every event before this step, because of struct padding; it is now fixed and tested. | Verified |
| `elf_rpath` audits every exec | `TestSensor8_ElfRpath_OriginTmpCleanEnv` (10/10), `TestSensor8_ElfRpath_SuspiciousPath` (10/10) | Since step 4, every successful exec (execve and execveat) runs through `sched_process_exec`. The binary is identified by the kernel's inode and mtime, with an LRU cache that also remembers binaries with no RPATH. Not analysed if the process has already exited and its path can't be resolved: relative paths outside the cwd, `/dev/fd/N` (fexecve, memfd), scripts (the interpreter is what loads), other mount namespaces, and names of 255 bytes or more. | Verified |
| Heartbeat every 10 s independent of traffic | `TestHeartbeat_IdleAllAlive` (`HOOKMON_E2E_LONG=1`); `agent/health_test.go` | Since step 3, every 10 s the bus fires each eBPF hook itself. A sensor is alive only if its kernel heartbeat map advanced and its program and link are still attached. On an idle host all sensors were alive at every one of 120 polls over 10 minutes. Detaching a hook can't be tested on kernel 5.19 (`bpftool link detach` returns EOPNOTSUPP for these links), so the dead path is covered by unit tests. The two fanotify sensors have no kernel heartbeat map. They beat from a Go ticker, and since 7f the ticker beats only while their fanotify reads are succeeding. A root attacker can forge the heartbeat map (see SECURITY.md). | Verified |
| `/status` plus a 30 s collector poll | `TestHeartbeat_KillBusCollectorUnreachable` | Default poll is 30 s. After `kill -9` of the bus, the collector (set to poll every 2 s for the test) reported the host unreachable 1.955 s later, within one poll. A root attacker can serve a fake `/status` (see SECURITY.md). | Verified |
| Four-row alert hierarchy, including "zero events for 24h" | `promtool test rules deploy/docker/grafana/alerts/tests/*.yml`; live run on drl-nuc8i3bek | There are five rules: HostUnreachable, SensorDead, FleetDegraded, plus CollectorSilent and NoEvents24h (new in step 3). Alertmanager now routes them to a placeholder webhook. CollectorSilent fired live after the collector was stopped and reached Alertmanager. Both new rules pass promtool unit tests; NoEvents24h has not fired on a live host. Step 5 found that the periodic `BPF_INVENTORY` events (added in step 4) kept NoEvents24h from ever firing; the rule now excludes them, and a promtool case covers a host with inventory events only. The blog's "four rows" no longer matches the count. | Verified |
| Fleet health banner | `deploy/docker/grafana/dashboards/hookmon.json`; `fleet_banner_test.yml` (promtool, in CI); `docs/evidence/step8-grafana.png` | The banner exists and is green or red from the collector's fleet metrics. The step 8 screenshot showed it broken: two tiles, because the query's `or vector(0)` kept an unlabelled zero next to the labelled Pushgateway series. With only the unreachable count pushed, the same mismatch would have shown green with hosts unreachable. The query now sums each side first. A promtool test proves one correct series with both metrics, with only one, and with none, and it fails on the old query. CI runs it. The fixed banner has not been screenshotted again. | Verified |
| Read-only in default mode | Audit of the sensors | Tracepoints, uprobes and `FAN_CLASS_NOTIF` fanotify only. No blocking path exists. | Code reading |
| Enforcement mode available | Audit of the whole repo | No enforcement code exists. | Not true |
| Learning mode auto-populates candidates | `test/integration/policy_test.go`; real bus, server and Postgres on drl-nuc8i3bek | Since step 7c, learning mode runs on the server, per fleet or per host, with an end time. Each unmatched unique tuple becomes a PENDING allowlist entry with occurrence count, first and last seen, and the hosts it appeared on. A 5-minute fleet learning run on the idle test host produced 14 PENDING entries. There is no bus-side candidate file; plan step 6 is out of scope. | Verified |
| Every way code enters a Linux process | `docs/threat-model.md` | Since step 5, the threat model lists each way code enters a process and rates its coverage. Tested: `bpf()` load and the LINK_CREATE and RAW_TRACEPOINT_OPEN attach paths, BPF inventory, LD_PRELOAD/LD_AUDIT/LD_DEBUG, ld.so.preload and ld.so.conf.d, executable RPATH, `.so` files in the four library directories, glibc dlopen (including in containers), ptrace register writes, and /dev/shm via openat and openat2. Not covered: attaches outside `bpf()`, BPF_LINK_UPDATE, dlmopen, musl and static binaries, libraries' own RUNPATH, other library directories, process_vm_writev, writes to /proc/<pid>/mem, reflective and JIT loaders, SysV shm, io_uring opens, kernel modules, binfmt_misc, and GCONV_PATH and interpreter variables. | Not true |
| mTLS enrollment | `server/ingestion` Postgres integration tests; real `hookmon-bus` and `hookmon-server` on drl-nuc8i3bek | Since step 7a: the bus enrolls on a separate port (9444) that authenticates the server only, using a token from the server config (constant-time compare, expiry, optional single-use). The server signs the CSR and assigns the HostID as the certificate CN. Every other RPC (port 9443) requires a CA-signed client certificate, and the HostID comes from that certificate, never from the message. Since 7b, TLS is the default: the server and the bus refuse plaintext unless `--insecure` is given. | Verified |
| SIEM connectors (Syslog/CEF, Splunk HEC, Elastic, webhook, Kafka) | `TestSIEM_RealStackCanaryReachesSyslogAndWebhook` on drl-nuc8i3bek; `server/connectors` tests | Since step 7d, connectors are configured in the server config, and a bad setting fails startup. Each connector delivers asynchronously from its own queue. A BPF canary reached real syslog and webhook receivers: an RFC 5424 line with valid CEF fields, and the full JSON event. AGENT_OFFLINE reached both after the bus stopped. Splunk HEC, Elastic (bulk, auth, ILM policy and index template) and Kafka are tested only against stand-ins (`httptest` servers and sarama's mock producer), not real products. Syslog has no TLS, and Kafka has no TLS or SASL. | Verified |
| Allowlist scopes and learning mode on the server | `test/integration/policy_test.go`; `pkg/allowlist` tests; real stack on drl-nuc8i3bek | Since step 7c, candidates are approved or rejected through the API and CLI, either for the fleet or for one host (a `host_id`-scoped entry). After all 14 PENDING entries were approved, the only non-ALLOW events came from a newly loaded BPF canary. A policy change through the API takes effect in about 26 ms, with no restart; SIGHUP also reloads. The dashboard approval page comes in 7e. | Verified |
| Dashboard pages (event feed, policies, hosts, investigation, settings) | `dashboard/e2e/smoke.spec.ts` (Playwright) against the real server on drl-nuc8i3bek; `TestIntegration_WebSocketFanOut` | Since step 7e, all six pages render real data from a seeded server: events (200 rows, live feed), investigation (BPF program tag), "allowlist this event", hosts (8 of 8 sensors alive), policies (edit, enable/disable), pending approvals (42), and settings (real enrollment command, connector status). The WebSocket checks the same token as REST, sent as a subprotocol so it never appears in a URL. It also checks Origin, and fans every event out to every tab: two tabs each received the same 62 live events. | Verified |
| Appliance and package formats (OVA, QCOW2, VHD, ISO, DEB, RPM, Ansible, compose) | CI job "Compose appliance"; infinichat-u9 (compose, Packer under KVM, Ansible appliance role); drl-nuc8i3bek (DEB, Ansible agent role); Rocky 9 container and a Rocky 9.8 VM (RPM, Ansible agent role) | Since 7g: the compose appliance runs, and CI checks it on every push. QCOW2 is built with Packer, VHD and OVA are converted from it, and each boots under QEMU/KVM to a healthy TLS server. The DEB installs, enrolls into the compose appliance from a second host, and purges cleanly. The RPM builds, installs and erases in a pinned Rocky 9 container. On a Rocky 9.8 VM the Ansible agent role installs it, and the bus enrolls with 8 of 8 sensors alive (since 3465875). Both Ansible roles, agent and appliance, work and are idempotent. Not true as worded: there is no ISO (bare-metal installer); on bare metal, install Ubuntu 24.04 and use the Ansible appliance role. Untested: importing the OVA into VMware or VirtualBox, the VHD into Hyper-V or Azure, and RHEL itself (its rebuild, Rocky 9.8, was tested). | Not true |

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
| Detaching a sensor's link marks it dead within 30 s | `TestHeartbeat_LinkDetach` | Not possible as written on 5.19, and on 6.17 either (infinichat-u9, 2026-10-11, static bpftool v7.7.0): `bpftool link detach` returns EOPNOTSUPP for perf_event links, and the hook keeps running. The test skips with that reason. The dead path is covered by `TestHealthCycleDetachedHookGoesDead` and `TestHealthCycleAttachmentCheckBlocksBeat`; the worst case is 20 s with a 15 s threshold and a 10 s cycle. | Code reading |
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

### Step 7c: Policy and learning mode (2026-10-10)

Ran on drl-nuc8i3bek with a real root bus (enrolled), a TLS server and Postgres 16.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| 5 minutes of fleet learning on an idle host produces a PENDING list | Real stack | 14 PENDING entries: 13 BPF_INVENTORY programs, by tag and type, each seen 12 times; 1 shared-memory entry from `/opt/slimjet/slimjet`, pattern `unknown`, seen 576 times. All on one host. | Verified |
| After approving everything, a new BPF canary is the only alert | Real stack, `hello_bpf_v2.o` | The only non-ALLOW events were 6 from `load_canary`: 4 BPF_LOAD (including cilium/ebpf feature probes) and 2 BPF_ATTACH. They were CRITICAL because they ran as root. The 50 slimjet shm events in that window matched the learned entry. | Verified |
| A policy change through the API takes effect within 1 s, with no restart | `test/integration/policy_test.go`; real stack | 26 ms from the start of the POST to the next event stored as ALLOW. On the real stack, a canary launched 8 ms after the POST was allowed. SIGHUP reload is tested with a real signal. | Verified |
| One matcher for the server and the e2e tests | `pkg/allowlist`; `TestPolicy_*ByProgHash` | The e2e copy of the matcher is deleted. The policy tests now run through the real matcher and assert the same results. | Verified |
| `prog_hash` is stored | Postgres integration test | Stored and read back (migration 006). | Verified |
| No regressions | `make build-all`, `go vet ./...`, `go test -race ./...`, root `go test -race ./agent/...`, 18 Postgres tests, `make test-e2e` | Pass. e2e: 38 pass, 2 skip, 0 fail. | Verified |

Design:
- **Severity.** The server keeps the bus's rating, with two increases: an event from root becomes CRITICAL, and a WARN event with no exe hash becomes ALERT. Neither increase applies to an event the bus rated INFO, or to ELF_RPATH. The full table is in CLAUDE.md.
- **Dedupe key.** The key is event type, exe hash, subject, and a flag for whether the event came from a container.
- **Shared memory is keyed on the bus's pattern, not the segment name.** On the first run, Chromium's random names made 566 of 599 candidates.
- **Containers.** The bus reports container IDs, not image names. The key uses "ran in a container", and `container_image` in an allowlist entry is still compared against the container ID.
- **Multiple matches.** When several entries match, the most restrictive action wins.

Fixed while merging:
- The server turned an event with no severity into INFO, which the new table never raises. It now leaves the severity empty, so the engine rates the event itself.
- The shm `bpf_related` rule matched "bpf" anywhere in a name. That made Chromium's random `.org.chromium.Chromium.BtbpfW` an ALERT. It now needs "bpf", "ebpf" or "libbpf" as a separate word.

### Step 7d: Alerting and SIEM (2026-10-10)

Ran on drl-nuc8i3bek with a real root bus (enrolled), a TLS server, Postgres 16, and syslog and webhook receivers in `alpine:3.20` containers pinned by digest. All were removed afterwards.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| A BPF canary load reaches syslog and webhook | `TestSIEM_RealStackCanaryReachesSyslogAndWebhook`, run twice | Syslog received `<130>1 2026-10-10T23:46:59.185902Z drl-NUC8i3BEK hookmon - BPF_LOAD - CEF:0\|HookMon\|HookMon\|1.0\|BPF_LOAD\|BPF Program Loaded\|10\|... cs2=hello_count cs5Label=ProgTag cs5=aa93b500236fde34 ...`. The webhook received the event JSON with `bpf_detail.prog_hash` set to the tag and `policy_result.action` ALERT. | Verified |
| Hosts going offline reach the connectors | Real stack, plus an integration test | AGENT_OFFLINE reached the webhook 8.8 s after SIGTERM (10 s timeout) and also reached syslog. In the integration test it arrived in 2.2 s (2 s timeout). | Verified |
| Connector config errors fail startup | `server/config_test.go`, `cmd/hookmon-server/main_test.go` | Pass. | Verified |
| A slow sink doesn't block ingestion; drops are counted | `server/connectors` queue tests | Pass. | Verified |
| Splunk HEC, Elastic bulk with auth and ILM, webhook batching (no retry on 4xx), Kafka | `httptest` and sarama mock tests | Pass, against stand-ins only. | Verified |
| No regressions | `make build-all`, `go vet ./...`, `go test -race ./...`, root `go test -race ./agent/...`, 20 Postgres tests, `make test-e2e` | All pass. e2e: 38 pass, 3 skip (the SIEM test is env-gated), 0 fail. | Verified |

Design:
- Each connector has a `min_severity`. The default, ALERT, sends unallowed events at that level or above, deduplicated for 5 minutes. INFO or WARN sends every event. AGENT_OFFLINE always goes out.
- The dedup key is host + exe path + the learning key. On the NUC, `load_canary`'s feature-probe loads would otherwise have hidden the canary.
- CEF uses only valid keys (no `cs7`) and has fields for every event type. Pipes are escaped only in the header, as the CEF spec says. Events without a process no longer claim `suid=0`.
- Elastic installs a delete-after ILM policy (90 days by default) and an index template at startup. `ilm.setup: false` skips this.

Fixed while merging: AGENT_OFFLINE timestamps were in local time; they are now UTC. Doc lines that still said connectors didn't work are corrected.

Still open:
- No AGENT_RECOVERED event is sent.
- The hostname in events (syslog HOSTNAME, CEF `shost`) is what the bus reports. The host ID comes from its certificate (7f).

### Step 7e: API and dashboard (2026-10-11)

The real server and Postgres ran on drl-nuc8i3bek, seeded by a 3-minute learning run with a real root bus. Playwright ran on the Mac against it over the tailnet, with browsers installed under the session scratchpad.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| Two browser tabs both receive every event | Playwright (two pages); two raw WebSocket clients against the server binary; `TestIntegration_WebSocketFanOut` | Same events in the same order in each: 62 in Playwright, 78 for the raw clients, 40 of 40 in the integration test. | Verified |
| An unauthenticated WebSocket is rejected | Raw clients against the server binary | No token, a wrong token, or a token in the URL get 401. A foreign Origin gets 403. | Verified |
| Playwright smoke test opens every page and sees real data | `npx playwright test` with `HOOKMON_E2E_URL` | 2 of 2 tests pass: events, investigation, allowlist-from-event (created and then deleted), hosts, policies (toggled), pending (42), and settings. | Verified |
| Policy edits are validated | Go tests | PUT/PATCH work. Bodies over 64 KiB get 413. Unknown fields and bad actions are refused. PENDING entries can't be edited. | Verified |
| Lists return `[]` when empty | Go tests | Pass. | Verified |
| No regressions | `make build-all`, `go vet ./...`, `go test -race ./...`, root agent tests, 23 Postgres tests, `make test-e2e`, `npx tsc --noEmit`, `npx vite build` | Pass. e2e: 38 pass, 3 skip, 0 fail. | Verified |

Design:
- The WebSocket token travels as a `hookmon.bearer.<base64url>` subprotocol, and the server answers with `hookmon.v1`.
- Each subscriber gets a 256-event buffer. A subscriber that falls behind is disconnected (close code 1013), and the dashboard reconnects and reloads.
- `api.allowed_origins` adds origins beyond the server's own.
- The Vite dev server moved to port 5173, with an HTTPS proxy and `ws: true`.

Still open, for 7f:
- A missing event and a database error both return 404 (`server/store/postgres.go:395`).
- The 256-event buffer between ingestion and the hub drops events silently when full (`server/ingestion/grpc.go:274`).
- The event feed loads its history twice on first load.

### Second kernel: e2e on infinichat-u9 (2026-10-11)

infinichat-u9 runs Ubuntu 24.04.2 with kernel 6.17.0-23, on x86_64 with 16 CPUs and Docker. The binaries, eBPF objects, canaries and e2e test binary were built on drl-nuc8i3bek from `main` at 14c176f. They ran on u9 unchanged: CO-RE objects compiled against 5.19 type info load on 6.17.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| Full e2e suite on kernel 6.17 | `e2e.test -test.v` as root | 38 pass, 2 skip (env-gated idle and SIEM tests), 1 fail. The failure was `TestHeartbeat_LinkDetach`: Ubuntu's `/usr/sbin/bpftool` wrapper has no binary for 6.17, so the test misread the broken tool as "the bus holds no link". `/etc/ld.so.preload` was absent before and after, and no canary library or container image was left behind. | Verified |
| Link detach on 6.17 | The same test, with static bpftool v7.7.0 first in PATH | `bpftool link detach id 330` failed with "Operation not supported". The hook kept running, ptrace_monitor stayed alive, and the test skipped with that reason. Detach-to-dead can't be exercised on 5.19 or on 6.17. | Verified |
| A broken bpftool is reported as such | `TestHeartbeat_LinkDetach` with the Ubuntu wrapper | The test now checks `bpftool version` first. It skips with "bpftool is not usable here … bpftool not found for kernel 6.17.0-23" instead of failing on a false reason. | Verified |

### Step 7f: Robustness (2026-10-11)

Ran on drl-nuc8i3bek with a real stack: a root bus enrolled with `--enroll-token-file`, a TLS server, and Postgres (`postgres:16-alpine`, pinned by digest, removed afterwards).

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| Every audit Security row is fixed or documented | `SECURITY.md` table, rows (a) to (u) | Every row is fixed and names its step and test, except `/status`. `/status` stays unauthenticated by design, and SECURITY.md gives the reason: root on the host can answer in the bus's place. | Verified |
| A handler panic does not crash the server | Hostile-proto test (nil entries, empty oneofs, huge strings) | Recovery interceptors on both gRPC listeners. The panicking call gets `Internal`, and the server keeps serving. Events with no type or an unknown type are now refused; the test found they were being stored. | Verified |
| The rate limiter is keyed by certificate and bounded | Unit test with many distinct certificates | Keyed by the certificate's HostID. It holds at most 10,000 hosts and evicts the least recently seen. | Verified |
| Offline and recovered are consistent | Real stack, plus integration tests | Stopping the bus stored AGENT_OFFLINE 15.9 s later. Restarting it stored exactly one AGENT_RECOVERED 6.8 s later. A WebSocket client and an ALERT-level webhook received both. A bus can no longer send lifecycle events itself. | Verified |
| The hostname comes from enrollment | Real stack | All 152 events carry the enrolled name, though the restarted bus reported a different one. | Verified |
| The collector's SSH mode verifies host keys | Test with a real `ssh-keygen` host key | An unknown key is refused and a known key is accepted. Startup fails closed without a known_hosts file. The collector uses the host's configured status port. | Verified |
| No read loop spins on an error | `agent/sensors/readloop_test.go`; `agent/gosensor_health_test.go` | All six ring-buffer loops back off from 10 ms to 1 s. A persistent error fails the sensor's attachment check. The fanotify watcher now uses the same tracking, and its sensors stop beating while reads keep failing (added while merging). | Verified |
| A missing row is 404, a database error is 500 | API tests | Pass. | Verified |
| The enrollment token is kept out of the process list | Real stack, `ps` during first start | `--enroll-token-file` was used, and the token never appeared in `ps`. `--enroll-token` still works but warns. | Verified |
| A wrong `--ca-file` fails fast | Real bus | Exits 1 after 0.03 s, with an error naming `--ca-file`. | Verified |
| The event feed loads history once | Playwright first-load spec | 1 history request, where the old dashboard made 2. | Verified |
| No regressions | `make build-all`, `go vet ./...` (also `-tags e2e`), `go test -race ./...`, root `go test -race ./agent/...`, 27 Postgres tests, `make test-e2e` | Pass. e2e: 38 pass, 3 skip, 0 fail. | Verified |

Test expectation changes: `TestWire_StreamEvents` and `TestSIEM_AlertsReachSyslogAndWebhook` now expect the enrolled hostname instead of the one the bus sent. The dashboard smoke test expects the `--enroll-token-file` enrollment command.

Still open: `hostTracker` is unbounded in insecure (development) mode.

### Step 7g, part 1: Compose appliance (2026-10-11)

Ran on infinichat-u9 under compose project `hookmon-7g`, with an override that moves the published ports off the host's own services. Torn down afterwards. CI runs the same checks on every push; first green run at fd70a45.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| `docker compose up` on a clean Linux host gives a working stack | `hookmon-init.sh --mode compose`, then `docker compose up -d --build --wait` | All 8 services became healthy in 1:20 with nothing cached: server, Postgres, Loki, Prometheus, Pushgateway, Alertmanager, Grafana and the collector. Every image is pinned by digest. | Verified |
| The stack works | `deploy/appliance/check-stack.sh`, run twice | Every check passes. Secrets are 0600. Postgres is not published. TLS health returns `{"status":"ok"}`. The dashboard and its assets load. The API token gives 401 without it and 200 with it. The enrollment port verifies the hostname. Grafana is healthy and provisioned. Prometheus targets are up, with 5 of 5 alert rules loaded. Alertmanager is up. The collector's `push_time_seconds` is fresh. Loki is ready. | Verified |
| The first-run script is idempotent | `hookmon-init.sh` run twice, hashes compared | No file changed. Edge cases tested: SAN change, `--new-enroll-token`, `--force`, a wrong mode, half a CA missing. | Verified |
| The same, in CI | GitHub Actions job "Compose appliance" | Green, on the merged code including 7f. | Verified |

### Step 7g, part 2: DEB, RPM and the Ansible agent role (2026-10-11)

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| `make package-deb` from a clean tree | drl-nuc8i3bek, fresh extract | Builds the eBPF objects, the helper and the bus, then the `.deb`. `dpkg-deb --info/--contents` shows everything root-owned and `Depends: libc6 (>= 2.34)`. | Verified |
| The DEB ships `hookmon-bus`, a unit, a config and a state directory | `dpkg -i`, then configure, start, upgrade and purge on the NUC | Installed, the unit is enabled but stays inactive until `/etc/hookmon/enroll-token` or a certificate exists. With a token file it enrolled: key and certificates 0600, token never visible in `ps`. The host showed ONLINE with 8 of 8 sensors and 130 events. A reinstall kept the edited `bus.yaml`. `dpkg --purge` removed everything. | Verified |
| The RPM builds, installs and erases | `rockylinux:9` container pinned by digest, on infinichat-u9 | `rpm -qpl` lists the expected files. `rpmlint` reports only the static Go binary and the 0750 log directory, both on purpose. `dnf install` enabled the unit, a reinstall kept the edited config, and `rpm -e` removed everything. The bus was not run on an RPM host. | Verified |
| The Ansible agent role is valid and idempotent | `ansible-playbook --syntax-check`, `ansible-lint` (production profile), a real run against the NUC | Both checks pass. The real run made 8 changes, and the host showed ONLINE with 8 sensors. The rerun made 0 changes. Purged afterwards. The role's dnf path was only linted. | Verified |

Unit hardening: the capability bounding set is limited to what the bus needs, with `NoNewPrivileges` and a seccomp filter. Two kinds of option are left out on purpose:
- Options that give the service its own mount namespace (`ProtectSystem`, `PrivateTmp` and the like). The bus resolves other processes' executables against its own mount namespace.
- `RestrictSUIDSGID`. On the NUC it made `openat2()` return ENOSYS, which killed shm_monitor.

### Step 7g: Cross-host acceptance (2026-10-11)

Compose appliance on infinichat-u9 at 4f2989a, under project `hookmon-xhost` with alternate ports. DEB built from the same tree and installed on drl-nuc8i3bek. Checks ran from the Mac over the tailnet. Both sides were torn down afterwards.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| The appliance comes up | `hookmon-init.sh --mode compose --hostname infinichat-u9 --ip 100.95.196.103`, then `docker compose up --build --wait` | All 8 services healthy. `/api/v1/health` returns `{"status":"ok"}` from the Mac, with the generated CA. | Verified |
| A bus installed from the DEB on a second host enrolls | `make package-deb` and `dpkg -i` on the NUC; token file plus CA; `systemctl start hookmon-bus` | The unit stayed inactive until configured. Once configured, the bus enrolled and wrote `bus.key`, `bus.crt` and `ca.crt` with mode 0600. The token never appeared in `ps`. | Verified |
| Its events show in the dashboard | REST API; Playwright `every page renders the server data` | The host `drl-NUC8i3BEK` is ONLINE with 8 of 8 sensors alive, and 233 events arrived (169 SHM_CREATE, 33 DLOPEN, 31 BPF_INVENTORY). In Playwright, the event feed, investigation, allowlist-from-event and hosts pages rendered that data. Fleet learning produced 46 PENDING entries. | Verified |
| The full smoke test on a fresh appliance | Playwright | 2 of 3 tests passed. The page walk stopped at Policies: the test assumed an approved entry already exists, which is true of a seeded server but not of a fresh appliance. The test now creates a temporary entry when there is none and deletes it afterwards; 7h runs it in CI against a fresh appliance. | Verified |
| Clean removal | `dpkg --purge`; `docker compose down -v --rmi all` | The unit, `/var/lib/hookmon` and `/etc/hookmon` are gone from the NUC. The stack, its volumes and its images are gone from u9. The user's own containers and images on both hosts are untouched. | Verified |

### Step 7g, part 3: Packer image, VHD/OVA, Ansible appliance role (2026-10-11)

Built and booted on infinichat-u9 under KVM. qemu-system-x86 and qemu-utils were installed through apt, with David's approval. Packer ran as a pinned standalone binary under `/tmp`. Every VM and image was removed afterwards.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| Packer builds the QCOW2 appliance | `make appliance-qcow2` recipe | 2m01s, 837 MiB. The base is the Ubuntu 24.04 cloud image (`release-20260926`), pinned by URL and sha256 and seeded through NoCloud. The image ships no keys, tokens, passwords, host keys or machine ID. | Verified |
| First boot configures and starts the server | Boot under KVM | `hookmon-firstboot` runs `hookmon-init.sh --mode host` with the VM's hostname and IPs, sets up PostgreSQL, and starts `hookmon-server`. After a reboot it does not run again, and the CA stays the same. A boot with no cloud-init datasource still comes up healthy. | Verified |
| QCOW2, VHD and OVA each boot to a healthy server | `curl --cacert` from u9 against each image | `/api/v1/health` returns ok; without the CA, curl refuses. The dashboard index and its JS return 200. The API token gives 401 without and 200 with. TLS verifies on enrollment port 9444. | Verified |
| The Ansible appliance role deploys the server and is idempotent | `--syntax-check`, `ansible-lint` (production profile), and a real run against a throwaway Ubuntu 24.04 VM | First run: changed=12, then the same checks pass. Second run: changed=0. | Verified |
| ISO | — | Not shipped. `build-iso.sh` (a stub) is deleted, and so is the make target. | Not true |
| Hypervisor imports (OVA into VMware or VirtualBox, VHD into Hyper-V or Azure) | — | Not tested. | Code reading |

Design:
- nginx is gone; the server terminates TLS on 8443 and serves the dashboard.
- The VM runs `hookmon-server` as user `hookmon` in a sandboxed unit, with PostgreSQL 16 on loopback.
- ufw allows 22, 8443, 9443 and 9444.

Fixed while merging:
- `hookmon-init.sh` printed the enrollment command with the secret in `--enroll-token`. It now prints `--enroll-token-file`.
- The deployment guide now asks for clock sync, because certificates are valid from the moment they are made. u9's clock running 38 s slow made one check fail until it caught up.

### Step 7h: Tests (2026-10-11)

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| Coverage for the packages the plan names | `go test -cover` with `HOOKMON_TEST_PG_DSN`, on drl-nuc8i3bek | server/api 85.0% → 94.6%; server/store 69.3% → 86.6%; pkg/crypto 74.3% → 95.2%; agent/enrichment 87.5% → 93.0%; cmd/hookmon-collector 45.6% → 84.2%. | Verified |
| Full path: canary → bus (not console) → enrollment → gRPC → server → Postgres → policy → connector → WebSocket | `make test-e2e-full` (`TestFullPath_*`), 3 runs in a row on the NUC | 3 of 3 pass. The bus enrolls with a single-use token file (key and certificate 0600, CN = host ID, token use recorded) and reports 8 sensors. The canary loads twice, before and after an ALLOW entry is added through the API. Each event is found by ID in Postgres, at a webhook receiver and on a WebSocket client, with the same policy result everywhere: CRITICAL/ALERT the first time, INFO/ALLOW with the entry's ID the second. | Verified |
| Postgres tests run in CI | GitHub Actions run at 9c8be31: Go job with a pinned Postgres service, plus a guard step that fails if they skip | Pass. The guard step confirms they ran. | Verified |
| The dashboard e2e runs in CI against a fresh appliance with a real bus | GitHub Actions job "Dashboard e2e (appliance + bus)" at 9c8be31 | On the GitHub runner (Azure kernel 6.17), the eBPF objects built. A root bus enrolled into the fresh compose appliance with 8 of 8 sensors alive, and all Playwright tests passed. This includes the smoke test's temporary-policy path on a fresh server. | Verified |
| e2e as a separate job | `.github/workflows/e2e.yml` | `workflow_dispatch` only, on `[self-hosted, linux, hookmon-e2e]`. No runner is registered: registering one is David's call. CONTRIBUTING.md explains how, and why fork PRs can't trigger it. | Code reading |
| No regressions | `make test-e2e` on the NUC; full suite as root with the DSN, `-race` | e2e: 38 pass, 4 skip (env-gated), 0 fail. Full suite: 680 pass, 0 fail, 1 skip (on purpose). | Verified |

### Deferred docs: API reference and allowlist guide (2026-10-11)

`docs/api-reference.md` covers all 20 routes, the WebSocket, event JSON, query parameters, settings, learning, approve/reject and allowlist-from-event, with CLI equivalents. `docs/allowlist-guide.md` covers matching, the dedupe key, learning mode, review, scopes, severity and bootstrapping, and lists the pitfalls. Every curl and `hookmon-cli` example in both ran against a real TLS `hookmon-server` on drl-nuc8i3bek (Verified). Not run: the browser JavaScript WebSocket snippet, and the 503 response.

Bugs found while writing them, all fixed in the follow-up commit (`10e0f4f` on its branch; each has a named test, and the NUC ran the full suite with Postgres and a live server under `TZ=America/New_York`):
- An empty API token authenticated.
- `hosts.last_event_at` was never written.
- A duplicate policy ID returned 500 instead of 409.
- Unparseable `since`/`until` were ignored.
- 401 responses had a text/plain content type.

Also fixed in that commit: timestamps now read back in UTC whatever the server's time zone (`TestStore_TimesReadBackInUTC`). Malformed `limit` and `offset` now return 400, as `since` and `until` do. Still documented as known issues in `docs/api-reference.md`:
- A policy created without `enabled` is stored disabled.
- `event_type` and `severity` filters accept any string.

### Step 8: First five minutes on two real hosts (2026-10-11)

Evidence is in `docs/evidence/`: `step8.md` (write-up), `step8-drl-nuc8i3bek-events.json` (646 events), `step8-infinichat-u9-events.json` (469 events) and `step8-grafana.png`.

- **Hosts, as they were (David's decision):**
  - drl-nuc8i3bek: a workstation on kernel 5.19.
  - infinichat-u9: a container host on kernel 6.17, running Docker, containerd and GPU/LLM services.
  - Neither is a Kubernetes node, and neither runs Cilium or Falco, so the plan's k8s-node and Cilium/Falco cases are not covered.
- **Coverage held:** each bus started fresh, enrolled into a compose appliance on u9, and pushed to its Loki. All 8 sensors were alive on both hosts for the whole window, and the bus counters match the stored events.
- **NUC:** SHM_CREATE 570, DLOPEN 39, BPF_INVENTORY 33, EXEC_INJECTION 4. Server severity: INFO 603, CRITICAL 30, WARN 13.
  - 88% of events were INFO shared-memory segments from the Slimjet browser.
  - 33 of the 43 non-INFO events came from the capture's own SSH login and sudo.
  - The other 10 came from a parallel test removing a Postgres container.
- **u9:** EXEC_INJECTION 410, BPF_INVENTORY 34, DLOPEN 24, ELF_RPATH 1. Server severity: CRITICAL 419, INFO 34, WARN 15, ALERT 1.
  - 87% of events were CRITICAL EXEC_INJECTION from Docker healthchecks. containerd's shim runs `runc` with `LD_LIBRARY_PATH=/opt/containerd/lib:`, so every healthcheck run is one CRITICAL event.
  - A root cron PAM session gave 9 CRITICAL.
  - llama-server's RUNPATH has an empty entry (ALERT).
- **First BPF inventory:** 32 programs on the NUC and 33 on u9. They are systemd device and firewall filters, runc device filters, two snap filters, and the bus's own programs. Nothing unexpected. The same `.o` gets different tags on 5.19 and 6.17.
- **Learning:** 99 PENDING entries after the windows.
- **Bugs the capture found:**
  - The Fleet Health banner (fixed; see the row above).
  - Unlabelled Active Sensors tiles (now labelled per host).
  - The compose docs didn't say to list buses in `prometheus/buses.yml` and `collector.yaml` (now documented).
- **Open, for David:** a fresh deployment on a Docker host raises a CRITICAL on every container healthcheck until learning mode is run and its entries approved. Ranking `LD_LIBRARY_PATH` directories by writability, as RPATH entries now are, would make these INFO. The plan doesn't ask for that, so nothing was changed.

### Step 9: Release gate (2026-10-11)

The claims table above has 20 rows: the 15 claims the plan lists and 5 server-path claims. No cell is blank. 15 are Verified, 1 is Code reading ("read-only in default mode"), and 4 are Not true:
- "SHA256 bytecode hashing": detection works, through the kernel program tag, not SHA256.
- Enforcement mode: no code exists.
- "Every way code enters a Linux process": see `docs/threat-model.md` for the gaps.
- The formats row: there is no ISO.

David edits the blog from this table.

Checked against the plan's "Done means", at `ebe9d8d`:

| Item | Evidence | Result |
| --- | --- | --- |
| Steps 1–5 and 7–9 are committed | `git log` on main; this ledger's step log | Done. Step 6 is out of scope. Every step is pushed. |
| CI is green | GitHub Actions run at ebe9d8d | All four jobs pass: Go Build & Test (with Postgres), Dashboard Typecheck & Build, Compose appliance (including the promtool rule tests), and Dashboard e2e (a real root bus enrolled on the runner, 8 of 8 sensors alive, Playwright). |
| The e2e suite passes on the Linux host, including the full-path test from 7h | `make test-e2e` and `make test-e2e-full` on drl-nuc8i3bek at ebe9d8d | `make test-e2e`: 38 pass, 4 skip, 0 fail. The skips are the full-path test (run by its own target), the opt-in 10-minute idle test, link detach (the kernel returns EOPNOTSUPP), and the env-gated SIEM test. `make test-e2e-full`: PASS. The suite also passed on kernel 6.17 (infinichat-u9). |
| The compose appliance runs on a clean host | CI job "Compose appliance"; infinichat-u9 (7g, cross-host and step 8) | Done. |
| `docs/claims.md` has no row left blank | This table | Done. |

Left for David:
- **Docker hosts:** a fresh deployment raises a CRITICAL on every container healthcheck until learning mode has run and its entries are approved (step 8).
- **e2e runner:** registering a self-hosted runner for `e2e.yml`.
- **Untested imports:** importing the OVA or VHD into real VMware, VirtualBox, Hyper-V or Azure, and the RPM on RHEL itself. Rocky Linux 9.8 was tested after the release gate.

### After the release gate: the bus on an RPM host (2026-10-11)

A Rocky Linux 9.8 VM under KVM on infinichat-u9: `Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2` (sha256 `92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8`), kernel 5.14.0-687.10.1.el9_8.0.1, SELinux enforcing. The RPM was built in the pinned `rockylinux:9` container and installed with the Ansible agent role. The bus enrolled into a compose appliance on u9. The VM and the appliance were removed afterwards.

| Check | Command | Result | Status |
| --- | --- | --- | --- |
| The bus runs from the RPM on a RHEL 9 kernel, at 747f74e | Ansible agent role; `/status`; one test trigger per sensor | Not at first. The role's dnf path worked (8 changes, then 0 on the rerun) and the bus enrolled, but only 6 of 8 sensors were alive. `bpf_syscall` and `shm_monitor` failed to attach ("cannot create bpf perf link: permission denied"), so no BPF_LOAD, BPF_INVENTORY or SHM_CREATE event arrived. `ptrace_monitor` showed alive but read each argument one slot over, and `strace -p` raised nothing. | Not true |
| Cause | tracefs formats and kernel BTF on the VM | The three sensors hook `syscalls:sys_enter_*`/`sys_exit_*` but took `struct trace_event_raw_sys_enter`/`_exit`, the `raw_syscalls` record. RHEL 9 adds `preempt_lazy_count` to the common trace header (12 bytes, not 8), so CO-RE put `args` and `ret` at byte 24, while the syscalls record keeps them at 16. A read past the end of the record makes the kernel refuse the attach. SELinux was not involved: no AVC denials. | Verified |
| The fix, at 3465875 | The same VM, a fresh install | The three sensors take `struct syscall_trace_enter`/`_exit`, the tracepoints' own records, from the kernel BTF. All 8 sensors alive, the host ONLINE. Each trigger raised its event: EXEC_INJECTION, SHM_CREATE (pattern `bpftime`), DLOPEN, LINKER_CONFIG, LIB_INTEGRITY, ELF_RPATH (CRITICAL), BPF_LOAD with the tag `bpftool` showed, 16 BPF_INVENTORY events, and PTRACE_INJECT for `strace -p` (PTRACE_SEIZE, the right target PID and comm) and for a POKEDATA at the exact address written. The journal had no warnings. | Verified |
| The packaged bus is static | `file`; `rpm -qpR` | Built with `CGO_ENABLED=0`, as `make package-rpm` builds it, the bus is static. The RPM still needs glibc 2.34 or later, for the dlopen helper, which calls glibc's `dlopen`. The first run above packed a `make build-bus` binary, which is dynamic. | Verified |
| Uninstall | `dnf remove hookmon-bus` | The unit, the binaries, `/var/lib/hookmon` and `/var/log/hookmon` are gone, and no bus BPF program is left. The edited config stays as `bus.yaml.rpmsave`, and the role's copy of the package stays in `/var/cache/hookmon`. | Verified |
| No change on 5.19 and 6.17 | `make test-e2e` and `make test-e2e-full` on drl-nuc8i3bek; `e2e.test` on infinichat-u9 | The same as at the release gate. drl-nuc8i3bek: 38 pass, 4 skip, 0 fail, and the full-path test passes. infinichat-u9 (6.17): 38 pass, 4 skip, 0 fail. The skips are the same four. Every bpf_syscall, shm_monitor and ptrace_monitor test passes on both. | Verified |
| A guard for kernels the e2e hosts don't cover | `TestSyscallTracepointContext` | Fails if a syscalls tracepoint program in `agent/sensors` takes any other struct. It fails on the 747f74e sources. | Verified |

The health check did not catch the `ptrace_monitor` fault: a heartbeat shows that the hook runs, not that it reads its arguments correctly.

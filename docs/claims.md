# HookMon claims ledger

One row per claim the blog makes. Status values:

- **Verified**: a command or test was run and the result was seen.
- **Code reading**: the code was read but nothing was run.
- **Not true**: the code does not do what the claim says.

A claim is never made true by changing its test. Rows are updated as each fix-plan step lands. The step log below records what was run.

## Claims

| Claim | Test or command | Result | Status |
| --- | --- | --- | --- |
| Eight sensors | Audit of `agent/sensors/` at d961b69 | Eight implementations exist. `elf_rpath` is not a started sensor: it only runs on events other sensors emit (`agent/agent.go:240`). | Code reading |
| SHA256 bytecode hashing detects a modified program with the same name | Audit of `agent/sensors/bpf_syscall.go` | The hash covers the loader's buffer, which includes map fd numbers, and is read from `/proc/<pid>/mem` after the call. It is unstable across loads and races the loader. To be replaced by the kernel program tag in step 4. | Not true |
| Enrichment with PID, UID, cmdline, exe path, exe SHA256, cgroup, container ID | Audit of `agent/enrichment/` | Partial. fanotify events default UID to 0. Container IDs are only recognized for docker/64-hex. The exe hash uses the host-namespace path for container processes. | Not true |
| `lib_integrity` baselines at startup; package-manager writes are INFO | Audit of `agent/sensors/lib_integrity.go` | No baseline is taken (`OldHash` is never set). There is no package-manager detection. | Not true |
| `linker_config` catches linker-cache poisoning | Audit of `agent/sensors/linker_config.go` | `/etc/ld.so.cache` is not watched. Only close-write events are seen, so rename, delete and `sed -i` are missed. | Not true |
| `ptrace_monitor` sees register manipulation | Audit of `agent/sensors/ptrace_monitor.c` | Filters only ATTACH, SEIZE, POKETEXT and POKEDATA. SETREGS, SETREGSET and POKEUSER are not seen. | Not true |
| `elf_rpath` audits every exec | Audit of `agent/agent.go` | It runs only on events emitted by other sensors, not on every exec. | Not true |
| Heartbeat every 10 s independent of traffic | Audit of the sensor `.c` files and grep of Go code | The heartbeat maps are written only when a hook fires. No Go code reads them, and liveness is driven by events. | Not true |
| `/status` plus a 30 s collector poll | Audit of `agent/observability/status.go`, `cmd/hookmon-collector/main.go` | Implemented: 30 s default interval, pushes to Pushgateway. | Code reading |
| Four-row alert hierarchy, including "zero events for 24h" | `deploy/docker/grafana/alerts/hookmon-alerts.yaml` | There are three rules: HostUnreachable, SensorDead, FleetDegraded. There is no 24h-silence rule and no Alertmanager, so alerts notify nobody. | Not true |
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

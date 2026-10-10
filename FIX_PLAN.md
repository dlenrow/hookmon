# HookMon fix plan (revised)

Read this whole file before changing code. It replaces the "Fix order" section of the HookMon Audit doc. It adds what the audit missed, sets acceptance tests for every step, and ties the work to the claims the blog will make.

## 0. Scope (decided by David)

**Chosen: full product. Both paths ship working.**

- The published path is: sensor bus → Loki/Prometheus, and collector → Pushgateway → Grafana.
- The server path is: sensor bus → gRPC → hookmon-server → Postgres, plus allowlist, learning mode, enrollment, SIEM connectors, the React dashboard, the appliance and the packages.

The allowlist and learning mode live in the server (step 7). Step 6, a separate allowlist inside the bus, is not in scope. Do steps 1–5 first, then step 7, then steps 8–9.

## Ground rules

- Work on a Linux host with root, a BTF-enabled kernel (5.15 or newer), clang and bpftool. `prometheus.yml` already targets infinichat-1. Apple clang has no BPF target, so nothing involving eBPF counts as verified on the Mac.
- Every finished step ends with a commit and a short note in `docs/claims.md` (step 9). The note records the command you ran and its result. Use the audit's labels: "Verified" means you ran something and saw the result; "Code reading" means you didn't.
- Never make a test pass by weakening or deleting it. If a test is wrong, say why in the commit message.
- This is a reference design David will not maintain. Fix what the blog claims and what stops it from working. Don't add features beyond this plan.
- If a step can't be done as written (kernel limits, a library gap), stop that step, write down why in `docs/claims.md`, and move on.

## 1. Build (in progress; uncommitted changes exist)

Finish and commit the work already in the tree as its own commit.

Acceptance:
- On a clean clone, `make build-all` builds the five eBPF objects and every binary.
- CI's Go job passes.
- e2e tests sit behind their own build tag (for example `//go:build linux && e2e`), so the plain `go test ./...` in CI never runs them unprivileged.
- `Dockerfile.agent` builds `hookmon-bus`, not `hookmon-agent`.

## 2. Wire format (in progress; uncommitted changes exist)

The generated code under `gen/` was hand-written at HEAD and is being regenerated now. Finish that and commit it separately.

Acceptance:
- A bufconn round-trip test exists for every RPC in `agent.proto`.
- The bus reconnects after a send failure. Today `RetryLoop` runs once. Test it by killing and restarting the server; events must resume.
- A single goroutine owns `stream.Send`, because gRPC streams are not safe for concurrent sends.

## 3. Heartbeat and tamper detection

Today the five eBPF sensors write heartbeat maps only when their hook fires, and no Go code reads those maps. Quiet sensors are marked dead about 35 s after startup.

**Design: active probe.** Do not add a `bpf_timer` to write the map. A timer only proves the program is loaded; it keeps ticking after an attacker detaches the hook. What matters is whether the hook still runs. So every 10 s, the bus will:

1. Trigger each hook itself with a harmless call. The heartbeat write already happens before the event filter, so any call that hits the hook updates the map. Candidates:
   - `bpf_syscall`: the bus's own map lookup already triggers it.
   - `shm_monitor`: `openat` on any path.
   - `ptrace_monitor`: `ptrace` with an invalid request; the `sys_enter` tracepoint fires before the kernel rejects it.
   - `exec_injection`: run `/bin/true` once a minute.
   - `dlopen_monitor`: a small helper that calls `dlopen` (the code in `test/canary/dlopen_canary.c` will do).
   - Confirm each one on the target kernel.
2. Read every `hookmon_heartbeat_*` map. A sensor is alive only if its map value moved forward since the last check. Map values are `CLOCK_MONOTONIC`; compare them against the same clock.
3. Also check that each sensor's program ID and link are still present (cilium/ebpf `Program.Info`, `Link.Info`). This is a second, independent signal.
4. Drop the bus's own probe events by PID, in BPF or in Go, so they never show up as detections.

Also fix:
- A sensor that fails to start is reported `failed` and counts against `Overall()`. Today "unknown" is ignored, so a host with a missing sensor reports alive.
- Make `elf_rpath` a real started component (see step 4), or remove it from the registry.
- Read `DeadThreshold` from config instead of the constant.
- Add a Prometheus alert for collector silence: `time() - push_time_seconds{job="hookmon-collector"} > 90`. Today, if the collector dies, Pushgateway keeps serving the last "all alive" values forever.
- Add an Alertmanager service to compose with a placeholder webhook receiver, so the alerts route somewhere.
- Add the "sensors alive but zero events for 24h" alert from `theory-of-operations.md`, or delete that row from the docs.
- Let the `/status` bind address be configured. Pin the Pushgateway image version.
- Remove the personal hostname from `prometheus.yml`; use a commented example instead.
- **Limitation, write it down; don't try to solve it:** a root attacker can kill the bus and serve a fake "alive" on the status port. Put this in `SECURITY.md`. The blog will say it plainly.

Acceptance (e2e, Linux):
- An idle host shows all sensors alive for 10 minutes.
- Detaching one sensor's link with `bpftool link detach` marks that sensor dead within 30 s.
- `kill -9` on the bus makes the collector report the host unreachable within one poll.
- Stopping the collector fires the silence alert.

## 4. Sensor correctness

Each item below has an e2e test that does the attack and asserts the event.

**`elf_rpath` on every exec.** Add a `sched_process_exec` tracepoint program. It fires after every successful exec, covers both `execve` and `execveat`, and sees the new binary. It emits pid and filename into a light ring buffer. Go runs the RPATH analysis on every exec, cached by (device, inode, mtime). Cache "no RPATH" results too. Use a real LRU.
Test: a binary with `RUNPATH=$ORIGIN/../tmp`, run with a clean environment, produces an `ELF_RPATH` event.

**`exec_injection`.**
- Today only the first 64 environment variables are scanned. Raise the limit as far as the verifier allows. If a process has more variables than were scanned, emit an event flagged `scan_truncated`; never stay silent.
- Hook `execveat` too, or move the env scan to `sched_process_exec` and read the new process's `env_start..env_end`.
Test: `LD_PRELOAD` placed as the 100th variable is detected. An `execveat` with `LD_PRELOAD` is detected.

**`bpf_syscall`.** Three changes:
1. **Stable hash.** Today the hash covers the loader's buffer, which contains map file-descriptor numbers that change between loads, and it is read from `/proc/pid/mem` after the call. That read races with the loader, and it fails if the loader has already exited. Replace it with the kernel's view: after each `PROG_LOAD` event, find the new program by ID (`ProgramGetNextID` plus `Info()`) and record the kernel's `tag`, along with name, type, load time and `created_by_uid`. The kernel's tag zeroes the map-fd fields, so it is stable across loads on the same kernel. Keep the old hash only if you can make it equivalent (zero the immediates of `ld_imm64` pseudo-map instructions, both halves).
2. **Inventory.** At startup and every 5 minutes, list every loaded BPF program and emit a `BPF_INVENTORY` event per program, with a host summary. This catches programs loaded before HookMon started — the blog's "infinite dwell time" point — and today nothing does it.
3. **Attach coverage.** Capture `BPF_LINK_CREATE` and `BPF_RAW_TRACEPOINT_OPEN`. Give `MAP_CREATE` its own event type or drop it.

Tests:
- Loading the same canary twice gives the same tag.
- A modified canary gives a different tag.
- A program loaded before the bus starts appears in the first inventory.
- A link-based attach is reported.

**`shm_monitor`.**
- Severity by pattern: `bpftime` → CRITICAL, `bpf_related` → ALERT, anything else → INFO. Today every `/dev/shm` creation is CRITICAL.
- Check bpftime's real segment names and environment overrides in the upstream source, and match those, not only the canary's name.
- Hook `openat2` too.
- If bpftime can be installed on the test host, add one e2e test with the real runtime. The blog describes a real attack chain; today the test simulates it.

**`dlopen_monitor`.**
- Today it attaches only to the first host libc it finds. At startup and every 5 minutes, find each distinct libc (by device and inode) in `/proc/*/maps`, including container root filesystems, and attach to each one.
- Deduplicate events by (exe hash, library path).
- Record musl and static binaries as not covered in `docs/claims.md`.
Test: a `dlopen` inside a container with its own libc is detected.

**`linker_config` and `lib_integrity`.**
- Move to fanotify with directory-entry events: `FAN_REPORT_DFID_NAME` (kernel 5.9 or newer), plus `FAN_CREATE`, `FAN_DELETE`, `FAN_MOVED_TO` and `FAN_CLOSE_WRITE`. Directory-entry events are refused on mount marks, so use `FAN_MARK_FILESYSTEM` or one mark per directory.
- Watch `/etc/ld.so.cache`.
- At startup, record a baseline hash of every watched file. That fills `OldHash` and gives the blog's "baseline at startup" claim real code.
- Fill `InLdCache` by parsing `ld.so.cache`.
- Package-manager detection: if the writer's process ancestry includes dpkg, rpm, apt, dnf or yum, set severity INFO.
- If no fanotify mark succeeds, fail the sensor start.
- Get the UID from `/proc/<pid>/status` instead of defaulting to 0.
Tests: `sed -i`, `mv`, `cp`, `rm` and `ln -sf` against `/etc/ld.so.preload` and against a `.so` in `/usr/lib` each produce an event. An `apt-get install --reinstall` of one library produces an INFO event, not an ALERT.

**`ptrace_monitor`.** Add `PTRACE_SETREGS`, `PTRACE_SETREGSET` and `PTRACE_POKEUSER`. Fill `TargetComm`.

**Enrichment.**
- Use one hash format everywhere: `sha256:<hex>`.
- Cache the exe hash by (device, inode, mtime).
- For container processes, hash through `/proc/<pid>/root`.
- Recognize cri-containerd, CRI-O and libpod container IDs.

**Out of scope; list as not covered in `docs/claims.md`:** `process_vm_writev`, writes to `/proc/<pid>/mem`, memfd and reflective loaders that bypass `dlopen`.

## 5. Docs and packaging

- Fix every doc mismatch in the audit's Docs section: `--prometheus-port`, `hookmon-cli host add`, learning mode, the sensor list in `deployment-guide.md`, CONTRIBUTING and SECURITY claims, author emails, and paths in `CLAUDE.md` that don't exist.
- Packaging and the appliance are fixed in step 7g, not here.
- Write the missing spec docs: `docs/api-reference.md` and `docs/allowlist-guide.md`. The allowlist guide covers learning mode, approval and scopes.
- Add `docs/threat-model.md`: every way code enters a Linux process, and for each one, which sensor covers it or "not covered".

## 6. Bus-side allowlist — not in scope

The allowlist and learning mode live in the server; see step 7c.

## 7. Server path

Work in this order; each part depends on the ones before it. The audit's Blockers and Security sections have the file and line references.

### 7a. Enrollment and host identity

- Enrollment must work for a bus that has no client certificate yet. Use TLS with server-side authentication only, either on a separate enrollment port or on an `Enroll` RPC that is exempt from the client-cert requirement. Every other RPC still requires mTLS.
- `Enroll` checks the token, calls `SignCSR` and returns a signed certificate plus the CA certificate. Today it returns the CA certificate itself.
- Tokens:
  - Read them from server config. Today they are never passed in, so every enrollment is rejected.
  - Compare with `subtle.ConstantTimeCompare`.
  - Tokens expire, and can be single-use.
  - Drop the "length ≥ 32" check as the only validation.
- The server assigns the HostID and writes it as the certificate CN. It does not copy the requester's CN.
- On every later RPC, the server takes the HostID from the peer certificate and ignores any HostID inside the message. Today a host can send events or heartbeats as another host.
- The bus:
  - On first start with `--enroll-token` and no certificate, it generates a keypair (`GenerateAgentKeypair`, unused today), enrolls, and stores the key and certificate with mode 0600 under `/var/lib/hookmon`.
  - It then connects with mTLS.
  - Its heartbeat RPC carries the sensor-registry snapshot, so the server knows sensor health.
- Hosts are created at enrollment. Heartbeats update them. The offline watchdog fires.
- Fix the nil-PEM panics in `SignCSR`.

Acceptance:
- A fresh host enrolls with a valid token and appears in the inventory.
- An expired, reused or invalid token is rejected.
- A test proves host A's certificate cannot send events or heartbeats as host B.
- Stopping the bus raises an offline alert within the watchdog timeout.

### 7b. Secure by default

- The server refuses to start gRPC or REST without TLS unless `--insecure` is given. The bus refuses a plaintext connection unless `--insecure` is given. Today plaintext happens silently.
- REST runs on TLS (it is plain HTTP on 8443 today).
- The server serves the built dashboard. Today `Dockerfile.server` copies it in, but nothing serves it.

Acceptance: starting the server with no certificates and no `--insecure` exits with a clear error.

### 7c. Policy and learning mode

- One matcher package, used by the server and by the e2e policy tests. Delete the copy in `test/e2e/helpers.go:177-194`.
- The allowlist reloads on every API write and on SIGHUP. Today it loads once at startup.
- Learning mode, per host or per fleet, with an end time:
  - Every unmatched unique tuple becomes a PENDING allowlist entry. The dedupe key is event type + exe hash + BPF tag, library hash or path + container image.
  - Each entry records its occurrence count, first and last time seen, and the hosts it was seen on.
  - Approve or reject through the API, the CLI and the dashboard, scoped to the fleet or to one host.
- Fix severity ordering: today the root-UID check runs before RPATH classification, so a MEDIUM RPATH from a root process is rated CRITICAL.
- Match on the unified `sha256:` hash format and the BPF tag from step 4.

Acceptance:
- Learning for 5 minutes on an idle test host produces a PENDING list.
- After everything is approved, loading a new BPF canary produces an alert for the canary only.
- A policy change through the API takes effect within 1 s, without a restart.

### 7d. Alerting and SIEM

- Wire up `AlertManager`. Today it is created and never called. Unmatched events at ALERT or above, and hosts going offline, go out to the configured connectors.
- Add a server config file (YAML) with sections for connectors, tokens, TLS and the database. Today nothing fills `Connectors`.
- Connectors: Splunk HEC, Elasticsearch, Syslog/CEF, Kafka and webhook. An init error fails startup; today errors are discarded.
- Implement Elastic ILM, or remove the claim from the README.

Acceptance: an e2e test with syslog and webhook receiver containers. A BPF canary load arrives at both.

### 7e. API and dashboard

- **WebSocket:**
  - The same token validation as REST.
  - A real Origin check.
  - A fan-out hub, so every subscriber gets every event. Today one shared channel splits events across open tabs.
- **New endpoints and UI:**
  - Policy edit and enable/disable (PUT/PATCH).
  - "Allowlist this event" from the event card.
  - A PENDING-approval page.
  - Per-sensor health on HostInventory, from the heartbeat snapshot in 7a.
- The Settings page shows the real enrollment command from 7a.
- Body-size limits and action validation on policy writes.
- The Vite dev proxy matches the server's scheme and sets `ws: true`.

Acceptance:
- Two browser tabs both receive every event.
- An unauthenticated WebSocket is rejected.
- A Playwright smoke test opens all five pages against a seeded server and checks they render real data.

### 7f. Robustness

- Change `events.uid` and `events.pid` to BIGINT with a migration.
- Add a gRPC recovery interceptor. Add nil checks in the event conversion (`ElfRpathDetail.Entries`).
- Key the rate limiter by the authenticated HostID, and bound its map with eviction.
- Every row in the audit's Security table is either fixed or listed in `SECURITY.md` with the reason it remains.

### 7g. Appliance and packaging

- **Compose appliance (first, because CI can test it):** server, Postgres, Loki, Prometheus, Pushgateway, Alertmanager, Grafana and the collector. Pin every image version. A first-run script generates the CA, the server certificate, an enrollment token and an API token.
- **Packer qcow2 image:**
  - Upload the server binary.
  - The systemd unit passes the TLS and API-token settings through the config file from 7d.
  - `firstboot.sh` writes that same config. Today it writes a file nothing reads.
  - Fix `iso_checksum` and add the missing `user-data.yaml`.
- **OVA, VHD and ISO:** make them work, or remove their make targets and list them as not shipped in `docs/claims.md`.
- **DEB and RPM:** ship `hookmon-bus` (not `hookmon-agent`), a systemd unit, a default config and a postinst that creates the state directory. Fix the RPM sources.
- **Ansible:** make the agent role valid (handlers in `handlers/`, real templates and binary path). Create the missing appliance roles and templates.

Acceptance:
- `docker compose up` on a clean Linux host gives a working stack.
- A bus installed from the DEB on a second host enrolls into it and its events show in the dashboard.

### 7h. Tests

- Add tests for `server/api`, `server/store` (against a real Postgres CI service), `pkg/crypto`, `agent/enrichment` and `cmd/hookmon-collector`.
- Add a full-path e2e test on the Linux host. Today every e2e test runs the bus with `--console`, so this path has never been exercised. The test runs a BPF canary through: bus (not console mode) → enrollment → gRPC → server → Postgres → policy → connector → WebSocket.
- CI gets a Postgres service for the store and API tests. e2e stays a separate job, run on the Linux host or a self-hosted runner.

## 8. First-minute capture for the blog

On 2–3 real hosts (a workstation, a Kubernetes node, a server running Cilium or Falco), start the bus and record the first 5 minutes. Save the events as JSON and take a screenshot of the Grafana dashboard into `docs/evidence/`. Write down, without editing, what showed up and how many. If the hosts show no surprises, report that too.

## 9. Claims ledger (the release gate)

Create `docs/claims.md`, a table with one row per blog claim. Columns: claim · test name or command · result · Verified / Code reading / Not true.

At minimum, add a row for each of these claims from the current blog draft:

- eight sensors
- SHA256 bytecode hashing detects a modified program with the same name
- enrichment with PID, UID, cmdline, exe path, exe SHA256, cgroup and container ID
- `lib_integrity` baselines at startup, and package-manager writes are INFO
- `linker_config` catches linker-cache poisoning
- `ptrace_monitor` sees register manipulation
- `elf_rpath` audits every exec
- heartbeat every 10 s independent of traffic
- `/status` plus a 30 s collector poll
- the four-row alert hierarchy, including "zero events for 24h"
- fleet health banner
- read-only in default mode
- enforcement mode available
- learning mode auto-populates candidates
- every way code enters a Linux process

Also add a row for each server-path claim in the README and docs: mTLS enrollment, SIEM connectors, allowlist scopes, the dashboard pages, and each appliance and package format.

Mark a claim "Not true" whenever the code doesn't do it. Don't change a test to fit the claim. David will edit the blog from this table.

Done means:
- Steps 1–5 and 7–9 are committed.
- CI is green.
- The e2e suite passes on the Linux host, including the full-path test from 7h.
- The compose appliance runs on a clean host.
- `docs/claims.md` has no row left blank.

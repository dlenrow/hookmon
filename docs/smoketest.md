# HookMon Smoketest

The smoketest verifies that every sensor detects what it should. It fires
one trigger per hook type, waits for the events to appear in the server,
then prints a host × hook-type table.

## Prerequisites

- `hookmon-bus` running on the target hosts
- `hookmon-server` running and reachable
- The smoketest binary and helpers installed (shipped in the DEB/RPM at
  `/usr/libexec/hookmon/`)

## Running

On each monitored host (as root):

```bash
hookmon-smoketest --id run-001 run
```

Or across the fleet with Ansible:

```bash
ansible-playbook -i inventory.ini deploy/ansible/hookmon-smoketest.yml \
    -e run_id=run-001
```

Each trigger prints `ok` or `FAIL`. The binary exits non-zero if any
trigger fails. After running, files in `/tmp/hookmon-smoketest/` are left
for the bus to process; `hookmon-smoketest cleanup` removes them (the
Ansible playbook does this automatically).

## Checking results

Wait a few seconds for events to reach the server, then:

```bash
hookmon-cli smoketest check --since 10m
```

This prints a table of hook types vs hosts, where each cell is one of:

| Status  | Meaning |
|---------|---------|
| new     | A PENDING entry exists (first sighting arrived) |
| allowed | An ALLOW entry matches (previously approved) |
| denied  | An ALERT/DENY entry matches (previously rejected) |
| MISSING | No entry found — the sensor did not detect the trigger |

Exit code is non-zero if any cell is MISSING.

Filter by host with `--host`:

```bash
hookmon-cli smoketest check --since 10m --host web-01 --host web-02
```

## What each trigger does

| Trigger | Sensor | What happens |
|---------|--------|-------------|
| bpf_load | bpf_syscall | Loads a minimal tracepoint program with cilium/ebpf, attaches it, then closes both |
| exec_injection | exec_injection | Execs `/bin/true` with `LD_PRELOAD` pointing to the no-op library |
| shm_create | shm_monitor | Creates `/dev/shm/bpftime_hookmon_smoketest` (bpftime pattern) and unlinks it |
| dlopen | dlopen_monitor | Execs the helper binary which calls `dlopen()` on the no-op library |
| ptrace_inject | ptrace_monitor | Starts a child process, attaches with `PTRACE_ATTACH`, pokes its memory with `PTRACE_POKEDATA` |
| linker_config | linker_config | Creates `/etc/ld.so.conf.d/hookmon-smoketest.conf` and removes it |
| lib_integrity | lib_integrity | Copies the no-op .so to `/usr/lib/libhookmon_smoketest_canary.so` and removes it |
| elf_rpath | elf_rpath | Execs the helper binary (compiled with RUNPATH `/tmp/hookmon-smoketest`, which is CRITICAL) |

Every trigger cleans up after itself. The library is staged in
`/tmp/hookmon-smoketest/` so it is in a non-root-writable directory
(required by the bus's signal filter for dlopen events to be reported).

## Reruns

The smoketest is designed for reruns. Once you allow the smoketest entries,
a second run produces no new first sightings (the keys match).

Run with `--variant` to produce new keys (different library hashes, different
BPF program tag). This is useful for verifying that the system still detects
unknown hooks after the first run has been allowed.

## Cleanup

Remove smoketest allowlist entries (PENDING, APPROVED, REJECTED):

```bash
hookmon-cli smoketest cleanup
```

This deletes entries whose learned exe path contains `hookmon-smoketest`.

Remove any leftover files on a host:

```bash
hookmon-smoketest cleanup
```

## Shipped files

The DEB and RPM install these under `/usr/libexec/hookmon/`:

| File | Description |
|------|-------------|
| `hookmon-smoketest` | Static Go binary — the trigger runner |
| `libhookmon_smoketest.so` | No-op shared library (LD_PRELOAD and dlopen target) |
| `hookmon-smoketest-helper` | Dynamically-linked C binary with RUNPATH `/tmp/hookmon-smoketest` |

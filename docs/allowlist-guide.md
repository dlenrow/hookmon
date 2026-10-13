# HookMon Allowlist Guide

This guide is for the SOC operators who run HookMon's server path. It explains how the allowlist decides which events are known, how a hook HookMon has not seen before reaches you once as a new hook to decide on, how to review and change the allowlist, and how it changes an event's severity.

The model: the first time the server sees a hook (a key, below), it stores that event and records the hook as a PENDING entry. Its repeats only add to the entry's count. You investigate it once, then decide: **allow** it (benign, for example from an update to a trusted program: it never alerts again) or **reject** it (unwanted or an attack: it alerts every time it happens again). In steady state a host should bring a new hook every few days or weeks, and an update brings a batch you can decide in one action.

The allowlist lives in `hookmon-server` (PostgreSQL). It applies only to events that reach the server. The bus's own outputs (console, Loki, Prometheus) never see it. Every endpoint named here is in [api-reference.md](api-reference.md).

The commands and the "example run" results below come from a real server with two test hosts; [api-reference.md](api-reference.md#example-runs) says how it was set up.

The examples use the shell variables from the API reference:

```bash
HM=https://hookmon.internal:8443
CA=/etc/hookmon/tls/ca.crt
TOKEN=<api-token>
FLAGS="--server $HM --token $TOKEN --ca-file $CA"
```

## Contents

- [Concepts](#concepts)
- [How Matching Works](#how-matching-works)
- [The Dedupe Key](#the-dedupe-key)
- [New Hooks](#new-hooks)
- [Learning Mode](#learning-mode)
- [Reviewing PENDING Entries](#reviewing-pending-entries)
- [Approving and Rejecting](#approving-and-rejecting)
- [Allowlisting One Event](#allowlisting-one-event)
- [Writing Entries by Hand](#writing-entries-by-hand)
- [Editing, Disabling and Deleting](#editing-disabling-and-deleting)
- [How Allowlisting Changes Severity](#how-allowlisting-changes-severity)
- [Bootstrapping a New Deployment](#bootstrapping-a-new-deployment)
- [Pitfalls](#pitfalls)

## Concepts

An **allowlist entry** (a "policy" in the API and dashboard) says what to do with the events it matches.

| Status | Where it comes from | Matches events? |
|--------|---------------------|-----------------|
| `APPROVED` | Written by hand, created from an event, or a new hook you approved | Yes |
| `PENDING` | A new hook: the server saw its key for the first time, and it waits for your decision | Never |
| `REJECTED` | A new hook you rejected. Its action is always ALERT | Yes, with ALERT: the event is stored and alerts every time, and the key is never proposed again |

| Action | Effect on a matched event |
|--------|---------------------------|
| `ALLOW` | Known good. Not stored, shown or sent anywhere |
| `ALERT` | Treated as unmatched: the normal severity and alerts |
| `DENY` | The same as ALERT, but outranks it. **Nothing is blocked**: HookMon has no enforcement mode |

There are two kinds of entry:

- **Field entries** are written by hand. They match on criteria such as `exe_path` or `prog_hash`.
- **Learned entries** come from new hooks (the server creates the PENDING entry) or from "Allowlist this event". They carry a `learned.key` and match only events with exactly that key (see [The Dedupe Key](#the-dedupe-key)). They can also have field criteria added later.

Every change made through the API or dashboard takes effect for the next event. The server reloads the policy before it answers. For changes made directly in PostgreSQL, send the server SIGHUP.

## How Matching Works

### When an Entry Can Match

An entry is **in force** when all of these hold:

- `enabled` is true;
- `expires` is null or in the future;
- `status` is not PENDING.

A disabled, expired or PENDING entry stays in the list but matches nothing.

### Criteria Are ANDed

An entry matches an event when every criterion it sets matches. An empty criterion (`""`, `[]` or `null`) matches anything. A learned entry must also have the same key as the event.

| Field | Matches | Kind |
|-------|---------|------|
| `event_types` | The event's type is in the list | List |
| `exe_hash` | The executable's hash | `sha256:` hash |
| `exe_path` | The executable path | Glob |
| `library_hash` | The library hash in `exec_injection_detail` or `dlopen_detail`. An event without one doesn't match | `sha256:` hash |
| `library_path` | The library path in `exec_injection_detail` or `dlopen_detail`. Other event types don't match | Glob |
| `prog_name` | `bpf_detail.prog_name`. Events without `bpf_detail` don't match | Glob |
| `prog_type` | `bpf_detail.prog_type`. Events without `bpf_detail` don't match | Exact number |
| `prog_hash` | `bpf_detail.prog_hash`, the kernel program tag, ignoring case. Events without `bpf_detail` don't match | 16 hex digits |
| `host_pattern` | The hostname the host enrolled with | Glob |
| `host_id` | The enrolled host ID | Exact |
| `uid_range` | `min <= uid <= max` | Range |
| `container_image` | The event's **container ID**, exactly or as a glob. An event outside a container doesn't match | Glob |
| `allowed_rpaths` | Every entry in `elf_rpath_detail.entries` matches one of the globs. An event with no RPATH detail passes | Globs |

### Globs

`exe_path`, `library_path`, `prog_name`, `host_pattern`, `container_image` and `allowed_rpaths` use Go's `path.Match` syntax:

- `*` matches any run of characters except `/`. `/usr/bin/*` matches `/usr/bin/cilium-agent`, not `/usr/bin/x/y`.
- There is no `**`.
- `?` matches one character. `[a-z]` matches a class. `\` escapes.
- The whole string must match. `cilium` does not match `/usr/bin/cilium-agent`.
- A malformed pattern, such as `/usr/bin/[`, matches nothing. The API accepts it without an error.

### Hashes

- `exe_hash` and `library_hash` are SHA-256 file hashes, as the bus reports them: `sha256:<64 hex digits>`.
- On write, the API also accepts the bare 64 hex digits and any letter case, and stores `sha256:<lowercase hex>`. Matching ignores the prefix and case too.
- Anything else, such as an MD5 or a truncated hash, is a 400: it could never match.

### BPF Programs: Tag Plus Type

`prog_hash` is the kernel's **program tag**: 16 hex digits, as `bpftool prog show` prints it. It is not a SHA-256.

- The kernel computes it over the program's instructions, with map references zeroed. So it is the same every time the same program is loaded on the same kernel, and it changes when any instruction changes.
- A loader that relocates instructions for each kernel (CO-RE) can produce a different tag on a different kernel. Expect new tags after a kernel upgrade.
- **Identical instructions of different program types have the same tag.** Pin `prog_type` whenever you set `prog_hash` (see [Pitfalls](#the-same-tag-for-different-program-types)).

Common `prog_type` values: 1 SOCKET_FILTER, 2 KPROBE, 3 SCHED_CLS, 4 SCHED_ACT, 5 TRACEPOINT, 6 XDP, 7 PERF_EVENT, 8 CGROUP_SKB, 9 CGROUP_SOCK, 17 RAW_TRACEPOINT, 26 TRACING, 29 LSM.

### Scope: host_id and host_pattern

- `host_id` limits an entry to one enrolled host. The host ID comes from the bus's certificate, so a host can't claim another's. Empty means the whole fleet.
- `host_pattern` is a glob on the hostname (`web-*`). The hostname is the one the host enrolled with.
- Approving or rejecting a candidate "for one host" sets `host_id`.

### When Several Entries Match

The most restrictive action wins: DENY, then ALERT, then ALLOW. So allowing something for the fleet never overrides a rejection, and a rejection for the fleet beats an approval for one host. Among entries with the same action, a host-scoped entry beats a fleet entry. `policy_result.matched_entry_id` names the entry that decided.

In the example run, gdb's ptrace candidate was rejected for the fleet, and a hand-written ALLOW entry for gdb on `web-01` was added. gdb's next ptrace on `web-01` was still ALERT, matched by the rejected entry. After the rejected entry was disabled, the same event was INFO, matched by the host entry.

## The Dedupe Key

The server groups unmatched events by a key. The first unmatched event with a key is stored and creates the PENDING entry; every later one only counts toward it. Approving the entry allows exactly the events with that key. "Allowlist this event" uses the same key.

| Part | Value |
|------|-------|
| `event_type` | The event type |
| `exe_hash` | The acting binary's `sha256:` hash. **Empty when the bus could not hash it**, and always empty for BPF_INVENTORY, which has no process |
| `subject_kind`, `subject` | What the binary acted on; see below |
| `prog_type` | The BPF program type, for BPF events |
| `in_container` | Whether the process ran in a container (the event had a container ID) |

The subject, by event type:

| Event type | `subject_kind` | `subject` |
|------------|----------------|-----------|
| BPF_LOAD, BPF_ATTACH, BPF_INVENTORY | `bpf_tag` | The program tag, with `prog_type` beside it. `bpf_name` (the program name) only when the kernel gave no tag |
| EXEC_INJECTION, DLOPEN | `library_hash` | The library's hash. `library_path` when it has none (such as a relative LD_PRELOAD, or LD_LIBRARY_PATH) |
| LIB_INTEGRITY | `library_path` | The library path |
| LINKER_CONFIG | `file_path` | The file path, such as `/etc/ld.so.preload` |
| SHM_CREATE | `shm_pattern` | The bus's pattern for the segment name: `bpftime`, `bpf_related` or `unknown`. Not the name itself. `shm_name` only when the bus gave no pattern |
| PTRACE_INJECT, ELF_RPATH | none | The exe hash identifies the binary. For ELF_RPATH that fixes the RPATH, which is part of the binary |

What the key leaves out, and what that means:

- **The host.** One PENDING entry covers every host that saw the key; `learned.hosts` lists them.
- **The container image.** The bus reports a container ID, which changes with every container, not an image. The key records only "in a container". The exe hash, taken inside the container, identifies the binary.
- **For PTRACE_INJECT, the target and the request.** Approving gdb's candidate allows gdb to attach to any process, with any of the reported requests.
- **The user.** The same binary doing the same thing as root and as a user is one key.

A learned entry matches its key exactly. A new binary version, a changed library or a new BPF program is a new key, so it is a new hook again.

## New Hooks

Every event that **no in-force entry matched** is recorded against its key, whether or not a learning window is open:

- **The first event with a key** is a first sighting. The server stores it, shows it in the dashboard and on the live feed, and sends it to the connectors by severity. It creates a PENDING entry: `status` PENDING, `action` ALERT, `created_by` `learning-mode`, `event_types` set to the event type, a generated description such as `learned: BPF_LOAD by /usr/bin/cilium-agent: BPF tag 1f2e3d4c5b6a7980, prog type 3`, and `learned.first_event_id` naming the stored event. `policy_result.disposition` is `first_sighting`, `policy_result.candidate_id` is the entry, and `reason` ends with `; first sighting: PENDING entry <id>`.
- **Each later event with the same key** is a repeat. It adds to the entry's count, last-seen time and hosts, and is not stored, shown or sent. The key is fleet-wide: a new hook on 40 hosts is one PENDING entry listing 40 hosts, with one stored event.

Once you decide:

- **Approved** (action ALLOW): its events are dropped. Not stored, shown or sent, and not counted.
- **Rejected** (action ALERT): its events are stored and alert every time (`disposition` `denied`).

These are never recorded as new hooks:

- Events that matched any in-force entry, including a REJECTED one or a hand-written ALERT or DENY entry.
- AGENT_OFFLINE, AGENT_RECOVERED and the BPF inventory summary.
- A key that already has an in-force APPROVED or REJECTED entry for the fleet or for that host.

Each PENDING entry records:

| Field | Meaning |
|-------|---------|
| `learned.occurrences` | How many unmatched events had this key |
| `learned.first_seen`, `learned.last_seen` | The earliest and latest event time |
| `learned.hosts` | IDs of the hosts that sent it |
| `learned.exe_path` | The binary's path in the first event |
| `learned.first_event_id` | The stored first-sighting event: the evidence |
| `learned.key` | The key |

A BPF program found by the inventory (at startup and every five minutes) that is not on the allowlist is a new hook like any other, at severity ALERT: a loaded program nobody approved, however long ago it was loaded. A program on the allowlist is dropped.

## Learning Mode

A learning window is a quiet period. It does not change what is recorded: first sightings inside it are stored, shown and become PENDING entries as always. It only keeps them away from alert connectors (`min_severity` ALERT or CRITICAL): they are marked `policy_result.quiet` and still go to event-feed connectors. Use one when HookMon first meets a fleet, so the first day's batch of new hooks doesn't page anyone, then review the PENDING list. It never allows anything by itself.

### Starting and Stopping

A learning window covers the fleet or one host, and always has an end time.

```bash
hookmon-cli $FLAGS learning start --fleet --for 14d                           # or 90m, 36h
hookmon-cli $FLAGS learning start --host "$HOST_ID" --until 2026-11-01T00:00:00Z
hookmon-cli $FLAGS learning                                                    # windows; "active": true while open
hookmon-cli $FLAGS learning stop --fleet                                       # end now
```

- There is one window per scope. Starting again replaces its end time.
- A host is in a quiet period while the fleet window or its own window is open.
- Windows are stored in PostgreSQL, so a restarted server keeps the quiet period until the end time.
- An ended window stays listed with `"active": false` until it is replaced or stopped.
- Stopping deletes the window: later first sightings go to alert connectors again. PENDING entries stay.
- The dashboard can't start or stop windows. Use the CLI or the API.

Learning mode changes no severity. `policy_result.quiet` is the only difference it makes to an event.

In the example run (before first sightings), a two-hour fleet window over two hosts produced six PENDING entries from 26 events. The Chromium shared-memory entry counted five events with two different segment names from both hosts, because the key is the pattern (`unknown`), not the name. Today the same run stores six events, one per entry.

## Reviewing PENDING Entries

### Dashboard

The **New hooks** page (it replaced Pending Approval) lists every PENDING entry, newest first by first sighting, with:

- when it was first seen, and when last;
- the event type and what it is (the description);
- the binary's path;
- the hosts that saw it, and how many times;
- a link to the first-sighting event, the evidence.

Filter by first-seen time, host, event type or text, select the rows (or "select all shown"), and decide them together: **Allow — ignore in future** (for the fleet, or only the hosts where each was seen) or **Deny — alert every time**. After a software update, filter to the update's time and host, check the rows, and allow them in one action.

### CLI

```bash
hookmon-cli $FLAGS policies pending
hookmon-cli $FLAGS policies pending --since 2h --host web-01 --type BPF_LOAD
```

`--since` takes an RFC 3339 time or a duration back from now (`90m`, `36h`, `7d`) and keeps entries first seen since then. `--host` takes a host ID or hostname, `--type` an event type.

A one-line-per-entry summary with `jq`:

```bash
hookmon-cli $FLAGS policies pending | jq -r '.[] | [.id, .learned.key.event_type,
  (.learned.exe_path // "-"), (.learned.key.subject // "-"), .learned.occurrences,
  (.learned.hosts | length)] | @tsv'
```

```
4dc9ca54-856b-494c-8c2f-67ea10bb916f  DLOPEN         /opt/app/bin/server           sha256:a27366146aa9d318d492ab1c2d6b057623221c0e75b5c8de52ce1d92ac52f276  1  1
43b2f928-d94b-431c-8fff-1df7fe2eb8fd  ELF_RPATH      /opt/vendor/bin/agent         -                                                                        1  1
7e48aac7-fcdf-4137-be62-2fe7674a7582  BPF_LOAD       /tmp/loader                   9a8b7c6d5e4f3021                                                         1  1
210cfbec-f30c-4c4a-b3f1-1de21dba279b  SHM_CREATE     /home/eve/.local/bin/bpftime  bpftime                                                                  1  1
d4cee498-f1a9-4e60-b4e5-a64fb55e9529  LINKER_CONFIG  /usr/bin/tee                  /etc/ld.so.preload                                                       1  1
f26bffc4-4347-41e6-adfb-ceb82d44595e  SHM_CREATE     /opt/google/chrome/chrome     unknown                                                                  5  1
```

The columns are the entry ID, event type, binary, subject, occurrences and number of hosts.

To see the event behind a new hook, fetch its first sighting:

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$HM/api/v1/events/$FIRST_EVENT_ID"
```

`$FIRST_EVENT_ID` is the entry's `learned.first_event_id`. Repeats are not stored, so there is one event per new hook; its process context (command line, parent, user, container) is what you investigate.

### What to Check

- **Is the binary expected?** Check its path and hash against your packages or images. An empty exe hash means the bus could not hash the binary: find out why before approving (see [Pitfalls](#an-empty-exe-hash-is-not-a-wildcard)).
- **Is the subject expected?** A BPF tag from your observability agent, a library your application loads, a known shared-memory user.
- **Where was it seen?** A key seen on one host of a fleet of identical hosts is worth a look. Approve it for that host, not the fleet.
- **How often?** A count of 1 in a long window may be a one-off, such as an installer or an attacker.

## Approving and Rejecting

| Decision | For the fleet | For one host |
|----------|---------------|--------------|
| Approve | The entry becomes APPROVED, action ALLOW, on every host. Its events are dropped from now on | A new APPROVED ALLOW entry for that host (`host_id` set). The host comes off the PENDING entry's `learned.hosts`; the PENDING entry is deleted when no host is left |
| Reject | The entry becomes REJECTED, action ALERT. Matching events are stored and alert every time, and are never proposed again | A new REJECTED entry for that host, handled the same way |

```bash
hookmon-cli $FLAGS policies approve "$ENTRY_ID" --fleet
hookmon-cli $FLAGS policies approve "$ENTRY_ID" --host "$HOST_ID"
hookmon-cli $FLAGS policies reject "$ENTRY_ID" --fleet
```

**Many at once.** Give several IDs, or `--seen-hosts` to decide each entry for exactly the hosts it was seen on (one host-scoped entry per host; the PENDING entry goes away, and a host that sees the hook later gets a new first sighting). The CLI calls `POST /api/v1/policies/decide`, which decides them all in one transaction and reloads the policy once. An ID that is no longer PENDING fails alone, and the command then exits 1.

```bash
hookmon-cli $FLAGS policies approve "$ID1" "$ID2" "$ID3" --seen-hosts
# every new hook first seen in the last two hours on web-01, after an update there:
hookmon-cli $FLAGS policies pending --since 2h --host web-01 | jq -r '.[].id' \
  | xargs hookmon-cli $FLAGS policies approve --seen-hosts
```

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X POST \
  "$HM/api/v1/policies/$ENTRY_ID/approve" -d "{\"scope\": \"host\", \"host_id\": \"$HOST_ID\"}"
```

- Only PENDING entries can be decided. A second approve is a 409.
- A host-scoped decision needs an enrolled host ID (404 otherwise).
- In the dashboard, select the rows on the New hooks page and choose Allow or Deny, and for Allow, the fleet or the hosts where seen.

In the example run, Chromium's shared-memory candidate was approved for `web-01` only. The PENDING entry stayed, now listing only `web-02`. On the next run, `web-01`'s segment matched the new host entry (today it is dropped). `web-02`'s was unmatched (today a repeat, counted on the PENDING entry).

To undo a decision, delete the decided entry. The next event with the key is a first sighting again.

## Allowlisting One Event

When an alert turns out to be legitimate, allowlist it from the event instead of writing an entry. In the dashboard, open the event (or its row in the Event Feed), click **Allowlist**, and choose "This host only" or "Every host (fleet)".

The result matches exactly the events with the event's [key](#the-dedupe-key):

- **For a first sighting**, whose key has a PENDING entry, that entry is approved, as on the New hooks page: for the fleet, the entry itself becomes APPROVED; for this host, a host-scoped entry is created and the host comes off the PENDING entry (which is deleted when no host is left). The hook leaves the New hooks list, and no second entry is made.
- **Otherwise** (a denied event, or an event from before first sightings), a new APPROVED ALLOW entry with the key is created.

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X POST \
  "$HM/api/v1/events/$EVENT_ID/allowlist" -d '{"scope": "host", "description": "approved in SEC-1234"}'
```

- `{"scope": "fleet"}` covers every host.
- A `description` replaces the PENDING entry's, when there is one.
- If an enabled ALLOW entry for the same key and scope already exists, the answer is 409 with that entry's `id`.
- AGENT_OFFLINE and AGENT_RECOVERED can't be allowlisted (400).
- There is no CLI command for this.

## Writing Entries by Hand

Write an entry by hand when you know in advance what is allowed, or when the key is too narrow (for example, to allow every build of a binary under one path).

- Always set `"enabled": true`. Without it, the entry is stored disabled.
- `action` is required.

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X POST "$HM/api/v1/policies" -d '{
  "description": "cilium datapath program, kernel 6.8 build",
  "event_types": ["BPF_LOAD", "BPF_INVENTORY"],
  "prog_hash": "1f2e3d4c5b6a7980",
  "prog_type": 3,
  "action": "ALLOW",
  "enabled": true
}'
```

```bash
echo '{"description": "gdb on build hosts", "event_types": ["PTRACE_INJECT"],
       "exe_path": "/usr/bin/gdb", "host_pattern": "build-*",
       "action": "ALLOW", "enabled": true}' | hookmon-cli $FLAGS policies create
```

More patterns:

| Goal | Entry |
|------|-------|
| One binary, any version, at one path | `"exe_path": "/usr/bin/cilium-agent"`. Weaker than a hash: whoever can write the path is allowed |
| One build of a binary | `"exe_hash": "sha256:..."` |
| A known LD_PRELOAD library | `"event_types": ["EXEC_INJECTION"], "library_hash": "sha256:..."` |
| A vendor binary with a known RUNPATH | `"event_types": ["ELF_RPATH"], "exe_path": "/opt/vendor/bin/*", "allowed_rpaths": ["/opt/vendor/lib"]` |
| Temporary allowance during an incident | Any of the above with `"expires": "2026-10-12T00:00:00Z"` |
| Keep alerting on something, whatever else matches | `"action": "ALERT"` (or `DENY`) with the criteria; it outranks ALLOW entries |

`allowed_rpaths` globs match each entry as written in the binary, before `$ORIGIN` expansion (for example `$ORIGIN/../lib`).

## Editing, Disabling and Deleting

APPROVED and REJECTED entries can be edited. PENDING entries can't (409): approve or reject them first.

**Disable or enable** (the toggle in the dashboard's Policy Manager):

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X PATCH \
  "$HM/api/v1/policies/$ENTRY_ID" -d '{"enabled": false}'
```

**Change some fields** with PATCH. `null` clears a field.

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X PATCH \
  "$HM/api/v1/policies/$ENTRY_ID" -d '{"description": "cilium datapath (SEC-77)", "expires": "2026-12-31T00:00:00Z"}'
```

**Replace an entry** with PUT. Send the whole entry: fields left out become empty, and an omitted `enabled` becomes false. The dashboard's Edit button does this.

**Delete** an entry:

```bash
hookmon-cli $FLAGS policies delete "$ENTRY_ID"
```

What can't change:

- `id`, `created_at`, `created_by` and `status`.
- `learned`, including the key. To allow a different key, allowlist an event or write a field entry.
- The action of a REJECTED entry, which stays ALERT. Delete it to stop rejecting.

You can add field criteria to a learned entry. For example, set `host_pattern` to narrow it, or `expires` to make it temporary. The key still has to match too.

Disabling, expiring or deleting a REJECTED entry makes its events unmatched again: the next one is a first sighting, proposed again as a new hook.

A hand-written entry (or a field added to a learned one) that starts matching a key with a PENDING entry does not remove that PENDING entry. Approve or delete it too.

## How Allowlisting Changes Severity

The bus rates every event when it sees it, with context the server lacks: whether a package manager wrote the file, the shared-memory segment's name, who can write an RPATH directory. The server keeps that rating, then applies the allowlist and two increases, for root and for a binary the bus could not hash. Neither increase applies to an event the bus rated INFO, or to ELF_RPATH.

The server walks this table top to bottom and uses the first row that applies (`server/policy/severity.go`). "Not on the allowlist" includes events that matched an ALERT or DENY entry, such as a rejected candidate.

| # | Condition | Severity |
|---|-----------|----------|
| 1 | AGENT_OFFLINE: the watchdog saw no heartbeat | CRITICAL |
| 2 | AGENT_RECOVERED: the first heartbeat after an outage | INFO |
| 3 | BPF_INVENTORY: a program on the allowlist INFO (and dropped); one that is not, a new hook, or a rejected one, ALERT | INFO or ALERT |
| 4 | Matches an ALLOW entry, for the fleet or for this host | INFO |
| 5 | The bus rated it INFO: a package manager wrote the library or linker file, or a `/dev/shm` segment has no BPF pattern | INFO |
| 6 | bpftime-pattern shared memory | CRITICAL |
| 7 | Linker configuration changed (not by a package manager) | CRITICAL |
| 8 | ELF_RPATH, by the binary's highest risk: CRITICAL, HIGH or MEDIUM, whatever the UID | CRITICAL, ALERT or WARN |
| 9 | Any other event from root (UID 0) | CRITICAL |
| 10 | Exec injection | ALERT |
| 11 | Ptrace | ALERT |
| 12 | Shared library changed on disk (not by a package manager) | ALERT |
| 13 | Shared memory with a BPF-related name | ALERT |
| 14 | The bus could not hash the binary (BPF load or attach, dlopen) | ALERT |
| 15 | BPF load or attach, or dlopen, not on the allowlist | WARN |

What this means in practice:

- **ALLOW makes an event INFO**, whatever it is, and the server then drops it. Nothing else lowers a severity.
- **The bus's INFO is never raised.** A package manager's write to a library is INFO even though it runs as root. In the example run, `dpkg` renaming `libpam.so.0` as root stayed INFO, while `cp` writing the same file as root was CRITICAL.
- **Root raises the rest.** An unmatched event from root that rows 1 to 8 don't cover is CRITICAL. An unmatched BPF load by root is CRITICAL, not WARN.
- **ALERT and DENY entries don't change the severity.** They only keep an event from being allowed.
- **`severity` and `policy_result.action` are separate.** A first sighting of a `/dev/shm` segment with no BPF pattern is INFO with action ALERT.

Connectors receive only stored events: first sightings, denied hooks and host status events. Alert connectors (`min_severity` ALERT or CRITICAL) receive those at or above that severity whose action is not ALLOW, except first sightings during a learning window (quiet). Event-feed connectors (`min_severity` INFO or WARN) receive every stored event at or above theirs. Repeats of a new hook and allowed hooks reach no connector.

## Bootstrapping a New Deployment

A new deployment has no allowlist, so on its first day every hook is new: the fleet's normal BPF programs, preloads and library loads arrive as a batch of first sightings. Decide that batch once.

1. **Start a quiet period before the buses connect**, so the first day's batch doesn't page anyone. A day or two is enough to catch daily jobs; the first sightings are recorded either way.

   ```bash
   hookmon-cli $FLAGS learning start --fleet --for 2d
   ```

2. **Enroll the buses.** Check that every host is `ONLINE` with all sensors `alive`:

   ```bash
   hookmon-cli $FLAGS hosts
   ```

3. **Review the New hooks page.** Allow the obvious ones for the fleet: your observability agent's BPF programs, your runtime's libraries. Allow host-specific ones for the hosts where seen. Reject what should never happen, so it alerts every time. Investigate the rest from their first-sighting events. Decided keys are never proposed again.

4. **Let the quiet period end, or stop it.** Anything still PENDING keeps waiting for a decision; from now on each new first sighting goes to the alert connectors.

   ```bash
   hookmon-cli $FLAGS learning stop --fleet
   ```

5. **Monitor.** Each alert is one new hook, once: decide it (allowlist it from the event, or approve or reject it on the New hooks page). Its repeats are counted, not alerted.

6. **Updates.** A package or kernel upgrade changes hashes and tags, so its hooks arrive as a batch of first sightings around the upgrade's time. Filter the New hooks page to that time and host, check that they came from the update, and allow them together. To keep an expected upgrade from paging anyone, run a host quiet period over it:

   ```bash
   hookmon-cli $FLAGS learning start --host "$HOST_ID" --for 2h
   ```

## Pitfalls

### The Same Tag for Different Program Types

Two programs with identical instructions have the same tag even if their program types differ. A kprobe and a socket filter can share a tag. An entry with `prog_hash` and no `prog_type` allows both.

In the example run, an entry with only `"prog_hash": "1F2E3D4C5B6A7980"` (stored in lower case) allowed a RAW_TRACEPOINT (type 17) program from `/tmp/other`. After `{"prog_type": 3}` was patched in, the same load was CRITICAL. Learned keys already include the type.

### Shared Memory Is Keyed on the Pattern, Not the Name

An SHM_CREATE key uses the bus's pattern for the segment name: `bpftime`, `bpf_related` or `unknown`. Browsers and other programs name segments randomly, and keying on the name made one candidate per segment.

So approving Chromium's `unknown` candidate allows Chromium (that exe hash) to create **any** `/dev/shm` segment the bus calls `unknown`. It doesn't allow bpftime or BPF-related names, which have their own patterns and keys.

### container_image Is Matched Against the Container ID

The bus reports container IDs, not image names. `container_image` is compared with the event's `container_id`, exactly or as a glob.

- An image name such as `registry.example.com/plugin-host:1.4` never matches. In the example run, such an entry did not match a DLOPEN from a container. After it was patched to `3f4e9a0b1c2d*`, the next one was INFO.
- Container IDs change every time a container is recreated, so an entry tied to one is short-lived.
- To allow a binary in any container, use its `exe_hash`. The bus hashes container binaries inside the container. Learned keys do this.

### An Empty Exe Hash Is Not a Wildcard

In a **learned key**, `exe_hash` is part of the key like any other value. An empty `exe_hash` means "the bus could not hash the binary". It matches only events whose exe hash is also empty, not every binary. It does match **any** unhashable binary that does the same thing: an approved DLOPEN key with no exe hash allows every unhashable process to load that library. Find out why the hash is missing before approving such a candidate. The bus leaves it empty when the process exited before the bus could read it, when the executable was deleted after it started, or when it is not a regular file (a memfd, for example). BPF_INVENTORY keys always have an empty exe hash, because the inventory has no process.

In a **hand-written entry**, it is the other way round: leaving `exe_hash` empty means any binary. Combine `exe_path` with `exe_hash` when you can.

### Denied BPF Programs Alert on Every Inventory Scan

A REJECTED or DENY entry matches events that carry its key or criteria. The BPF inventory sensor reports every loaded program every 5 minutes, and the policy engine evaluates each inventory event against the allowlist. A denied BPF program that is still loaded in the kernel produces an alert on every scan — roughly 288 per day per host — until the program is actually removed.

This is intentional: a denied program is one you decided should not be there, and a repeating alert is the only pressure HookMon can apply, since it has no enforcement mode. To stop the alerts, remove the program (unload it, restart the service that loaded it, or reboot the host). Disabling the REJECTED entry silences it but leaves the program unmonitored — it will not be proposed again because the key is remembered.

### Also Watch For

- **`enabled` defaults to false.** `POST /api/v1/policies` without `"enabled": true` creates an entry that matches nothing.
- **PUT replaces everything.** Fields you leave out are cleared, and `enabled` becomes false. Use PATCH for small changes.
- **`allowed_rpaths` passes events that have no RPATH.** An entry with only `allowed_rpaths` set allows every event of every other type; in the example run, such an entry allowed an unrelated DLOPEN. Always pair it with `"event_types": ["ELF_RPATH"]`.
- **Empty `event_types` means every type.** An entry with only `exe_path` set allows everything that binary does.
- **Malformed globs fail silently.** The API accepts `"/usr/bin/["`, and it never matches.
- **DENY blocks nothing.** It ranks above ALERT. Nothing in HookMon prevents an operation.
- **Upgrades create new keys.** A new binary build has a new exe hash; a new kernel can give new BPF tags (the same object file had different tags on kernels 5.19 and 6.17). Each upgrade's hooks arrive as a batch of first sightings; allow them together once you know the update brought them.

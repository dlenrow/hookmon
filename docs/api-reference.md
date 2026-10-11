# HookMon REST API Reference

`hookmon-server` serves a REST API, a WebSocket event feed and the dashboard on one HTTPS listener (`http_addr`, default `:8443`). This document lists every route in `server/api/router.go`. For what the allowlist does and how to build one, see [allowlist-guide.md](allowlist-guide.md).

The examples were run against a real `hookmon-server` with PostgreSQL 16. Events came from a test client that enrolled two hosts and streamed events over the bus's own gRPC transport. See [Example Runs](#example-runs).

## Contents

- [Conventions](#conventions)
- [Endpoints](#endpoints)
- [Health](#health)
- [Events](#events)
- [Event JSON](#event-json)
- [Hosts](#hosts)
- [Policies (Allowlist)](#policies-allowlist)
- [Learning Mode](#learning-mode)
- [Settings](#settings)
- [WebSocket Event Feed](#websocket-event-feed)
- [hookmon-cli](#hookmon-cli)
- [Example Runs](#example-runs)

## Conventions

### Shell Variables

Every example uses these variables:

```bash
HM=https://hookmon.internal:8443                     # the server's http_addr
CA=/etc/hookmon/tls/ca.crt                           # the CA that signed the server certificate
TOKEN=<api-token>                                    # one of api.tokens
FLAGS="--server $HM --token $TOKEN --ca-file $CA"    # global flags for hookmon-cli
```

Examples that act on one object use `$EVENT_ID`, `$HOST_ID` or `$ENTRY_ID`. Set them from a list call first.

### Transport

- HTTPS only, TLS 1.2 or newer, with the server certificate from `tls.cert_file`. Pass `--cacert` to curl, or `--ca-file` (or `HOOKMON_CA_FILE`) to `hookmon-cli`. In `--insecure` mode (development only) the listener is plain HTTP.
- The REST API needs no client certificate. Only the bus's gRPC port (9443) does.
- The server waits at most 10 s for request headers and 30 s for a whole request. Idle keep-alive connections close after 120 s. There is no write timeout, because the WebSocket feed is one long response.
- There is no rate limit on REST.

### Authentication

Every route except `/api/v1/health` needs an API token:

```
Authorization: Bearer <token>
```

- Tokens come from `api.tokens` in the server config, or `--api-tokens` (comma-separated), which overrides the file. They are compared in constant time.
- **Never leave an empty token in the list** (`tokens: [""]`, or a stray comma in `--api-tokens`). The server accepts it, and then a request with an empty bearer token is authenticated. See [Known Issues](#known-issues).
- With no token configured, every authenticated request gets 401. The server does not warn about this at startup.
- Every token can read and write everything. There are no roles or scopes.
- The server strips a leading `Bearer ` if present, so a bare token in the header also works.
- The WebSocket takes the same token, in a subprotocol (see [WebSocket Event Feed](#websocket-event-feed)).

### Request Bodies

These rules apply to every write that takes a body: create, replace and patch a policy; approve and reject; start learning; allowlist an event.

- The body is one JSON value. Data after it is a 400.
- The body is at most 64 KiB (65536 bytes). A larger body is a 413.
- Unknown fields are a 400, so a misspelled field is never silently ignored. PATCH refuses any field it may not change.
- The `Content-Type` header is not checked.

### Responses and Errors

Responses are JSON (`application/json`). List endpoints return `[]`, never `null`, when nothing matches. An error is a JSON object:

```json
{"error": "action must be ALLOW, ALERT or DENY, not \"allow\""}
```

| Status | When |
|--------|------|
| 200 | Read, update, approve, reject, start learning |
| 201 | Created: `POST /policies`, `POST /events/{id}/allowlist` |
| 204 | Deleted: `DELETE /policies/{id}`, `DELETE /learning/...`. No body |
| 400 | The body or a parameter is invalid. The message says which field and why |
| 401 | Missing or wrong token. The body is JSON, but the `Content-Type` is `text/plain` |
| 403 | WebSocket only: the `Origin` is not allowed |
| 404 | The event, host, policy entry or learning window does not exist, or the path is unknown under `/api` |
| 405 | A known path with the wrong method. Empty body |
| 409 | The entry is PENDING and can't be edited, is not PENDING and can't be approved or rejected, or an allowlist entry for the event already exists |
| 413 | The body is over 64 KiB |
| 500 | A database error, including a database that is down. Also a duplicate `id` on `POST /policies` (see [Known Issues](#known-issues)) |
| 503 | WebSocket only: the server is shutting down |

A missing row is always 404 and a database failure is always 500, so an outage is never reported as "not found".

### Times

Times are RFC 3339. Values the server reads back from PostgreSQL carry the server's local UTC offset (for example `-04:00`). Values it has just set, such as a new entry's `created_at`, are in UTC (`Z`). Compare them as instants, not as strings.

### Writes Apply at Once

Every write to the allowlist or to learning mode reloads the policy engine before the server answers. The next event is evaluated with the change. If the write is saved but the reload fails, the answer is 500 with `saved, but reloading the policy failed; send SIGHUP to retry`.

### Paths Outside the API

With `dashboard_dir` set, any path outside `/api` that is not a route serves the dashboard (`index.html` for its client-side routes, or the asset file). An unknown path under `/api` always gets the JSON 404. With no dashboard, every unknown path gets the JSON 404.

## Endpoints

| Method | Path | Auth | Success | Purpose | CLI |
|--------|------|------|---------|---------|-----|
| GET | `/api/v1/health` | none | 200 | Liveness of the HTTP listener | `health` |
| GET | `/api/v1/events` | token | 200 | List events, newest first | `events` |
| GET | `/api/v1/events/{id}` | token | 200 | One event | none |
| POST | `/api/v1/events/{id}/allowlist` | token | 201 | Allowlist this event | none |
| GET | `/api/v1/hosts` | token | 200 | Host inventory | `hosts` |
| GET | `/api/v1/hosts/{id}` | token | 200 | One host | none |
| GET | `/api/v1/policies` | token | 200 | List allowlist entries | `policies`, `policies pending` |
| POST | `/api/v1/policies` | token | 201 | Create an entry | `policies create` |
| PUT | `/api/v1/policies/{id}` | token | 200 | Replace an entry | none |
| PATCH | `/api/v1/policies/{id}` | token | 200 | Change some fields of an entry | none |
| DELETE | `/api/v1/policies/{id}` | token | 204 | Delete an entry | `policies delete` |
| POST | `/api/v1/policies/{id}/approve` | token | 200 | Approve a PENDING entry | `policies approve` |
| POST | `/api/v1/policies/{id}/reject` | token | 200 | Reject a PENDING entry | `policies reject` |
| GET | `/api/v1/learning` | token | 200 | Learning windows | `learning` |
| PUT | `/api/v1/learning/fleet` | token | 200 | Start fleet learning | `learning start --fleet` |
| DELETE | `/api/v1/learning/fleet` | token | 204 | Stop fleet learning | `learning stop --fleet` |
| PUT | `/api/v1/learning/hosts/{hostID}` | token | 200 | Start learning for one host | `learning start --host` |
| DELETE | `/api/v1/learning/hosts/{hostID}` | token | 204 | Stop learning for one host | `learning stop --host` |
| GET | `/api/v1/settings` | token | 200 | Server settings for the dashboard | none |
| GET | `/api/v1/ws/events` | token (subprotocol or header) | 101 | Live event feed | none |

"none" in the CLI column means use curl or the dashboard.

## Health

### GET /api/v1/health

No token. Answers `{"status":"ok"}` with 200 while the HTTP listener is up. It does not check the database.

```bash
curl --cacert "$CA" "$HM/api/v1/health"
hookmon-cli $FLAGS health
```

```json
{"status":"ok"}
```

## Events

### GET /api/v1/events

Lists stored events, newest first (by `timestamp`).

| Parameter | Type | Default | Meaning |
|-----------|------|---------|---------|
| `limit` | integer | 100 | Most events to return. A missing, non-numeric, zero or negative value means 100. There is no maximum. |
| `offset` | integer | 0 | Events to skip, for paging. A non-numeric or negative value means 0. |
| `host_id` | string | | Only this host (exact match on the enrolled host ID). |
| `event_type` | string | | Only this type, such as `BPF_LOAD`. Exact and case-sensitive: `bpf_load` matches nothing. |
| `severity` | string | | Only this severity: `INFO`, `WARN`, `ALERT` or `CRITICAL`. Exact and case-sensitive. |
| `since` | RFC 3339 time | | Events at or after this time. |
| `until` | RFC 3339 time | | Events at or before this time. |

Filters combine with AND. Unknown parameters are ignored.

- **An unparseable `since` or `until` is ignored, not refused.** The request then returns events without that bound. In a query string a `+` means a space, so write a positive UTC offset as `%2B` (`2026-10-11T02:58:00%2B00:00`) or use `Z`.
- **Paging.** There is no total count and no cursor. New events shift offset-based pages. To page a fixed set, take the newest `timestamp` from the first page and pass it as `until` on every later page.

Response: an array of [events](#event-json).

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$HM/api/v1/events?limit=20"
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  "$HM/api/v1/events?host_id=$HOST_ID&severity=CRITICAL&since=2026-10-11T00:00:00Z"
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$HM/api/v1/events?event_type=BPF_LOAD&limit=50&offset=50"
```

CLI: `hookmon-cli $FLAGS events [--limit N] [--host HOST_ID] [--type EVENT_TYPE]`. Its `--limit` defaults to 50. It has no severity or time filters.

```bash
hookmon-cli $FLAGS events --limit 20 --type BPF_LOAD
```

### GET /api/v1/events/{id}

Returns one event. 404 if no event has that ID; 500 on a database error.

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$HM/api/v1/events/$EVENT_ID"
```

### POST /api/v1/events/{id}/allowlist

"Allowlist this event" in the dashboard. Creates an APPROVED entry with action ALLOW that matches exactly the events with this event's [learning key](allowlist-guide.md#the-dedupe-key), for the fleet or for the event's host.

Body:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `scope` | string | yes | `fleet` or `host`. `host` scopes the entry to the event's host. |
| `host_id` | string | no | With `host`, may repeat the event's host ID; any other ID is a 400. With `fleet`, must be empty. |
| `description` | string | no | Defaults to `from event <id>: <event type> by <exe path>: <subject>`. |

The new entry has `created_by` `api`, `event_types` set to the event's type, and a `learned` block: the key, the event's exe path, `occurrences` 1, `first_seen` and `last_seen` set to the event's time, and `hosts` set to the event's host. The key is its only criterion. Field criteria can't express some subjects (a shared memory pattern, a linker config file), and an empty `exe_hash` criterion would match any binary.

| Status | When |
|--------|------|
| 201 | The new entry |
| 400 | Bad `scope`; `host_id` with `fleet`; a `host_id` that is not the event's host; scope `host` for an event with no host ID; the event is AGENT_OFFLINE or AGENT_RECOVERED (`... is a host status event, not a hook; there is nothing to allowlist`) |
| 404 | `{"error":"event not found"}` |
| 409 | An enabled, unexpired ALLOW entry with the same key and scope already exists. The body names it: `{"error":"an entry for this event's key and scope already allows it","id":"<entry id>"}` |

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X POST \
  "$HM/api/v1/events/$EVENT_ID/allowlist" \
  -d '{"scope": "fleet", "description": "cilium kprobe build of cil_from_netdev"}'
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X POST \
  "$HM/api/v1/events/$EVENT_ID/allowlist" -d '{"scope": "host"}'
```

Response (201, abridged):

```json
{
  "id": "da520ec3-5bbd-4993-bfa8-0c6a10146ee5",
  "created_at": "2026-10-11T02:57:59.543360943Z",
  "created_by": "api",
  "description": "cilium kprobe build of cil_from_netdev",
  "event_types": ["BPF_LOAD"],
  "exe_hash": "",
  "prog_type": null,
  "prog_hash": "",
  "action": "ALLOW",
  "expires": null,
  "enabled": true,
  "status": "APPROVED",
  "learned": {
    "key": {
      "event_type": "BPF_LOAD",
      "exe_hash": "sha256:3a2256b638700579130078cbaa19011a42615c0ea30c85178348d89cefbec26a",
      "subject_kind": "bpf_tag",
      "subject": "1f2e3d4c5b6a7980",
      "prog_type": 2,
      "in_container": false
    },
    "exe_path": "/usr/bin/cilium-agent",
    "occurrences": 1,
    "first_seen": "2026-10-10T22:56:59.437243-04:00",
    "last_seen": "2026-10-10T22:56:59.437243-04:00",
    "hosts": ["6d4e295e-3725-4641-b1a9-efe3c8890a7c"]
  }
}
```

CLI: none.

## Event JSON

Every event, from REST and from the WebSocket, has this shape. Detail objects are present only for their event type; the others are omitted.

```json
{
  "id": "3433b8bc-5c9b-4c76-8fd0-de531ab2cc5b",
  "timestamp": "2026-10-10T22:56:59.437187-04:00",
  "host_id": "6d4e295e-3725-4641-b1a9-efe3c8890a7c",
  "hostname": "web-01",
  "event_type": "BPF_LOAD",
  "severity": "CRITICAL",
  "pid": 8104,
  "ppid": 1,
  "uid": 0,
  "gid": 0,
  "comm": "loader",
  "cmdline": "/tmp/loader",
  "exe_path": "/tmp/loader",
  "exe_hash": "sha256:20cd6f458a31cbc5b5c44ab824dcd2d3edc60d51e44b61683bfe9fae7e04f67d",
  "cgroup_path": "/system.slice/x.service",
  "container_id": "",
  "namespace": "",
  "bpf_detail": {
    "bpf_cmd": 5,
    "prog_type": 2,
    "prog_name": "hide_pid",
    "attach_type": 0,
    "target_fd": 0,
    "insn_count": 96,
    "prog_hash": "9a8b7c6d5e4f3021",
    "prog_id": 412,
    "load_time": "2026-10-10T22:00:00Z",
    "created_by_uid": 0
  },
  "policy_result": {
    "action": "ALERT",
    "reason": "no allowlist match for BPF_LOAD event from web-01 (exe=/tmp/loader, hash=sha256:20cd6f458a31cbc5b5c44ab824dcd2d3edc60d51e44b61683bfe9fae7e04f67d)"
  }
}
```

### Common Fields

| Field | Type | Meaning |
|-------|------|---------|
| `id` | string | Event ID (a UUID the bus assigns; the server assigns it for AGENT_OFFLINE and AGENT_RECOVERED) |
| `timestamp` | time | When the bus detected it |
| `host_id` | string | The host, from the bus's client certificate. Never from the event itself |
| `hostname` | string | The name the host enrolled with |
| `event_type` | string | See [Event Types](#event-types) |
| `severity` | string | `INFO`, `WARN`, `ALERT` or `CRITICAL`, after the server's [severity table](allowlist-guide.md#how-allowlisting-changes-severity) |
| `pid`, `ppid`, `uid`, `gid` | integer | The acting process. `uid` 4294967295 means unknown (the writer of a file had exited before the bus could read it). Events with no process (BPF_INVENTORY, AGENT_OFFLINE, AGENT_RECOVERED) have 0 |
| `comm` | string | The task name (up to 15 characters) |
| `cmdline` | string | Full command line, arguments separated by spaces |
| `exe_path` | string | Resolved executable path |
| `exe_hash` | string | `sha256:<64 hex>` of the executable, hashed through `/proc/<pid>/root` for container processes. Empty if the bus could not hash it |
| `cgroup_path` | string | cgroup v2 path |
| `container_id` | string | Container ID (docker, cri-containerd, CRI-O, libpod), or empty. Not an image name |
| `namespace` | string | Reserved for a Kubernetes namespace. The bus does not fill it |
| `policy_result` | object | The server's decision; see below |

`policy_result`:

| Field | Type | Meaning |
|-------|------|---------|
| `action` | string | `ALLOW` if an ALLOW entry matched; otherwise the action of the entry that matched (`ALERT` or `DENY`), or `ALERT` when nothing matched. AGENT_OFFLINE and AGENT_RECOVERED are always `ALERT`. `DENY` blocks nothing |
| `matched_entry_id` | string | The entry that decided the event. Omitted when none did |
| `reason` | string | Why. For example `matched allowlist entry: <description>`, `no allowlist match for ...`, a built-in rule such as `rule:linker_config_modified — ...`, and `; learning mode: PENDING entry <id>` when learning mode recorded it |

`action` and `severity` are separate. An unmatched `/dev/shm` segment the bus rated INFO has `severity` INFO and `action` ALERT.

### Event Types

| `event_type` | Source | Detail object | Severity the bus sets |
|--------------|--------|---------------|-----------------------|
| `BPF_LOAD` | `bpf_syscall`: `bpf(BPF_PROG_LOAD)` | `bpf_detail` | WARN |
| `BPF_ATTACH` | `bpf_syscall`: `BPF_PROG_ATTACH`, `BPF_RAW_TRACEPOINT_OPEN`, `BPF_LINK_CREATE` | `bpf_detail` | WARN |
| `BPF_INVENTORY` | `bpf_syscall`: one event per loaded program at startup and every 5 minutes, then one summary | `bpf_detail` (programs), `bpf_inventory_detail` | INFO |
| `EXEC_INJECTION` | `exec_injection`: LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH or LD_DEBUG in a new process's environment | `exec_injection_detail` | ALERT |
| `SHM_CREATE` | `shm_monitor`: a file opened with `O_CREAT` under `/dev/shm` | `shm_detail` | CRITICAL (bpftime), ALERT (BPF-related name), INFO (other) |
| `DLOPEN` | `dlopen_monitor`: glibc `dlopen()` | `dlopen_detail` | WARN |
| `LINKER_CONFIG` | `linker_config`: `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.cache` changed | `linker_config_detail` | CRITICAL; INFO when a package manager wrote it |
| `PTRACE_INJECT` | `ptrace_monitor`: ATTACH, SEIZE, POKETEXT, POKEDATA, POKEUSER, SETREGS, SETREGSET | `ptrace_detail` | ALERT |
| `LIB_INTEGRITY` | `lib_integrity`: a `.so` in `/usr/lib`, `/usr/lib64`, `/lib` or `/lib64` changed | `lib_integrity_detail` | ALERT; INFO when a package manager wrote it |
| `ELF_RPATH` | `elf_rpath`: an executed binary has a risky DT_RPATH or DT_RUNPATH | `elf_rpath_detail` | CRITICAL, ALERT or WARN for a highest risk of CRITICAL, HIGH or MEDIUM. LOW and NONE raise no event |
| `AGENT_OFFLINE` | The server's watchdog: no heartbeat for `watchdog.heartbeat_timeout` | none | CRITICAL (server) |
| `AGENT_RECOVERED` | The server: the first heartbeat after AGENT_OFFLINE | none | INFO (server) |

The server keeps the bus's severity, raises it in two cases (root, and a binary the bus could not hash), and lowers it to INFO when an ALLOW entry matches; see [How Allowlisting Changes Severity](allowlist-guide.md#how-allowlisting-changes-severity). A bus cannot send AGENT_OFFLINE or AGENT_RECOVERED.

### Detail Objects

**`bpf_detail`** (BPF_LOAD, BPF_ATTACH, and per-program BPF_INVENTORY)

| Field | Type | Meaning |
|-------|------|---------|
| `bpf_cmd` | integer | `bpf()` command: 5 PROG_LOAD, 8 PROG_ATTACH, 17 RAW_TRACEPOINT_OPEN, 28 LINK_CREATE. 0 on BPF_INVENTORY |
| `prog_type` | integer | Kernel `bpf_prog_type`: 2 KPROBE, 3 SCHED_CLS, 5 TRACEPOINT, 6 XDP, 8 CGROUP_SKB, 17 RAW_TRACEPOINT, 26 TRACING, 29 LSM, and so on |
| `prog_name` | string | Program name (up to 15 characters) |
| `attach_type` | integer | Kernel `bpf_attach_type`, for attaches |
| `target_fd` | integer | Target file descriptor, for attaches |
| `insn_count` | integer | Instruction count |
| `prog_hash` | string | The kernel's program tag: 16 hex digits, as `bpftool prog show` prints it. The same for every load of the same instructions on the same kernel. Not a SHA-256 |
| `prog_id` | integer | Kernel program ID. Omitted when unknown (a failed load) |
| `load_time` | time | When the kernel loaded the program. Omitted when unknown |
| `created_by_uid` | integer | UID that loaded it, from the kernel. Omitted when unknown |
| `attach_target` | string | Tracepoint name of a RAW_TRACEPOINT_OPEN. Omitted otherwise |

**`bpf_inventory_detail`** (BPF_INVENTORY)

| Field | Type | Meaning |
|-------|------|---------|
| `scan_id` | string | Shared by every event of one scan |
| `summary` | boolean | `false`: one loaded program, described by `bpf_detail`. `true`: the host summary |
| `prog_count` | integer | Summary only: programs reported |
| `by_type` | object | Summary only: count per program type, keyed by cilium/ebpf type name (`SchedCLS`, `Kprobe`, `TracePoint`, ...) |

A program event's `policy_result` says whether the program is on the allowlist (`ALLOW` with `matched_entry_id`) or not (`ALERT`). The severity is INFO either way. The summary is always `ALLOW`.

**`exec_injection_detail`** (EXEC_INJECTION)

| Field | Type | Meaning |
|-------|------|---------|
| `env_var` | string | `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` or `LD_DEBUG`. Empty on a `scan_truncated` event |
| `library_path` | string | The variable's value |
| `library_hash` | string | `sha256:<hex>` of the library, for an absolute LD_PRELOAD or LD_AUDIT path. Empty otherwise |
| `target_binary` | string | The binary the process executed |
| `set_by` | string | `env` |
| `scan_truncated` | boolean | The environment was longer than the sensor scans, so a variable may have been missed. Such an event names no variable. Omitted when false |
| `value_truncated` | boolean | The value was longer than the sensor captures; `library_path` holds its start and `library_hash` is empty. Omitted when false |

**`shm_detail`** (SHM_CREATE)

| Field | Type | Meaning |
|-------|------|---------|
| `shm_name` | string | Name under `/dev/shm` |
| `size` | integer | Size in bytes, when known |
| `pattern` | string | `bpftime` (bpftime's segment names, including its `BPFTIME_GLOBAL_SHM_NAME` override), `bpf_related` ("bpf", "ebpf" or "libbpf" as a separate word in the name), or `unknown` |

**`dlopen_detail`** (DLOPEN)

| Field | Type | Meaning |
|-------|------|---------|
| `library_path` | string | The path passed to `dlopen()` |
| `library_hash` | string | `sha256:<hex>` of the library, or empty |
| `flags` | integer | `dlopen()` flags (1 `RTLD_LAZY`, 2 `RTLD_NOW`, ...) |

**`linker_config_detail`** (LINKER_CONFIG)

| Field | Type | Meaning |
|-------|------|---------|
| `file_path` | string | The file that changed |
| `operation` | string | `create`, `write`, `rename` or `delete` |
| `old_hash` | string | `sha256:<hex>` before the change (from the startup baseline or the last event). Omitted when unknown |
| `new_hash` | string | `sha256:<hex>` after. Omitted for `delete` |

**`ptrace_detail`** (PTRACE_INJECT)

| Field | Type | Meaning |
|-------|------|---------|
| `request` | integer | ptrace request number |
| `request_name` | string | `PTRACE_ATTACH`, `PTRACE_SEIZE`, `PTRACE_POKETEXT`, `PTRACE_POKEDATA`, `PTRACE_POKEUSER`, `PTRACE_SETREGS` or `PTRACE_SETREGSET` |
| `target_pid` | integer | Target process |
| `target_comm` | string | Target's task name. Empty when the target is in a PID namespace nested below the caller's |
| `addr` | integer | Address, for POKE requests. Omitted when 0 |

**`lib_integrity_detail`** (LIB_INTEGRITY)

| Field | Type | Meaning |
|-------|------|---------|
| `library_path` | string | The library that changed |
| `operation` | string | `create`, `write`, `rename` or `delete` |
| `old_hash`, `new_hash` | string | `sha256:<hex>` before and after. Omitted when unknown |
| `in_ld_cache` | boolean | Whether `/etc/ld.so.cache` lists the library |

**`elf_rpath_detail`** (ELF_RPATH)

| Field | Type | Meaning |
|-------|------|---------|
| `has_rpath`, `has_runpath` | boolean | Whether the binary has DT_RPATH, DT_RUNPATH |
| `rpath_raw`, `runpath_raw` | string | The raw values. Omitted when absent |
| `entries` | array | One object per path entry: `path` (as written in the binary, before `$ORIGIN` expansion), `risk` (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `reason`, `exists`, `is_rpath` (true for DT_RPATH) |
| `highest_risk` | string | The highest `risk` of any entry |
| `uses_origin` | boolean | An entry uses `$ORIGIN` |
| `uses_deprecated` | boolean | DT_RPATH is present |
| `is_setuid` | boolean | The binary is setuid or setgid |

AGENT_OFFLINE and AGENT_RECOVERED have no detail object and no process fields. Their `policy_result.reason` says what happened, for example `Heartbeats resumed after 1m3s without one (last at 2026-10-11T02:55:55Z); the host was UNRESPONSIVE, and events from that time may be missing`.

## Hosts

### GET /api/v1/hosts

Lists enrolled hosts, ordered by hostname.

### GET /api/v1/hosts/{id}

Returns one host. 404 if it is not enrolled.

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$HM/api/v1/hosts"
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$HM/api/v1/hosts/$HOST_ID"
hookmon-cli $FLAGS hosts
```

| Field | Type | Meaning |
|-------|------|---------|
| `id` | string | Host ID, assigned by the server at enrollment and written into the bus certificate's CN |
| `hostname` | string | The name the host enrolled with |
| `ip_address` | string | The address the host enrolled from |
| `agent_version` | string | Bus version from the latest heartbeat |
| `os_info` | string | OS description from enrollment |
| `status` | string | `ONLINE`, or `UNRESPONSIVE` after `watchdog.heartbeat_timeout` with no heartbeat. `OFFLINE` is defined but nothing sets it |
| `enrolled_at` | time | Enrollment time |
| `last_heartbeat` | time | When the server received the latest heartbeat (server clock) |
| `last_event_at` | time | Meant to be the latest event's time. Nothing sets it, so it is always omitted (see [Known Issues](#known-issues)) |
| `sensors` | array | Sensor health from the latest heartbeat: `name`, `status` (`alive`, `dead`, `failed`, `unverifiable` or `unknown`) and `reason`. Omitted before the first heartbeat |

```json
{
  "id": "6d4e295e-3725-4641-b1a9-efe3c8890a7c",
  "hostname": "web-01",
  "ip_address": "127.0.0.1",
  "agent_version": "dev",
  "os_info": "simbus",
  "status": "ONLINE",
  "enrolled_at": "2026-10-10T22:55:46.965627-04:00",
  "last_heartbeat": "2026-10-10T23:12:12.934581-04:00",
  "sensors": [
    {"name": "bpf_syscall", "status": "alive"},
    {"name": "exec_injection", "status": "alive"}
  ]
}
```

(The `sensors` list is abridged; a real bus reports all eight.)

## Policies (Allowlist)

Policies are allowlist entries. How they match events is in [allowlist-guide.md](allowlist-guide.md#how-matching-works).

### Allowlist Entry Object

| Field | Type | Set by | Meaning |
|-------|------|--------|---------|
| `id` | string | server, or the creator | Entry ID. A UUID unless the creator gives one |
| `created_at` | time | server, or the creator | Creation time |
| `created_by` | string | creator | Free text. Learning mode sets `learning-mode`; allowlisting an event sets `api`; otherwise whatever the body says (empty by default) |
| `description` | string | operator | Shown in the dashboard and in `policy_result.reason` |
| `event_types` | array of strings | operator | Event types it applies to. Empty: every type |
| `exe_hash` | string | operator | `sha256:<hex>` of the executable |
| `exe_path` | string | operator | Glob on the executable path |
| `library_hash` | string | operator | `sha256:<hex>` of the library (EXEC_INJECTION, DLOPEN) |
| `library_path` | string | operator | Glob on the library path (EXEC_INJECTION, DLOPEN) |
| `prog_name` | string | operator | Glob on the BPF program name |
| `prog_type` | integer or null | operator | BPF program type. `null`: any |
| `prog_hash` | string | operator | BPF program tag, 16 hex digits |
| `host_pattern` | string | operator | Glob on the hostname |
| `uid_range` | object or null | operator | `{"min": 0, "max": 999}`, inclusive |
| `container_image` | string | operator | Glob, matched against the event's **container ID** (the bus reports no image) |
| `allowed_rpaths` | array of strings | operator | Globs; every RPATH entry of an ELF_RPATH event must match one. Omitted when empty |
| `host_id` | string | operator | One enrolled host. Omitted or empty: the whole fleet |
| `action` | string | operator | `ALLOW`, `ALERT` or `DENY`. Required |
| `expires` | time or null | operator | The entry stops matching at this time. `null`: never |
| `enabled` | boolean | operator | Only enabled entries match. **Defaults to false when omitted** |
| `status` | string | server | `APPROVED`, `PENDING` or `REJECTED` |
| `learned` | object | server | Present on entries from learning mode or from an event: `key`, `exe_path`, `occurrences`, `first_seen`, `last_seen`, `hosts`. See [the dedupe key](allowlist-guide.md#the-dedupe-key) |

On write, `exe_hash` and `library_hash` accept `sha256:<64 hex digits>` (prefix in any case) or the 64 hex digits alone, and are stored as `sha256:<lowercase hex>`. `prog_hash` must be 16 hex digits and is stored in lower case. Anything else is a 400, since it could never match.

### GET /api/v1/policies

| Parameter | Meaning |
|-----------|---------|
| (none) | Entries in force: `APPROVED` and `REJECTED` |
| `status=PENDING` | Learning-mode candidates |
| `status=APPROVED`, `status=REJECTED` | Those only |
| `status=ALL` | Every entry |

Statuses can be combined with commas (`status=PENDING,REJECTED`) and are case-insensitive. Any other value is a 400 (`status must be APPROVED, PENDING, REJECTED or ALL`). The list is newest first and includes disabled and expired entries.

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$HM/api/v1/policies"
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$HM/api/v1/policies?status=PENDING"
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$HM/api/v1/policies?status=ALL"
hookmon-cli $FLAGS policies            # APPROVED and REJECTED
hookmon-cli $FLAGS policies pending    # PENDING
```

There is no route for one entry. Filter the list by `id`, for example with `jq`.

### POST /api/v1/policies

Creates an entry. It is APPROVED and in force at once (if `enabled` is true).

- The body is an [entry object](#allowlist-entry-object). `action` is required.
- Set `"enabled": true`. An entry created without it is stored disabled and matches nothing.
- `status` must be empty or `APPROVED`; PENDING entries come only from learning mode.
- `learned` must be absent.
- `id` and `created_at` are generated when absent.

| Status | When |
|--------|------|
| 201 | The stored entry |
| 400 | No or bad `action`; bad hash format; `status` other than APPROVED; `learned` set; unknown field |
| 413 | Body over 64 KiB |
| 500 | Database error, or an `id` that already exists |

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

CLI: `hookmon-cli $FLAGS policies create` reads the same JSON from stdin:

```bash
echo '{"description": "gdb on build hosts", "event_types": ["PTRACE_INJECT"],
       "exe_path": "/usr/bin/gdb", "host_pattern": "build-*",
       "action": "ALLOW", "enabled": true}' | hookmon-cli $FLAGS policies create
```

### PUT /api/v1/policies/{id}

Replaces an entry's criteria, `action`, `expires`, `description` and `enabled`. Fields left out of the body become empty, `null` or false, so send the whole entry, such as one from GET with fields changed.

- `id`, `created_at`, `created_by` and `learned` are kept from the stored entry. An `id` in the body must match the URL.
- `status` cannot change. It may be omitted or repeat the current value.
- A REJECTED entry must keep action ALERT.
- A PENDING entry cannot be edited (409). Approve or reject it first.

| Status | When |
|--------|------|
| 200 | The stored entry |
| 400 | Validation as for POST; `id in the body does not match the URL`; `status cannot change from APPROVED with PUT`; `a REJECTED entry keeps action ALERT; delete it instead` |
| 404 | No such entry |
| 409 | `entry <id> is PENDING: approve or reject it first` |

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$HM/api/v1/policies?status=ALL" \
  | jq --arg id "$ENTRY_ID" '.[] | select(.id == $id) | .expires = "2026-12-31T00:00:00Z"' > entry.json
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X PUT \
  "$HM/api/v1/policies/$ENTRY_ID" --data-binary @entry.json
```

CLI: none.

### PATCH /api/v1/policies/{id}

Changes only the fields in the body. A field set to `null` is cleared.

- Fields it may change: `description`, `event_types`, `exe_hash`, `exe_path`, `library_hash`, `library_path`, `prog_name`, `prog_type`, `prog_hash`, `host_pattern`, `uid_range`, `container_image`, `allowed_rpaths`, `host_id`, `action`, `expires`, `enabled`.
- Any other field (`id`, `status`, `learned`, `created_at`, `created_by`) is a 400 (`"status" cannot be changed with PATCH`).
- An empty object is a 400. The same rules as PUT apply to the result.

| Status | When |
|--------|------|
| 200 | The stored entry |
| 400 | A field PATCH may not change; empty patch; a value of the wrong type (`invalid patch: ...`); validation as for POST |
| 404 | No such entry |
| 409 | The entry is PENDING |

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X PATCH \
  "$HM/api/v1/policies/$ENTRY_ID" -d '{"enabled": false}'
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X PATCH \
  "$HM/api/v1/policies/$ENTRY_ID" -d '{"expires": null, "description": "gdb on web-01 (SEC-42)"}'
```

CLI: none. The dashboard's Policy Manager uses PATCH for its enable toggle and PUT for Edit.

### DELETE /api/v1/policies/{id}

Deletes any entry, including a PENDING one. 204 with no body; 404 if there is no such entry. If learning mode is on and the event happens again, a deleted entry's key is proposed again.

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X DELETE "$HM/api/v1/policies/$ENTRY_ID"
hookmon-cli $FLAGS policies delete "$ENTRY_ID"
```

### POST /api/v1/policies/{id}/approve and /reject

Decide a PENDING entry for the fleet or for one host.

Body: `{"scope": "fleet"}` or `{"scope": "host", "host_id": "<enrolled host ID>"}`.

| Decision | Scope | Effect | Answer |
|----------|-------|--------|--------|
| approve | fleet | The entry becomes APPROVED with action ALLOW, for every host | The same entry |
| reject | fleet | The entry becomes REJECTED with action ALERT. Its events keep alerting, and learning mode does not propose them again | The same entry |
| approve or reject | host | A new entry with the same key, for that host only (`host_id` set, `learned.hosts` set to the host). The host is taken off the PENDING entry's `learned.hosts`; the PENDING entry is deleted when no host is left | The new entry |

| Status | When |
|--------|------|
| 200 | The entry now in force |
| 400 | `scope must be "fleet" or "host"`; `scope "host" needs host_id`; `scope "fleet" takes no host_id`; missing body |
| 404 | No such entry (`not found`), or the host is not enrolled (`host <id> is not enrolled`) |
| 409 | The entry is not PENDING (`allowlist entry <id> is APPROVED: allowlist entry is not PENDING`) |

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X POST \
  "$HM/api/v1/policies/$ENTRY_ID/approve" -d '{"scope": "fleet"}'
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X POST \
  "$HM/api/v1/policies/$ENTRY_ID/reject" -d "{\"scope\": \"host\", \"host_id\": \"$HOST_ID\"}"
hookmon-cli $FLAGS policies approve "$ENTRY_ID" --fleet
hookmon-cli $FLAGS policies reject "$ENTRY_ID" --host "$HOST_ID"
```

The ID and the flags can come in either order.

## Learning Mode

While a learning window covers a host, every event from it that no entry matches becomes a PENDING entry. See [allowlist-guide.md](allowlist-guide.md#learning-mode).

### GET /api/v1/learning

Lists every window, ended ones included, with the server's time.

```json
{
  "now": "2026-10-11T03:08:37.56103544Z",
  "windows": [
    {
      "scope": "fleet",
      "started_at": "2026-10-10T23:08:37.543263-04:00",
      "ends_at": "2026-10-11T01:08:37.543263-04:00",
      "started_by": "api",
      "active": true
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `scope` | `fleet` or `host` |
| `host_id` | The host, for `host`. Omitted for `fleet` |
| `started_at`, `ends_at` | The window. It is active while `now` is before `ends_at` |
| `started_by` | `api` |
| `active` | Whether it is open now |

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$HM/api/v1/learning"
hookmon-cli $FLAGS learning
```

### PUT /api/v1/learning/fleet and /api/v1/learning/hosts/{hostID}

Starts learning mode, or restarts it with a new end time. There is one window per scope; a PUT replaces it.

Body, exactly one of:

| Field | Type | Meaning |
|-------|------|---------|
| `duration` | string | From now: a Go duration (`90m`, `36h`) or whole days (`7d`). Must be positive |
| `ends_at` | RFC 3339 time | Must be in the future |

| Status | When |
|--------|------|
| 200 | The window (as in GET) |
| 400 | `learning mode needs an end: give ends_at or duration`; `give ends_at or duration, not both`; a bad or non-positive duration; `ends_at must be in the future` |
| 404 | `host <id> is not enrolled` (host scope) |

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X PUT "$HM/api/v1/learning/fleet" -d '{"duration": "7d"}'
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X PUT \
  "$HM/api/v1/learning/hosts/$HOST_ID" -d '{"ends_at": "2026-11-01T00:00:00Z"}'
hookmon-cli $FLAGS learning start --fleet --for 7d
hookmon-cli $FLAGS learning start --host "$HOST_ID" --until 2026-11-01T00:00:00Z
```

### DELETE /api/v1/learning/fleet and /api/v1/learning/hosts/{hostID}

Ends learning mode now by deleting the window. PENDING entries stay for review. 204; 404 (`no learning window for that scope`) when there is none. An ended window that was not deleted also gives 204.

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" -X DELETE "$HM/api/v1/learning/fleet"
hookmon-cli $FLAGS learning stop --fleet
hookmon-cli $FLAGS learning stop --host "$HOST_ID"
```

## Settings

### GET /api/v1/settings

What the dashboard's Settings page shows. It holds no secrets: enrollment tokens appear by name, and connector targets and credentials are left out.

```bash
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" "$HM/api/v1/settings"
```

```json
{
  "version": "dev",
  "tls": true,
  "grpc_addr": "127.0.0.1:28943",
  "enroll_addr": "127.0.0.1:28944",
  "http_addr": "127.0.0.1:28443",
  "enrollment": {
    "enabled": true,
    "tokens": [
      {"name": "wdocs", "expires": "2026-10-13T02:54:21Z", "expired": false, "single_use": false}
    ]
  },
  "connectors": [
    {"name": "syslog", "min_severity": "ALERT", "sent": 20, "dropped": 0, "failed": 0, "queued": 0}
  ],
  "websocket": {
    "subscribers": 0,
    "published": 32,
    "lagged": 0,
    "buffer": 256,
    "protocol": "hookmon.v1",
    "token_protocol_prefix": "hookmon.bearer.",
    "allowed_origins": ["https://dash.example.com"]
  }
}
```

(This server listened on loopback test ports. With the default config the addresses are `[::]:9443`, `[::]:9444` and `[::]:8443`.)

| Field | Meaning |
|-------|---------|
| `version` | Server build version |
| `tls` | False only in `--insecure` mode |
| `grpc_addr`, `enroll_addr`, `http_addr` | Bound listener addresses. `enroll_addr` is empty when enrollment is off |
| `enrollment.enabled` | Whether the enrollment listener runs (it needs at least one token) |
| `enrollment.tokens[]` | `name`, `expires`, `expired` and `single_use` of each configured token. Never the secret |
| `connectors[]` | Each configured connector: `name`, `min_severity` (ALERT when unset), and `sent`, `dropped`, `failed` and `queued` since the server started |
| `websocket.subscribers` | Clients connected now |
| `websocket.published` | Events handed to the feed since start |
| `websocket.lagged` | Clients dropped for falling behind |
| `websocket.buffer` | Each client's buffer, in events (256) |
| `websocket.protocol`, `websocket.token_protocol_prefix` | The subprotocols a client offers |
| `websocket.allowed_origins` | `api.allowed_origins`, normalized, sorted |

CLI: none.

## WebSocket Event Feed

`GET /api/v1/ws/events` upgrades to a WebSocket and streams every event the server processes, from the moment the handshake completes. It sends no history: load recent events over REST, then follow the feed.

### Handshake

The server checks, in this order:

1. **Origin.** A request with no `Origin` header is not from a browser and passes. A browser's `Origin` passes when its host equals the `Host` the request was sent to (the server's own page), or when it is in `api.allowed_origins` (`scheme://host[:port]`, compared in lower case). `null` and malformed origins are refused. Failure: 403 `{"error":"origin not allowed"}`.
2. **Token.** Either an `Authorization: Bearer <token>` header (for clients that can set headers), or a subprotocol `hookmon.bearer.<token as unpadded base64url>` in `Sec-WebSocket-Protocol` (for browsers, which can't). A `?token=` query parameter is refused, so the token never lands in access or proxy logs. Failures are 401:
   - `missing token: offer the hookmon.bearer.<base64url> subprotocol, or send an Authorization header`
   - `a token in the URL is not accepted: ...`
   - `token subprotocol is not unpadded base64url`
   - `invalid token`
3. **Feed.** 503 when the server is shutting down.

Offer `hookmon.v1` next to the token subprotocol. The server selects `hookmon.v1` and never echoes the token back. A browser fails the connection if it offered subprotocols and the server selected none.

Browser:

```js
const b64url = btoa(token).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ws = new WebSocket('wss://hookmon.internal:8443/api/v1/ws/events',
                         ['hookmon.v1', 'hookmon.bearer.' + b64url]);
ws.onmessage = (m) => console.log(JSON.parse(m.data));
ws.onclose = (e) => { if (e.code === 1013) { /* reload recent events over REST, then reconnect */ } };
```

(`btoa` takes Latin-1 text; the dashboard encodes the token as UTF-8 bytes first.)

curl can show the handshake and the raw frames. Each event is printed as a WebSocket frame: a few binary header bytes, then the JSON.

```bash
WS_TOKEN=$(printf %s "$TOKEN" | base64 | tr -d '\n=' | tr '+/' '-_')
curl -i -N --http1.1 --max-time 30 --cacert "$CA" \
  -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
  -H "Sec-WebSocket-Protocol: hookmon.v1, hookmon.bearer.$WS_TOKEN" \
  "$HM/api/v1/ws/events"
```

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: O8VP+Jn2QOfbER4wubi4DuaJghY=
Sec-WebSocket-Protocol: hookmon.v1

??{"id":"64c6a93f-0bf0-446d-ab1e-97863f9c2a71","timestamp":"2026-10-11T03:07:57.394419218Z","host_id":"6d4e295e-3725-4641-b1a9-efe3c8890a7c","hostname":"web-01","event_type":"AGENT_RECOVERED","severity":"INFO",...}??{"id":"3b474752-755a-46e6-b21d-cb7680d3175f",...,"event_type":"BPF_LOAD","severity":"INFO",...}
```

curl exits with code 28 when `--max-time` runs out; that is expected.

### Messages

- Each event is one text message: the [event JSON](#event-json) after policy evaluation, the same object REST returns for it (times may show a different UTC offset).
- Every subscriber gets every event, in the order the server processed them. Several tabs each get the full feed.
- AGENT_OFFLINE and AGENT_RECOVERED are sent too.
- The server sends a ping every 30 s and closes the connection when no pong has arrived for 60 s. Browsers answer pings on their own.
- Client messages are read and ignored. A client message over 4096 bytes closes the connection.

### Close Codes

| Code | Reason text | Meaning | What the client should do |
|------|-------------|---------|---------------------------|
| 1013 (try again later) | `fell behind the event feed; reconnect` | The client fell more than 256 events behind, and the server dropped it so it could not slow ingestion or other clients. The events already queued for it are delivered before the close | Reconnect, and reload recent events over REST to fill the gap |
| 1001 (going away) | `server shutting down` | The server is stopping | Reconnect with backoff |

A client that stops reading entirely may instead see the connection drop without a close frame, when a write to it has blocked for 10 s.

## hookmon-cli

`hookmon-cli` is a REST client. Global flags come before the command:

| Flag | Default | Meaning |
|------|---------|---------|
| `--server` | `https://localhost:8443` | Server URL |
| `--token` | | API token. It is visible in the process list; there is no environment variable for it |
| `--ca-file` | `$HOOKMON_CA_FILE` | CA that signed the server certificate. Empty: system roots |
| `--version` | | Print the version |

Output is the server's JSON, indented, with object keys sorted. Errors print `error: server returned <status>: <body>` and exit 1.

| Command | Request |
|---------|---------|
| `health` | `GET /api/v1/health` |
| `events [--limit N] [--host ID] [--type TYPE]` | `GET /api/v1/events?limit=N&host_id=ID&event_type=TYPE` (limit 50 by default) |
| `hosts` | `GET /api/v1/hosts` |
| `policies` | `GET /api/v1/policies` |
| `policies pending` | `GET /api/v1/policies?status=PENDING` |
| `policies create` (JSON on stdin) | `POST /api/v1/policies` |
| `policies delete ID` | `DELETE /api/v1/policies/ID` |
| `policies approve ID --fleet\|--host HOST_ID` | `POST /api/v1/policies/ID/approve` |
| `policies reject ID --fleet\|--host HOST_ID` | `POST /api/v1/policies/ID/reject` |
| `learning` (or `learning status`) | `GET /api/v1/learning` |
| `learning start --fleet\|--host HOST_ID --for DURATION\|--until TIME` | `PUT /api/v1/learning/fleet` or `/hosts/HOST_ID` |
| `learning stop --fleet\|--host HOST_ID` | `DELETE /api/v1/learning/fleet` or `/hosts/HOST_ID` |

No CLI command covers one event, one host, PUT, PATCH, allowlisting an event, `status=ALL` or settings. Use curl for those.

## Example Runs

Every curl and `hookmon-cli` example in this document and in [allowlist-guide.md](allowlist-guide.md) was run on 2026-10-11 against `hookmon-server` built from this tree, on drl-nuc8i3bek (Ubuntu 22.10), with TLS from a test CA and `postgres:16-alpine` pinned by digest. A test client enrolled two hosts, `web-01` and `web-02`, through the enrollment port, and streamed synthetic events of every type over the bus's gRPC transport (`agent/transport`). No real bus ran, so the events' process details are made up; their shape and the server's handling of them are real. The outputs shown are from that run; IDs differ on every server.

Notes on the run:

- The server address was `https://localhost:28443`, so the examples ran with `HM=https://localhost:28443`.
- Every status in the error table except 503 was produced, including 500 with PostgreSQL stopped. The server recovered once PostgreSQL was back.
- The WebSocket handshake rules were checked with a Go client (gorilla/websocket). No token, a wrong token and a token in the URL got 401. A foreign and a `null` Origin got 403. The server's own origin, a configured origin and no Origin connected.
- The `Authorization` header form of the handshake was not run live. `TestWebSocket_TokenAndOrigin` in `server/api/websocket_test.go` covers it, and passes.
- The slow-subscriber close was produced too. A client that stopped reading for 7 s, while two hosts streamed large events, received 298 events and then close 1013, and `websocket.lagged` became 1.
- The browser snippet was not run. It does what `dashboard/src/api/client.ts` does.

### Known Issues

Found while writing this document. None is fixed here.

- **An empty API token authenticates.** With `--api-tokens "abc,"` (or an empty string in `api.tokens`), `curl -H "Authorization: Bearer " $HM/api/v1/hosts` got 200 over HTTP/2. Over HTTP/1.1 the server trims the trailing space, so the same header got 401. Neither the config check nor the middleware refuses an empty token (`server/api/auth.go:18,54-56`, `cmd/hookmon-server/main.go:79`). The WebSocket refuses an empty token.
- `POST /api/v1/policies` with an `id` that already exists returns 500 `failed to create policy`, not 409 (`server/api/policies.go:127-130`).
- An unparseable `since` or `until` on `GET /api/v1/events` is ignored instead of refused (`server/api/events.go:62-71`).
- 401 responses carry a JSON body with `Content-Type: text/plain` (`server/api/auth.go:34,39`).
- `POST /api/v1/policies` stores an entry without `enabled` as disabled, with no warning (`server/api/policies.go:98-136`).
- `hosts.last_event_at` is never written: `InsertEvent` does not update the host row (`server/store/postgres.go:118`), so `last_event_at` is always omitted and the dashboard's Host Inventory shows "None" for every host's last event (`dashboard/src/pages/HostInventory.tsx:166`).

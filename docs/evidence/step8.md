# Step 8: the first five minutes on two hosts

Captured 2026-10-11 from `main` at 22cd49d. Plan step 8 asked for a workstation, a Kubernetes node and a server running Cilium or Falco. Two hosts were used as they are, with nothing installed on them. **Neither host is a Kubernetes node, and neither runs Cilium or Falco.** Those two cases were not captured.

## Hosts

| | drl-nuc8i3bek | infinichat-u9 |
| --- | --- | --- |
| Role | Workstation | Container and GPU host |
| OS, kernel | Ubuntu 22.10, 5.19.0-46-generic | Ubuntu 24.04.2, 6.17.0-23-generic |
| CPUs | 4 | 16 |
| Docker | 24.0.5 (containerd 1.6.21, runc 1.1.7) | 29.1.3 (containerd 1.7.28, runc 1.3.3) |
| Running | GNOME desktop with the Slimjet browser; the user's `docker-grafana`, `docker-prometheus` and `docker-loki` containers; another engineer's test Postgres container, which was removed during the window | llama-server (`llamampere-qwen38.service`), `ollama.service`, `infinichat.service`, `curator.service`. No containers of the user's were running. For this capture it also ran the HookMon compose appliance: 8 containers |
| Is not | A server, a Kubernetes node, a Cilium or Falco host | A Kubernetes node, a Cilium or Falco host |
| Enrolled host ID | `1b4b470b-7b54-4450-8b39-4ddc394d40fb` (hostname `drl-NUC8i3BEK`) | `d352138f-978e-4abf-9f8e-e78c35bb1c2e` |

**Clocks.** u9's clock was about 38 s behind the NUC's and the Mac's (`timedatectl`: "System clock synchronized: no"). It was left as it was. Each bus stamps events with its own host's clock, so each host's window below is in that host's clock. The server, Grafana, Prometheus and Loki ran on u9 and use u9's clock.

**The appliance ran on one of the monitored hosts.** The server, Postgres, Grafana, Prometheus, Loki, Pushgateway, Alertmanager and the collector ran as containers on u9 while u9's bus watched it. Their Docker healthchecks are most of u9's events (see below).

## Commands

All binaries were built from 22cd49d (`git archive HEAD`, copied to both hosts).

**NUC: lock and build.** The lock `/tmp/hookmon-nuc.lock` was held from 03:25:47Z until after teardown by a background `flock -w 3600 /tmp/hookmon-nuc.lock sh -c '…; exec sleep 86400'`.

```sh
cd ~/hookmon-w8/src
make CC=clang VERSION=22cd49d COMMIT=22cd49d build-bus build-dlopen-probe   # Go 1.24.4, clang
```

`bin/hookmon-bus` (sha256 `a144f025…a298f0`) and `bin/hookmon-dlopen-probe` (sha256 `9968db33…0231f8`) were copied unchanged to u9, which has no compiler.

**u9: the appliance.** u9 already listens on 22, 53, 80, 2222, 2223, 5432, 8080, 8090, 9090, 11434 and 20241. The server (8443, 9443, 9444), Grafana (3000) and Loki (3100) kept their ports.

```sh
cd ~/hookmon-w8/src
deploy/appliance/hookmon-init.sh --mode compose --out-dir ~/hookmon-s8-init \
  --hostname infinichat-u9 --ip 100.95.196.103
# then replaced ~/hookmon-s8-init/prometheus/buses.yml and the hosts list in
# ~/hookmon-s8-init/collector.yaml (below)
HOOKMON_CONFIG_DIR=~/hookmon-s8-init docker compose -p hookmon-s8 \
  -f deploy/appliance/docker-compose.yml -f ~/hookmon-w8/ports-override.yml \
  up -d --build --wait --wait-timeout 600          # 1m30s, 8 services healthy
deploy/appliance/check-stack.sh --config-dir ~/hookmon-s8-init --hostname infinichat-u9 -- \
  docker compose -p hookmon-s8 -f deploy/appliance/docker-compose.yml -f ~/hookmon-w8/ports-override.yml
                                                   # 13 checks, all ok
```

`ports-override.yml` (outside the repository) moved only the three services whose ports collide with u9's Prometheus on 9090:

```yaml
services:
  prometheus:   { ports: !override ["127.0.0.1:19090:9090"] }
  pushgateway:  { ports: !override ["127.0.0.1:19091:9091"] }
  alertmanager: { ports: !override ["127.0.0.1:19093:9093"] }
```

Scrape and poll targets, by tailnet IP. The containers use Docker's upstream resolver, which can't resolve the tailnet's MagicDNS names.

```yaml
# ~/hookmon-s8-init/prometheus/buses.yml
- targets: ["100.74.132.84:2112"]
  labels: { instance: drl-nuc8i3bek:2112 }
- targets: ["100.95.196.103:2112"]
  labels: { instance: infinichat-u9:2112 }
# ~/hookmon-s8-init/collector.yaml, hosts:
  - { hostname: drl-NUC8i3BEK, status_url: http://100.74.132.84:2112/status }
  - { hostname: infinichat-u9, status_url: http://100.95.196.103:2112/status }
```

**Learning mode.** Fleet learning was started just before the buses (`PUT /api/v1/learning/fleet {"duration": "30m"}`, at 03:31:19.48 on the server's clock). It was stopped with `DELETE /api/v1/learning/fleet` at 03:36:24.60 on the server's clock (03:37:02.57 on the Mac's), just after both windows ended.

**Buses.** On each host, as root, with everything under `/tmp/hookmon-s8` (mode 0700): `ca.crt` (the appliance CA), `enroll-token` (0600, from the init out-dir), and `bus.yaml`:

```yaml
state_dir: /tmp/hookmon-s8/state
fallback_log_path: /tmp/hookmon-s8/fallback.jsonl
status_port: 2112
```

```sh
sudo sh -c 'setsid nohup /tmp/hookmon-s8/run-bus.sh BUS > /tmp/hookmon-s8/bus.log 2>&1 < /dev/null &'
# run-bus.sh writes T0 (date -u +%Y-%m-%dT%H:%M:%S.%NZ) and its PID, then:
exec BUS --config /tmp/hookmon-s8/bus.yaml \
  --enroll-token-file /tmp/hookmon-s8/enroll-token \
  --server-addr infinichat-u9:9443 --enroll-addr infinichat-u9:9444 \
  --ca-file /tmp/hookmon-s8/ca.crt --state-dir /tmp/hookmon-s8/state \
  --loki-url http://infinichat-u9:3100 --status-port 2112
```

`BUS` was `~/hookmon-w8/src/bin/hookmon-bus` on the NUC and `/tmp/hookmon-s8/bin/hookmon-bus` on u9. Both enrolled, connected and started 8 sensors within 0.8 s. `/status` showed 8 of 8 alive 7 to 10 s after T0 and again at the end of each window. Neither bus logged a warning or an error (16 info lines each).

**Events.** For each host, `GET /api/v1/events?host_id=…&since=T0&until=T0+5m&limit=500&offset=N`, from offset 0 in steps of 500 until a page came back short. The NUC took two pages (500, 146) and u9 one (469). One request with `limit=100000` returned the same counts. The file is the pages' arrays joined in the order the server returned them (newest first), pretty-printed with nothing else changed.

**Screenshot.** Headless Chromium from Playwright 1.64.0 (the worktree's `dashboard/node_modules`), on the Mac. Viewport 1600×1860, browser time zone UTC. It logged in as `admin` through the login form, with the password from `secrets/grafana.env`. It opened `/d/hookmon-main/hookmon?orgId=1&from=1791689430000&to=1791689880000&refresh=1h&kiosk`, which is 03:30:30Z to 03:38:00Z with auto-refresh stopped. It waited until no panel showed a loading bar, then 5 s more. Taken at 03:37:39Z, 37 s after both windows ended.

## T0

| Host | T0 (that host's clock, UTC) | Window end | First event | Last event |
| --- | --- | --- | --- | --- |
| drl-nuc8i3bek | 2026-10-11T03:32:01.935933668Z | 03:37:01.935933668Z | 03:32:02.221945Z | 03:37:01.706901Z |
| infinichat-u9 | 2026-10-11T03:31:24.054517065Z (about 03:32:02 on the NUC's clock) | 03:36:24.054517065Z | 03:31:24.178375Z | 03:36:22.194044Z |

## Raw facts

Severity and policy action are the server's (the API's), not the bus's.

### drl-nuc8i3bek: 646 events

| event type | events |
| --- | --- |
| SHM_CREATE | 570 |
| DLOPEN | 39 |
| BPF_INVENTORY | 33 |
| EXEC_INJECTION | 4 |
| **total** | **646** |

| severity | events |
| --- | --- |
| INFO | 603 |
| CRITICAL | 30 |
| WARN | 13 |
| **total** | **646** |

| event type | severity | policy action | events |
| --- | --- | --- | --- |
| SHM_CREATE | INFO | ALERT | 570 |
| BPF_INVENTORY | INFO | ALERT | 32 |
| DLOPEN | CRITICAL | ALERT | 26 |
| DLOPEN | WARN | ALERT | 13 |
| EXEC_INJECTION | CRITICAL | ALERT | 4 |
| BPF_INVENTORY | INFO | ALLOW | 1 |
| **total** | | | **646** |

By sensor: shm_monitor 570, dlopen_monitor 39, bpf_syscall (inventory) 33, exec_injection 4. elf_rpath, ptrace_monitor, linker_config and lib_integrity: 0. No BPF_LOAD or BPF_ATTACH.

### infinichat-u9: 469 events

| event type | events |
| --- | --- |
| EXEC_INJECTION | 410 |
| BPF_INVENTORY | 34 |
| DLOPEN | 24 |
| ELF_RPATH | 1 |
| **total** | **469** |

| severity | events |
| --- | --- |
| CRITICAL | 419 |
| INFO | 34 |
| WARN | 15 |
| ALERT | 1 |
| **total** | **469** |

| event type | severity | policy action | events |
| --- | --- | --- | --- |
| EXEC_INJECTION | CRITICAL | ALERT | 410 |
| BPF_INVENTORY | INFO | ALERT | 33 |
| DLOPEN | WARN | ALERT | 15 |
| DLOPEN | CRITICAL | ALERT | 9 |
| BPF_INVENTORY | INFO | ALLOW | 1 |
| ELF_RPATH | ALERT | ALERT | 1 |
| **total** | | | **469** |

By sensor: exec_injection 410, bpf_syscall (inventory) 34, dlopen_monitor 24, elf_rpath 1. shm_monitor, ptrace_monitor, linker_config and lib_integrity: 0. No BPF_LOAD or BPF_ATTACH.

### Bus counters against stored events

`hookmon_events_total` from each bus's `/metrics`, read just after its window (NUC at 03:37:02.47, u9 at 03:36:24.29, each on its own clock), against the API:

| Host | Bus counter | Stored in the window | Second inventory scan (T0+5 m, just after the window) |
| --- | --- | --- | --- |
| drl-nuc8i3bek | 682 | 646 | 36 (35 programs + summary) |
| infinichat-u9 | 508 | 469 | 39 (38 programs + summary) |

Each counter equals the stored events plus the second scan, so no event was lost between bus and server. The bus's own severities differ from the server's. On the bus, every DLOPEN is WARN and every EXEC_INJECTION is ALERT. In the API, the NUC's 39 DLOPEN are 26 CRITICAL and 13 WARN, and u9's 24 are 9 CRITICAL and 15 WARN. Every EXEC_INJECTION (4 on the NUC, 410 on u9) is CRITICAL. The server raised the events from UID 0.

### BPF programs in the first inventory

One scan per host, at T0+0.29 s (NUC) and T0+0.12 s (u9). It ran while the bus was still starting, after `elf_rpath` and during `bpf_syscall`, so it lists 3 of the bus's own programs and not the others. Every program event has severity INFO and policy action ALERT; the scan's summary event has action ALLOW.

**drl-nuc8i3bek: 32 programs, 15 distinct** (summary: CGroupDevice 17, CGroupSKB 12, TracePoint 3)

| name | type | tag | created_by_uid | count | prog ids |
| --- | --- | --- | --- | --- | --- |
| `rpath_on_exec` | TRACEPOINT (5) | `a26a58e10de68efd` | 0 | 1 | 16856 |
| `trace_bpf_enter` | TRACEPOINT (5) | `13443d24c302919b` | 0 | 1 | 16859 |
| `trace_bpf_exit` | TRACEPOINT (5) | `8ba6a816be027107` | 0 | 1 | 16858 |
| `sd_fw_egress` | CGROUP_SKB (8) | `6deef7357e7b4530` | 0 | 6 | 16212, 16215, 16217, 16221, 16224, 16226 |
| `sd_fw_ingress` | CGROUP_SKB (8) | `6deef7357e7b4530` | 0 | 6 | 16213, 16216, 16218, 16222, 16225, 16227 |
| `(empty)` | CGROUP_DEVICE (15) | `ab4bc4523b7fe6b4` | 0 | 4 | 36, 40, 44, 16854 |
| `s_snap_store_ub` | CGROUP_DEVICE (15) | `03b4eaae2f14641a` | 1000 | 1 | 47 |
| `s_snapd_desktop` | CGROUP_DEVICE (15) | `03b4eaae2f14641a` | 1000 | 1 | 48 |
| `sd_devices` | CGROUP_DEVICE (15) | `0ecd07b7b633809f` | 0 | 1 | 16214 |
| `sd_devices` | CGROUP_DEVICE (15) | `5b66259bfca5c6d7` | 0 | 3 | 16207, 16210, 16219 |
| `sd_devices` | CGROUP_DEVICE (15) | `81dfab3bd7eb416a` | 0 | 1 | 16851 |
| `sd_devices` | CGROUP_DEVICE (15) | `8b9c33f36f812014` | 0 | 1 | 16211 |
| `sd_devices` | CGROUP_DEVICE (15) | `c8b47a902f1cc68b` | 0 | 2 | 16206, 16223 |
| `sd_devices` | CGROUP_DEVICE (15) | `e3dbd137be8d6168` | 0 | 1 | 16220 |
| `sd_devices` | CGROUP_DEVICE (15) | `ee0e253c78993a24` | 0 | 2 | 16208, 16209 |

**infinichat-u9: 33 programs, 12 distinct** (summary: CGroupDevice 22, CGroupSKB 8, TracePoint 3)

| name | type | tag | created_by_uid | count | prog ids |
| --- | --- | --- | --- | --- | --- |
| `rpath_on_exec` | TRACEPOINT (5) | `3bb911deb8a44f72` | 0 | 1 | 1112 |
| `trace_bpf_enter` | TRACEPOINT (5) | `de4f4478859669c1` | 0 | 1 | 1114 |
| `trace_bpf_exit` | TRACEPOINT (5) | `52b4e738e18d137f` | 0 | 1 | 1115 |
| `sd_fw_egress` | CGROUP_SKB (8) | `6deef7357e7b4530` | 0 | 4 | 881, 885, 889, 892 |
| `sd_fw_ingress` | CGROUP_SKB (8) | `6deef7357e7b4530` | 0 | 4 | 882, 886, 890, 893 |
| `(empty)` | CGROUP_DEVICE (15) | `ab4bc4523b7fe6b4` | 0 | 8 | 1075, 1080, 1085, 1090, 1095, 1100, 1105, 1110 |
| `sd_devices` | CGROUP_DEVICE (15) | `134b8a301991f6b7` | 0 | 2 | 888, 891 |
| `sd_devices` | CGROUP_DEVICE (15) | `384856681694f215` | 0 | 1 | 884 |
| `sd_devices` | CGROUP_DEVICE (15) | `654d7024997e7811` | 0 | 1 | 883 |
| `sd_devices` | CGROUP_DEVICE (15) | `81dfab3bd7eb416a` | 0 | 8 | 1071, 1076, 1081, 1086, 1091, 1096, 1101, 1106 |
| `sd_devices` | CGROUP_DEVICE (15) | `ee0e253c78993a24` | 0 | 1 | 880 |
| `sd_devices` | CGROUP_DEVICE (15) | `fba67f14acbaee05` | 0 | 1 | 894 |

The bus's own programs (`rpath_on_exec`, `trace_bpf_enter`, `trace_bpf_exit`) have different tags on the two kernels, from the same `.o` files in the same binary. The second scans, just after the windows, had five tags per host that the first scan did not (four TRACEPOINT and one KPROBE, in the PENDING list below). By type and timing, they are the programs of the four sensors that started after the first scan. Their names are in the second-scan events, which are outside the windows and were not saved.

### Every non-INFO event, one line each

Format: timestamp, type, severity/action, pid, uid, comm, exe, detail. `exe=(empty)` means the event has no `exe_path`. That is true of 13 process events, and 3 of them also have no `exe_hash`.

**drl-nuc8i3bek: 43**

```
2026-10-11T03:32:08.699227Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_unix.so flags=2
2026-10-11T03:32:08.699409Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_sss.so flags=2
2026-10-11T03:32:08.699488Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_deny.so flags=2
2026-10-11T03:32:08.699581Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_permit.so flags=2
2026-10-11T03:32:08.699689Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_cap.so flags=2
2026-10-11T03:32:08.699784Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_nologin.so flags=2
2026-10-11T03:32:08.699889Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_localuser.so flags=2
2026-10-11T03:32:08.700032Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_selinux.so flags=2
2026-10-11T03:32:08.700152Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_loginuid.so flags=2
2026-10-11T03:32:08.700262Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_keyinit.so flags=2
2026-10-11T03:32:08.700364Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_umask.so flags=2
2026-10-11T03:32:08.701721Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_systemd.so flags=2
2026-10-11T03:32:08.701814Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_motd.so flags=2
2026-10-11T03:32:08.701898Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_mail.so flags=2
2026-10-11T03:32:08.702027Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_limits.so flags=2
2026-10-11T03:32:08.70211Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_env.so flags=2
2026-10-11T03:32:08.702182Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_pwquality.so flags=2
2026-10-11T03:32:08.702298Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/lib/x86_64-linux-gnu/security/pam_gnome_keyring.so flags=2
2026-10-11T03:32:08.746637Z DLOPEN CRITICAL/ALERT pid=531290 uid=0 comm=sshd exe=/usr/sbin/sshd lib=/usr/lib/x86_64-linux-gnu/libnss_systemd.so.2 flags=4097
2026-10-11T03:32:08.748075Z DLOPEN CRITICAL/ALERT pid=763 uid=0 comm=systemd-logind exe=/usr/lib/systemd/systemd-logind lib=/usr/lib/x86_64-linux-gnu/libnss_systemd.so.2 flags=4097
2026-10-11T03:32:08.839725Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/usr/libexec/sudo/sudoers.so flags=257
2026-10-11T03:32:08.840847Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/lib/x86_64-linux-gnu/security/pam_limits.so flags=2
2026-10-11T03:32:08.840895Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/lib/x86_64-linux-gnu/security/pam_env.so flags=2
2026-10-11T03:32:08.840933Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/lib/x86_64-linux-gnu/security/pam_unix.so flags=2
2026-10-11T03:32:08.840967Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/lib/x86_64-linux-gnu/security/pam_sss.so flags=2
2026-10-11T03:32:08.841003Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/lib/x86_64-linux-gnu/security/pam_deny.so flags=2
2026-10-11T03:32:08.84104Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/lib/x86_64-linux-gnu/security/pam_permit.so flags=2
2026-10-11T03:32:08.841104Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/lib/x86_64-linux-gnu/security/pam_cap.so flags=2
2026-10-11T03:32:08.841144Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=(empty) lib=/lib/x86_64-linux-gnu/security/pam_localuser.so flags=2
2026-10-11T03:32:08.841181Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=(empty) lib=/lib/x86_64-linux-gnu/security/pam_umask.so flags=2
2026-10-11T03:32:08.841218Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=(empty) lib=/lib/x86_64-linux-gnu/security/pam_pwquality.so flags=2
2026-10-11T03:32:08.841259Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=(empty) lib=/lib/x86_64-linux-gnu/security/pam_gnome_keyring.so flags=2
2026-10-11T03:32:08.841298Z DLOPEN WARN/ALERT pid=531329 uid=1000 comm=sudo exe=(empty) lib=/lib/x86_64-linux-gnu/security/pam_systemd.so flags=2
2026-10-11T03:32:50.285138Z EXEC_INJECTION CRITICAL/ALERT pid=531430 uid=0 comm=runc exe=/usr/bin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/bin/runc
2026-10-11T03:32:50.318475Z EXEC_INJECTION CRITICAL/ALERT pid=531436 uid=0 comm=runc exe=/usr/bin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/bin/runc
2026-10-11T03:32:50.331706Z EXEC_INJECTION CRITICAL/ALERT pid=531442 uid=0 comm=containerd-shim exe=/usr/bin/containerd-shim-runc-v2 LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/bin/containerd-shim-runc-v2
2026-10-11T03:32:50.334845Z EXEC_INJECTION CRITICAL/ALERT pid=531448 uid=0 comm=runc exe=(empty) LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/bin/runc
2026-10-11T03:32:50.349593Z DLOPEN CRITICAL/ALERT pid=531455 uid=0 comm=iptables exe=(empty) lib=/usr/lib/x86_64-linux-gnu/xtables/libxt_tcp.so flags=2
2026-10-11T03:32:50.349615Z DLOPEN CRITICAL/ALERT pid=531455 uid=0 comm=iptables exe=(empty) lib=/usr/lib/x86_64-linux-gnu/xtables/libipt_DNAT.so flags=2
2026-10-11T03:32:50.349631Z DLOPEN CRITICAL/ALERT pid=531455 uid=0 comm=iptables exe=(empty) lib=/usr/lib/x86_64-linux-gnu/xtables/libxt_standard.so flags=2
2026-10-11T03:32:50.35125Z DLOPEN CRITICAL/ALERT pid=531456 uid=0 comm=iptables exe=/usr/sbin/xtables-nft-multi lib=/usr/lib/x86_64-linux-gnu/xtables/libipt_DNAT.so flags=2
2026-10-11T03:32:50.351776Z DLOPEN CRITICAL/ALERT pid=531456 uid=0 comm=iptables exe=(empty) lib=/usr/lib/x86_64-linux-gnu/xtables/libxt_standard.so flags=2
2026-10-11T03:32:50.390845Z DLOPEN CRITICAL/ALERT pid=531459 uid=0 comm=iptables exe=/usr/sbin/xtables-nft-multi lib=/usr/lib/x86_64-linux-gnu/xtables/libipt_MASQUERADE.so flags=2
```

**infinichat-u9: 435** (410 of them are the `runc` lines)

```
2026-10-11T03:31:24.378959Z DLOPEN WARN/ALERT pid=712573 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/usr/libexec/sudo/sudoers.so flags=257
2026-10-11T03:31:24.379745Z DLOPEN WARN/ALERT pid=712573 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/usr/lib/x86_64-linux-gnu/security/pam_limits.so flags=2
2026-10-11T03:31:24.379831Z DLOPEN WARN/ALERT pid=712573 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/usr/lib/x86_64-linux-gnu/security/pam_env.so flags=2
2026-10-11T03:31:24.379907Z DLOPEN WARN/ALERT pid=712573 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/usr/lib/x86_64-linux-gnu/security/pam_unix.so flags=2
2026-10-11T03:31:24.379943Z DLOPEN WARN/ALERT pid=712573 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/usr/lib/x86_64-linux-gnu/security/pam_deny.so flags=2
2026-10-11T03:31:24.379973Z DLOPEN WARN/ALERT pid=712573 uid=1000 comm=sudo exe=/usr/bin/sudo lib=/usr/lib/x86_64-linux-gnu/security/pam_permit.so flags=2
2026-10-11T03:31:24.380005Z DLOPEN WARN/ALERT pid=712573 uid=1000 comm=sudo exe=(empty) lib=/usr/lib/x86_64-linux-gnu/security/pam_cap.so flags=2
2026-10-11T03:31:24.380087Z DLOPEN WARN/ALERT pid=712573 uid=1000 comm=sudo exe=(empty) lib=/usr/lib/x86_64-linux-gnu/security/pam_umask.so flags=2
2026-10-11T03:31:24.380492Z DLOPEN WARN/ALERT pid=712573 uid=1000 comm=sudo exe=(empty) lib=/usr/lib/x86_64-linux-gnu/security/pam_systemd.so flags=2
2026-10-11T03:31:24.625523Z EXEC_INJECTION CRITICAL/ALERT pid=712578 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:24.627215Z EXEC_INJECTION CRITICAL/ALERT pid=712584 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:24.628465Z EXEC_INJECTION CRITICAL/ALERT pid=712590 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:24.631652Z EXEC_INJECTION CRITICAL/ALERT pid=712616 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:24.635136Z EXEC_INJECTION CRITICAL/ALERT pid=712636 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:24.635419Z EXEC_INJECTION CRITICAL/ALERT pid=712637 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:27.667153Z ELF_RPATH ALERT/ALERT pid=712685 uid=1000 comm=llama-server exe=/opt/llama.cpp/build-cuda/bin/llama-server runpath='/opt/llama.cpp/build-cuda/bin:' rpath=None highest_risk=HIGH
2026-10-11T03:31:27.683452Z DLOPEN WARN/ALERT pid=712685 uid=1000 comm=llama-server exe=/opt/llama.cpp/build-cuda/bin/llama-server lib=(empty) flags=1
2026-10-11T03:31:27.683572Z DLOPEN WARN/ALERT pid=712685 uid=1000 comm=llama-server exe=/opt/llama.cpp/build-cuda/bin/llama-server lib=libcuda.so.1 flags=1
2026-10-11T03:31:27.68366Z DLOPEN WARN/ALERT pid=712685 uid=1000 comm=llama-server exe=/opt/llama.cpp/build-cuda/bin/llama-server lib=libnvrtc.so flags=1
2026-10-11T03:31:27.759423Z DLOPEN WARN/ALERT pid=712685 uid=1000 comm=llama-server exe=/opt/llama.cpp/build-cuda/bin/llama-server lib=/opt/llama.cpp/build-cuda/bin/libggml-cuda.so flags=2
2026-10-11T03:31:27.759802Z DLOPEN WARN/ALERT pid=712685 uid=1000 comm=llama-server exe=/opt/llama.cpp/build-cuda/bin/llama-server lib=/opt/llama.cpp/build-cuda/bin/libggml-cpu.so flags=2
2026-10-11T03:31:28.86762Z EXEC_INJECTION CRITICAL/ALERT pid=712708 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:29.65581Z EXEC_INJECTION CRITICAL/ALERT pid=712730 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:29.661468Z EXEC_INJECTION CRITICAL/ALERT pid=712747 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:29.663281Z EXEC_INJECTION CRITICAL/ALERT pid=712753 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:29.663301Z EXEC_INJECTION CRITICAL/ALERT pid=712754 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:29.664132Z EXEC_INJECTION CRITICAL/ALERT pid=712755 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:29.672182Z EXEC_INJECTION CRITICAL/ALERT pid=712816 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:33.53467Z EXEC_INJECTION CRITICAL/ALERT pid=712863 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:34.683771Z EXEC_INJECTION CRITICAL/ALERT pid=712883 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:34.688848Z EXEC_INJECTION CRITICAL/ALERT pid=712890 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:34.689076Z EXEC_INJECTION CRITICAL/ALERT pid=712894 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:34.689084Z EXEC_INJECTION CRITICAL/ALERT pid=712895 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:34.692448Z EXEC_INJECTION CRITICAL/ALERT pid=712932 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:34.699752Z EXEC_INJECTION CRITICAL/ALERT pid=712969 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:38.905787Z EXEC_INJECTION CRITICAL/ALERT pid=713014 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:39.712515Z EXEC_INJECTION CRITICAL/ALERT pid=713034 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:39.717587Z EXEC_INJECTION CRITICAL/ALERT pid=713040 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:39.718232Z EXEC_INJECTION CRITICAL/ALERT pid=713047 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:39.718481Z EXEC_INJECTION CRITICAL/ALERT pid=713050 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:39.718656Z EXEC_INJECTION CRITICAL/ALERT pid=713055 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:39.728521Z EXEC_INJECTION CRITICAL/ALERT pid=713120 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:44.743292Z EXEC_INJECTION CRITICAL/ALERT pid=713166 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:44.748236Z EXEC_INJECTION CRITICAL/ALERT pid=713172 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:44.748244Z EXEC_INJECTION CRITICAL/ALERT pid=713173 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:44.748249Z EXEC_INJECTION CRITICAL/ALERT pid=713174 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:44.754303Z EXEC_INJECTION CRITICAL/ALERT pid=713232 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:44.769099Z EXEC_INJECTION CRITICAL/ALERT pid=713250 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:48.567404Z EXEC_INJECTION CRITICAL/ALERT pid=713270 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:48.943574Z EXEC_INJECTION CRITICAL/ALERT pid=713288 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:49.773126Z EXEC_INJECTION CRITICAL/ALERT pid=713331 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:49.77802Z EXEC_INJECTION CRITICAL/ALERT pid=713337 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:49.778428Z EXEC_INJECTION CRITICAL/ALERT pid=713339 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:49.779605Z EXEC_INJECTION CRITICAL/ALERT pid=713359 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:49.799089Z EXEC_INJECTION CRITICAL/ALERT pid=713399 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:49.800062Z EXEC_INJECTION CRITICAL/ALERT pid=713401 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:54.80351Z EXEC_INJECTION CRITICAL/ALERT pid=713439 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:54.808558Z EXEC_INJECTION CRITICAL/ALERT pid=713455 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:54.808612Z EXEC_INJECTION CRITICAL/ALERT pid=713456 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:54.810287Z EXEC_INJECTION CRITICAL/ALERT pid=713467 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:54.822744Z EXEC_INJECTION CRITICAL/ALERT pid=713504 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:54.841536Z EXEC_INJECTION CRITICAL/ALERT pid=713524 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:58.981232Z EXEC_INJECTION CRITICAL/ALERT pid=713567 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:59.830723Z EXEC_INJECTION CRITICAL/ALERT pid=713587 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:59.836043Z EXEC_INJECTION CRITICAL/ALERT pid=713596 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:59.83636Z EXEC_INJECTION CRITICAL/ALERT pid=713597 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:59.837711Z EXEC_INJECTION CRITICAL/ALERT pid=713614 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:59.862681Z EXEC_INJECTION CRITICAL/ALERT pid=713657 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:31:59.881061Z EXEC_INJECTION CRITICAL/ALERT pid=713674 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:03.596055Z EXEC_INJECTION CRITICAL/ALERT pid=713716 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:04.859906Z EXEC_INJECTION CRITICAL/ALERT pid=713735 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:04.867529Z EXEC_INJECTION CRITICAL/ALERT pid=713754 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:04.867555Z EXEC_INJECTION CRITICAL/ALERT pid=713753 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:04.867563Z EXEC_INJECTION CRITICAL/ALERT pid=713752 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:04.88637Z EXEC_INJECTION CRITICAL/ALERT pid=713803 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:04.912825Z EXEC_INJECTION CRITICAL/ALERT pid=713822 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:09.017774Z EXEC_INJECTION CRITICAL/ALERT pid=713865 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:09.888746Z EXEC_INJECTION CRITICAL/ALERT pid=713886 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:09.894033Z EXEC_INJECTION CRITICAL/ALERT pid=713896 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:09.894536Z EXEC_INJECTION CRITICAL/ALERT pid=713898 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:09.895546Z EXEC_INJECTION CRITICAL/ALERT pid=713914 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:09.905578Z EXEC_INJECTION CRITICAL/ALERT pid=713953 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:09.938975Z EXEC_INJECTION CRITICAL/ALERT pid=713971 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:14.919645Z EXEC_INJECTION CRITICAL/ALERT pid=714014 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:14.924506Z EXEC_INJECTION CRITICAL/ALERT pid=714021 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:14.924519Z EXEC_INJECTION CRITICAL/ALERT pid=714020 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:14.924807Z EXEC_INJECTION CRITICAL/ALERT pid=714024 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:14.93075Z EXEC_INJECTION CRITICAL/ALERT pid=714081 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:14.969964Z EXEC_INJECTION CRITICAL/ALERT pid=714100 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:18.628904Z EXEC_INJECTION CRITICAL/ALERT pid=714141 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:19.055492Z EXEC_INJECTION CRITICAL/ALERT pid=714159 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:19.946642Z EXEC_INJECTION CRITICAL/ALERT pid=714179 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:19.951777Z EXEC_INJECTION CRITICAL/ALERT pid=714196 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:19.951786Z EXEC_INJECTION CRITICAL/ALERT pid=714197 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:19.951843Z EXEC_INJECTION CRITICAL/ALERT pid=714198 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:19.969168Z EXEC_INJECTION CRITICAL/ALERT pid=714252 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:20.004127Z EXEC_INJECTION CRITICAL/ALERT pid=714271 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:24.971598Z EXEC_INJECTION CRITICAL/ALERT pid=714314 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:24.971608Z EXEC_INJECTION CRITICAL/ALERT pid=714315 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:24.978526Z EXEC_INJECTION CRITICAL/ALERT pid=714349 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:24.978534Z EXEC_INJECTION CRITICAL/ALERT pid=714348 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:24.995255Z EXEC_INJECTION CRITICAL/ALERT pid=714378 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:25.044671Z EXEC_INJECTION CRITICAL/ALERT pid=714397 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:28.054751Z DLOPEN WARN/ALERT pid=714423 uid=1000 comm=pgrep exe=/usr/bin/pgrep lib=(empty) flags=1
2026-10-11T03:32:29.089986Z EXEC_INJECTION CRITICAL/ALERT pid=714450 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:30.001553Z EXEC_INJECTION CRITICAL/ALERT pid=714470 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:30.006396Z EXEC_INJECTION CRITICAL/ALERT pid=714476 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:30.008373Z EXEC_INJECTION CRITICAL/ALERT pid=714488 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:30.022115Z EXEC_INJECTION CRITICAL/ALERT pid=714519 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:30.02248Z EXEC_INJECTION CRITICAL/ALERT pid=714520 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:30.085207Z EXEC_INJECTION CRITICAL/ALERT pid=714554 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:33.665677Z EXEC_INJECTION CRITICAL/ALERT pid=714616 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:35.032164Z EXEC_INJECTION CRITICAL/ALERT pid=714637 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:35.038453Z EXEC_INJECTION CRITICAL/ALERT pid=714648 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:35.04702Z EXEC_INJECTION CRITICAL/ALERT pid=714671 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:35.048324Z EXEC_INJECTION CRITICAL/ALERT pid=714676 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:35.058187Z EXEC_INJECTION CRITICAL/ALERT pid=714705 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:35.11653Z EXEC_INJECTION CRITICAL/ALERT pid=714725 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:39.128362Z EXEC_INJECTION CRITICAL/ALERT pid=714781 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:40.065978Z EXEC_INJECTION CRITICAL/ALERT pid=714801 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:40.066654Z EXEC_INJECTION CRITICAL/ALERT pid=714802 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:40.066674Z EXEC_INJECTION CRITICAL/ALERT pid=714803 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:40.072144Z EXEC_INJECTION CRITICAL/ALERT pid=714850 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:40.078038Z EXEC_INJECTION CRITICAL/ALERT pid=714860 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:40.14986Z EXEC_INJECTION CRITICAL/ALERT pid=714885 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:45.091756Z EXEC_INJECTION CRITICAL/ALERT pid=714928 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:45.092152Z EXEC_INJECTION CRITICAL/ALERT pid=714929 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:45.098851Z EXEC_INJECTION CRITICAL/ALERT pid=714964 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:45.099084Z EXEC_INJECTION CRITICAL/ALERT pid=714965 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:45.102249Z EXEC_INJECTION CRITICAL/ALERT pid=714980 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:45.183094Z EXEC_INJECTION CRITICAL/ALERT pid=715015 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:48.699953Z EXEC_INJECTION CRITICAL/ALERT pid=715032 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:49.162744Z EXEC_INJECTION CRITICAL/ALERT pid=715051 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:50.120813Z EXEC_INJECTION CRITICAL/ALERT pid=715094 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:50.121013Z EXEC_INJECTION CRITICAL/ALERT pid=715095 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:50.121234Z EXEC_INJECTION CRITICAL/ALERT pid=715096 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:50.123383Z EXEC_INJECTION CRITICAL/ALERT pid=715112 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:50.124609Z EXEC_INJECTION CRITICAL/ALERT pid=715127 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:50.22013Z EXEC_INJECTION CRITICAL/ALERT pid=715184 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:55.153409Z EXEC_INJECTION CRITICAL/ALERT pid=715206 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:55.153979Z EXEC_INJECTION CRITICAL/ALERT pid=715207 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:55.157357Z EXEC_INJECTION CRITICAL/ALERT pid=715226 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:55.157885Z EXEC_INJECTION CRITICAL/ALERT pid=715231 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:55.158381Z EXEC_INJECTION CRITICAL/ALERT pid=715242 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:55.251299Z EXEC_INJECTION CRITICAL/ALERT pid=715292 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:32:59.203376Z EXEC_INJECTION CRITICAL/ALERT pid=715334 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:00.182582Z EXEC_INJECTION CRITICAL/ALERT pid=715353 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:00.182591Z EXEC_INJECTION CRITICAL/ALERT pid=715354 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:00.184022Z EXEC_INJECTION CRITICAL/ALERT pid=715365 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:00.184224Z EXEC_INJECTION CRITICAL/ALERT pid=715366 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:00.184468Z EXEC_INJECTION CRITICAL/ALERT pid=715367 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:00.289353Z EXEC_INJECTION CRITICAL/ALERT pid=715441 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:03.73243Z EXEC_INJECTION CRITICAL/ALERT pid=715482 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:05.213292Z EXEC_INJECTION CRITICAL/ALERT pid=715502 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:05.213305Z EXEC_INJECTION CRITICAL/ALERT pid=715503 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:05.214635Z EXEC_INJECTION CRITICAL/ALERT pid=715514 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:05.216566Z EXEC_INJECTION CRITICAL/ALERT pid=715525 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:05.216677Z EXEC_INJECTION CRITICAL/ALERT pid=715527 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:05.322815Z EXEC_INJECTION CRITICAL/ALERT pid=715589 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:09.239539Z EXEC_INJECTION CRITICAL/ALERT pid=715633 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:10.248691Z EXEC_INJECTION CRITICAL/ALERT pid=715653 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:10.248695Z EXEC_INJECTION CRITICAL/ALERT pid=715654 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:10.25315Z EXEC_INJECTION CRITICAL/ALERT pid=715673 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:10.253168Z EXEC_INJECTION CRITICAL/ALERT pid=715676 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:10.261118Z EXEC_INJECTION CRITICAL/ALERT pid=715721 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:10.354771Z EXEC_INJECTION CRITICAL/ALERT pid=715740 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:15.27504Z EXEC_INJECTION CRITICAL/ALERT pid=715781 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:15.27505Z EXEC_INJECTION CRITICAL/ALERT pid=715782 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:15.278805Z EXEC_INJECTION CRITICAL/ALERT pid=715805 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:15.279379Z EXEC_INJECTION CRITICAL/ALERT pid=715816 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:15.279746Z EXEC_INJECTION CRITICAL/ALERT pid=715820 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:15.391601Z EXEC_INJECTION CRITICAL/ALERT pid=715868 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:18.764758Z EXEC_INJECTION CRITICAL/ALERT pid=715909 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:19.278121Z EXEC_INJECTION CRITICAL/ALERT pid=715927 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:20.301748Z EXEC_INJECTION CRITICAL/ALERT pid=715946 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:20.302836Z EXEC_INJECTION CRITICAL/ALERT pid=715947 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:20.303162Z EXEC_INJECTION CRITICAL/ALERT pid=715953 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:20.305671Z EXEC_INJECTION CRITICAL/ALERT pid=715966 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:20.306582Z EXEC_INJECTION CRITICAL/ALERT pid=715977 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:20.425506Z EXEC_INJECTION CRITICAL/ALERT pid=716032 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:25.33103Z EXEC_INJECTION CRITICAL/ALERT pid=716076 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:25.331049Z EXEC_INJECTION CRITICAL/ALERT pid=716075 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:25.336008Z EXEC_INJECTION CRITICAL/ALERT pid=716091 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:25.336354Z EXEC_INJECTION CRITICAL/ALERT pid=716093 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:25.33637Z EXEC_INJECTION CRITICAL/ALERT pid=716094 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:25.462258Z EXEC_INJECTION CRITICAL/ALERT pid=716162 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:29.311826Z EXEC_INJECTION CRITICAL/ALERT pid=716203 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:30.361314Z EXEC_INJECTION CRITICAL/ALERT pid=716223 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:30.361331Z EXEC_INJECTION CRITICAL/ALERT pid=716224 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:30.3665Z EXEC_INJECTION CRITICAL/ALERT pid=716258 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:30.366848Z EXEC_INJECTION CRITICAL/ALERT pid=716259 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:30.384026Z EXEC_INJECTION CRITICAL/ALERT pid=716292 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:30.497092Z EXEC_INJECTION CRITICAL/ALERT pid=716310 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:33.793449Z EXEC_INJECTION CRITICAL/ALERT pid=716328 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:35.388304Z EXEC_INJECTION CRITICAL/ALERT pid=716371 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:35.388319Z EXEC_INJECTION CRITICAL/ALERT pid=716372 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:35.39272Z EXEC_INJECTION CRITICAL/ALERT pid=716400 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:35.393288Z EXEC_INJECTION CRITICAL/ALERT pid=716402 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:35.403731Z EXEC_INJECTION CRITICAL/ALERT pid=716437 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:35.528535Z EXEC_INJECTION CRITICAL/ALERT pid=716456 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:39.346423Z EXEC_INJECTION CRITICAL/ALERT pid=716474 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:40.418797Z EXEC_INJECTION CRITICAL/ALERT pid=716515 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:40.418808Z EXEC_INJECTION CRITICAL/ALERT pid=716516 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:40.424803Z EXEC_INJECTION CRITICAL/ALERT pid=716550 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:40.42481Z EXEC_INJECTION CRITICAL/ALERT pid=716549 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:40.427658Z EXEC_INJECTION CRITICAL/ALERT pid=716561 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:40.566026Z EXEC_INJECTION CRITICAL/ALERT pid=716601 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:45.445393Z EXEC_INJECTION CRITICAL/ALERT pid=716644 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:45.451342Z EXEC_INJECTION CRITICAL/ALERT pid=716659 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:45.45198Z EXEC_INJECTION CRITICAL/ALERT pid=716660 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:45.452892Z EXEC_INJECTION CRITICAL/ALERT pid=716669 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:45.471601Z EXEC_INJECTION CRITICAL/ALERT pid=716713 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:45.599353Z EXEC_INJECTION CRITICAL/ALERT pid=716732 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:48.816665Z EXEC_INJECTION CRITICAL/ALERT pid=716750 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:49.380591Z EXEC_INJECTION CRITICAL/ALERT pid=716770 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:50.474945Z EXEC_INJECTION CRITICAL/ALERT pid=716812 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:50.474958Z EXEC_INJECTION CRITICAL/ALERT pid=716813 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:50.479519Z EXEC_INJECTION CRITICAL/ALERT pid=716840 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:50.491832Z EXEC_INJECTION CRITICAL/ALERT pid=716863 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:50.499585Z EXEC_INJECTION CRITICAL/ALERT pid=716878 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:50.628687Z EXEC_INJECTION CRITICAL/ALERT pid=716897 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:55.506286Z EXEC_INJECTION CRITICAL/ALERT pid=716918 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:55.506323Z EXEC_INJECTION CRITICAL/ALERT pid=716919 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:55.523791Z EXEC_INJECTION CRITICAL/ALERT pid=716952 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:55.525117Z EXEC_INJECTION CRITICAL/ALERT pid=716953 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:55.525329Z EXEC_INJECTION CRITICAL/ALERT pid=716954 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:55.657582Z EXEC_INJECTION CRITICAL/ALERT pid=717006 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:33:59.413091Z EXEC_INJECTION CRITICAL/ALERT pid=717049 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:00.54321Z EXEC_INJECTION CRITICAL/ALERT pid=717070 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:00.54793Z EXEC_INJECTION CRITICAL/ALERT pid=717081 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:00.553099Z EXEC_INJECTION CRITICAL/ALERT pid=717094 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:00.557312Z EXEC_INJECTION CRITICAL/ALERT pid=717106 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:00.560278Z EXEC_INJECTION CRITICAL/ALERT pid=717126 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:00.708317Z EXEC_INJECTION CRITICAL/ALERT pid=717162 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:03.851864Z EXEC_INJECTION CRITICAL/ALERT pid=717203 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:05.589966Z EXEC_INJECTION CRITICAL/ALERT pid=717222 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:05.590301Z EXEC_INJECTION CRITICAL/ALERT pid=717223 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:05.590384Z EXEC_INJECTION CRITICAL/ALERT pid=717221 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:05.592318Z EXEC_INJECTION CRITICAL/ALERT pid=717231 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:05.594638Z EXEC_INJECTION CRITICAL/ALERT pid=717241 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:05.758029Z EXEC_INJECTION CRITICAL/ALERT pid=717312 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:09.477981Z EXEC_INJECTION CRITICAL/ALERT pid=717373 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:10.627227Z EXEC_INJECTION CRITICAL/ALERT pid=717393 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:10.627309Z EXEC_INJECTION CRITICAL/ALERT pid=717394 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:10.627433Z EXEC_INJECTION CRITICAL/ALERT pid=717395 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:10.634841Z EXEC_INJECTION CRITICAL/ALERT pid=717417 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:10.638226Z EXEC_INJECTION CRITICAL/ALERT pid=717436 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:10.808472Z EXEC_INJECTION CRITICAL/ALERT pid=717480 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:15.673873Z EXEC_INJECTION CRITICAL/ALERT pid=717524 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:15.673889Z EXEC_INJECTION CRITICAL/ALERT pid=717525 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:15.679342Z EXEC_INJECTION CRITICAL/ALERT pid=717543 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:15.679546Z EXEC_INJECTION CRITICAL/ALERT pid=717544 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:15.681645Z EXEC_INJECTION CRITICAL/ALERT pid=717560 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:15.864108Z EXEC_INJECTION CRITICAL/ALERT pid=717611 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:18.904318Z EXEC_INJECTION CRITICAL/ALERT pid=717651 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:19.518742Z EXEC_INJECTION CRITICAL/ALERT pid=717670 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:20.714689Z EXEC_INJECTION CRITICAL/ALERT pid=717690 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:20.715061Z EXEC_INJECTION CRITICAL/ALERT pid=717691 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:20.715558Z EXEC_INJECTION CRITICAL/ALERT pid=717692 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:20.716161Z EXEC_INJECTION CRITICAL/ALERT pid=717693 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:20.726046Z EXEC_INJECTION CRITICAL/ALERT pid=717748 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:20.915748Z EXEC_INJECTION CRITICAL/ALERT pid=717782 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:25.747188Z EXEC_INJECTION CRITICAL/ALERT pid=717826 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:25.749081Z EXEC_INJECTION CRITICAL/ALERT pid=717832 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:25.749102Z EXEC_INJECTION CRITICAL/ALERT pid=717833 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:25.754977Z EXEC_INJECTION CRITICAL/ALERT pid=717861 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:25.762844Z EXEC_INJECTION CRITICAL/ALERT pid=717890 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:25.975996Z EXEC_INJECTION CRITICAL/ALERT pid=717917 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:29.568094Z EXEC_INJECTION CRITICAL/ALERT pid=717959 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:30.798722Z EXEC_INJECTION CRITICAL/ALERT pid=717981 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:30.798733Z EXEC_INJECTION CRITICAL/ALERT pid=717982 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:30.79882Z EXEC_INJECTION CRITICAL/ALERT pid=717980 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:30.819797Z EXEC_INJECTION CRITICAL/ALERT pid=718025 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:30.823905Z EXEC_INJECTION CRITICAL/ALERT pid=718033 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:31.02704Z EXEC_INJECTION CRITICAL/ALERT pid=718070 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:33.944146Z EXEC_INJECTION CRITICAL/ALERT pid=718107 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:35.840027Z EXEC_INJECTION CRITICAL/ALERT pid=718151 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:35.850183Z EXEC_INJECTION CRITICAL/ALERT pid=718168 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:35.850336Z EXEC_INJECTION CRITICAL/ALERT pid=718169 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:35.861672Z EXEC_INJECTION CRITICAL/ALERT pid=718204 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:35.882701Z EXEC_INJECTION CRITICAL/ALERT pid=718224 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:36.0917Z EXEC_INJECTION CRITICAL/ALERT pid=718242 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:39.628825Z EXEC_INJECTION CRITICAL/ALERT pid=718261 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:40.878669Z EXEC_INJECTION CRITICAL/ALERT pid=718303 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:40.879571Z EXEC_INJECTION CRITICAL/ALERT pid=718304 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:40.890586Z EXEC_INJECTION CRITICAL/ALERT pid=718336 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:40.905053Z EXEC_INJECTION CRITICAL/ALERT pid=718353 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:40.917163Z EXEC_INJECTION CRITICAL/ALERT pid=718368 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:41.139046Z EXEC_INJECTION CRITICAL/ALERT pid=718390 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:45.930938Z EXEC_INJECTION CRITICAL/ALERT pid=718434 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:45.933944Z EXEC_INJECTION CRITICAL/ALERT pid=718440 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:45.935442Z EXEC_INJECTION CRITICAL/ALERT pid=718444 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:45.943481Z EXEC_INJECTION CRITICAL/ALERT pid=718478 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:46.001393Z EXEC_INJECTION CRITICAL/ALERT pid=718508 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:46.197732Z EXEC_INJECTION CRITICAL/ALERT pid=718525 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:48.99726Z EXEC_INJECTION CRITICAL/ALERT pid=718541 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:49.681276Z EXEC_INJECTION CRITICAL/ALERT pid=718560 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:50.979381Z EXEC_INJECTION CRITICAL/ALERT pid=718582 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:50.980566Z EXEC_INJECTION CRITICAL/ALERT pid=718583 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:50.997104Z EXEC_INJECTION CRITICAL/ALERT pid=718612 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:51.010236Z EXEC_INJECTION CRITICAL/ALERT pid=718652 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:51.052108Z EXEC_INJECTION CRITICAL/ALERT pid=718669 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:51.247848Z EXEC_INJECTION CRITICAL/ALERT pid=718691 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:56.020509Z EXEC_INJECTION CRITICAL/ALERT pid=718711 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:56.033716Z EXEC_INJECTION CRITICAL/ALERT pid=718728 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:56.035966Z EXEC_INJECTION CRITICAL/ALERT pid=718734 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:56.078056Z EXEC_INJECTION CRITICAL/ALERT pid=718763 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:56.157077Z EXEC_INJECTION CRITICAL/ALERT pid=718782 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:56.299302Z EXEC_INJECTION CRITICAL/ALERT pid=718800 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:34:59.723134Z EXEC_INJECTION CRITICAL/ALERT pid=718842 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:01.066596Z EXEC_INJECTION CRITICAL/ALERT pid=718863 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:01.066608Z EXEC_INJECTION CRITICAL/ALERT pid=718862 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:01.073951Z EXEC_INJECTION CRITICAL/ALERT pid=718881 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:01.117386Z EXEC_INJECTION CRITICAL/ALERT pid=718915 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:01.197597Z EXEC_INJECTION CRITICAL/ALERT pid=718935 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:01.348048Z EXEC_INJECTION CRITICAL/ALERT pid=718953 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:01.611205Z DLOPEN CRITICAL/ALERT pid=718970 uid=0 comm=cron exe=/usr/sbin/cron lib=/usr/lib/x86_64-linux-gnu/security/pam_unix.so flags=2
2026-10-11T03:35:01.61163Z DLOPEN CRITICAL/ALERT pid=718970 uid=0 comm=cron exe=/usr/sbin/cron lib=/usr/lib/x86_64-linux-gnu/security/pam_deny.so flags=2
2026-10-11T03:35:01.611698Z DLOPEN CRITICAL/ALERT pid=718970 uid=0 comm=cron exe=/usr/sbin/cron lib=/usr/lib/x86_64-linux-gnu/security/pam_permit.so flags=2
2026-10-11T03:35:01.61185Z DLOPEN CRITICAL/ALERT pid=718970 uid=0 comm=cron exe=/usr/sbin/cron lib=/usr/lib/x86_64-linux-gnu/security/pam_cap.so flags=2
2026-10-11T03:35:01.612227Z DLOPEN CRITICAL/ALERT pid=718970 uid=0 comm=cron exe=/usr/sbin/cron lib=/usr/lib/x86_64-linux-gnu/security/pam_loginuid.so flags=2
2026-10-11T03:35:01.612307Z DLOPEN CRITICAL/ALERT pid=718970 uid=0 comm=cron exe=/usr/sbin/cron lib=/usr/lib/x86_64-linux-gnu/security/pam_env.so flags=2
2026-10-11T03:35:01.612467Z DLOPEN CRITICAL/ALERT pid=718970 uid=0 comm=cron exe=/usr/sbin/cron lib=/usr/lib/x86_64-linux-gnu/security/pam_umask.so flags=2
2026-10-11T03:35:01.612567Z DLOPEN CRITICAL/ALERT pid=718970 uid=0 comm=cron exe=/usr/sbin/cron lib=/usr/lib/x86_64-linux-gnu/security/pam_limits.so flags=2
2026-10-11T03:35:01.612755Z DLOPEN CRITICAL/ALERT pid=718970 uid=0 comm=cron exe=/usr/sbin/cron lib=/usr/lib/x86_64-linux-gnu/security/pam_systemd.so flags=2
2026-10-11T03:35:04.03428Z EXEC_INJECTION CRITICAL/ALERT pid=718996 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:06.099263Z EXEC_INJECTION CRITICAL/ALERT pid=719016 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:06.110157Z EXEC_INJECTION CRITICAL/ALERT pid=719033 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:06.121134Z EXEC_INJECTION CRITICAL/ALERT pid=719051 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:06.167608Z EXEC_INJECTION CRITICAL/ALERT pid=719070 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:06.239399Z EXEC_INJECTION CRITICAL/ALERT pid=719089 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:06.398085Z EXEC_INJECTION CRITICAL/ALERT pid=719107 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:09.775225Z EXEC_INJECTION CRITICAL/ALERT pid=719151 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:11.141236Z EXEC_INJECTION CRITICAL/ALERT pid=719171 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:11.142583Z EXEC_INJECTION CRITICAL/ALERT pid=719172 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:11.144481Z EXEC_INJECTION CRITICAL/ALERT pid=719183 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:11.205175Z EXEC_INJECTION CRITICAL/ALERT pid=719224 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:11.290421Z EXEC_INJECTION CRITICAL/ALERT pid=719244 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:11.451485Z EXEC_INJECTION CRITICAL/ALERT pid=719261 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:16.191116Z EXEC_INJECTION CRITICAL/ALERT pid=719304 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:16.19149Z EXEC_INJECTION CRITICAL/ALERT pid=719305 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:16.192241Z EXEC_INJECTION CRITICAL/ALERT pid=719307 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:16.256592Z EXEC_INJECTION CRITICAL/ALERT pid=719358 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:16.338041Z EXEC_INJECTION CRITICAL/ALERT pid=719377 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:16.505934Z EXEC_INJECTION CRITICAL/ALERT pid=719392 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:19.08622Z EXEC_INJECTION CRITICAL/ALERT pid=719434 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:19.816255Z EXEC_INJECTION CRITICAL/ALERT pid=719451 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:21.234108Z EXEC_INJECTION CRITICAL/ALERT pid=719470 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:21.237843Z EXEC_INJECTION CRITICAL/ALERT pid=719476 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:21.249261Z EXEC_INJECTION CRITICAL/ALERT pid=719505 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:21.316546Z EXEC_INJECTION CRITICAL/ALERT pid=719523 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:21.386021Z EXEC_INJECTION CRITICAL/ALERT pid=719543 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:21.569328Z EXEC_INJECTION CRITICAL/ALERT pid=719561 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:26.272404Z EXEC_INJECTION CRITICAL/ALERT pid=719604 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:26.279239Z EXEC_INJECTION CRITICAL/ALERT pid=719622 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:26.328706Z EXEC_INJECTION CRITICAL/ALERT pid=719639 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:26.359394Z EXEC_INJECTION CRITICAL/ALERT pid=719656 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:26.423845Z EXEC_INJECTION CRITICAL/ALERT pid=719675 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:26.614452Z EXEC_INJECTION CRITICAL/ALERT pid=719693 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:29.869352Z EXEC_INJECTION CRITICAL/ALERT pid=719735 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:31.319116Z EXEC_INJECTION CRITICAL/ALERT pid=719756 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:31.322165Z EXEC_INJECTION CRITICAL/ALERT pid=719761 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:31.370837Z EXEC_INJECTION CRITICAL/ALERT pid=719789 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:31.390939Z EXEC_INJECTION CRITICAL/ALERT pid=719807 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:31.472315Z EXEC_INJECTION CRITICAL/ALERT pid=719827 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:31.669158Z EXEC_INJECTION CRITICAL/ALERT pid=719844 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:34.121265Z EXEC_INJECTION CRITICAL/ALERT pid=719861 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:36.36107Z EXEC_INJECTION CRITICAL/ALERT pid=719904 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:36.365812Z EXEC_INJECTION CRITICAL/ALERT pid=719910 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:36.424199Z EXEC_INJECTION CRITICAL/ALERT pid=719938 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:36.426898Z EXEC_INJECTION CRITICAL/ALERT pid=719944 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:36.518045Z EXEC_INJECTION CRITICAL/ALERT pid=719975 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:36.735785Z EXEC_INJECTION CRITICAL/ALERT pid=719992 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:39.923552Z EXEC_INJECTION CRITICAL/ALERT pid=720011 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:41.406973Z EXEC_INJECTION CRITICAL/ALERT pid=720054 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:41.419788Z EXEC_INJECTION CRITICAL/ALERT pid=720062 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:41.468465Z EXEC_INJECTION CRITICAL/ALERT pid=720088 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:41.483886Z EXEC_INJECTION CRITICAL/ALERT pid=720106 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:41.561044Z EXEC_INJECTION CRITICAL/ALERT pid=720125 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:41.797646Z EXEC_INJECTION CRITICAL/ALERT pid=720142 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:46.44956Z EXEC_INJECTION CRITICAL/ALERT pid=720185 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:46.45417Z EXEC_INJECTION CRITICAL/ALERT pid=720191 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:46.511628Z EXEC_INJECTION CRITICAL/ALERT pid=720219 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:46.515088Z EXEC_INJECTION CRITICAL/ALERT pid=720225 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:46.608123Z EXEC_INJECTION CRITICAL/ALERT pid=720257 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:46.846811Z EXEC_INJECTION CRITICAL/ALERT pid=720274 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:49.175582Z EXEC_INJECTION CRITICAL/ALERT pid=720293 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:49.962959Z EXEC_INJECTION CRITICAL/ALERT pid=720312 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:51.494342Z EXEC_INJECTION CRITICAL/ALERT pid=720335 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:51.500254Z EXEC_INJECTION CRITICAL/ALERT pid=720352 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:51.556456Z EXEC_INJECTION CRITICAL/ALERT pid=720388 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:51.556901Z EXEC_INJECTION CRITICAL/ALERT pid=720389 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:51.659093Z EXEC_INJECTION CRITICAL/ALERT pid=720428 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:51.890892Z EXEC_INJECTION CRITICAL/ALERT pid=720446 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:56.523786Z EXEC_INJECTION CRITICAL/ALERT pid=720466 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:56.528453Z EXEC_INJECTION CRITICAL/ALERT pid=720472 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:56.590331Z EXEC_INJECTION CRITICAL/ALERT pid=720500 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:56.605302Z EXEC_INJECTION CRITICAL/ALERT pid=720517 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:56.694035Z EXEC_INJECTION CRITICAL/ALERT pid=720537 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:35:56.933994Z EXEC_INJECTION CRITICAL/ALERT pid=720555 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:00.004115Z EXEC_INJECTION CRITICAL/ALERT pid=720596 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:01.576309Z EXEC_INJECTION CRITICAL/ALERT pid=720617 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:01.576484Z EXEC_INJECTION CRITICAL/ALERT pid=720616 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:01.62853Z EXEC_INJECTION CRITICAL/ALERT pid=720650 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:01.646991Z EXEC_INJECTION CRITICAL/ALERT pid=720667 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:01.764867Z EXEC_INJECTION CRITICAL/ALERT pid=720686 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:01.99325Z EXEC_INJECTION CRITICAL/ALERT pid=720702 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:04.214285Z EXEC_INJECTION CRITICAL/ALERT pid=720744 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:06.618164Z EXEC_INJECTION CRITICAL/ALERT pid=720765 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:06.626431Z EXEC_INJECTION CRITICAL/ALERT pid=720783 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:06.66149Z EXEC_INJECTION CRITICAL/ALERT pid=720800 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:06.695424Z EXEC_INJECTION CRITICAL/ALERT pid=720818 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:06.801696Z EXEC_INJECTION CRITICAL/ALERT pid=720836 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:07.038179Z EXEC_INJECTION CRITICAL/ALERT pid=720854 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:10.07832Z EXEC_INJECTION CRITICAL/ALERT pid=720895 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:11.662031Z EXEC_INJECTION CRITICAL/ALERT pid=720914 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:11.667225Z EXEC_INJECTION CRITICAL/ALERT pid=720923 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:11.702456Z EXEC_INJECTION CRITICAL/ALERT pid=720948 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:11.738037Z EXEC_INJECTION CRITICAL/ALERT pid=720964 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:11.868967Z EXEC_INJECTION CRITICAL/ALERT pid=720984 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:12.104914Z EXEC_INJECTION CRITICAL/ALERT pid=721000 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:16.70423Z EXEC_INJECTION CRITICAL/ALERT pid=721053 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:16.722865Z EXEC_INJECTION CRITICAL/ALERT pid=721069 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:16.733117Z EXEC_INJECTION CRITICAL/ALERT pid=721082 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:16.763203Z EXEC_INJECTION CRITICAL/ALERT pid=721104 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:16.912934Z EXEC_INJECTION CRITICAL/ALERT pid=721124 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:17.156138Z EXEC_INJECTION CRITICAL/ALERT pid=721141 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:19.25619Z EXEC_INJECTION CRITICAL/ALERT pid=721188 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:20.134668Z EXEC_INJECTION CRITICAL/ALERT pid=721208 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:21.761189Z EXEC_INJECTION CRITICAL/ALERT pid=721228 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:21.765076Z EXEC_INJECTION CRITICAL/ALERT pid=721236 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:21.774404Z EXEC_INJECTION CRITICAL/ALERT pid=721254 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:21.798078Z EXEC_INJECTION CRITICAL/ALERT pid=721279 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:21.955273Z EXEC_INJECTION CRITICAL/ALERT pid=721300 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
2026-10-11T03:36:22.194044Z EXEC_INJECTION CRITICAL/ALERT pid=721317 uid=0 comm=runc exe=/usr/sbin/runc LD_LIBRARY_PATH=/opt/containerd/lib: target=/usr/sbin/runc
```

### PENDING learning candidates: 99

The learning window covered both bus windows. It ended 0.63 s after the NUC's window (NUC and Mac clock) and 0.55 s after u9's (u9 clock). Entries 1–99 below are every PENDING entry on the server. Ten were first seen in the second inventory scans, after the windows ("after window"). Occurrence counts on BPF entries include those second scans. By type and host: DLOPEN 39 NUC, 24 u9; BPF_INVENTORY 14 NUC, 12 u9, 4 both; EXEC_INJECTION 3 NUC, 1 u9; ELF_RPATH 1 u9; SHM_CREATE 1 NUC.

| # | event type | hosts | key | in container | occurrences | first seen (bus clock) | after window |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | BPF_INVENTORY | NUC | tag `03b4eaae2f14641a`, CGROUP_DEVICE, name s_snap_store_ub, s_snapd_desktop | no | 4 | 2026-10-11T03:32:02.221Z |  |
| 2 | BPF_INVENTORY | NUC | tag `0ecd07b7b633809f`, CGROUP_DEVICE, name sd_devices | no | 2 | 2026-10-11T03:32:02.221Z |  |
| 3 | BPF_INVENTORY | NUC | tag `13443d24c302919b`, TRACEPOINT, name trace_bpf_enter | no | 2 | 2026-10-11T03:32:02.221Z |  |
| 4 | BPF_INVENTORY | NUC | tag `454eb3a45713bcff`, TRACEPOINT, name (not in the saved events) | no | 1 | 2026-10-11T03:37:02.222Z | yes |
| 5 | BPF_INVENTORY | NUC | tag `4b010a362585cab7`, TRACEPOINT, name (not in the saved events) | no | 1 | 2026-10-11T03:37:02.222Z | yes |
| 6 | BPF_INVENTORY | NUC | tag `5b66259bfca5c6d7`, CGROUP_DEVICE, name sd_devices | no | 6 | 2026-10-11T03:32:02.221Z |  |
| 7 | BPF_INVENTORY | NUC | tag `6b75aff6d335de17`, TRACEPOINT, name (not in the saved events) | no | 1 | 2026-10-11T03:37:02.222Z | yes |
| 8 | BPF_INVENTORY | NUC | tag `8b9c33f36f812014`, CGROUP_DEVICE, name sd_devices | no | 2 | 2026-10-11T03:32:02.221Z |  |
| 9 | BPF_INVENTORY | NUC | tag `8ba6a816be027107`, TRACEPOINT, name trace_bpf_exit | no | 2 | 2026-10-11T03:32:02.221Z |  |
| 10 | BPF_INVENTORY | NUC | tag `9f61d014bc423023`, TRACEPOINT, name (not in the saved events) | no | 1 | 2026-10-11T03:37:02.222Z | yes |
| 11 | BPF_INVENTORY | NUC | tag `a26a58e10de68efd`, TRACEPOINT, name rpath_on_exec | no | 2 | 2026-10-11T03:32:02.221Z |  |
| 12 | BPF_INVENTORY | NUC | tag `adc566247672d2c8`, KPROBE, name (not in the saved events) | no | 1 | 2026-10-11T03:37:02.222Z | yes |
| 13 | BPF_INVENTORY | NUC | tag `c8b47a902f1cc68b`, CGROUP_DEVICE, name sd_devices | no | 4 | 2026-10-11T03:32:02.221Z |  |
| 14 | BPF_INVENTORY | NUC | tag `e3dbd137be8d6168`, CGROUP_DEVICE, name sd_devices | no | 2 | 2026-10-11T03:32:02.221Z |  |
| 15 | BPF_INVENTORY | NUC+u9 | tag `6deef7357e7b4530`, CGROUP_SKB, name sd_fw_egress, sd_fw_ingress | no | 40 | 2026-10-11T03:31:24.178Z |  |
| 16 | BPF_INVENTORY | NUC+u9 | tag `81dfab3bd7eb416a`, CGROUP_DEVICE, name sd_devices | no | 17 | 2026-10-11T03:31:24.178Z |  |
| 17 | BPF_INVENTORY | NUC+u9 | tag `ab4bc4523b7fe6b4`, CGROUP_DEVICE, name (empty) | no | 23 | 2026-10-11T03:31:24.178Z |  |
| 18 | BPF_INVENTORY | NUC+u9 | tag `ee0e253c78993a24`, CGROUP_DEVICE, name sd_devices | no | 6 | 2026-10-11T03:31:24.178Z |  |
| 19 | BPF_INVENTORY | u9 | tag `0cf8779cecd085e3`, TRACEPOINT, name (not in the saved events) | no | 1 | 2026-10-11T03:36:24.178Z | yes |
| 20 | BPF_INVENTORY | u9 | tag `134b8a301991f6b7`, CGROUP_DEVICE, name sd_devices | no | 4 | 2026-10-11T03:31:24.178Z |  |
| 21 | BPF_INVENTORY | u9 | tag `1c48a4a25666f3e3`, TRACEPOINT, name (not in the saved events) | no | 1 | 2026-10-11T03:36:24.178Z | yes |
| 22 | BPF_INVENTORY | u9 | tag `384856681694f215`, CGROUP_DEVICE, name sd_devices | no | 2 | 2026-10-11T03:31:24.178Z |  |
| 23 | BPF_INVENTORY | u9 | tag `3bb911deb8a44f72`, TRACEPOINT, name rpath_on_exec | no | 2 | 2026-10-11T03:31:24.178Z |  |
| 24 | BPF_INVENTORY | u9 | tag `52b4e738e18d137f`, TRACEPOINT, name trace_bpf_exit | no | 2 | 2026-10-11T03:31:24.178Z |  |
| 25 | BPF_INVENTORY | u9 | tag `654d7024997e7811`, CGROUP_DEVICE, name sd_devices | no | 2 | 2026-10-11T03:31:24.178Z |  |
| 26 | BPF_INVENTORY | u9 | tag `722e84622310ce57`, KPROBE, name (not in the saved events) | no | 1 | 2026-10-11T03:36:24.178Z | yes |
| 27 | BPF_INVENTORY | u9 | tag `b6df636eb71bef45`, TRACEPOINT, name (not in the saved events) | no | 1 | 2026-10-11T03:36:24.178Z | yes |
| 28 | BPF_INVENTORY | u9 | tag `de4f4478859669c1`, TRACEPOINT, name trace_bpf_enter | no | 2 | 2026-10-11T03:31:24.178Z |  |
| 29 | BPF_INVENTORY | u9 | tag `e12ada16ccea916a`, TRACEPOINT, name (not in the saved events) | no | 1 | 2026-10-11T03:36:24.178Z | yes |
| 30 | BPF_INVENTORY | u9 | tag `fba67f14acbaee05`, CGROUP_DEVICE, name sd_devices | no | 2 | 2026-10-11T03:31:24.178Z |  |
| 31 | DLOPEN | NUC | `(no exe path)` library_hash `sha256:1c23aa1f91aa2970…` | no | 1 | 2026-10-11T03:32:08.841Z |  |
| 32 | DLOPEN | NUC | `(no exe path)` library_hash `sha256:acf468d0024231bd…` | no | 1 | 2026-10-11T03:32:08.841Z |  |
| 33 | DLOPEN | NUC | `(no exe path)` library_hash `sha256:ade3603b45672218…` | no | 1 | 2026-10-11T03:32:08.841Z |  |
| 34 | DLOPEN | NUC | `(no exe path)` library_hash `sha256:bdbbcb71a92f56d2…` | no | 1 | 2026-10-11T03:32:08.841Z |  |
| 35 | DLOPEN | NUC | `(no exe path)` library_hash `sha256:c37b5405af636c32…` | no | 1 | 2026-10-11T03:32:08.841Z |  |
| 36 | DLOPEN | NUC | `(no exe path)` library_hash `sha256:f94dae0bd342ae52…` | no | 1 | 2026-10-11T03:32:50.351Z |  |
| 37 | DLOPEN | NUC | `(no exe path)` library_path `/usr/lib/x86_64-linux-g…` | no | 1 | 2026-10-11T03:32:50.349Z |  |
| 38 | DLOPEN | NUC | `(no exe path)` library_path `/usr/lib/x86_64-linux-g…` | no | 1 | 2026-10-11T03:32:50.349Z |  |
| 39 | DLOPEN | NUC | `(no exe path)` library_path `/usr/lib/x86_64-linux-g…` | no | 1 | 2026-10-11T03:32:50.349Z |  |
| 40 | DLOPEN | NUC | `/usr/bin/sudo` library_hash `sha256:34f79b8b4ac7c0a6…` | no | 1 | 2026-10-11T03:32:08.840Z |  |
| 41 | DLOPEN | NUC | `/usr/bin/sudo` library_hash `sha256:8d9086d1634710ec…` | no | 1 | 2026-10-11T03:32:08.840Z |  |
| 42 | DLOPEN | NUC | `/usr/bin/sudo` library_hash `sha256:8ec4949d29ca9b7d…` | no | 1 | 2026-10-11T03:32:08.841Z |  |
| 43 | DLOPEN | NUC | `/usr/bin/sudo` library_hash `sha256:ab3ec87d27346161…` | no | 1 | 2026-10-11T03:32:08.840Z |  |
| 44 | DLOPEN | NUC | `/usr/bin/sudo` library_hash `sha256:cf08c165b20eb007…` | no | 1 | 2026-10-11T03:32:08.840Z |  |
| 45 | DLOPEN | NUC | `/usr/bin/sudo` library_hash `sha256:d917f4a8375231b1…` | no | 1 | 2026-10-11T03:32:08.839Z |  |
| 46 | DLOPEN | NUC | `/usr/bin/sudo` library_hash `sha256:e715a88e24593256…` | no | 1 | 2026-10-11T03:32:08.841Z |  |
| 47 | DLOPEN | NUC | `/usr/bin/sudo` library_hash `sha256:f3f90b51c9f0b006…` | no | 1 | 2026-10-11T03:32:08.841Z |  |
| 48 | DLOPEN | NUC | `/usr/lib/systemd/systemd-logind` library_hash `sha256:a1afceb5a3d3c9ab…` | no | 1 | 2026-10-11T03:32:08.748Z |  |
| 49 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:1538333bebc693ab…` | no | 1 | 2026-10-11T03:32:08.701Z |  |
| 50 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:15bec2450a315b58…` | no | 1 | 2026-10-11T03:32:08.701Z |  |
| 51 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:1c23aa1f91aa2970…` | no | 1 | 2026-10-11T03:32:08.700Z |  |
| 52 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:2511c04653aa0f27…` | no | 1 | 2026-10-11T03:32:08.700Z |  |
| 53 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:34f79b8b4ac7c0a6…` | no | 1 | 2026-10-11T03:32:08.702Z |  |
| 54 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:358fe54cdde9da1f…` | no | 1 | 2026-10-11T03:32:08.699Z |  |
| 55 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:72def79457b5ef60…` | no | 1 | 2026-10-11T03:32:08.700Z |  |
| 56 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:7c9d9bd7c2d0dc5b…` | no | 1 | 2026-10-11T03:32:08.700Z |  |
| 57 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:8d9086d1634710ec…` | no | 1 | 2026-10-11T03:32:08.699Z |  |
| 58 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:8ec4949d29ca9b7d…` | no | 1 | 2026-10-11T03:32:08.699Z |  |
| 59 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:a1afceb5a3d3c9ab…` | no | 1 | 2026-10-11T03:32:08.746Z |  |
| 60 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:ab3ec87d27346161…` | no | 1 | 2026-10-11T03:32:08.699Z |  |
| 61 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:acf468d0024231bd…` | no | 1 | 2026-10-11T03:32:08.701Z |  |
| 62 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:ade3603b45672218…` | no | 1 | 2026-10-11T03:32:08.702Z |  |
| 63 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:bdbbcb71a92f56d2…` | no | 1 | 2026-10-11T03:32:08.702Z |  |
| 64 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:c37b5405af636c32…` | no | 1 | 2026-10-11T03:32:08.699Z |  |
| 65 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:cf08c165b20eb007…` | no | 1 | 2026-10-11T03:32:08.702Z |  |
| 66 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:e715a88e24593256…` | no | 1 | 2026-10-11T03:32:08.699Z |  |
| 67 | DLOPEN | NUC | `/usr/sbin/sshd` library_hash `sha256:f3f90b51c9f0b006…` | no | 1 | 2026-10-11T03:32:08.699Z |  |
| 68 | DLOPEN | NUC | `/usr/sbin/xtables-nft-multi` library_hash `sha256:7b24c0697379b0e6…` | no | 1 | 2026-10-11T03:32:50.390Z |  |
| 69 | DLOPEN | NUC | `/usr/sbin/xtables-nft-multi` library_hash `sha256:efac8d0def549b95…` | no | 1 | 2026-10-11T03:32:50.351Z |  |
| 70 | DLOPEN | u9 | `(no exe path)` library_hash `sha256:9b88fa633ac437ad…` | no | 1 | 2026-10-11T03:31:24.380Z |  |
| 71 | DLOPEN | u9 | `(no exe path)` library_hash `sha256:d228575bae4d8212…` | no | 1 | 2026-10-11T03:31:24.380Z |  |
| 72 | DLOPEN | u9 | `(no exe path)` library_hash `sha256:ffedf11582acad2a…` | no | 1 | 2026-10-11T03:31:24.380Z |  |
| 73 | DLOPEN | u9 | `/opt/llama.cpp/build-cuda/bin/llama-server` (exe hash only) | no | 1 | 2026-10-11T03:31:27.683Z |  |
| 74 | DLOPEN | u9 | `/opt/llama.cpp/build-cuda/bin/llama-server` library_hash `sha256:1efe4284e4ab3304…` | no | 1 | 2026-10-11T03:31:27.759Z |  |
| 75 | DLOPEN | u9 | `/opt/llama.cpp/build-cuda/bin/llama-server` library_hash `sha256:ea84700b0c6c3161…` | no | 1 | 2026-10-11T03:31:27.759Z |  |
| 76 | DLOPEN | u9 | `/opt/llama.cpp/build-cuda/bin/llama-server` library_path `libcuda.so.1` | no | 1 | 2026-10-11T03:31:27.683Z |  |
| 77 | DLOPEN | u9 | `/opt/llama.cpp/build-cuda/bin/llama-server` library_path `libnvrtc.so` | no | 1 | 2026-10-11T03:31:27.683Z |  |
| 78 | DLOPEN | u9 | `/usr/bin/pgrep` (exe hash only) | no | 1 | 2026-10-11T03:32:28.054Z |  |
| 79 | DLOPEN | u9 | `/usr/bin/sudo` library_hash `sha256:482cafb6ee0cf18f…` | no | 1 | 2026-10-11T03:31:24.379Z |  |
| 80 | DLOPEN | u9 | `/usr/bin/sudo` library_hash `sha256:4955ef472c43e574…` | no | 1 | 2026-10-11T03:31:24.378Z |  |
| 81 | DLOPEN | u9 | `/usr/bin/sudo` library_hash `sha256:c71ed5533ac8cc21…` | no | 1 | 2026-10-11T03:31:24.379Z |  |
| 82 | DLOPEN | u9 | `/usr/bin/sudo` library_hash `sha256:e014016d5d5bdfe3…` | no | 1 | 2026-10-11T03:31:24.379Z |  |
| 83 | DLOPEN | u9 | `/usr/bin/sudo` library_hash `sha256:e559d29253b2e619…` | no | 1 | 2026-10-11T03:31:24.379Z |  |
| 84 | DLOPEN | u9 | `/usr/bin/sudo` library_hash `sha256:f2e5b0631cf15ffc…` | no | 1 | 2026-10-11T03:31:24.379Z |  |
| 85 | DLOPEN | u9 | `/usr/sbin/cron` library_hash `sha256:482cafb6ee0cf18f…` | no | 1 | 2026-10-11T03:35:01.611Z |  |
| 86 | DLOPEN | u9 | `/usr/sbin/cron` library_hash `sha256:5d8937a9c111f6e6…` | no | 1 | 2026-10-11T03:35:01.612Z |  |
| 87 | DLOPEN | u9 | `/usr/sbin/cron` library_hash `sha256:9b88fa633ac437ad…` | no | 1 | 2026-10-11T03:35:01.612Z |  |
| 88 | DLOPEN | u9 | `/usr/sbin/cron` library_hash `sha256:c71ed5533ac8cc21…` | no | 1 | 2026-10-11T03:35:01.612Z |  |
| 89 | DLOPEN | u9 | `/usr/sbin/cron` library_hash `sha256:d228575bae4d8212…` | no | 1 | 2026-10-11T03:35:01.611Z |  |
| 90 | DLOPEN | u9 | `/usr/sbin/cron` library_hash `sha256:e014016d5d5bdfe3…` | no | 1 | 2026-10-11T03:35:01.611Z |  |
| 91 | DLOPEN | u9 | `/usr/sbin/cron` library_hash `sha256:e559d29253b2e619…` | no | 1 | 2026-10-11T03:35:01.612Z |  |
| 92 | DLOPEN | u9 | `/usr/sbin/cron` library_hash `sha256:f2e5b0631cf15ffc…` | no | 1 | 2026-10-11T03:35:01.611Z |  |
| 93 | DLOPEN | u9 | `/usr/sbin/cron` library_hash `sha256:ffedf11582acad2a…` | no | 1 | 2026-10-11T03:35:01.612Z |  |
| 94 | ELF_RPATH | u9 | `/opt/llama.cpp/build-cuda/bin/llama-server` (exe hash only) | no | 1 | 2026-10-11T03:31:27.667Z |  |
| 95 | EXEC_INJECTION | NUC | `(no exe path)` library_path `/opt/containerd/lib:` | no | 1 | 2026-10-11T03:32:50.334Z |  |
| 96 | EXEC_INJECTION | NUC | `/usr/bin/containerd-shim-runc-v2` library_path `/opt/containerd/lib:` | no | 1 | 2026-10-11T03:32:50.331Z |  |
| 97 | EXEC_INJECTION | NUC | `/usr/bin/runc` library_path `/opt/containerd/lib:` | no | 2 | 2026-10-11T03:32:50.285Z |  |
| 98 | EXEC_INJECTION | u9 | `/usr/sbin/runc` library_path `/opt/containerd/lib:` | no | 410 | 2026-10-11T03:31:24.625Z |  |
| 99 | SHM_CREATE | NUC | `/opt/slimjet/slimjet` shm_pattern `unknown` | no | 570 | 2026-10-11T03:32:03.210Z |  |

## Where each non-INFO event came from

This attribution comes from the events' cmdline, cgroup and container ID fields, `docker events` and `docker ps` on the hosts, and my own command history. The raw lines are above.

| Host | Source | Events |
| --- | --- | --- |
| NUC | My SSH login to check the bus (`sshd: drl [priv]`, PAM modules, as root) | 19 DLOPEN CRITICAL |
| NUC | systemd-logind for that login (`libnss_systemd.so.2`) | 1 DLOPEN CRITICAL |
| NUC | My `sudo` to read the bus log | 13 DLOPEN WARN |
| NUC | Another engineer's container `hookmon-wfix-pg` killed and removed at 03:32:50 (`docker events`): `runc` and `containerd-shim-runc-v2` with `LD_LIBRARY_PATH=/opt/containerd/lib:` | 4 EXEC_INJECTION CRITICAL |
| NUC | The same removal: `iptables` loading xtables modules (`libxt_tcp`, `libipt_DNAT`, `libxt_standard`, `libipt_MASQUERADE`) | 6 DLOPEN CRITICAL |
| u9 | Docker healthchecks of the 8 HookMon appliance containers: `runc exec` with `LD_LIBRARY_PATH=/opt/containerd/lib:`. By container ID in the cmdline: 60 each for postgres, loki, prometheus, pushgateway, alertmanager and grafana (5 s interval), 30 for the server (10 s), 20 for the collector (15 s) | 410 EXEC_INJECTION CRITICAL |
| u9 | A cron job at 03:35:01 (u9 clock), `/usr/sbin/CRON -f -P` opening PAM modules as root | 9 DLOPEN CRITICAL |
| u9 | `curator.service` starting `/opt/llama.cpp/build-cuda/bin/llama-server -m /mnt/ssd/models/gemma-4-E4B-it-Q4_K_M.gguf … --port 8093` as uid 1000, 3 s after T0: RUNPATH `/opt/llama.cpp/build-cuda/bin:` (the trailing colon is an empty entry, rated HIGH) | 1 ELF_RPATH ALERT |
| u9 | The same llama-server: `dlopen(NULL)`, `libcuda.so.1`, `libnvrtc.so`, `libggml-cuda.so`, `libggml-cpu.so` | 5 DLOPEN WARN |
| u9 | My `sudo` to read T0 and the bus PID | 9 DLOPEN WARN |
| u9 | My `pgrep -o dockerd` (`dlopen(NULL)`) | 1 DLOPEN WARN |

Each DLOPEN source appears only once because the bus drops a repeat of the same (exe hash, library path) for an hour (`agent/sensors/dlopen_dedupe.go:14`). That is why my later SSH logins and sudo calls in the windows left no events.

## Surprises

**drl-nuc8i3bek**
- **One browser made 88% of the host's events.** 570 SHM_CREATE in 5 minutes came from Slimjet (`/opt/slimjet/slimjet`, thread `Chrome_IOThread`, uid 1000), each with a different name `.org.chromium.Chromium.XXXXXX`. That is 1.9 a second, or about 164,000 a day. The bus rates them INFO, but the server stores each one with policy action ALERT, and each goes to Loki and the dashboard. Learning mode folded them into one PENDING entry (#99).
- **Watching the host made most of its alerts.** 33 of the 43 non-INFO events came from my own SSH login and sudo. The other 10 came from another engineer's routine `docker rm` of a test container. Removing a container produced 10 CRITICAL events.
- Nothing else: no BPF loads or attaches, no ptrace, no linker-config or library writes, and no RPATH findings. The BPF inventory held only systemd's device and firewall programs, runc's device filters, two snap device filters created by uid 1000, and the bus's own three.

**infinichat-u9**
- **The appliance's own healthchecks made 87% of the host's events.** 410 of 469 events are CRITICAL EXEC_INJECTION. containerd's shim carries `LD_LIBRARY_PATH=/opt/containerd/lib:` and passes it to `runc`, so every healthcheck run is one CRITICAL event. The NUC's shim carries the same variable. The rate here was 1.37 a second, or about 118,000 a day, for 8 containers. Learning mode folded them into one PENDING entry (#98).
- A cron job's PAM session is CRITICAL (9 events), because it runs as root.
- A real ELF_RPATH finding on a service binary: `/opt/llama.cpp/build-cuda/bin/llama-server` has `RUNPATH=/opt/llama.cpp/build-cuda/bin:`. Its empty entry makes the loader search the current directory.
- No unknown BPF programs. Eight unnamed runc device filters and eight `sd_devices` programs with tag `81dfab3bd7eb416a` match the eight appliance containers.

Every non-INFO event on both hosts traces to a named process (the table above). No event points at an unknown program, library or process.

## The Grafana screenshot (`step8-grafana.png`)

The capture finished at 03:37:39Z. It shows the dashboard as it was then, about 35 s after both windows ended. The time range is 03:30:30Z to 03:38:00Z.

- **Fleet Health** shows two tiles, both "ALL SENSORS OPERATIONAL" (see the first item under "Did not work as documented").
- **Fleet Status:** both hosts reachable. **Sensor Health Grid:** 16 rows (8 sensors × 2 hosts), all alive from about 03:32. The row labels overlap in the 6-row-high panel. **Active Sensors:** 8 and 8.
- **Total Events: 1275.** This is the sum of both buses' counters at the moment of the screenshot. It includes both second inventory scans and the events after the windows.
- **Sensor Errors:** "No data" (no sensor failed to start).
- **Events by Severity:** INFO, ALERT and WARN. These are the bus's ratings. The server's CRITICAL does not appear anywhere in Grafana.
- **Event Timeline:** the newest Loki entry, a Slimjet SHM_CREATE at 03:37:31Z, after the window. **Exec Injection Detections:** u9's `runc` events, with times on u9's clock.
- **Recent BPF Loads:** "No data". **BPF Instruction Count Distribution:** "No histogram found in response". Neither window had a BPF load.

## Did not work as documented

- **The Fleet Health banner shows two tiles** (`deploy/docker/grafana/dashboards/hookmon.json:42`). The query is `(hookmon_fleet_hosts_degraded or vector(0)) + (hookmon_fleet_hosts_unreachable or vector(0))`. `or vector(0)` always adds a label-less 0, so the query returns a `{job="hookmon-collector"}` series and a `{}` series that is always 0. The panel description (line 13) says it shows one state or the other. Before the buses started, with both hosts unreachable, it showed "ALL SENSORS OPERATIONAL" in green next to "SENSOR COVERAGE DEGRADED" in red. With the fleet healthy it shows two green tiles.
- **The compose appliance's monitoring needs two edits the guide never mentions** (`docs/deployment-guide.md:331-347`). Its Compose Appliance section never says to list the buses in `<out-dir>/prometheus/buses.yml` and in `collector.yaml` (`hosts: []` as written). Only the comments in those generated files and in `deploy/appliance/prometheus.yml:24-26` say so. Following the guide alone leaves Fleet Status, the sensor grid and every bus-metric panel empty.
- **The bus binary is not static** (`Makefile:50`). The comment there says "the bus itself is static Go". The `make build-bus` binary is dynamically linked: `libc.so.6` and `libresolv.so.2`, with GLIBC_2.34 symbols. It ran unchanged on u9 (glibc 2.39).
- **check-stack.sh runs 13 checks** (`docs/claims.md:369`). The ledger says "14 of 14 checks pass". The script has 13 checks; all 13 passed.
- The host inventory records u9's IP as `172.18.0.1`, the Docker bridge gateway, because u9's bus reached the server through Docker's published port on the same host.

## Evidence files

| File | Size | Contents |
| --- | --- | --- |
| `step8-drl-nuc8i3bek-events.json` | 710,596 bytes | 646 events, T0 to T0+5 m |
| `step8-infinichat-u9-events.json` | 707,033 bytes | 469 events, T0 to T0+5 m |
| `step8-grafana.png` | 465,224 bytes | 1600×1860, the whole dashboard in one image |

No file is over 5 MB. One screenshot shows every panel, so there is no `step8-grafana-2.png`.

## Teardown

- **NUC:** the bus stopped on SIGTERM, and `bpftool prog show` lists none of its programs. `/tmp/hookmon-s8` is removed and port 2112 is closed. `~/hookmon-w8` (31 MB, source and build) is kept, like the other `~/hookmon-w*` directories. The lock is released (`flock -n` succeeds). `go clean -cache` ran for drl and root. `docker ps -a` lists only `docker-grafana-1`, `docker-prometheus-1` and `docker-loki-1`, as before.
- **u9:** the bus stopped on SIGTERM. Ubuntu's `bpftool` has no build for 6.17, so the kernel's program list was not checked; no `hookmon-bus` process remains and nothing is pinned in `/sys/fs/bpf`. `/tmp/hookmon-s8`, with the copied binaries, is removed. `docker compose -p hookmon-s8 down -v --rmi all` removed the 8 containers, 6 volumes, 2 networks and 8 images. `~/hookmon-s8-init` and `~/hookmon-w8` are removed. `docker ps -a` lists nothing, as before. The images, volumes and networks match the baseline, and `ss -ltn` matches the baseline line for line. Docker's build cache holds 33 entries (2.6 GB). It wasn't measured beforehand and was not pruned.

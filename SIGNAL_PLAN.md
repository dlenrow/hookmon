# HookMon signal plan: every alert needs action, nothing else reaches the dashboard

Work on the `first-sighting` branch. When everything below passes, merge it into `main`, push, and remove the agent worktrees under `.claude/worktrees/`.

## The rule

HookMon's dashboard and alerts show only things a person must act on. Alerts should be rare: days or weeks apart on a large fleet. Every alert is real; there are no warnings and no false positives.

Everything else is still logged for forensics. Forensic logs never alert and never appear on the main dashboard.

Every hook event goes through one triage, keyed on **what** was loaded or changed:

| What was loaded | Result |
| --- | --- |
| On the allow list | Nothing. Logged for forensics only. |
| On the deny list | High-priority alert, every time (see part 4). |
| Never seen before | High-priority alert once, then it waits on the New hooks page until someone allows or denies it. |

A new hash is a new thing. A software update creates new hashes, and they should alert. Part 2 makes approving a known update a single bulk action.

---

## Part 1. HookMon's own health: one alert when broken, silent otherwise

**Healthy.** No alert and nothing on the dashboard, except one quiet line (for example, "412 hosts, all sensors healthy").

**Broken.** One high-priority alert per host per incident. It is raised when the problem starts and resolved, with a single notice, when the problem ends. It is never repeated at each evaluation.

The conditions:

| Condition | Meaning |
| --- | --- |
| Dead | The sensor bus can't be reached, and no clean shutdown, suspend or retirement was announced. |
| Wedged | The bus answers, but a sensor fails its active probe. Or the end-to-end check below stops arriving. |
| Crazy | Any of: event rate far above the host's own normal; events dropped in the ring buffer or channel (today they are dropped silently); a restart loop (for example, 3 restarts in 10 minutes); a client certificate that expires within 7 days; the bus version or config differs from what the server expects. |
| Collector or server down | The thing that watches the fleet has stopped. One alert, not one per host. |

To build:

1. **No alerts for expected absences.**
   - Laptops sleep and servers are shut down for maintenance. The bus sends "going offline (shutdown / suspend)" on clean stop, using systemd stop and sleep hooks.
   - An announced absence does not alert. A host that goes silent without announcing it does.
   - Add "retire host" and a maintenance window, per host and per group, in the API, CLI and dashboard.
2. **End-to-end check.**
   - Every minute, the bus sends a marker through the same gRPC stream that events use. The server records the time it arrived.
   - Missing for 3 minutes on a host that has not announced it is going offline means **Wedged**.
   - This replaces `HookMonNoEvents24h`. Delete that rule: a quiet host with no events is normal, and that rule cannot tell normal from broken.
3. **One alert for a fleet-wide outage.** If more than a set share of hosts go dead within one minute (default 20%), raise one "fleet outage / network partition" alert, not one per host.
4. **Group the rules so each incident alerts once.** Rework `HookMonHostUnreachable`, `SensorDead`, `FleetDegraded` and `CollectorSilent` so that one broken host gives exactly one alert, whatever the cause. Today a dead host can fire several of these rules for the same incident.
5. **Same behavior in both places.** The server dashboard and the Alertmanager path both follow these rules.

Acceptance:
- An idle, healthy 3-host test fleet runs for 24 hours with **zero** alerts.
- `kill -9` of the bus gives one high alert within 60 s, and one resolve notice after restart.
- `systemctl stop hookmon-bus` and a suspend give no alert.
- Detaching one sensor's hook gives one alert.
- Blocking the gRPC stream while `/status` still answers gives one Wedged alert.
- Stopping 2 of 3 hosts within a minute gives one fleet alert.

## Part 2. Key on what was loaded, not who loaded it

Change `pkg/allowlist/key.go`. Take the acting binary's hash (`ExeHash`) and the event type out of the key. One thing loaded means one entry, whether it was seen at load, at attach, or in the inventory scan.

| Hook | Key (what was loaded or changed) |
| --- | --- |
| eBPF: load, attach and inventory share one key | Kernel program tag + program type |
| `LD_PRELOAD`, `LD_AUDIT` | Variable name + hash of the library it names |
| `LD_LIBRARY_PATH` | Variable name + the directory list |
| `LD_DEBUG` | Variable name |
| `dlopen` | Hash of the library loaded |
| Library replacement | Library path + new content hash |
| Linker config files | File path + new content hash |
| Shared memory | The bpftime/BPF pattern |
| RPATH | Hash of the binary that carries the RPATH |
| ptrace | Hash of the tracing binary (the tracer is the thing being approved here) |

What else to do:
- Keep the acting binary, the host, the user and the container on every event, as context shown with the alert and stored for forensics. They are not part of the key.
- Migrate existing PENDING, APPROVED and REJECTED entries to the new key. Merge entries that collapse into one, keeping the most restrictive decision.
- **Bulk approval for known updates.** On the New hooks page, group new sightings into batches: same time window (default 1 hour), same set of hosts, and similar names or paths. One click selects a batch, and one click allows it.
  - Example: "Cilium 1.16.3 rolled out to 340 hosts at 14:05; 27 new programs; select all, allow."
  - Allowing a batch writes one allow entry per key, with a shared note naming the change.

Acceptance:
- A new BPF program on a test fleet gives exactly **one** first-sighting alert, though it is seen at load, at attach and in inventory on every host.
- The same program loaded by a different binary gives no new alert.
- A simulated agent upgrade (new hashes on 3 hosts within minutes) appears as one batch that is approved in one action.

## Part 3. Kernel upgrades

A program's kernel tag changes with the kernel version. Today a kernel upgrade makes every loaded program look new.

1. The bus reports the kernel release (`uname -r`) in its heartbeat and on every BPF event. The server records each host's current and previous kernel.
2. When a host's kernel changes, gather the first sightings of BPF programs on that host in the hours after the change. Match each one to a program allowed under the previous kernel, by program name + program type + the loading binary's hash. The loader is used here only as evidence of a match; it is not part of the key.
3. Show one item per kernel change, across all hosts that made the same change:
   - "Kernel 6.8.0-45 → 6.8.0-47 on 120 hosts. 900 programs have new tags. 880 match programs allowed under the previous kernel: allow all. 20 do not match: review."
   - The unmatched ones stay as ordinary first sightings.
4. Allowing is always a person's click. Never allow automatically.
5. Store the kernel release on BPF allow entries as information, not as part of the key.

Acceptance: on the Linux test host, simulate a kernel change by replaying an inventory with changed tags and a changed kernel release. The result is one kernel-change item; one click allows the matched programs; the unmatched ones remain as first sightings.

## Part 4. Denied hooks: no change

A denied program that is still loaded alerts on every inventory scan until it is removed. Keep this behavior, and document it in the allowlist guide.

## Part 5. Dashboards and logs

- **Server dashboard home:** only open items — new hooks, denied hits and health incidents — plus the one quiet health line.
- **Grafana:** split it in two.
  - **Fleet health** shows Part 1's states and nothing else.
  - **Forensics** holds the raw event panels: timeline, events by type, recent BPF loads.
  - The Forensics dashboard has no alert rules and is not the default dashboard.
- **Loki keeps every event**, including every inventory scan, for forensics.

## Part 6. Docs, ledger, blog

- Update `README.md`, `docs/theory-of-operations.md`, `docs/allowlist-guide.md`, `docs/api-reference.md` and `docs/threat-model.md` to describe the triage, the new key, batches, kernel changes and health.
- Update `docs/claims.md` with one row per acceptance test above.
- List, in the merge commit message, every sentence of the October blog that no longer matches. Don't edit the blog; David will.

## Merge gate

- Every acceptance test above passes on the Linux e2e host.
- CI is green.
- `docs/claims.md` has no blank cells.
- Then merge `first-sighting` into `main`, push, and delete the agent worktrees and branches.

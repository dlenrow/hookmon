# Security Policy

## Scope

HookMon is a security monitoring tool. The sensor bus runs as root, which its eBPF programs and fanotify marks require. Vulnerabilities in HookMon could allow an attacker to escalate privileges, tamper with detection, or read data from monitored hosts.

## Reporting a Vulnerability

This is a reference implementation and is **not actively maintained** (see [MAINTAINERS.md](MAINTAINERS.md)). There is no security response team or patch SLA.

If you discover a security vulnerability:

1. **Do not open a public GitHub issue.**
2. Email the original author: david.lenrow@illumio.com
3. Include: affected component, reproduction steps, and impact assessment.

A response is not guaranteed on any timeline, but reports will be read.

## Known Trust Boundaries

The sensor bus (`hookmon-bus`) is a privileged process. Its attack surface includes:

- **eBPF programs** loaded into the kernel. They are compiled from checked-in C source at build time and embedded in the binary, not downloaded at runtime.
- **Helper processes.** Every 10 seconds the bus, as root, runs `/bin/true` and `hookmon-dlopen-probe` (from the bus binary's directory unless `dlopen_probe_path` says otherwise). Keep both binaries and their directory owned by root and not writable by anyone else.
- **gRPC transport.** TLS is opt-in today. If no certificate is configured, the bus and the server talk plaintext gRPC, and nothing warns you. When TLS is configured, it is mutual TLS, and the bus private key should be root-readable only. Making TLS the default is fix plan step 7b.
- **Loki push.** Plain, unauthenticated HTTP. Anyone on the path can read, drop or forge events.
- **Status and metrics endpoint** (port 2112). Unauthenticated HTTP serving `/status` and `/metrics`. Anyone who can reach the port can read it. Bind it to one address with `status_addr` (`--status-addr`), and limit access to the collector and Prometheus with a host firewall.
- **Configuration file.** YAML parsed by the bus; should be root-readable only.

The collector (`hookmon-collector`):

- **SSH mode does not verify host keys.** It accepts any host key, so a machine-in-the-middle can answer in place of the host.

The server (`hookmon-server`) accepts gRPC streams from sensor buses and exposes an HTTP API. Its attack surface includes:

- **gRPC ingestion.** Mutual TLS only when certificates are configured; otherwise plaintext (see above). The host ID in each event and heartbeat is whatever the bus sends, so one host can report as another (fix plan step 7a). The per-host rate limit is keyed by that self-asserted ID (step 7f).
- **Enrollment.** Not working: the `Enroll` RPC returns the CA certificate instead of signing the request, and no enrollment token reaches the server (step 7a).
- **REST API.** Token-authenticated (`--api-tokens`), except `/api/v1/health`. It is plain HTTP; TLS for REST is step 7b. Do not expose it to untrusted networks.
- **WebSocket** (`/api/v1/ws/events`). It accepts any non-empty token and any Origin (step 7e).
- **PostgreSQL.** The default connection string points at localhost with `sslmode=disable` and a fixed password. Credentials are passed with `--db`, so they show in the process list; a server config file is step 7d.
- **SIEM connectors.** Outbound connections to configured endpoints. Today nothing configures them (step 7d).

## Known Limitations

**A root attacker can fake a healthy bus.** The collector decides a host is healthy from the bus's `/status` response. `/status` is unauthenticated, and nothing proves the response came from the real bus. An attacker with root on a monitored host can kill the bus and run a small server on the status port that always answers "alive". The collector, Prometheus and Grafana will then show the host as healthy while nothing is monitored. HookMon does not detect this. The collector's SSH mode does not help: it fetches the same `/status` response with `curl` on the host.

**A root attacker can fake a sensor heartbeat.** Every 10 seconds the bus fires each eBPF sensor's hook with a harmless call. It then counts a sensor as alive only if that sensor's kernel heartbeat map moved forward. A root attacker who detaches or disables a hook can keep the sensor looking alive by writing fresh timestamps into its heartbeat map (`bpftool map update`). The bus also checks that each program and link are still attached, which raises the cost but does not close the gap. Root on the monitored host is the boundary of what the bus can vouch for.

**Root can also stop HookMon outright** without either trick above: by loading a kernel module, by replacing the bus binary or its config, or by killing the bus and accepting the unreachable alert. [docs/threat-model.md](docs/threat-model.md) lists what HookMon trusts and what it does not cover.

## If You Fork This

If you maintain a fork and want to establish your own security reporting process, update this file in your fork.

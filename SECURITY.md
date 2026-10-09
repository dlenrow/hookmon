# Security Policy

## Scope

HookMon is a security monitoring tool that runs with elevated privileges (CAP_BPF, CAP_SYS_ADMIN). Vulnerabilities in HookMon could allow an attacker to escalate privileges, tamper with detection, or exfiltrate data from monitored hosts.

## Reporting a Vulnerability

This is a reference implementation and is **not actively maintained** (see [MAINTAINERS.md](MAINTAINERS.md)). There is no security response team or patch SLA.

If you discover a security vulnerability:

1. **Do not open a public GitHub issue.**
2. Email the original author: drl@clevercraft.energy
3. Include: affected component, reproduction steps, and impact assessment.

A response is not guaranteed on any timeline, but reports will be read.

## Known Trust Boundaries

The agent (sensor bus) is a privileged process. Its attack surface includes:

- **eBPF programs** loaded into the kernel — compiled from checked-in C source, not downloaded at runtime
- **gRPC transport** — TLS is opt-in today. If no certificate is configured, the bus and the server talk plaintext gRPC, and nothing warns you. When TLS is configured, it is mutual TLS and the bus private key should be root-readable only. Making TLS the default is planned (fix plan step 7b).
- **Status and metrics endpoint** (port 2112) — unauthenticated HTTP serving `/status` and `/metrics`. Anyone who can reach the port can read it. Limit access to the collector and Prometheus with a host firewall.
- **Configuration file** — YAML parsed by the agent; should be root-readable only

The server accepts gRPC streams from enrolled agents and exposes an HTTP API. Its attack surface includes:

- **gRPC ingestion** — rate-limited per host. Mutual TLS only when certificates are configured; otherwise plaintext (see above)
- **REST API** — token-authenticated; do not expose to untrusted networks
- **PostgreSQL** — localhost only; credentials in server config file
- **SIEM connectors** — outbound connections to configured endpoints

## Known Limitations

**A root attacker can fake a healthy bus.** The collector decides a host is healthy from the bus's `/status` response. `/status` is unauthenticated, and nothing proves the response came from the real bus. An attacker with root on a monitored host can kill the bus and run a small server on the status port that always answers "alive". The collector, Prometheus and Grafana will then show the host as healthy while nothing is monitored. HookMon does not detect this. The collector's SSH mode does not help: it fetches the same `/status` response with `curl` on the host.

**A root attacker can fake a sensor heartbeat.** Every 10 seconds the bus fires each eBPF sensor's hook with a harmless call. It then counts a sensor as alive only if that sensor's kernel heartbeat map moved forward. A root attacker who detaches or disables a hook can keep the sensor looking alive by writing fresh timestamps into its heartbeat map (`bpftool map update`). The bus also checks that each program and link are still attached, which raises the cost but does not close the gap. Root on the monitored host is the boundary of what the bus can vouch for.

## If You Fork This

If you maintain a fork and want to establish your own security reporting process, update this file in your fork.

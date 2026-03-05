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
- **gRPC transport** — mTLS required; agent private key is root-readable only
- **Metrics endpoint** (port 2112) — unauthenticated HTTP; bind to localhost in production
- **Configuration file** — YAML parsed by the agent; should be root-readable only

The server accepts gRPC streams from enrolled agents and exposes an HTTP API. Its attack surface includes:

- **gRPC ingestion** — mTLS authenticated, rate-limited per host
- **REST API** — token-authenticated; do not expose to untrusted networks
- **PostgreSQL** — localhost only; credentials in server config file
- **SIEM connectors** — outbound connections to configured endpoints

## If You Fork This

If you maintain a fork and want to establish your own security reporting process, update this file in your fork.

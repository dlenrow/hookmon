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
- **gRPC transport.** Mutual TLS. On first start the bus enrolls with a token (`--enroll-token`) and stores its key, certificate and CA certificate in `state_dir` (default `/var/lib/hookmon`), each with mode 0600. A bus with no certificate and no token refuses to connect. `--insecure` (or `tls.insecure: true`) connects in plaintext instead; use it only for development. The enrollment token is visible in the process list while the first start runs.
- **Loki push.** Plain, unauthenticated HTTP. Anyone on the path can read, drop or forge events.
- **Status and metrics endpoint** (port 2112). Unauthenticated HTTP serving `/status` and `/metrics`. Anyone who can reach the port can read it. Bind it to one address with `status_addr` (`--status-addr`), and limit access to the collector and Prometheus with a host firewall.
- **Configuration file.** YAML parsed by the bus; should be root-readable only.

The collector (`hookmon-collector`):

- **SSH mode does not verify host keys.** It accepts any host key, so a machine-in-the-middle can answer in place of the host.

The server (`hookmon-server`) accepts gRPC streams from sensor buses and exposes an HTTP API. Its attack surface includes:

- **TLS by default.** The server refuses to start without a certificate (`tls.cert_file` or `--tls-cert`) unless `--insecure` (or `tls.insecure: true`) is given. Insecure mode runs gRPC and REST in plaintext, takes each host ID from the message, and cannot be combined with enrollment tokens. Use it only for development.
- **gRPC ingestion** (port 9443). The TLS handshake requires a client certificate signed by `tls.ca_file`. The server takes the host ID from that certificate's CN and ignores the host ID in each event and heartbeat. The per-host rate limit is keyed by that host ID, and its table of hosts is never trimmed (step 7f). There is no recovery interceptor, so a panic in an RPC handler stops the server (step 7f).
- **Enrollment** (port 9444). TLS that authenticates the server only, since an enrolling bus has no certificate yet. Only the `Enroll` RPC is served there, and it needs a token from the server config: compared in constant time, with an expiry, and optionally single-use (recorded in PostgreSQL, so it stays used across restarts). The server signs the request with the CA key (`tls.ca_key_file`) and assigns the host ID itself. Anyone holding a valid token can enroll a host. The listener runs only when tokens are configured.
- **REST API and dashboard** (port 8443). HTTPS with the server certificate, TLS 1.2 or newer; plain HTTP only in insecure mode. API calls need a token (`api.tokens` or `--api-tokens`), except `/api/v1/health`. The dashboard's static files need none. The dashboard keeps its API token in the browser's local storage.
- **WebSocket** (`/api/v1/ws/events`). The same API tokens as REST, sent as the `hookmon.bearer.<base64url>` subprotocol (browsers) or an Authorization header, never in the URL. A browser page is accepted only from the server's own origin or one in `api.allowed_origins`; a handshake without an Origin header (not a browser) needs only the token. Each client has a bounded buffer, so a slow client is disconnected and cannot hold up ingestion.
- **PostgreSQL.** The default connection string points at localhost with `sslmode=disable` and a fixed password. Set it in the server config file (`database.url`) rather than with `--db`, which shows in the process list.
- **Server config file** (`/etc/hookmon/server.yaml` by default). It holds the database password, API tokens and enrollment secrets, and names the CA key, which can sign a certificate for any host. Keep the file and the key root-only (mode 0600).
- **SIEM connectors.** Outbound connections to the endpoints in the server config's `connectors` section. Their secrets (HEC token, Elastic credentials, webhook headers) live in that file. Syslog is plain TCP or UDP, and Kafka has no TLS or SASL options yet.

## Known Limitations

**A root attacker can fake a healthy bus.** The collector decides a host is healthy from the bus's `/status` response. `/status` is unauthenticated, and nothing proves the response came from the real bus. An attacker with root on a monitored host can kill the bus and run a small server on the status port that always answers "alive". The collector, Prometheus and Grafana will then show the host as healthy while nothing is monitored. HookMon does not detect this. The collector's SSH mode does not help: it fetches the same `/status` response with `curl` on the host.

**A root attacker can fake a sensor heartbeat.** Every 10 seconds the bus fires each eBPF sensor's hook with a harmless call. It then counts a sensor as alive only if that sensor's kernel heartbeat map moved forward. A root attacker who detaches or disables a hook can keep the sensor looking alive by writing fresh timestamps into its heartbeat map (`bpftool map update`). The bus also checks that each program and link are still attached, which raises the cost but does not close the gap. Root on the monitored host is the boundary of what the bus can vouch for.

**Root can also stop HookMon outright** without either trick above: by loading a kernel module, by replacing the bus binary or its config, or by killing the bus and accepting the unreachable alert. [docs/threat-model.md](docs/threat-model.md) lists what HookMon trusts and what it does not cover.

## If You Fork This

If you maintain a fork and want to establish your own security reporting process, update this file in your fork.

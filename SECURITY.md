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
- **gRPC transport.** Mutual TLS. On first start the bus enrolls with a token and stores its key, certificate and CA certificate in `state_dir` (default `/var/lib/hookmon`), each with mode 0600. Give the token in a root-only file (`--enroll-token-file`, mode 0600) or in `HOOKMON_ENROLL_TOKEN`; `--enroll-token` also works, but the token is then visible in the process list while the first start runs. A bus with no certificate and no token refuses to connect. If the server's certificate does not verify against the CA file (`--ca-file`, `tls.ca_file`), enrollment and the first connection stop with an error instead of retrying. `--insecure` (or `tls.insecure: true`) connects in plaintext instead; use it only for development.
- **Loki push.** Plain, unauthenticated HTTP. Anyone on the path can read, drop or forge events.
- **Status and metrics endpoint** (port 2112). Unauthenticated HTTP serving `/status` and `/metrics`. Anyone who can reach the port can read it. Bind it to one address with `status_addr` (`--status-addr`), and limit access to the collector and Prometheus with a host firewall.
- **Configuration file.** YAML parsed by the bus; should be root-readable only.

The collector (`hookmon-collector`):

- **SSH mode verifies host keys** against a known_hosts file (`ssh_known_hosts`, at the top level or per host), and fails closed: the collector does not start with an SSH host and no known_hosts file, and a host whose key is not listed, or does not match, is reported unreachable. It fetches `/status` from the host's `status_port` (default 2112).

The server (`hookmon-server`) accepts gRPC streams from sensor buses and exposes an HTTP API. Its attack surface includes:

- **TLS by default.** The server refuses to start without a certificate (`tls.cert_file` or `--tls-cert`) unless `--insecure` (or `tls.insecure: true`) is given. Insecure mode runs gRPC and REST in plaintext, takes each host ID from the message, and cannot be combined with enrollment tokens. Use it only for development.
- **gRPC ingestion** (port 9443). The TLS handshake requires a client certificate signed by `tls.ca_file`. The server takes the host ID from that certificate's CN and ignores the host ID in each event and heartbeat; it records the hostname the host enrolled with, not the one in each event. The per-host rate limit is keyed by that host ID, never by a value in a message, and keeps at most 10,000 hosts, evicting the one seen least recently. A recovery interceptor turns a panic in an RPC handler into an error for that call or stream; the server keeps running. AGENT_OFFLINE and AGENT_RECOVERED are raised only by the server; a bus that sends them gets a negative ack.
- **Enrollment** (port 9444). TLS that authenticates the server only, since an enrolling bus has no certificate yet. Only the `Enroll` RPC is served there, and it needs a token from the server config: compared in constant time, with an expiry, and optionally single-use (recorded in PostgreSQL, so it stays used across restarts). The server signs the request with the CA key (`tls.ca_key_file`) and assigns the host ID itself. Anyone holding a valid token can enroll a host. The listener runs only when tokens are configured.
- **REST API and dashboard** (port 8443). HTTPS with the server certificate, TLS 1.2 or newer; plain HTTP only in insecure mode. Headers must arrive within 10 s and a request within 30 s; idle connections close after 120 s. API calls need a token (`api.tokens` or `--api-tokens`), except `/api/v1/health`. The dashboard's static files need none. The dashboard keeps its API token in the browser's local storage.
- **WebSocket** (`/api/v1/ws/events`). The same API tokens as REST, sent as the `hookmon.bearer.<base64url>` subprotocol (browsers) or an Authorization header, never in the URL. A browser page is accepted only from the server's own origin or one in `api.allowed_origins`; a handshake without an Origin header (not a browser) needs only the token. Each client has a bounded buffer, so a slow client is disconnected and cannot hold up ingestion.
- **PostgreSQL.** The default connection string points at localhost with `sslmode=disable` and a fixed password. Set it in the server config file (`database.url`) rather than with `--db`, which shows in the process list.
- **Server config file** (`/etc/hookmon/server.yaml` by default). It holds the database password, API tokens and enrollment secrets, and names the CA key, which can sign a certificate for any host. Keep the file and the key root-only (mode 0600).
- **SIEM connectors.** Outbound connections to the endpoints in the server config's `connectors` section. Their secrets (HEC token, Elastic credentials, webhook headers) live in that file. Syslog is plain TCP or UDP, and Kafka has no TLS or SASL options yet.

## Audit Security Findings

Every row of the audit's Security table, and where it stands. "Fixed" names the fix plan step and the tests that cover it.

| # | Finding | Status | Step | Tests, or why it remains |
|---|---------|--------|------|---------------------------|
| a | Server: WebSocket auth bypass | Fixed | 7e | `TestWebSocket_TokenAndOrigin`, `TestIntegration_WebSocketFanOut` (no token, a wrong token, a token in the URL: 401; a foreign Origin: 403) |
| b | Server: gRPC fails open without TLS | Fixed | 7b | `TestCheckTLS`, `TestRun_RefusesWithoutTLS` |
| c | Server: self-asserted HostID | Fixed | 7a | `TestWire_HostCannotSendAsAnother`, `TestIntegration_HostCannotSendAsAnother` |
| d | Server: one WebSocket channel shared by every client | Fixed | 7e | `TestHub_EverySubscriberGetsEveryEvent`, `TestWebSocket_TwoClientsGetEveryEvent`, `TestIntegration_WebSocketFanOut` |
| e | Server: `SignCSR` panics on input that is not PEM | Fixed | 7a | `TestSignCSR_MalformedCSR`, `TestParseCA_Malformed` |
| f | Server: a nil list element crashes the server; no recovery interceptor | Fixed | 7f | Nil RPATH entries and sensor entries are skipped (`TestRobustness_NilListElements`). Unary and stream recovery interceptors on both gRPC listeners: `TestRobustness_StreamPanicKeepsServing`, `TestRobustness_EnrollPanicKeepsServing`. Hostile messages (empty oneofs, empty and unknown enums, 3 MiB of strings, a message over 4 MiB): `TestRobustness_HostileProtos` |
| g | Server: rate-limiter table unbounded, keyed by a host ID the message chooses | Fixed | 7f | Keyed by the certificate's host ID (peer IP in insecure mode); at most 10,000 hosts, least recently seen evicted: `TestRateLimiter_Bounded`, `TestRateLimiter_KeyedByCertificate` |
| h | Server: UID and PID overflow the 32-bit columns | Fixed | 7b | Migration 005 (BIGINT): `TestMigration_UnknownUIDStored`, `TestIntegration_UnknownUIDEventStored` |
| i | Server: token compare not constant-time | Fixed | 7a | Enrollment and API tokens use `subtle.ConstantTimeCompare`: `TestTokenSet_Validate` |
| j | Server: no body limit or action validation on policy writes | Fixed | 7e | `TestWrites_BodyLimit`, `TestCreatePolicy_ActionAndFields`, `TestReplacePolicy`, `TestPatchPolicy` |
| k | Server: offline handling inconsistent (watchdog AGENT_OFFLINE never reached the WebSocket feed; a bus-sent AGENT_OFFLINE was rated differently; no AGENT_RECOVERED) | Fixed | 7f | The server is the only source of both events: a bus-sent one is refused (`TestStatusEventsFromBusRefused`, `TestValidateEvent_BusEventTypes`). The first heartbeat after the watchdog marked a host UNRESPONSIVE raises one AGENT_RECOVERED (INFO), in the same statement that reads the old status (`TestRecordHeartbeat_ReportsPreviousStatus`, `TestRecordHeartbeat_ConcurrentReportsRecoveryOnce`, `TestRecovered_OnHeartbeatAfterUnresponsive`). Both go to every connector, whatever its `min_severity`, and to the WebSocket feed (`TestWatchdog_OfflineReachesFeed`, `TestDispatcher_HostStatusReachesEveryConnector`, `TestIntegration_OfflineAndRecoveredReachFeedAndConnector`) |
| l | Bus: heartbeat false alarms | Fixed | 3 | `TestHeartbeatProblem`, `TestHealthCycle*`, `TestProbeFilter`; e2e `TestHeartbeat_IdleAllAlive` |
| m | Bus: file sensors evaded by rename (`mv`, `ln -sf`) | Fixed | 4 | `TestFileOp`, `TestLinkerConfigSensorTempEtc`, `TestLibIntegritySensorTempTree`; e2e `TestLinkerConfig_PreloadOperations`, `TestLibIntegrity_SoOperations` |
| n | Bus: concurrent `stream.Send` | Fixed | 2 | One goroutine sends (`sendLoop`): `TestConcurrentSendersAcrossRestart` under `-race` |
| o | Bus: `lib_integrity` starts with no fanotify marks | Fixed | 4 | `TestStartFailsWithoutMarks` |
| p | Bus: silent plaintext | Fixed | 7b | `TestEnsureIdentity_RefusesPlaintext`, `TestGRPCTransport_RefusesPlaintext`, `TestMain_RefusesPlaintext` |
| q | Bus: tamper detection spoofable: `/status` unauthenticated; collector SSH accepts any host key and always uses port 2112 | SSH part fixed (7f); `/status` remains | 7f | SSH verifies host keys against `ssh_known_hosts` and fails closed, and uses each host's `status_port`: `TestSSH_HostKeyVerification` (keys from `ssh-keygen`; known, hashed and other-type entries accepted; unknown and changed keys refused), `TestLoadConfig_SSHNeedsKnownHosts`. **`/status` stays unauthenticated by design**: Prometheus and the collector must read it without credentials the bus would have to store, and authenticating it would not help, because a root attacker on the host can read any credential the bus holds and answer in its place. See Known Limitations below. |
| r | Bus: exe hashing (format, cache, containers) | Fixed | 4 | `TestEnrichHashCache*`, `TestEnrichContainerExeHashedThroughProcRoot` |
| s | Bus: fanotify writer UID defaults to 0 | Fixed | 4 | "unknown" (4294967295) instead: `TestPcacheShortLivedWriterFromExecRecords`, the `pkgmgr` tests |
| t | Bus: ELF_RPATH events without a severity | Fixed | 4 | `TestRpathSeverity`, `TestRpathWEmitOncePerBinaryVersion`; e2e `TestSensor8_ElfRpath_OriginTmpCleanEnv` |
| u | Bus: read loops spin on errors other than close | Fixed | 7f | The six ring-buffer loops spun on any error. They now stop on close and otherwise back off from 10 ms to 1 s; while errors continue, the sensor's attachment check reports the read error, so the sensor goes dead in `/status`: `TestReadErrors_NoSpin`, `TestReadErrors_BackoffAndReport`, `TestCheckAttached_ReportsReadErrors`. The fanotify read loop already slept 100 ms after an unexpected error. |

Other gaps closed in step 7f: a missing event, host or policy is 404 and a database failure is 500 (`TestGetters_NotFoundIsErrNotFound`, `TestSingleRowReads_NotFoundVersusFailure`); events dropped from a full WebSocket feed buffer are counted and logged (`TestPublish_DropsCountedAndLogged`); the REST server has header, request and idle timeouts (`TestNewHTTPServer_Timeouts`).

## Known Limitations

**A root attacker can fake a healthy bus.** The collector decides a host is healthy from the bus's `/status` response. `/status` is unauthenticated, and nothing proves the response came from the real bus. An attacker with root on a monitored host can kill the bus and run a small server on the status port that always answers "alive". The collector, Prometheus and Grafana will then show the host as healthy while nothing is monitored. HookMon does not detect this. The collector's SSH mode does not help: it verifies that it reached the real host, but then fetches the same `/status` response with `curl` on that host. On the server path, a stopped bus stops heartbeating and the watchdog raises AGENT_OFFLINE, but an attacker with the bus's key and certificate from `/var/lib/hookmon` can keep heartbeating in its place.

**A root attacker can fake a sensor heartbeat.** Every 10 seconds the bus fires each eBPF sensor's hook with a harmless call. It then counts a sensor as alive only if that sensor's kernel heartbeat map moved forward. A root attacker who detaches or disables a hook can keep the sensor looking alive by writing fresh timestamps into its heartbeat map (`bpftool map update`). The bus also checks that each program and link are still attached, which raises the cost but does not close the gap. Root on the monitored host is the boundary of what the bus can vouch for.

**Root can also stop HookMon outright** without either trick above: by loading a kernel module, by replacing the bus binary or its config, or by killing the bus and accepting the unreachable alert. [docs/threat-model.md](docs/threat-model.md) lists what HookMon trusts and what it does not cover.

## If You Fork This

If you maintain a fork and want to establish your own security reporting process, update this file in your fork.

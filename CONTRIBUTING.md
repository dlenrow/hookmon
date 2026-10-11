# Contributing

## Read MAINTAINERS.md First

HookMon is a reference implementation, not an actively maintained project. There is no commitment to review pull requests, triage issues, or merge contributions. See [MAINTAINERS.md](MAINTAINERS.md) for the full explanation.

The most productive path for significant changes is to **fork the repo** and develop independently. If your fork gains traction, the conversation about upstream recognition is welcome.

## Building from Source

Prerequisites:
- Go 1.23+
- make and a C compiler (for `hookmon-dlopen-probe`)
- Node.js 20+ (dashboard only)
- On Linux: clang, llvm-strip, libbpf headers (`libbpf-dev`), bpftool, and a kernel with BTF (`/sys/kernel/btf/vmlinux`)

On Linux, `make build-all`, `make test-unit`, `make smoketest` and `make ci` first run `make bpf`, which generates `vmlinux.h` from the running kernel's BTF and compiles the eBPF objects. The Go code embeds those objects, so on Linux even `go build ./...` and `go test ./...` fail until `make bpf` has run. Root is not needed for any of these targets. On macOS, `make bpf` is skipped and stub sensors are built instead.

```bash
# Build all Go binaries and the dlopen helper (Linux: eBPF objects first)
make build-all

# Run unit tests
make test-unit

# Run smoketests (anti-tampering, sensor constructors, bus integration)
make smoketest

# Build dashboard
make build-dashboard

# build-all, test-unit and go vet
make ci
```

`make ci` is close to CI but not the same: CI also runs `go test -race -count=1 ./...` against a PostgreSQL service and `make smoketest`, builds the dashboard, checks the compose appliance, and runs the dashboard's Playwright tests against it (see [CI](#ci) below).

The end-to-end tests (`make test-e2e`, `make test-e2e-full`) need Linux, root and the eBPF toolchain. They load real eBPF programs and run real attacks. See [docs/theory-of-operations.md](docs/theory-of-operations.md#test-scenarios) and [End-to-end tests](#end-to-end-tests) below.

## Project Structure

- `agent/` — Sensor bus: sensors, health checks, registry, observability, transport
- `server/` — Central server: ingestion, policy engine, store, connectors, API
- `dashboard/` — React + TypeScript web UI
- `cmd/` — Binary entry points (hookmon-bus, hookmon-agent, hookmon-server, hookmon-cli, hookmon-collector)
- `proto/` — Protobuf definitions; `gen/` holds the generated code
- `pkg/` — Shared packages (event types, crypto, version)
- `test/e2e/` and `test/canary/` — End-to-end tests and the programs they run
- `test/smoketest/` — Pre-push smoketests
- `test/transport/` — Wire and transport tests
- `test/integration/` — The real server against PostgreSQL (needs `HOOKMON_TEST_PG_DSN`)
- `test/ci/` — Scripts the CI jobs run
- `docs/` — Architecture, deployment, theory of operations, threat model and the claims ledger

## Testing

The smoketests need no root and load no eBPF programs. They run on macOS and Linux. On Linux, `make smoketest` builds the eBPF objects first (see above). They check:

- Anti-tampering: sensor registry transitions (alive, dead, degraded, revival)
- Sensor constructors: all 8 sensors construct with the right name and type
- Bus integration: live HTTP `/status` and `/metrics` endpoints with real Prometheus metrics

```bash
make smoketest

# Install the pre-push hook. It runs `go test ./test/smoketest/...` directly,
# so on Linux run `make bpf` once first.
cp scripts/pre-push .git/hooks/pre-push && chmod +x .git/hooks/pre-push
```

### PostgreSQL tests

The store tests (`server/store`), the API tests over the real store (`server/api`) and the server integration tests (`test/integration`) need a PostgreSQL they can create schemas in. Without `HOOKMON_TEST_PG_DSN` they skip. Each test creates its own schema and drops it afterwards, so packages running in parallel can share one database.

```bash
docker run -d --name hookmon-test-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:55432:5432 \
  --tmpfs /var/lib/postgresql/data \
  postgres:16.15-alpine3.24@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
export HOOKMON_TEST_PG_DSN='postgres://postgres:pw@127.0.0.1:55432/postgres?sslmode=disable'
go test -race -count=1 ./...
docker rm -f hookmon-test-pg
```

### End-to-end tests

`make test-e2e` builds the bus, the eBPF objects and the canaries, and runs `test/e2e` as root. Most tests run the bus with `--console`. Tests that need more skip without it; the env vars are listed in [docs/theory-of-operations.md](docs/theory-of-operations.md#test-scenarios).

`make test-e2e-full` runs `TestFullPath_*`, the server path end to end. A BPF canary goes through a root bus (not console mode), enrollment, gRPC, `hookmon-server`, PostgreSQL, the policy engine, a webhook connector and the WebSocket feed. The test checks the event at each hop by ID. The target starts PostgreSQL in a container, builds the server, runs the test, and removes the container. It needs Docker and passwordless sudo. `E2E_FULL_RUN=.` runs the whole e2e suite against that stack instead, the SIEM test included.

Both targets pass `HOOKMON_STATUS_PORT` (and the other `HOOKMON_E2E_*` settings) through sudo when they are set. Use a status port other than 2112 on a host that runs its own bus.

### CI

`.github/workflows/ci.yml` runs on every push and pull request to `main`:

- **Go Build & Test.** Runs `make build-all`, `go vet`, and `go test -race ./...` with a PostgreSQL service, so the store, API and integration tests run. A step first checks that a PostgreSQL test passes rather than skips. Then `make smoketest`.
- **Dashboard Typecheck & Build.**
- **Compose appliance.** Runs `hookmon-init.sh`, `docker compose up` and `check-stack.sh`.
- **Dashboard e2e (appliance + bus).** Runs after the appliance job. It builds `hookmon-bus` with its eBPF objects on the runner and brings up a fresh compose appliance. `test/ci/appliance-bus.sh` turns fleet learning on and enrolls the bus as root. The script prints which sensors came alive and keeps live events flowing. The job then runs every Playwright test in `dashboard/e2e`.

### e2e in GitHub Actions

`.github/workflows/e2e.yml` runs `make test-e2e` and `make test-e2e-full` on a self-hosted runner with the labels `self-hosted`, `linux` and `hookmon-e2e`. It runs only when started from the Actions tab ("Run workflow"). No runner is registered for this repository by default, so until one is, a started run waits in the queue.

**Why fork pull requests cannot trigger it.** The workflow's only trigger is `workflow_dispatch`, and only users with write access to the repository can start that. It has no `push` or `pull_request` trigger. A fork's pull request therefore never runs on the runner, so it never gets root on the host, the host's network, or anything else there. Keep it that way. Never add a `pull_request` or `pull_request_target` trigger to a workflow that runs on this runner. Also keep "Require approval for all outside collaborators" set under Settings → Actions → General.

**Choosing a host.** The suites load eBPF programs and run attacks as root: LD_PRELOAD injection, writes to `/etc/ld.so.preload`, ptrace, and package reinstalls. They also run Docker containers. Use a dedicated test machine or VM, not a workstation or a production host. It needs:

- Linux with a BTF kernel, 5.15 or newer (`/sys/kernel/btf/vmlinux`)
- clang, llvm-strip, bpftool that works on the running kernel, Docker, and `flock`
- passwordless sudo for the runner's user
- a few GB of free disk

The workflow installs Go itself and builds with `CC=clang`, so the host needs no gcc.

**Registering a runner.** This is the repository owner's decision. To do it:

1. On GitHub: Settings → Actions → Runners → New self-hosted runner, Linux x64. Register it on this repository only, not on an organization.
2. On the host, as the user the runner will run as, follow the download steps on that page. Then configure it with the extra label:
   ```bash
   ./config.sh --url https://github.com/dlenrow/hookmon --token <registration token> \
     --labels hookmon-e2e --name "$(hostname)-hookmon-e2e" --unattended
   sudo ./svc.sh install "$USER" && sudo ./svc.sh start
   ```
3. Optional repository variables (Settings → Secrets and variables → Actions → Variables):
   - `HOOKMON_E2E_STATUS_PORT` (default 2157): the test buses' `/status` port.
   - `HOOKMON_E2E_LOCK` (default `/tmp/hookmon-e2e.lock`): a file the workflow holds with `flock` while a suite runs. Set it to the lock other e2e users of the host take.

To remove the runner: `sudo ./svc.sh uninstall`, then `./config.sh remove --token <removal token>`.

## Code Style

- Go: standard `gofmt`, no additional linter configuration required
- TypeScript: project tsconfig, no separate prettier/eslint config
- eBPF C: kernel style (tabs, snake_case)
- Commit messages: imperative mood, concise summary line

## License

All contributions are under the [Apache 2.0 License](LICENSE).

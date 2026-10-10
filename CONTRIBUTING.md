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

`make ci` is close to CI but not the same: CI also runs `go test -race -count=1 ./...` and `make smoketest`, and builds the dashboard in a separate job (`.github/workflows/`).

The end-to-end tests (`make test-e2e`) need Linux, root and the eBPF toolchain. They load real eBPF programs and run real attacks. See [docs/theory-of-operations.md](docs/theory-of-operations.md#test-scenarios).

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

## Code Style

- Go: standard `gofmt`, no additional linter configuration required
- TypeScript: project tsconfig, no separate prettier/eslint config
- eBPF C: kernel style (tabs, snake_case)
- Commit messages: imperative mood, concise summary line

## License

All contributions are under the [Apache 2.0 License](LICENSE).

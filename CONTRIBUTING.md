# Contributing

## Read MAINTAINERS.md First

HookMon is a reference implementation, not an actively maintained project. There is no commitment to review pull requests, triage issues, or merge contributions. See [MAINTAINERS.md](MAINTAINERS.md) for the full explanation.

The most productive path for significant changes is to **fork the repo** and develop independently. If your fork gains traction, the conversation about upstream recognition is welcome.

## Building from Source

Prerequisites:
- Go 1.22+
- Node.js 20+ (dashboard only)
- clang/llvm (eBPF C compilation, Linux only)

```bash
# Build all Go binaries
make build-all

# Run unit tests
make test-unit

# Run smoketests (anti-tampering, sensor constructors, bus integration)
make smoketest

# Build dashboard
make build-dashboard

# Full CI-equivalent check
make ci
```

## Project Structure

- `agent/` — Sensor bus: sensors, registry, observability, transport
- `server/` — Central server: ingestion, policy engine, store, connectors, API
- `dashboard/` — React + TypeScript web UI
- `cmd/` — Binary entry points (hookmon-bus, hookmon-server, hookmon-cli, hookmon-collector)
- `proto/` — Protobuf definitions
- `pkg/` — Shared packages (event types, crypto, version)
- `test/smoketest/` — Pre-push smoketests
- `docs/` — Architecture, deployment, and theory-of-operations documentation

## Testing

The smoketest suite runs on macOS and Linux without privileges (no eBPF required). It validates:

- Anti-tampering: sensor heartbeat registry transitions (alive → dead → degraded → revival)
- Sensor constructors: all 8 sensors instantiate correctly with proper name/type
- Bus integration: live HTTP /status and /metrics endpoints with real Prometheus metrics

```bash
# Run smoketests (also runs automatically on git push via pre-push hook)
make smoketest

# Install the pre-push hook
cp scripts/pre-push .git/hooks/pre-push
```

## Code Style

- Go: standard `gofmt`, no additional linter configuration required
- TypeScript: project tsconfig, no separate prettier/eslint config
- eBPF C: kernel style (tabs, snake_case)
- Commit messages: imperative mood, concise summary line

## License

All contributions are under the [Apache 2.0 License](LICENSE).

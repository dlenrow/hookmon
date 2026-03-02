#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Generating protobuf code..."
if command -v buf &>/dev/null; then
    cd "$REPO_ROOT/proto" && buf generate
else
    echo "WARN: buf not installed, skipping protobuf generation"
    echo "      Install: https://buf.build/docs/installation"
fi

echo "==> Generating eBPF code..."
if [[ "$(uname)" == "Linux" ]]; then
    if command -v bpf2go &>/dev/null || go tool -n bpf2go &>/dev/null 2>&1; then
        cd "$REPO_ROOT/agent/sensors"
        go generate ./...
    else
        echo "WARN: bpf2go not available, skipping eBPF generation"
        echo "      Install: go install github.com/cilium/ebpf/cmd/bpf2go@latest"
    fi
else
    echo "SKIP: eBPF generation only runs on Linux"
fi

echo "==> Done."

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
    make -C "$REPO_ROOT" bpf
else
    echo "SKIP: eBPF generation only runs on Linux"
fi

echo "==> Done."

#!/usr/bin/env bash
set -euo pipefail

echo "==> HookMon Development Environment Setup"

# Check Go
if command -v go &>/dev/null; then
    echo "  Go: $(go version)"
else
    echo "  ERROR: Go not found. Install Go 1.22+ from https://go.dev"
    exit 1
fi

# Check Node
if command -v node &>/dev/null; then
    echo "  Node: $(node --version)"
else
    echo "  WARN: Node.js not found. Required for dashboard build."
fi

# Install Go tools
echo "==> Installing Go tools..."
go install github.com/cilium/ebpf/cmd/bpf2go@latest 2>/dev/null || echo "  WARN: bpf2go install failed (requires Linux for eBPF)"

# Download Go dependencies
echo "==> Downloading Go modules..."
go mod download

# Dashboard dependencies
if [ -f dashboard/package.json ] && command -v npm &>/dev/null; then
    echo "==> Installing dashboard dependencies..."
    cd dashboard && npm install
fi

echo "==> Dev setup complete."

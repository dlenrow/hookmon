#!/bin/bash
# Build hookmon-agent natively on a Linux host.
# Compiles eBPF C programs to .o, then builds Go binary with embedded bytecode.
#
# Prerequisites: clang, llvm-strip, libbpf-dev, bpftool, Go 1.22+
# Usage: sudo bash scripts/build-on-linux.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SENSORS_DIR="$PROJECT_DIR/agent/sensors"

export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"

echo "=== Compiling eBPF C programs ==="
make -C "$PROJECT_DIR" bpf

echo "=== Building hookmon-agent ==="
cd "$PROJECT_DIR"
mkdir -p bin
CGO_ENABLED=0 go build \
    -ldflags "-X github.com/dlenrow/hookmon/pkg/version.Version=dev-$(date +%Y%m%d)" \
    -o bin/hookmon-agent \
    ./cmd/hookmon-agent

echo "=== Building canary loader ==="
CGO_ENABLED=0 go build -o bin/load-canary ./test/canary/load_canary.go

echo "=== Compiling canary eBPF programs ==="
ARCH=$(uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CANARY_DIR="$PROJECT_DIR/test/canary"
if [ ! -f "$CANARY_DIR/vmlinux.h" ]; then
    cp "$SENSORS_DIR/vmlinux.h" "$CANARY_DIR/vmlinux.h"
fi
for cfile in hello_bpf.c net_monitor.c hello_bpf_v2.c; do
    ofile="${cfile%.c}.o"
    echo "  $cfile -> $ofile"
    clang -g -O2 -target bpf -D__TARGET_ARCH_${ARCH} \
        -I"$CANARY_DIR" -c "$CANARY_DIR/$cfile" -o "$CANARY_DIR/$ofile"
    llvm-strip -g "$CANARY_DIR/$ofile"
done

echo ""
echo "=== Build complete ==="
ls -lh bin/hookmon-agent bin/load-canary
echo ""
echo "Run: sudo bin/hookmon-agent --console"

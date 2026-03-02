#!/usr/bin/env bash
# Build hookmon-agent and canary test programs for Linux amd64.
# Uses Docker to cross-compile with proper kernel headers and clang.
#
# Usage: ./scripts/build-linux.sh
# Output: bin/hookmon-agent-linux-amd64
#         bin/load-canary-linux-amd64
#         bin/canary/*.o  (compiled eBPF programs)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$PROJECT_DIR/bin"

mkdir -p "$OUTPUT_DIR/canary"

# Build everything inside a Linux container
docker run --rm \
    -v "$PROJECT_DIR":/src \
    -w /src \
    -e GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}" \
    golang:1.22-bookworm \
    bash -c '
set -euo pipefail

echo "=== Installing build dependencies ==="
apt-get update -qq && apt-get install -y -qq \
    clang llvm libbpf-dev linux-headers-generic \
    bpftool 2>/dev/null || true

# If bpftool is not available, try common paths
BPFTOOL=$(which bpftool 2>/dev/null || echo /usr/sbin/bpftool)
if [ ! -x "$BPFTOOL" ]; then
    echo "WARNING: bpftool not found, generating minimal vmlinux.h stub"
fi

echo "=== Generating vmlinux.h for canary programs ==="
cd /src/test/canary
if [ -x "$BPFTOOL" ] && [ -f /sys/kernel/btf/vmlinux ]; then
    $BPFTOOL btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
else
    echo "No kernel BTF available (running in container). Using bpf2go approach instead."
fi

echo "=== Compiling canary eBPF programs ==="
ARCH=$(uname -m | sed "s/x86_64/x86/" | sed "s/aarch64/arm64/")
for prog in hello_bpf.c net_monitor.c hello_bpf_v2.c; do
    out="${prog%.c}.o"
    echo "  Compiling $prog -> $out"
    clang -g -O2 -target bpf -D__TARGET_ARCH_${ARCH} \
        -I. -c "$prog" -o "$out" 2>&1 || echo "  WARNING: $prog failed to compile (vmlinux.h may be missing)"
    if [ -f "$out" ]; then
        llvm-strip -g "$out" 2>/dev/null || true
    fi
done
cp -f *.o /src/bin/canary/ 2>/dev/null || true

echo "=== Building canary loader ==="
cd /src/test/canary
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /src/bin/load-canary-linux-amd64 load_canary.go

echo "=== Generating eBPF bytecode for agent sensors ==="
cd /src
# Install bpf2go
go install github.com/cilium/ebpf/cmd/bpf2go@latest 2>/dev/null || true

# For now, build the agent without embedded eBPF bytecode
# (sensors will fail to start but the binary will run in console mode)
echo "=== Building hookmon-agent ==="
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-X github.com/dlenrow/hookmon/pkg/version.Version=dev-$(date +%Y%m%d)" \
    -o /src/bin/hookmon-agent-linux-amd64 \
    ./cmd/hookmon-agent

echo "=== Build complete ==="
ls -la /src/bin/
ls -la /src/bin/canary/ 2>/dev/null || true
'

echo ""
echo "Build artifacts:"
ls -la "$OUTPUT_DIR/hookmon-agent-linux-amd64" 2>/dev/null && echo "  Agent: $OUTPUT_DIR/hookmon-agent-linux-amd64"
ls -la "$OUTPUT_DIR/load-canary-linux-amd64" 2>/dev/null && echo "  Canary loader: $OUTPUT_DIR/load-canary-linux-amd64"
ls "$OUTPUT_DIR/canary/"*.o 2>/dev/null && echo "  Canary BPF programs: $OUTPUT_DIR/canary/"
echo ""
echo "Deploy to target host:"
echo '  scp bin/hookmon-agent-linux-amd64 drl@drl-nuc8i3bek:/tmp/hookmon-agent'
echo '  scp bin/load-canary-linux-amd64 bin/canary/*.o drl@drl-nuc8i3bek:/tmp/'
echo '  ssh drl@drl-nuc8i3bek "sudo /tmp/hookmon-agent --console"'

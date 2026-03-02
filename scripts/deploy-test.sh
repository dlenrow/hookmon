#!/usr/bin/env bash
# Deploy hookmon-agent and canary programs to a test host via SSH.
#
# Usage: ./scripts/deploy-test.sh [hostname]
# Default hostname: drl-nuc8i3bek
set -euo pipefail

HOST="${1:-drl-nuc8i3bek}"
USER="${HOOKMON_USER:-drl}"
BIN_DIR="$(cd "$(dirname "$0")/../bin" && pwd)"

echo "=== Deploying to $USER@$HOST ==="

# Check binaries exist
for f in hookmon-agent-linux-amd64 load-canary-linux-amd64; do
    if [ ! -f "$BIN_DIR/$f" ]; then
        echo "ERROR: $BIN_DIR/$f not found. Run scripts/build-linux.sh first."
        exit 1
    fi
done

echo "Copying agent and canary programs..."
scp "$BIN_DIR/hookmon-agent-linux-amd64" "$USER@$HOST:/tmp/hookmon-agent"
scp "$BIN_DIR/load-canary-linux-amd64" "$USER@$HOST:/tmp/load-canary"
scp "$BIN_DIR/canary/"*.o "$USER@$HOST:/tmp/" 2>/dev/null || echo "  (no compiled canary .o files found)"

echo ""
echo "=== Deployment complete ==="
echo ""
echo "On $HOST, run:"
echo ""
echo "  # Terminal 1: Start agent in console mode"
echo "  sudo /tmp/hookmon-agent --console"
echo ""
echo "  # Terminal 2: Load canary programs (one at a time)"
echo "  sudo /tmp/load-canary /tmp/hello_bpf.o syscalls sys_enter_getpid hello_count"
echo "  sudo /tmp/load-canary /tmp/net_monitor.o syscalls sys_enter_connect net_count"
echo "  sudo /tmp/load-canary /tmp/hello_bpf_v2.o syscalls sys_enter_getpid hello_count_v2"
echo ""
echo "The agent should print a JSON event for each BPF program loaded."

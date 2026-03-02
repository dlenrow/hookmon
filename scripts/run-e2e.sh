#!/usr/bin/env bash
# Run hookmon end-to-end tests on a Linux host.
#
# This script can run either locally on a Linux host or remotely via SSH.
#
# Usage:
#   Local:  sudo ./scripts/run-e2e.sh
#   Remote: ./scripts/run-e2e.sh --host drl-nuc8i3bek
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

HOST=""
USER="${HOOKMON_USER:-drl}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

if [ -n "$HOST" ]; then
    echo "=== Running e2e tests remotely on $HOST ==="

    # Ensure binaries are deployed
    echo "Step 1: Deploy binaries"
    "$SCRIPT_DIR/deploy-test.sh" "$HOST"

    # Copy test source and run on remote host
    echo "Step 2: Copy test files"
    ssh "$USER@$HOST" "mkdir -p /tmp/hookmon-test/test/e2e /tmp/hookmon-test/pkg"
    scp -r "$PROJECT_DIR/test/e2e/" "$USER@$HOST:/tmp/hookmon-test/test/e2e/"
    scp -r "$PROJECT_DIR/pkg/" "$USER@$HOST:/tmp/hookmon-test/pkg/"
    scp "$PROJECT_DIR/go.mod" "$PROJECT_DIR/go.sum" "$USER@$HOST:/tmp/hookmon-test/"

    echo "Step 3: Run tests"
    ssh -t "$USER@$HOST" "cd /tmp/hookmon-test && sudo go test -v -timeout 120s ./test/e2e/ -count=1"
else
    echo "=== Running e2e tests locally ==="

    if [ "$(id -u)" -ne 0 ]; then
        echo "ERROR: Must run as root (sudo) for eBPF operations"
        exit 1
    fi

    cd "$PROJECT_DIR"
    go test -v -timeout 120s ./test/e2e/ -count=1
fi

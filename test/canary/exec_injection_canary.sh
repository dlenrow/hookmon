#!/bin/bash
# exec_injection_canary.sh — Canary for testing exec injection sensor detection.
#
# Launches a target binary with LD_PRELOAD set, triggering the
# exec_injection eBPF sensor independently of the bpftime simulator.
#
# Usage: ./exec_injection_canary.sh <path-to-so> [target-binary]
#   e.g. ./exec_injection_canary.sh /tmp/libfake_hook.so /bin/true

set -e

if [ -z "$1" ]; then
    echo "usage: $0 <path-to-so> [target-binary]"
    exit 1
fi

LIB_PATH="$1"
TARGET="${2:-/bin/true}"

echo "[exec_injection_canary] LD_PRELOAD=$LIB_PATH $TARGET"
LD_PRELOAD="$LIB_PATH" "$TARGET"

# Brief pause to let sensor process
sleep 1

echo "[exec_injection_canary] done"

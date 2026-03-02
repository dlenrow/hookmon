#!/bin/bash
# Smoke test: run on the target Linux host
# Usage: sudo bash smoke-test.sh
set -e

AGENT=/tmp/hookmon-agent
LOADER=/tmp/load-canary
OUTLOG=/tmp/hookmon-output.log
ERRLOG=/tmp/hookmon-error.log

echo "=== Killing any existing agent ==="
pkill -f hookmon-agent 2>/dev/null || true
sleep 1

echo "=== Starting agent in console mode ==="
rm -f "$OUTLOG" "$ERRLOG"
$AGENT --console > "$OUTLOG" 2> "$ERRLOG" &
AGENT_PID=$!
echo "Agent PID: $AGENT_PID"
sleep 3

echo "=== Loading canary: hello_bpf ==="
$LOADER /tmp/hello_bpf.o syscalls sys_enter_getpid hello_count || true
sleep 2

echo "=== Loading canary: net_monitor ==="
$LOADER /tmp/net_monitor.o syscalls sys_enter_connect net_count || true
sleep 2

echo "=== Loading canary: hello_bpf_v2 ==="
$LOADER /tmp/hello_bpf_v2.o syscalls sys_enter_getpid hello_count_v2 || true
sleep 2

echo "=== Stopping agent ==="
kill $AGENT_PID 2>/dev/null || true
wait $AGENT_PID 2>/dev/null || true

echo ""
echo "=== AGENT STDERR ==="
cat "$ERRLOG" 2>/dev/null || echo "(empty)"
echo ""
echo "=== AGENT STDOUT (detected events) ==="
cat "$OUTLOG" 2>/dev/null || echo "(empty)"

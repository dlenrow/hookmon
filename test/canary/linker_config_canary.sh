#!/bin/bash
# linker_config_canary.sh — Canary for testing linker config sensor detection.
#
# Creates a temporary file in /etc/ld.so.conf.d/ to trigger the
# linker_config fanotify sensor, then immediately cleans it up.
#
# Must run as root.
#
# Usage: sudo ./linker_config_canary.sh

set -e

CANARY_FILE="/etc/ld.so.conf.d/hookmon-canary-test.conf"

echo "[linker_config_canary] writing canary file: $CANARY_FILE"
echo "# hookmon canary test — this file should be deleted immediately" > "$CANARY_FILE"

# Brief pause to let fanotify sensor detect the write
sleep 1

echo "[linker_config_canary] removing canary file"
rm -f "$CANARY_FILE"

echo "[linker_config_canary] done"

#!/bin/bash
# lib_integrity_canary.sh — Canary for testing library integrity sensor detection.
#
# Copies a dummy .so file into /usr/lib/ to trigger the lib_integrity
# fanotify sensor, then immediately cleans it up.
#
# Must run as root.
#
# Usage: sudo ./lib_integrity_canary.sh <path-to-libfake_hook.so>

set -e

if [ -z "$1" ]; then
    echo "usage: $0 <path-to-libfake_hook.so>"
    exit 1
fi

SRC_LIB="$1"
DEST_LIB="/usr/lib/libhookmon_canary_test.so"

if [ ! -f "$SRC_LIB" ]; then
    echo "[lib_integrity_canary] error: source library not found: $SRC_LIB"
    exit 1
fi

echo "[lib_integrity_canary] copying $SRC_LIB to $DEST_LIB"
cp "$SRC_LIB" "$DEST_LIB"

# Brief pause to let fanotify sensor detect the write
sleep 1

echo "[lib_integrity_canary] removing canary library"
rm -f "$DEST_LIB"

echo "[lib_integrity_canary] done"

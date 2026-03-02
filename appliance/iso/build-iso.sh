#!/bin/bash
set -euo pipefail

echo "==> Building HookMon appliance ISO..."

VERSION="${VERSION:-dev}"
OUTPUT_DIR="output"
ISO_NAME="hookmon-${VERSION}.iso"

mkdir -p "$OUTPUT_DIR"

echo "NOTE: This script requires genisoimage and the Ubuntu Server ISO."
echo "For production use, integrate with Packer (see hookmon.pkr.hcl)"
echo ""
echo "To build manually:"
echo "  1. Download Ubuntu Server 24.04 ISO"
echo "  2. Run: packer build -var 'hookmon_version=${VERSION}' hookmon.pkr.hcl"
echo ""
echo "ISO build is managed via Packer for reproducibility."

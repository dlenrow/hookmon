#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
ARCH="${ARCH:-amd64}"

cd "$REPO_ROOT"

echo "==> Building hookmon-server v${VERSION} for linux/${ARCH}..."
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build \
    -ldflags "-X github.com/dlenrow/hookmon/pkg/version.Version=${VERSION}" \
    -o "bin/hookmon-server-linux-${ARCH}" \
    ./cmd/hookmon-server

echo "==> Binary: bin/hookmon-server-linux-${ARCH}"

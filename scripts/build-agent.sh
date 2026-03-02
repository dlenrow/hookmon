#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
ARCH="${ARCH:-amd64}"

cd "$REPO_ROOT"

echo "==> Building hookmon-agent v${VERSION} for linux/${ARCH}..."
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build \
    -ldflags "-X github.com/dlenrow/hookmon/pkg/version.Version=${VERSION}" \
    -o "bin/hookmon-agent-linux-${ARCH}" \
    ./cmd/hookmon-agent

FORMAT="${1:-}"
case "$FORMAT" in
    deb)
        echo "==> Building .deb package..."
        mkdir -p "build/deb/usr/bin"
        cp "bin/hookmon-agent-linux-${ARCH}" "build/deb/usr/bin/hookmon-agent"
        chmod 755 "build/deb/usr/bin/hookmon-agent"
        mkdir -p "build/deb/DEBIAN"
        cp deploy/deb/control "build/deb/DEBIAN/control"
        sed -i "s/VERSION_PLACEHOLDER/${VERSION}/g" "build/deb/DEBIAN/control"
        dpkg-deb --build "build/deb" "bin/hookmon-agent_${VERSION}_${ARCH}.deb"
        echo "==> Package: bin/hookmon-agent_${VERSION}_${ARCH}.deb"
        ;;
    rpm)
        echo "==> Building .rpm package..."
        rpmbuild -bb deploy/rpm/hookmon-agent.spec \
            --define "version ${VERSION}" \
            --define "_topdir ${REPO_ROOT}/build/rpm"
        ;;
    "")
        echo "==> Binary: bin/hookmon-agent-linux-${ARCH}"
        ;;
    *)
        echo "Unknown format: $FORMAT (use deb or rpm)"
        exit 1
        ;;
esac

#!/usr/bin/env bash
# Builds the hookmon-bus binary and, optionally, its DEB or RPM package.
#
#   scripts/build-agent.sh        bin/hookmon-bus (static, linux/$ARCH)
#   scripts/build-agent.sh deb    ... and bin/hookmon-bus_<version>_<arch>.deb (dpkg-deb)
#   scripts/build-agent.sh rpm    ... and bin/hookmon-bus-<version>-1.<arch>.rpm (rpmbuild)
#
# The bus embeds the eBPF objects, and the packages ship the dlopen helper,
# so build those first: make bpf build-dlopen-probe. "make package-deb" and
# "make package-rpm" do that and then run this script.
#
# The eBPF objects are built for the build host's architecture, so ARCH
# defaults to it. PREBUILT=1 skips the Go build and packages the binaries
# already in bin/ (BUS_BIN, PROBE_BIN), for example on an RPM build host
# without the eBPF toolchain. PKG_VERSION overrides the package version,
# which is otherwise derived from VERSION (git describe).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
DATE="${DATE:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
BUS_BIN="${BUS_BIN:-bin/hookmon-bus}"
PROBE_BIN="${PROBE_BIN:-bin/hookmon-dlopen-probe}"

if [ -z "${ARCH:-}" ]; then
    case "$(uname -m)" in
        x86_64) ARCH=amd64 ;;
        aarch64 | arm64) ARCH=arm64 ;;
        *) echo "unsupported architecture $(uname -m); set ARCH" >&2; exit 1 ;;
    esac
fi
case "$ARCH" in
    amd64) RPM_ARCH=x86_64 ;;
    arm64) RPM_ARCH=aarch64 ;;
    *) echo "unsupported ARCH $ARCH (amd64 or arm64)" >&2; exit 1 ;;
esac

# Package versions must start with a digit, and RPM versions cannot contain
# "-": v1.2.3 -> 1.2.3, v1.2.3-4-gabc -> 1.2.3+4.gabc, abc123-dirty ->
# 0.0.0+git.abc123.dirty.
if [ -z "${PKG_VERSION:-}" ]; then
    v="${VERSION#v}"
    if [[ "$v" =~ ^([0-9]+(\.[0-9]+)*)(-(.*))?$ ]]; then
        PKG_VERSION="${BASH_REMATCH[1]}"
        if [ -n "${BASH_REMATCH[4]}" ]; then
            PKG_VERSION="${PKG_VERSION}+${BASH_REMATCH[4]//-/.}"
        fi
    else
        PKG_VERSION="0.0.0+git.${v//-/.}"
    fi
fi
if ! [[ "$PKG_VERSION" =~ ^[0-9][A-Za-z0-9.+~]*$ ]]; then
    echo "package version '$PKG_VERSION' is not usable; set PKG_VERSION" >&2
    exit 1
fi

if [ "${PREBUILT:-0}" != 1 ]; then
    if ! ls agent/sensors/*.o >/dev/null 2>&1; then
        echo "no eBPF objects in agent/sensors; run make bpf first" >&2
        exit 1
    fi
    echo "==> Building hookmon-bus ${VERSION} for linux/${ARCH}..."
    mkdir -p "$(dirname "$BUS_BIN")"
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build \
        -ldflags "-X github.com/dlenrow/hookmon/pkg/version.Version=${VERSION} \
            -X github.com/dlenrow/hookmon/pkg/version.Commit=${COMMIT} \
            -X github.com/dlenrow/hookmon/pkg/version.Date=${DATE}" \
        -o "$BUS_BIN" ./cmd/hookmon-bus
fi

FORMAT="${1:-}"
if [ -n "$FORMAT" ]; then
    for f in "$BUS_BIN" "$PROBE_BIN"; do
        if [ ! -x "$f" ]; then
            echo "$f is missing; build it first (make build-dlopen-probe for the helper)" >&2
            exit 1
        fi
    done
fi

case "$FORMAT" in
    deb)
        echo "==> Building hookmon-bus ${PKG_VERSION} .deb..."
        root="bin/pkgbuild/deb/hookmon-bus"
        rm -rf bin/pkgbuild/deb
        install -d "$root/DEBIAN"
        install -D -m 0755 "$BUS_BIN" "$root/usr/bin/hookmon-bus"
        install -D -m 0755 "$PROBE_BIN" "$root/usr/bin/hookmon-dlopen-probe"
        install -D -m 0644 deploy/systemd/hookmon-bus.service "$root/lib/systemd/system/hookmon-bus.service"
        install -D -m 0644 deploy/systemd/bus.yaml "$root/etc/hookmon/bus.yaml"
        install -D -m 0644 LICENSE "$root/usr/share/doc/hookmon-bus/copyright"
        install -m 0644 deploy/deb/conffiles "$root/DEBIAN/conffiles"
        install -m 0755 deploy/deb/postinst deploy/deb/prerm deploy/deb/postrm "$root/DEBIAN/"
        size="$(du -sk --exclude=DEBIAN "$root" | cut -f1)"
        # The dlopen helper links against the build host's glibc; require
        # at least the newest symbol version it uses.
        depends="libc6"
        if command -v objdump >/dev/null 2>&1; then
            glibc="$(objdump -T "$PROBE_BIN" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -1)"
            if [ -n "$glibc" ]; then
                depends="libc6 (>= ${glibc})"
            fi
        fi
        sed -e "s/VERSION_PLACEHOLDER/${PKG_VERSION}/" \
            -e "s/ARCH_PLACEHOLDER/${ARCH}/" \
            -e "s/SIZE_PLACEHOLDER/${size}/" \
            -e "s/DEPENDS_PLACEHOLDER/${depends}/" \
            deploy/deb/control > "$root/DEBIAN/control"
        (cd "$root" && find . -path ./DEBIAN -prune -o -type f -printf '%P\0' | sort -z | xargs -0 md5sum) \
            > "$root/DEBIAN/md5sums"
        out="bin/hookmon-bus_${PKG_VERSION}_${ARCH}.deb"
        dpkg-deb --root-owner-group --build "$root" "$out"
        echo "==> Package: $out"
        ;;
    rpm)
        echo "==> Building hookmon-bus ${PKG_VERSION} .rpm..."
        top="$REPO_ROOT/bin/pkgbuild/rpm"
        src="hookmon-bus-${PKG_VERSION}"
        rm -rf "$top"
        mkdir -p "$top"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,stage/"$src"}
        install -m 0755 "$BUS_BIN" "$top/stage/$src/hookmon-bus"
        install -m 0755 "$PROBE_BIN" "$top/stage/$src/hookmon-dlopen-probe"
        install -m 0644 deploy/systemd/hookmon-bus.service deploy/systemd/bus.yaml LICENSE "$top/stage/$src/"
        tar -C "$top/stage" --owner=0 --group=0 -czf "$top/SOURCES/$src.tar.gz" "$src"
        rpmbuild -bb deploy/rpm/hookmon-bus.spec \
            --target "$RPM_ARCH" \
            --define "_topdir $top" \
            --define "pkg_version ${PKG_VERSION}"
        mkdir -p bin
        cp "$top"/RPMS/"$RPM_ARCH"/hookmon-bus-*.rpm bin/
        echo "==> Package: $(ls bin/hookmon-bus-*.rpm)"
        ;;
    "")
        echo "==> Binary: $BUS_BIN"
        ;;
    *)
        echo "Unknown format: $FORMAT (use deb or rpm)" >&2
        exit 1
        ;;
esac

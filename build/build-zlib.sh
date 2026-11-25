#!/bin/sh
# Build a patched zlib1g .deb from Debian's own source package, with the
# backport in build/patches/zlib/ applied (CVE-2026-27171). Called by build.sh,
# inside the same clean debian:bookworm-20240513-slim builder.
#
# The package keeps Debian's version string on purpose: I do not fake a higher
# version. Scanners therefore still flag the CVE, and vex.json says it is fixed.
set -eu

ZLIB_DEB_VERSION="1:1.2.13.dfsg-1"   # what the baseline image has installed
ZLIB_SRC_DIR="zlib-1.2.13.dfsg"

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-/work}"
OUT="${OUT:-/out}"

echo "==> zlib: Debian source ${ZLIB_DEB_VERSION} plus build/patches/zlib"
mkdir -p "$WORK/zlib" "$OUT"

# apt source needs a deb-src line; same 2024-05-13 snapshot as everything else.
grep -q '^deb-src' /etc/apt/sources.list 2>/dev/null || \
  echo 'deb-src [check-valid-until=no] http://snapshot.debian.org/archive/debian/20240513T000000Z bookworm main' \
    >> /etc/apt/sources.list
apt-get update -qq > "$WORK/zlib-apt.log" 2>&1
apt-get install -y --no-install-recommends dpkg-dev fakeroot >> "$WORK/zlib-apt.log" 2>&1
apt-get build-dep -y "zlib=${ZLIB_DEB_VERSION}" >> "$WORK/zlib-apt.log" 2>&1

cd "$WORK/zlib"
apt-get source "zlib=${ZLIB_DEB_VERSION}" > "$WORK/zlib-source.log" 2>&1
cd "$ZLIB_SRC_DIR"

echo "==> zlib: apply patches (no fuzz)"
for p in "$HERE"/patches/zlib/*.patch; do
    echo "    $(basename "$p")"
    patch -p1 --fuzz=0 --no-backup-if-mismatch < "$p"
done

echo "==> zlib: build zlib1g .deb with dpkg-buildpackage"
dpkg-buildpackage -b -uc -us > "$WORK/zlib-build.log" 2>&1
cp ../zlib1g_*_amd64.deb "$OUT/"
ls -l "$OUT"/zlib1g_*_amd64.deb

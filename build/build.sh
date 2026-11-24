#!/bin/sh
# Build nginx from upstream source, apply CVE backports, and package a .deb.
# Runs inside build/Dockerfile (clean debian:bookworm-20240513-slim, apt on the
# 2024-05-13 snapshot). Inputs are pinned: tarball SHA-256, patches, base image.
set -eu

NGINX_VERSION="1.25.5"
REVISION="1~echo1"
# The bump: runtime must provide at least this libssl3 (see D12/D20).
LIBSSL3_MIN="3.0.22-1~deb12u2"

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK=/work
PKGROOT=/pkgroot
OUT=/out
TARBALL="nginx-${NGINX_VERSION}.tar.gz"

mkdir -p "$WORK" "$OUT"
cd "$WORK"

echo "==> fetch and verify source"
curl -fsSLO "https://nginx.org/download/${TARBALL}"
EXPECTED="$(cut -d' ' -f1 "$HERE/nginx.sha256")"
echo "${EXPECTED}  ${TARBALL}" | sha256sum -c -
tar xzf "$TARBALL"
cd "nginx-${NGINX_VERSION}"

echo "==> apply patches (no fuzz, in name order)"
for p in "$HERE"/patches/*.patch; do
    echo "    $(basename "$p")"
    patch -p1 --fuzz=0 --no-backup-if-mismatch < "$p"
done

echo "==> configure (flags copied from nginx:1.25-bookworm, docs/baseline-facts.txt)"
./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --user=nginx --group=nginx \
    --with-compat --with-file-aio --with-threads \
    --with-http_addition_module --with-http_auth_request_module \
    --with-http_dav_module --with-http_flv_module \
    --with-http_gunzip_module --with-http_gzip_static_module \
    --with-http_mp4_module --with-http_random_index_module \
    --with-http_realip_module --with-http_secure_link_module \
    --with-http_slice_module --with-http_ssl_module \
    --with-http_stub_status_module --with-http_sub_module \
    --with-http_v2_module --with-http_v3_module \
    --with-mail --with-mail_ssl_module \
    --with-stream --with-stream_realip_module \
    --with-stream_ssl_module --with-stream_ssl_preread_module \
    --with-cc-opt="-g -O2 -ffile-prefix-map=${WORK}/nginx-${NGINX_VERSION}=. -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC" \
    --with-ld-opt="-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie" \
    > "$WORK/configure.log"

echo "==> compile"
make -j"$(nproc)" > "$WORK/make.log"

echo "==> stage into $PKGROOT"
make install DESTDIR="$PKGROOT" > "$WORK/install.log"
mkdir -p "$PKGROOT/var/cache/nginx" "$PKGROOT/var/log/nginx" \
         "$PKGROOT/usr/lib/nginx/modules" "$PKGROOT/DEBIAN"
# /var/run is a symlink to /run on bookworm; do not ship it as a directory.
rmdir "$PKGROOT/var/run" 2>/dev/null || true
# Official layout: replace upstream's "make install" config extras with the
# config files and welcome page shipped by the nginx:1.25-bookworm package
# (build/pkgfiles, md5-identical to its recorded conffiles), plus the modules link.
rm -rf "$PKGROOT/etc/nginx/html" "$PKGROOT"/etc/nginx/*.default \
       "$PKGROOT/etc/nginx/fastcgi.conf" "$PKGROOT/etc/nginx/koi-utf" \
       "$PKGROOT/etc/nginx/koi-win" "$PKGROOT/etc/nginx/win-utf"
cp -a "$HERE/pkgfiles/." "$PKGROOT/"
# Files copied from a Windows checkout can arrive executable; the baseline is 0644.
find "$PKGROOT/etc/nginx" "$PKGROOT/usr/share/nginx" -type f -exec chmod 0644 {} +
ln -s /usr/lib/nginx/modules "$PKGROOT/etc/nginx/modules"
# Register the config files as dpkg conffiles, like the official package does.
# docker-entrypoint.d/10-listen-on-ipv6-by-default.sh compares default.conf with
# the checksum dpkg recorded here; without this the IPv6 listen is never enabled.
cat > "$PKGROOT/DEBIAN/conffiles" <<EOF
/etc/nginx/conf.d/default.conf
/etc/nginx/fastcgi_params
/etc/nginx/mime.types
/etc/nginx/nginx.conf
/etc/nginx/scgi_params
/etc/nginx/uwsgi_params
EOF
# Drop debug symbols (the baseline binary is stripped too; keeps size honest).
strip --strip-unneeded "$PKGROOT/usr/sbin/nginx"

echo "==> dependencies from the real binary (dpkg-shlibdeps)"
mkdir -p "$WORK/debian" && : > "$WORK/debian/control"
cd "$WORK"
DEPENDS="$(dpkg-shlibdeps -O "$PKGROOT/usr/sbin/nginx" | sed 's/^shlibs:Depends=//')"
DEPENDS="$(printf '%s' "$DEPENDS" | sed "s/libssl3 ([^)]*)/libssl3 (>= ${LIBSSL3_MIN})/")"
echo "    Depends: $DEPENDS"

SIZE="$(du -sk --exclude=DEBIAN "$PKGROOT" | cut -f1)"
cat > "$PKGROOT/DEBIAN/control" <<EOF
Package: nginx
Version: ${NGINX_VERSION}-${REVISION}
Architecture: amd64
Maintainer: Echo Homework <noreply@example.invalid>
Installed-Size: ${SIZE}
Depends: ${DEPENDS}
Section: httpd
Priority: optional
Homepage: https://nginx.org/
Description: nginx ${NGINX_VERSION} built from upstream source with CVE backports
 nginx built from the upstream ${NGINX_VERSION} tarball with the official docker
 image configure flags, plus backports of the patches in build/patches.
 Requires libssl3 >= ${LIBSSL3_MIN} (the bump).
EOF

echo "==> build .deb"
dpkg-deb --root-owner-group -b "$PKGROOT" "$OUT/nginx_${NGINX_VERSION}-${REVISION}_amd64.deb"
ls -l "$OUT"

# Drop-in replacement for nginx:1.25-bookworm, built from source.
#   docker build -f Containerfile -t echo/nginx:1.25-patched .
# Stage 1 builds the .deb (build/build.sh: pinned tarball, CVE backports).
# Stage 2 installs it on the same Debian as the baseline (12.5) with libssl3 bumped.

ARG BASE=debian:bookworm-20240513-slim@sha256:804194b909ef23fb995d9412c9378fb3505fe2427b70f3cc425339e48a828fca

# ---------------------------------------------------------------- build stage
FROM ${BASE} AS builder
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' \
    'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20240513T000000Z bookworm main' \
    'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20240513T000000Z bookworm-security main' \
    > /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential libpcre2-dev zlib1g-dev libssl-dev ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY build/ /build/
RUN sh /build/build.sh

# -------------------------------------------------------------- runtime stage
FROM ${BASE}

# 1) Runtime tools the entrypoint scripts need, from the same 2024-05-13 snapshot
#    as the baseline (gettext-base provides envsubst).
RUN mv /etc/apt/sources.list.d/debian.sources /root/debian.sources.orig \
 && printf '%s\n' \
    'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20240513T000000Z bookworm main' \
    'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20240513T000000Z bookworm-security main' \
    > /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends gettext-base ca-certificates

# 2) nginx user/group 101 BEFORE the package, same as the official image.
RUN groupadd --system --gid 101 nginx \
 && useradd --system --uid 101 --gid 101 --no-create-home --home-dir /nonexistent \
        --shell /bin/false --comment "nginx user" nginx

# 3) THE BUMP: the .deb declares libssl3 (>= 3.0.22-1~deb12u2). That version only
#    exists in the newer security snapshot, so add it just for this step. apt only
#    installs what is missing (libssl3); nothing already installed is upgraded.
COPY --from=builder /out/nginx_*.deb /tmp/nginx.deb
RUN echo 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20261123T000000Z bookworm-security main' \
        >> /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends /tmp/nginx.deb \
 && rm -f /tmp/nginx.deb \
 # restore the stock apt config and clean up
 && rm -f /etc/apt/sources.list \
 && mv /root/debian.sources.orig /etc/apt/sources.list.d/debian.sources \
 && rm -rf /var/lib/apt/lists/*

# 3b) Backport: swap in zlib1g rebuilt from Debian's source with the CVE-2026-27171
#     patch. Same version string as the stock package, so dpkg reinstalls it in place.
COPY --from=builder /out/zlib1g_*_amd64.deb /tmp/zlib1g.deb
RUN dpkg -i /tmp/zlib1g.deb && rm -f /tmp/zlib1g.deb

# 4) Entrypoint and its scripts, vendored from the baseline image. (The config and
#    welcome page already come from the .deb, as conffiles, like the official one.)
RUN mkdir -p /docker-entrypoint.d
COPY --chmod=755 image/rootfs/docker-entrypoint.sh /docker-entrypoint.sh
COPY --chmod=755 image/rootfs/docker-entrypoint.d/ /docker-entrypoint.d/

# 5) Logs to stdout/stderr, as in the official image.
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
 && ln -sf /dev/stderr /var/log/nginx/error.log

ENV NGINX_VERSION=1.25.5 \
    PKG_RELEASE=1~echo1
EXPOSE 80
STOPSIGNAL SIGQUIT
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]

# Hermetic build of the nginx .deb. Build context is the build/ directory:
#   docker build -f build/Dockerfile --output type=local,dest=dist build
# Base and apt snapshot match the nginx:1.25-bookworm baseline (Debian 12.5).
FROM debian:bookworm-20240513-slim@sha256:804194b909ef23fb995d9412c9378fb3505fe2427b70f3cc425339e48a828fca AS builder

RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' \
    'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20240513T000000Z bookworm main' \
    'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20240513T000000Z bookworm-security main' \
    > /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential libpcre2-dev zlib1g-dev libssl-dev ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

COPY . /build
RUN sh /build/build.sh

FROM scratch AS out
COPY --from=builder /out/ /

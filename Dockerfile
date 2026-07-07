# ============================================================
# Example build: strongSwan + the QKD key-exchange plugin
#
# Builds a stock strongSwan release and links this repo's plugin
# against it. Useful as a starting point for your own image, or to
# sanity-check that the plugin builds cleanly.
#
# Build:
#   docker build -t strongswan-qkd .
#
# QKD_BACKEND selects the qkd-etsi-api backend compiled into
# libqkd-etsi-api:
#   simulated (default) — hardcoded test key, no KME required.
#   http                — talks to a real/mock ETSI GS QKD 014 KME
#                         over REST JSON (requires libcurl).
# ============================================================

ARG UBUNTU_VERSION=22.04
ARG STRONGSWAN_TAG=6.0.2
ARG QKD_BACKEND=simulated

FROM ubuntu:${UBUNTU_VERSION} AS builder

ARG STRONGSWAN_TAG
ARG QKD_BACKEND

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool pkg-config cmake ninja-build \
    git ca-certificates \
    libssl-dev libgmp-dev libsystemd-dev libcurl4-openssl-dev \
    uuid-dev gperf bison flex \
    && rm -rf /var/lib/apt/lists/*

# ── 1. qkd-etsi-api (ETSI GS QKD 014 client library) ────────────────────────
COPY qkd-etsi-api/ /src/qkd-etsi-api/
RUN cmake -S /src/qkd-etsi-api -B /src/qkd-etsi-api/build \
        -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DQKD_BACKEND="${QKD_BACKEND}" \
    && cmake --build /src/qkd-etsi-api/build -j"$(nproc)" \
    && cmake --install /src/qkd-etsi-api/build

# ── 2. strongSwan ────────────────────────────────────────────────────────────
RUN git clone --depth 1 --branch "${STRONGSWAN_TAG}" \
        https://github.com/strongswan/strongswan.git /src/strongswan

WORKDIR /src/strongswan
RUN autoreconf -fi \
    && ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --with-dev-headers=/usr/include/strongswan \
        --enable-swanctl \
        --enable-vici \
        --enable-openssl \
        --enable-curve25519 \
        --enable-kernel-netlink \
        --enable-socket-default \
    && make -j"$(nproc)" \
    && make install

# ── 3. QKD key-exchange plugin (out-of-tree) ────────────────────────────────
# The plugin Makefile.am includes strongSwan's generated config.h.
COPY Makefile.am configure.ac /src/qkd-plugin/
COPY src/ /src/qkd-plugin/src/
WORKDIR /src/qkd-plugin

RUN mkdir -p /usr/lib/ipsec/include \
    && cp /src/strongswan/config.h /usr/lib/ipsec/include/config.h \
    && autoreconf -fi \
    && ./configure \
        --prefix=/usr \
        --with-strongswan-headers=/usr/include/strongswan \
        --with-qkd-etsi-api=/usr/local \
    && make -j"$(nproc)" \
    && make install \
    && printf 'qkd {\n    load = yes\n}\n' > /etc/strongswan.d/charon/qkd.conf

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM ubuntu:${UBUNTU_VERSION}

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgmp10 libssl3 libcurl4 libuuid1 iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/sbin/swanctl      /usr/sbin/swanctl
COPY --from=builder /usr/libexec/ipsec/    /usr/libexec/ipsec/
COPY --from=builder /usr/lib/ipsec/        /usr/lib/ipsec/
COPY --from=builder /usr/share/strongswan/ /usr/share/strongswan/
COPY --from=builder /etc/strongswan.d/     /etc/strongswan.d/
COPY --from=builder /usr/local/lib/libqkd* /usr/local/lib/

ENV LD_LIBRARY_PATH=/usr/local/lib
RUN ldconfig && mkdir -p /var/run/charon /etc/swanctl/{x509,x509ca,pkcs8,conf.d}

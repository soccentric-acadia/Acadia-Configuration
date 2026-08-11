# syntax=docker/dockerfile:1
# ──────────────────────────────────────────────────────────────────────────────
# SoCcentric WebConfig (webconfigd) — production container image.
#
# Builds the on-device configuration daemon for the host architecture and
# packages it together with the vanilla-JS frontend, JSON schemas and board
# manifest so a containerized / dev deployment behaves like the Yocto image
# (`/usr/share/webconfig/static`, `/usr/share/webconfig/schemas`,
# `<share>/board-manifest.json`).
#
# Uses the exact pinned Rust toolchain (rust-toolchain.toml) for
# reproducibility. The daemon has NO OpenSSL/DB system deps (rustls + bundled
# sqlite) so the runtime image stays minimal. Build with:
#
#   docker build -f docker/Dockerfile -t acadia-webconfigd .
#   docker run --rm -p 8443:8443 -v webconfig-data:/data acadia-webconfigd
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
# Stage 1 — builder
#   Compile webconfigd with the pinned toolchain.
# ──────────────────────────────────────────────────────────────────────────────
FROM rust:1.97-slim AS builder

# apt build helpers (none strictly required beyond the toolchain, but keep a
# minimal set in case of linker needs).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      pkg-config \
      libssl-dev \
      ca-certificates \
      gcc \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifest + lock first to leverage the layer cache.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY rust-toolchain.toml ./

# board-manifests + schemas are embedded at compile time via include_str!(), so
# they must be present before cargo build runs.
COPY board-manifests ./board-manifests
COPY schemas ./schemas

# Compile dependencies (cached layer).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p webconfigd

# Copy the runtime assets the image serves.
COPY frontend ./frontend

# Rebuild so the release binary is guaranteed fresh (deps layer is cached), then
# copy the binary out of the cache mount to a normal path for later stages.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p webconfigd \
    && mkdir -p /out \
    && cp target/release/webconfigd /out/webconfigd

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2 — runtime
#   Minimal image containing the daemon, static UI, schemas and manifest.
# ──────────────────────────────────────────────────────────────────────────────
FROM debian:13-slim AS runtime

# webconfigd is a static-ish binary (rustls, bundled sqlite); only libc + ca
# certs are needed at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --no-create-home --uid 1001 webconfig

# The canonical install layout the daemon resolves by default:
#   /usr/share/webconfig/static   → WEBCONFIG_STATIC_DIR default
#   /usr/share/webconfig/schemas  → schema drop-in dir
#   /usr/share/webconfig/board-manifest.json → BSP-installed canonical manifest
COPY --from=builder /out/webconfigd /usr/bin/webconfigd
COPY --from=builder /build/frontend       /usr/share/webconfig/static
COPY --from=builder /build/schemas        /usr/share/webconfig/schemas
COPY --from=builder /build/board-manifests/acadia.json /usr/share/webconfig/board-manifest.json

# Mutable state lives on the /data partition (mirrors the device layout).
RUN mkdir -p /data/webconfig \
 && chown -R webconfig:webconfig /data

USER webconfig
WORKDIR /data

ENV WEBCONFIG_PORT=8443 \
    WEBCONFIG_PLATFORM=acadia \
    WEBCONFIG_STATIC_DIR=/usr/share/webconfig/static \
    WEBCONFIG_DATA_DIR=/data/webconfig \
    RUST_LOG=info

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q --no-check-certificate -O /dev/null https://127.0.0.1:8443/ || exit 1

ENTRYPOINT ["/usr/bin/webconfigd"]

# SentinelX local-multiregion: sx-monolith container image.
#
# Two-stage build:
#   1. rust:bookworm  — compiles the `sx-monolith` binary in release mode.
#   2. debian-slim    — minimal runtime with CA bundle + libssl runtime.
#
# Notes:
#   - Uses debian-slim instead of alpine because the workspace builds
#     against glibc (the default rust:1 image targets glibc; musl would
#     require cross-compilation tooling and re-vendoring of openssl).
#   - The whole workspace is copied; the build step compiles only the
#     `sx-monolith` package (`-p sx-monolith`) to keep first-build time
#     bounded. Workspace member crates are still pulled in as deps.
#   - The runtime image bundles `wget` for the docker-compose healthcheck.

# --- builder ----------------------------------------------------------------

FROM rust:1.83-bookworm AS builder

WORKDIR /workspace

# System deps the workspace needs to link against (openssl + pkg-config for
# anything that ends up linking system libssl; libpq is needed by sqlx
# offline-mode metadata even when not connecting at build time).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         pkg-config libssl-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the full workspace. We do NOT cache `target/` across image
# rebuilds — keeps the dockerfile simple at the cost of a slower first
# build. CI builds in a separate cargo cache and doesn't run this stack.
COPY . /workspace

# Build just the monolith bin. The workspace has `default-run = "sx-monolith"`
# nowhere, so be explicit.
RUN cargo build --release -p sx-monolith --bin sx-monolith

# --- runtime ---------------------------------------------------------------

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         ca-certificates libssl3 wget tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /home/sentinelx --create-home sentinelx

WORKDIR /home/sentinelx

COPY --from=builder /workspace/target/release/sx-monolith /usr/local/bin/sx-monolith
RUN chmod +x /usr/local/bin/sx-monolith \
    && chown sentinelx:sentinelx /usr/local/bin/sx-monolith

USER sentinelx
EXPOSE 8080

# tini: clean signal handling so docker stop forwards SIGTERM cleanly to
# tokio's shutdown machinery.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/sx-monolith"]

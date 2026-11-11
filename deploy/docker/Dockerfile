# syntax=docker/dockerfile:1.7
# ---- builder stage -------------------------------------------------------
FROM rust:1.88-bookworm AS builder

WORKDIR /build

# Cache dependencies separately from sources by copying only manifests first.
COPY Cargo.toml Cargo.lock* rust-toolchain.toml ./
COPY .cargo ./.cargo
COPY crates ./crates
COPY services ./services

RUN cargo build --release -p sx-monolith

# ---- runtime stage -------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

USER nonroot:nonroot

COPY --from=builder /build/target/release/sx-monolith /usr/local/bin/sx-monolith

EXPOSE 8080
EXPOSE 9090

ENTRYPOINT ["/usr/local/bin/sx-monolith"]

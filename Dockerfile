# Multi-stage build producing a small, self-contained static (musl) binary.
# blapki uses a pure-Rust crypto stack (rustls, RustCrypto) with no OpenSSL, so
# it cross-compiles to musl and runs on a minimal image.

FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev cmake make g++ clang perl
WORKDIR /src
# Cache dependencies first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release && rm -rf src
# Build the real sources.
COPY . .
RUN touch src/main.rs && cargo build --release && \
    strip target/release/blapki

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    addgroup -S blapki && adduser -S -G blapki blapki
WORKDIR /app
COPY --from=builder /src/target/release/blapki /usr/local/bin/blapki
# Data directory for the SQLite DB and bootstrapped CA key (mount a volume here).
RUN mkdir -p /data /app/ca && chown -R blapki:blapki /data /app
USER blapki
ENV BLAPKI_CONFIG=/app/config.toml
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/blapki"]

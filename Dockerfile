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

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && \
    addgroup -S blapki && adduser -S -G blapki blapki
COPY --from=builder /src/target/release/blapki /usr/local/bin/blapki
# All state lives in /data: mount a volume here. It is the working directory,
# so the relative paths in the example config (the SQLite database and the CA
# key file) resolve inside the volume and survive the container.
RUN mkdir -p /data /app && chown -R blapki:blapki /data && chmod 700 /data
WORKDIR /data
VOLUME /data
USER blapki
ENV BLAPKI_CONFIG=/app/config.toml
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/blapki"]

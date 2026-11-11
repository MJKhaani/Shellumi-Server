# Stage 1: Build
FROM rust:1.80-bullseye AS builder

WORKDIR /usr/src/shellumi-server

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release --locked -p shellumi-server

# Stage 2: Runtime
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root user
RUN groupadd -g 10001 shellumi && \
    useradd -u 10001 -g shellumi -s /bin/sh shellumi

WORKDIR /app

COPY --from=builder /usr/src/shellumi-server/target/release/shellumi-server /app/shellumi-server

USER shellumi:shellumi

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8080/health/live || exit 1

ENTRYPOINT ["/app/shellumi-server"]

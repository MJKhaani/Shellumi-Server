# Stage 1: Build
FROM rust:1.80-bookworm AS builder

WORKDIR /usr/src/shellumi-server

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations

RUN cargo build --release --locked -p shellumi-server

# Stage 2: Runtime
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="Shellumi Server" \
      org.opencontainers.image.description="Self-hostable, zero-knowledge encrypted synchronization server for Shellumi" \
      org.opencontainers.image.url="https://github.com/MJKhaani/Shellumi-Server" \
      org.opencontainers.image.source="https://github.com/MJKhaani/Shellumi-Server" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root user
RUN groupadd -g 10001 shellumi && \
    useradd -u 10001 -g shellumi -s /bin/sh shellumi

WORKDIR /app

COPY --from=builder /usr/src/shellumi-server/target/release/shellumi-server /app/shellumi-server
COPY --from=builder /usr/src/shellumi-server/migrations /app/migrations

USER shellumi:shellumi

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8080/health/live || exit 1

ENTRYPOINT ["/app/shellumi-server"]
CMD ["serve"]

# Shellumi Server

**A secure, self-hostable, Rust-only sync and collaboration server for the [Shellumi](https://github.com/MJKhaani/Shellumi) ecosystem.**

[![CI](https://github.com/MJKhaani/Shellumi-Server/actions/workflows/ci.yml/badge.svg)](https://github.com/MJKhaani/Shellumi-Server/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust%202021-orange.svg)](https://www.rust-lang.org/)
[![Protocol Version](https://img.shields.io/badge/Protocol-v1-green.svg)](docs/API.md)
[![Security Model](https://img.shields.io/badge/Security-Zero%20Plaintext%20Server-success.svg)](docs/security/THREAT_MODEL.md)

---

## 1. Project Overview

Shellumi is built around a **local-first** philosophy. The core desktop application operates entirely independently without requiring an account, server, or internet connection.

**Shellumi Server** is an optional, lightweight, self-hosted service written entirely in Rust. It enables teams and individuals to:
- Synchronize encrypted personal and organization vaults across multiple devices.
- Securely share vaults with team members using cryptographic role-based access control (RBAC).
- Distribute recipient-wrapped vault keys without ever exposing plaintext keys to the server.
- Receive instant change notifications over WebSockets or long-polling.
- Optionally relay real-time, end-to-end encrypted terminal collaboration sessions.

### Three Sovereign Operating Modes

Shellumi strictly maintains separation between three user modes:

1. **Local-Only:** The desktop client runs 100% offline. No telemetry, no accounts, no central server.
2. **Personal Google Drive:** Clients use an opt-in, direct integration with Google Drive's sandboxed `appDataFolder`. Shellumi Server does not proxy Google OAuth, hold Google tokens, or inspect Drive payloads.
3. **Self-Hosted Shellumi Server:** Organizations and individuals run their own trusted instance for cross-device synchronization and team sharing.

### The Zero-Plaintext Principle

The server treats all vault contents as **opaque, client-encrypted envelopes**.
- **No Plaintext Vault Records:** All credentials, hosts, snippets, and environments are encrypted on client devices before transmission using authenticated encryption (`xchacha20poly1305_argon2id` or `aes256gcm_dek_v1`).
- **No Decryption Keys on Server:** Vault Data Encryption Keys (DEKs) and passphrases are never sent to or derived by the server. Shared vaults distribute DEKs wrapped individually for recipient devices using X25519 key agreement.
- **No SSH Credentials Decryption:** The server never stores, logs, or decrypts SSH private keys, passphrases, or plaintext terminal streams.
- **Proof-of-Possession Device Authentication:** Every client mutation is cryptographically signed by an enrolled Ed25519 device key and verified against a canonical binary preimage.

---

## 2. Core Features

- **Protocol v1 Wire Contract:** Strictly versioned REST endpoints (`/api/v1`) with deterministic JSON schemas, typed cursors (`seq:<u64>`), and standard HTTP status codes (`401`, `403`, `404`, `409`, `422`, `429`).
- **Atomic Compare-And-Swap (CAS) Synchronization:** Transactional optimistic concurrency control per vault. Sequence numbers are assigned monotonically within PostgreSQL transactions, preventing lost updates and primary key collisions with explicit `409 REVISION_CONFLICT` detection.
- **Monotonic Anti-Replay Protection:** Replay attacks and out-of-order mutations are rejected at the database boundary via strictly monotonic, per-device counters (`device_sync_counters`).
- **Delta Sync & Watermark Snapshots:** Fast synchronization using monotonic change feeds (`GET /api/v1/vaults/:id/changes?cursor=seq:N`), durable tombstones, and consistent recovery snapshots (`GET /api/v1/vaults/:id/snapshots` and `/snapshots/:revision`).
- **Cryptographic Team Sharing & RBAC:** Vault roles (`Owner`, `Administrator`, `Editor`, `Viewer`) enforced on every read/write. Key envelopes protect offline members, with forward-secure epoch rotation (`POST /api/v1/vaults/:id/rotate-epoch`) and single-use scoped invitations.
- **Live Sync Hints:** WebSockets (`/api/v1/events/ws`) and long-polling (`/api/v1/sync/poll`) provide advisory notifications. REST reconciliation is authoritative. Shared-database multi-process fanout is experimental and not a supported deployment guarantee.
- **Real-Time Terminal Collaboration Relay:** Feature-gated (`collab_enabled`) encrypted frame relay with Server-Sent Events (SSE) `/api/v1/collab/sessions/:id/events`, single-writer token leases, and host overrides. Plaintext terminal data is never accessible to the server.
- **Tamper-Evident Cryptographic Audit Log:** High-integrity, SHA-256 hash-chained audit trail for all vault membership, key rotations, and administrative events.
- **Session Revocation & Anti-Theft Detection:** Automatic token family invalidation upon refresh token reuse, device revocation, and immediate rejection of logged-out sessions across all 38 REST endpoints.
- **Dual Storage Engine Architecture:** Production-ready PostgreSQL storage (`PgStore`) with automatic forward SQL migrations alongside a high-performance in-memory engine (`InMemoryStore`) for testing and local development.
- **Comprehensive CLI Tooling:** Built-in subcommands for daemon management (`serve`), forward migrations (`migrate status` / `migrate run`), system diagnostics (`doctor`), administrative user management (`admin user`), and backup verification (`backup verify`).

---

## 3. Architecture

Shellumi Server is built in Rust using Tokio, Axum, Tower, and SQLx.

```
                              ┌─────────────────────────────────────────┐
                              │            Shellumi Clients             │
                              │  (Desktop GPUI / Headless CLI Devices)  │
                              └────────────────────┬────────────────────┘
                                                   │ TLS 1.3
                                                   ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Shellumi Server                                      │
│                                                                                        │
│  ┌───────────────────────┐  ┌──────────────────────────┐  ┌─────────────────────────┐  │
│  │     Axum Router       │  │    Authentication &      │  │      Rate Limiter       │  │
│  │   (/api/v1 REST)      │  │    Session Validator     │  │   & Prometheus Metrics  │  │
│  └───────────┬───────────┘  └─────────────┬────────────┘  └────────────┬────────────┘  │
│              │                            │                            │               │
│              ▼                            ▼                            ▼               │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                 Service Engines                                  │  │
│  │                                                                                  │  │
│  │  ┌────────────────────────┐  ┌────────────────────────┐  ┌────────────────────┐  │  │
│  │  │      Sync Engine       │  │      Auth Service      │  │   Collab Engine    │  │  │
│  │  │  • CAS Mutation Batch  │  │  • Argon2id Verifiers  │  │  • Frame Relay     │  │  │
│  │  │  • Monotonic Sequences │  │  • PoP Device Nonces   │  │  • Single-Writer   │  │  │
│  │  │  • Delta Feeds & Snaps │  │  • Refresh Rotation    │  │  • Token Fencing   │  │  │
│  │  └───────────┬────────────┘  └───────────┬────────────┘  └─────────┬──────────┘  │  │
│  │              │                           │                         │             │  │
│  │              ▼                           ▼                         ▼             │  │
│  │  ┌────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                           Storage Abstraction (Store)                      │  │  │
│  │  │               (SettingsRepo, UserRepo, VaultRepo, SyncRepo, ...)           │  │  │
│  │  └─────────────────────────────────────┬──────────────────────────────────────┘  │  │
│  └────────────────────────────────────────┼─────────────────────────────────────────┘  │
└───────────────────────────────────────────┼────────────────────────────────────────────┘
                                            │
                     ┌──────────────────────┴──────────────────────┐
                     ▼                                             ▼
       ┌───────────────────────────┐                 ┌───────────────────────────┐
       │      PostgreSQL Pool      │                 │    In-Memory Fast Store   │
       │    (Production / PgStore) │                 │   (Development & Testing) │
       │  • Atomic CAS & Sequences │                 │  • RwLock<MemoryState>    │
       │  • Optional event hints   │                 │  • Zero External Deps     │
       └───────────────────────────┘                 └───────────────────────────┘
```

### Crates Layout

The workspace is organized into modular crates that isolate protocol specifications, domain logic, cryptographic operations, and database implementations:

| Crate | Purpose |
| --- | --- |
| `crates/shellumi-server-protocol` | Versioned data transfer objects (DTOs), wire protocol serialization, error envelopes, and contract definitions. |
| `crates/shellumi-server-domain` | Storage-agnostic business domain entities (`User`, `Vault`, `Record`, `ChangeLogEntry`), roles, and typed error types. |
| `crates/shellumi-server-crypto` | Binary canonical preimage builders, Ed25519 signature verification, whole-envelope digest computation, and envelope validation. |
| `crates/shellumi-server-store` | Database interfaces, repository traits (`SyncRepository`, `UserRepository`), transactional in-memory store, and PostgreSQL implementation with forward SQL migrations. |
| `crates/shellumi-server-auth` | Argon2id password verification, JWT access tokens with device/session binding, refresh token theft detection, and Ed25519 proof-of-possession device enrollment. |
| `crates/shellumi-server-sync` | Atomic CAS mutation engine, delta change feeds, consistent watermark snapshots, team sharing, key envelopes, and real-time collaboration relays. |
| `crates/shellumi-server` | Axum HTTP server daemon, command-line interface (`clap`), Prometheus metrics exposition, rate limiting, and process lifecycle management. |

---

## 4. Usage

### Prerequisites

- **Rust:** Stable Rust 1.80+ (see `rust-toolchain.toml`).
- **PostgreSQL:** Version 14 or newer (required for persistent production deployments; in-memory mode requires zero dependencies).

### Building and Running

```bash
# Clone the repository
git clone https://github.com/MJKhaani/Shellumi-Server.git
cd Shellumi-Server

# Build release binary
cargo build --release --locked --workspace --all-features

# Run system diagnostic checks
./target/release/shellumi-server doctor

# Start the server daemon (in-memory development mode by default)
./target/release/shellumi-server serve
```

### CLI Subcommands

Shellumi Server includes an operational CLI for administrative and lifecycle operations:

```bash
# Display help and available commands
shellumi-server --help

# Start the server daemon
shellumi-server serve --config /etc/shellumi/config.toml

# Check database migration status
shellumi-server migrate status --config /etc/shellumi/config.toml

# Apply forward SQL database migrations
shellumi-server migrate run --config /etc/shellumi/config.toml

# Run operational environment diagnostics
shellumi-server doctor --config /etc/shellumi/config.toml

# Manage administrative users
shellumi-server admin user create --username admin --email admin@example.com --password "SecretPassword123!"
shellumi-server admin user disable --identifier admin
shellumi-server admin user reset-password --identifier admin --new-password "NewSecretPassword123!"

# Verify PostgreSQL backup dump integrity and zero-plaintext compliance
shellumi-server backup verify --file /backups/shellumi_2026-11-16.sql
```

### Initial Bootstrap

On a fresh installation, bootstrap the instance by creating the primary organization and root owner:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/bootstrap \
  -H "Content-Type: application/json" \
  -d '{
    "admin_username": "sysadmin",
    "admin_email": "admin@example.com",
    "admin_password": "ChangeThisPasswordImmediately123!",
    "org_name": "Main Organization",
    "bootstrap_token": null
  }'
```

The bootstrap endpoint returns the user profile and initial session credentials. Subsequent bootstrap attempts are rejected with `409 BOOTSTRAP_ALREADY_CONSUMED`.

### Health & Capabilities Inspection

```bash
# Liveness probe
curl http://127.0.0.1:8080/health/live

# Readiness probe (verifies database connectivity)
curl http://127.0.0.1:8080/health/ready

# Inspect server protocol, capabilities, and advertised payload limits
curl http://127.0.0.1:8080/api/v1/capabilities
```

---

## 5. Deployment

### Production Configuration (`config.toml`)

Create a production configuration file (e.g. `/etc/shellumi/config.toml`):

```toml
host = "0.0.0.0"
port = 8080

# Production PostgreSQL database connection string
database_url = "postgres://shellumi:secure_db_password@localhost:5432/shellumi_db"
max_db_connections = 32

# Cryptographically random token signing key (minimum 32 bytes)
# In production, set via SHELLUMI_TOKEN_SIGNING_KEY environment variable
token_signing_key = "generate_at_least_32_bytes_random_secret_key_here!"

# Session Token Lifetimes (seconds)
access_token_ttl_secs = 3600       # 1 hour
refresh_token_ttl_secs = 2592000    # 30 days

# Operational Limits
max_request_bytes = 10485760        # 10 MB maximum request body
max_record_bytes = 2097152          # 2 MB maximum single encrypted record
rate_limit_per_minute = 600

# TLS Enforcement & Reverse Proxy Trust
# If listening on non-loopback (0.0.0.0), trusted_proxies or https is mandatory
trusted_proxies = ["127.0.0.1", "10.0.0.0/8"]

# Optional Features
collab_enabled = true               # Enable real-time terminal collaboration relay
log_level = "info"
log_format = "json"                 # "json" for structured production logs or "pretty"
```

### Docker Compose Deployment

A complete production-ready `compose.yml` is provided:

```yaml
services:
  db:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_DB: shellumi_db
      POSTGRES_USER: shellumi
      POSTGRES_PASSWORD: secure_postgres_password
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U shellumi -d shellumi_db"]
      interval: 5s
      timeout: 5s
      retries: 5

  server:
    image: ghcr.io/mjkhaani/shellumi-server:latest
    restart: always
    depends_on:
      db:
        condition: service_healthy
    environment:
      SHELLUMI_HOST: "0.0.0.0"
      SHELLUMI_PORT: "8080"
      SHELLUMI_DATABASE_URL: "postgres://shellumi:secure_postgres_password@db:5432/shellumi_db"
      SHELLUMI_TOKEN_SIGNING_KEY: "change_me_to_a_minimum_32_bytes_random_secret_key_in_production!"
      SHELLUMI_LOG_FORMAT: "json"
      SHELLUMI_TRUSTED_PROXIES: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    ports:
      - "127.0.0.1:8080:8080"

volumes:
  pgdata:
```

Run with:
```bash
docker compose up -d
```

### Caddy Reverse Proxy (Recommended for TLS)

When exposing Shellumi Server to the internet, terminate TLS using a modern reverse proxy like Caddy:

```caddyfile
vault.yourdomain.com {
    encode gzip zstd

    # WebSocket and REST reverse proxy
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-Proto https
        header_up X-Real-IP {remote_host}
    }

    # Strict security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "no-referrer"
    }
}
```

---

## 6. Testing & Quality Gates

Every increment in Shellumi Server is tested and verified against strict quality gates before merging.

### Running Quality Checks

```bash
# Code formatting
cargo fmt --all -- --check

# Strict Clippy analysis with zero allowed warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

# Execute full automated test suite (unit, integration, and security tests)
cargo test --locked --workspace --all-features

# Documentation tests
cargo test --locked --doc --workspace

# Full workspace build verification
cargo build --locked --workspace --all-features
```

### Automated Test Matrix

The test suite covers:
- **Authentication & Sessions:** Password hashing (Argon2id), JWT access tokens, refresh token rotation, token theft invalidation, and immediate REST session revocation on logout.
- **Proof-of-Possession Device Enrollment:** Mandatory Ed25519 single-use challenge verification, device listing, and revoked device rejection.
- **CAS Synchronization:** Monotonic sequence assignments, concurrent conflict detection (`409`), idempotent retries, tombstone propagation, and anti-replay counters.
- **Watermark Snapshots:** Bounded snapshot pagination and consistent database state verification.
- **Cryptographic Envelopes:** Whole-envelope SHA-256 digest binding (`suite`, `nonce`, `salt`, `iterations`, `associated_data`, `ciphertext`) and signature preimage verification.
- **RBAC & Cryptographic Audit Trails:** Role hierarchies (`Owner`, `Administrator`, `Editor`, `Viewer`), scoped single-use invites, and append-only hash linkage.
- **Terminal Collaboration:** Lease token fencing, single-writer control, frame isolation, and read-only participant enforcement.
- **Operations & Disaster Recovery:** Configuration safety validation, rate limiting, Prometheus metrics exposition, and SQL backup corruption/leak detectors.

---

## 7. Documentation Index

Comprehensive technical guides and references are maintained under [`docs/`](docs/):

| Guide | Description |
| --- | --- |
| [Architecture Guide](docs/ARCHITECTURE.md) | High-level system design, crate separation, data flow, and concurrency model. |
| [API Specification](docs/API.md) | Exhaustive REST endpoint documentation, error codes, and headers. |
| [OpenAPI Specification](openapi/shellumi-server-v1.yaml) | Standard OpenAPI 3.1 YAML schema definition for Protocol v1. |
| [Progress Journal](docs/PROGRESS.md) | Append-only engineering log recording task executions, verification commands, and test counts. |
| [Roadmap](docs/ROADMAP.md) | Milestone tracking from bootstrap (M1) through production readiness. |
| [Threat Model](docs/security/THREAT_MODEL.md) | Cryptographic security assumptions, trust boundaries, and threat mitigation. |
| [Key Management](docs/security/KEY_MANAGEMENT.md) | Recipient-wrapped key envelopes, X25519 key agreements, and epoch rotation flows. |
| [Configuration Reference](docs/CONFIGURATION.md) | Complete list of environment variables, config options, and safety defaults. |
| [Deployment Guide](docs/DEPLOYMENT.md) | Containerization, systemd unit templates, Caddy/Nginx reverse proxy, and monitoring. |
| [Backup & Disaster Recovery](docs/BACKUP_RESTORE.md) | PostgreSQL backup scripts, zero-plaintext verification, and point-in-time recovery. |
| [Compatibility Guide](docs/COMPATIBILITY.md) | Wire protocol compatibility matrix and client migration notes. |
| [Testing Guide](docs/development/TESTING.md) | Test environment setup, Docker integration testing, and property-based tests. |
| [Release Guide](docs/development/RELEASES.md) | Reproducible multi-arch release builds, SBOM generation, and provenance signing. |
| [Contributor Rules](AGENT.md) | Mandatory contributor standards and engineering discipline contract. |

---

## 8. License

Shellumi Server is released under the **[MIT License](LICENSE)**.

Copyright (c) 2026 Shellumi Server Contributors.
All contributions are welcome; please see [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENT.md](AGENT.md) before submitting pull requests.

Independent Shellumi Server installations do not communicate with each other. A client can maintain a separate connection to each server and subscribe to multiple vaults on each connection; WebSocket notifications are hints and REST reconciliation remains authoritative. Multi-server client support has not been verified end-to-end.

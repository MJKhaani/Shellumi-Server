# Shellumi Server

[![CI](https://github.com/MJKhaani/Shellumi-Server/actions/workflows/ci.yml/badge.svg)](https://github.com/MJKhaani/Shellumi-Server/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust: 2021](https://img.shields.io/badge/Rust-2021_Stable-blue.svg)](https://www.rust-lang.org/)

An open-source, MIT-licensed, headless, self-hostable synchronization and collaboration backend for [Shellumi](https://github.com/MJKhaani/Shellumi) desktop and CLI clients.

Shellumi Server enables multi-device synchronization of encrypted personal and team vaults, cryptographic device registration, user invitations, role-based access control (RBAC), hash-chained audit trails, and optional real-time terminal collaboration signaling.

---

## Key Principles & Security Guarantees

- **Zero Server-Side Plaintext:** The server never holds or decrypts user vault data, SSH private keys, passphrases, credentials, or terminal keystrokes. It operates solely on client-sealed authenticated ciphertext envelopes (`EncryptedEnvelope`) and recipient-wrapped key envelopes.
- **Client Autonomy:** Shellumi desktop/CLI clients are completely functional offline. Connecting to Shellumi Server is strictly opt-in and self-hosted; neither the desktop application nor its direct Google Drive synchronization depends on Shellumi Server.
- **Self-Hosted Simplicity:** Single native Rust binary or minimal non-root Docker container with PostgreSQL. No Kubernetes, Redis, or proprietary cloud dependencies required.
- **Deterministic Concurrency & Conflict Safety:** Monotonically increasing revision sequence numbers, conditional writes with conflict detection (`409 Conflict`), durable tombstones, and mutation idempotency.
- **Single-Writer Collaboration:** Real-time terminal collaboration signaling enforces a monotonic write lease fencing token, blocking stale keystrokes and providing instant host emergency revocation.

---

## Architecture Overview

```text
+-------------------------------------------------------------+
|                      Shellumi Client                        |
|        (GPUI Desktop / CLI / Future Mobile Client)          |
+------------------------------+------------------------------+
                               | HTTPS / Server-Sent Events
                               v
+-------------------------------------------------------------+
|                      Shellumi Server                        |
|                                                             |
|  +--------------------+  +--------------------+             |
|  |   Health & Ops     |  |   Auth & Devices   |             |
|  |  /health, /metrics |  |  Argon2id, Tokens  |             |
|  |  CLI Admin, Doctor |  |  Ed25519 / X25519  |             |
|  +--------------------+  +--------------------+             |
|                                                             |
|  +--------------------+  +--------------------+             |
|  |     Sync & CAS     |  |   Vault & Invites  |             |
|  | Delta Feed, Cursor |  | Wrapped Envelopes  |             |
|  | 409 Conflict, Idem |  | RBAC Matrix, Audit |             |
|  +--------------------+  +--------------------+             |
|                                                             |
|  +--------------------------------------------+             |
|  |          Terminal Collab Relay Hub         |             |
|  |   SSE Streaming, Single-Writer Fencing     |             |
|  +--------------------------------------------+             |
|                                                             |
|  +--------------------------------------------+             |
|  |            PostgreSQL Persistence          |             |
|  |  Migrations: 001(core), 002(sync),         |             |
|  |              003(teams), 004(collab)       |             |
|  +--------------------------------------------+             |
+-------------------------------------------------------------+
```

---

## Quickstart

### Running locally with Cargo

```bash
# Clone the repository
git clone https://github.com/MJKhaani/Shellumi-Server.git
cd Shellumi-Server

# Run the server with default configuration (listens on 127.0.0.1:8080)
cargo run -p shellumi-server
```

Verify the server is running:

```bash
# Check liveness
curl http://127.0.0.1:8080/health/live

# Check capabilities and protocol version
curl http://127.0.0.1:8080/api/v1/capabilities
```

### Running with Docker Compose

```bash
cd deploy
cp .env.example .env
docker compose up -d
```

---

## CLI Administration & Operations

The `shellumi-server` binary provides headless operational subcommands:

```bash
# Run automated system, network, and configuration diagnostics
shellumi-server doctor

# Manage user accounts offline
shellumi-server admin user list
shellumi-server admin user create --username alice --email alice@example.com --password "SecurePass123!"
shellumi-server admin user disable <user-id>

# Inspect and revoke user sessions
shellumi-server admin session list --user-id <user-id>
shellumi-server admin session revoke-all --user-id <user-id>

# Check database schema migration status
shellumi-server migrate status

# Cryptographically verify database backups against corruption and plaintext leaks
shellumi-server backup verify /backups/shellumi_backup_20261111.sql
```

---

## Documentation

- [Roadmap & Milestone Status](docs/ROADMAP.md)
- [Architecture & System Design](docs/ARCHITECTURE.md)
- [Client Compatibility Matrix & Wire Protocol](docs/COMPATIBILITY.md)
- [Configuration Reference](docs/CONFIGURATION.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Disaster Recovery & Backup/Restore](docs/BACKUP_RESTORE.md)
- [API Reference & OpenAPI 3.1](docs/API.md)
- [Threat Model & Security Architecture](docs/security/THREAT_MODEL.md)
- [Key Management Specification](docs/security/KEY_MANAGEMENT.md)
- [Testing Guide & Quality Gates](docs/development/TESTING.md)
- [Release Engineering](docs/development/RELEASES.md)
- [Engineering Progress Journal](docs/PROGRESS.md)
- [Mandatory Contributor Rules](AGENT.md)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

# Shellumi Server

[![CI](https://github.com/MJKhaani/Shellumi-Server/actions/workflows/ci.yml/badge.svg)](https://github.com/MJKhaani/Shellumi-Server/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An open-source, MIT-licensed, headless, self-hostable synchronization backend for [Shellumi](https://github.com/MJKhaani/Shellumi) desktop and CLI clients.

Shellumi Server enables multi-device synchronization of encrypted personal and team vaults, cryptographic device registration, user invitations, role-based access control (RBAC), audit trails, and optional real-time terminal collaboration signaling.

## Key Principles & Security Guarantees

- **Zero Server-Side Plaintext:** The server never holds or decrypts user vault data, SSH private keys, passphrases, or credentials. It operates solely on client-sealed authenticated ciphertext envelopes and recipient-wrapped key envelopes.
- **Client Autonomy:** Shellumi desktop/CLI clients are completely functional offline. Connecting to Shellumi Server is strictly opt-in and self-hosted.
- **Self-Hosted Simplicity:** Single native Rust binary or minimal non-root Docker container with PostgreSQL. No Kubernetes or proprietary cloud dependencies required.
- **Strict Tenant & Role Isolation:** Monotonically increasing revision sequence numbers, conditional writes with conflict detection (`409 Conflict`), and role enforcement.

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

# Check capabilities
curl http://127.0.0.1:8080/api/v1/capabilities
```

### Running with Docker Compose

```bash
cd deploy
cp .env.example .env
docker compose up -d
```

## Documentation

- [Roadmap & Milestone Status](docs/ROADMAP.md)
- [Architecture & System Design](docs/ARCHITECTURE.md)
- [Configuration Reference](docs/CONFIGURATION.md)
- [Engineering Progress Journal](docs/PROGRESS.md)
- [Threat Model](docs/security/THREAT_MODEL.md)
- [Key Management](docs/security/KEY_MANAGEMENT.md)
- [Mandatory Contributor Rules](AGENT.md)

## License

MIT License. See [LICENSE](LICENSE) for details.

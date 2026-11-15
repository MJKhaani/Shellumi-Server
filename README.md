# Shellumi Server

**An optional, self-hosted sync and collaboration server for [Shellumi](https://github.com/MJKhaani/Shellumi).**

[![CI](https://github.com/MJKhaani/Shellumi-Server/actions/workflows/ci.yml/badge.svg)](https://github.com/MJKhaani/Shellumi-Server/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)

Shellumi works locally without an account or server. Shellumi Server is an opt-in Rust service for encrypted vault synchronization, team access, and collaboration. The existing direct Google Drive provider remains separate; the server does not proxy Google OAuth.

> **Development status:** The runtime currently uses an in-memory store. Data and notification state do not survive a restart, and the PostgreSQL configuration and migration files do not provide a wired persistence backend. Sync notifications are experimental; cross-tenant isolation, reconnect, timeout, and backpressure need further testing. Do not rely on this version for production data. See [the progress journal](docs/PROGRESS.md) for evidence and open work.

## What is here

- **Encrypted vault sync** — REST endpoints for encrypted records, conditional writes, change feeds, tombstones, and idempotent retries.
- **Teams and devices** — device registration, vault membership, role checks, invitations, and recipient-wrapped key envelopes.
- **Live sync hints** — a WebSocket and long-poll endpoint notify connected clients of team-vault changes. Clients still fetch authoritative data through REST.
- **Optional terminal collaboration** — session signaling and encrypted frame relay with single-writer controls.
- **Self-hosted by design** — MIT-licensed Rust workspace with no required hosted identity or subscription.

The server is designed to handle encrypted envelopes rather than decrypt vault contents. This is a design goal, not a claim of an independent security audit. Review the [threat model](docs/security/THREAT_MODEL.md) and [key management design](docs/security/KEY_MANAGEMENT.md) before evaluating a deployment.

## Try it locally

Install the Rust toolchain specified in [`rust-toolchain.toml`](rust-toolchain.toml), then run:

```bash
git clone https://github.com/MJKhaani/Shellumi-Server.git
cd Shellumi-Server
cargo run --locked -p shellumi-server
```

In another terminal:

```bash
curl http://127.0.0.1:8080/health/live
curl http://127.0.0.1:8080/api/v1/capabilities
```

The default address is loopback. Local data is temporary: restarting the process clears the in-memory store. The [configuration reference](docs/CONFIGURATION.md) and [deployment guide](docs/DEPLOYMENT.md) describe available settings and deployment artifacts; the included Compose PostgreSQL service is not currently connected to the runtime store.

## Connecting a client

The versioned REST API remains the source of truth. An experimental client can connect to `GET /api/v1/sync/events` with a session-bound bearer token and `X-Device-Id`, or use `GET /api/v1/sync/poll` for long polling. A `vault_changed` or `vault_deleted` event is a **hint**, not a durable update.

Reconcile the vault list, metadata, and change feeds through authenticated REST calls on startup and after a disconnect, polling gap, timeout, or overflow. Hints can be duplicated or missed and are confined to one server process. Shellumi client integration has not yet been implemented or verified. See the [API reference](docs/API.md) and [compatibility notes](docs/COMPATIBILITY.md) for the current wire contract and limitations.

## Explore the project

| Topic | Guide |
| --- | --- |
| Design and current work | [Architecture](docs/ARCHITECTURE.md) · [Roadmap](docs/ROADMAP.md) · [Progress](docs/PROGRESS.md) |
| Protocol and client integration | [API](docs/API.md) · [OpenAPI](openapi/shellumi-server-v1.yaml) · [Compatibility](docs/COMPATIBILITY.md) |
| Operations | [Configuration](docs/CONFIGURATION.md) · [Deployment](docs/DEPLOYMENT.md) · [Backup and restore](docs/BACKUP_RESTORE.md) |
| Security | [Threat model](docs/security/THREAT_MODEL.md) · [Key management](docs/security/KEY_MANAGEMENT.md) · [Security policy](SECURITY.md) |
| Contributing | [Testing](docs/development/TESTING.md) · [Releases](docs/development/RELEASES.md) · [Contributor instructions](AGENT.md) |

## License

[MIT](LICENSE). Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

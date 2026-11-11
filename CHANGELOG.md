# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Milestone M0: Repository foundations and project hygiene**
  - Modular Rust workspace layout (`shellumi-server`, `shellumi-server-protocol`, `shellumi-server-domain`).
  - Layered configuration loader with strict precedence: CLI flags > environment variables (`SHELLUMI_SERVER_*`) > config file (`config.toml`) > secure defaults.
  - Security validation: automated rejection of non-loopback plaintext listeners without HTTPS or explicit trusted proxies.
  - Health endpoints: `/health/live` (process liveness) and `/health/ready` (system readiness).
  - Versioned API capabilities endpoint: `/api/v1/capabilities`.
  - Machine-readable JSON error responses for unmapped routes (404).
  - Integration and unit tests for configuration, health, and capability negotiation.
  - CI workflow skeleton (`.github/workflows/ci.yml`).
  - Documentation suite: Architecture, Roadmap, Configuration, Progress Journal, and ADRs.
- **Milestone M1: Storage, migrations, tenants & authentication**
  - PostgreSQL schema and forward-only migrations for users, organizations, devices, sessions, and settings.
  - Interactive one-time admin bootstrap flow (`/api/v1/bootstrap`) with reuse protection.
  - Argon2id password hashing and constant-time authentication.
  - HMAC-SHA256 bearer tokens and cryptographically random rotating refresh tokens with theft detection.
  - Device identity registration validating Ed25519 signing and X25519 agreement keys.
  - Endpoints: `/api/v1/auth/login`, `/api/v1/auth/refresh`, `/api/v1/auth/logout`, `/api/v1/me`, `/api/v1/devices`.
- **Milestone M2: Encrypted private vault & sync engine v1**
  - Zero-knowledge encrypted vault storage holding only client-sealed `EncryptedEnvelope` payloads.
  - Canonical mutation preimage formatting and Ed25519 cryptographic signature verification.
  - Monotonic transaction sequence assignment and delta changes feed (`/api/v1/vaults/:id/changes`).
  - Conditional CAS writes with `expected_revision` conflict detection (`409 REVISION_CONFLICT`).
  - Idempotency key tracking preventing duplicate writes (`409 IDEMPOTENCY_CONFLICT`).
  - Durable soft-delete tombstones and full recovery snapshot downloads.
- **Milestone M3: Team vaults, invites, RBAC matrix & recipient-wrapped key envelopes**
  - Strict hierarchical RBAC matrix enforcing permissions across Owner, Administrator, Editor, and Viewer roles.
  - Last Owner protection preventing accidental lockout, demotion, or deletion of the sole vault owner.
  - Single-use scoped invitations generating 256-bit cryptographically random tokens stored only as SHA-256 hashes (`/api/v1/vaults/:id/invites`, `/api/v1/invites/accept`).
  - Recipient-wrapped Data Encryption Key (DEK) envelopes isolated strictly by calling device (`X-Device-Id`).
  - Monotonic key epoch rotation (`/api/v1/vaults/:id/keys/epochs`) rejecting mutations encrypted with stale epochs (`409 STALE_KEY_EPOCH`).
  - Tamper-evident, hash-chained cryptographic audit trail (`/api/v1/vaults/:id/audit`).

# Shellumi Server — Development Roadmap

This document outlines the milestones and progress of Shellumi Server.

## Milestone Status Overview

| Milestone | Title | Status | Primary Gates & Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| **M0** | Repository Foundations & Hygiene | **Complete** | Workspace skeleton, configuration parser, `/health/live`, `/health/ready`, `/api/v1/capabilities`, strict config validation, unit/integration tests, CI workflow, docs. |
| **M1** | Storage, Migrations, Tenants & Auth | **Complete** | PostgreSQL schema, admin bootstrap, accounts, sessions, device key registration, organizations, token revocation, cross-tenant isolation tests. |
| **M2** | Encrypted Private Vault & Sync v1 | **Complete** | Stable UUIDs, opaque ciphertext envelopes, device signatures, transactional change feed, conditional `expected_revision` writes, conflict resolution (409), tombstones. |
| **M3** | Team Vaults, Invites, RBAC & E2EE Keys | **Complete** | Owner/Admin/Editor/Viewer permission matrix, one-time invitations, per-device recipient-wrapped DEKs, epoch rotation, audit trail. |
| **M4** | Resilience, Operations & Releases | Current | CLI admin commands, backup/restore verification, metrics, rate limits, multi-arch Docker image, reproducible release automation. |
| **M5** | Optional Live Terminal Collaboration | Planned | WSS relay, ephemeral E2EE session keys, single-writer fencing token, owner emergency revocation, bounded queues. Relay disabled until gates pass. |
| **M6** | Advanced Self-Hosting & Integrations | Planned | OIDC/SSO, optional SMTP, large encrypted attachments, horizontal PostgreSQL coordination. |

---

## Detailed Milestone Scope

### M0 — Repository Foundations & Hygiene (Complete)
- **Rust Workspace:** Modular layout (`shellumi-server`, `shellumi-server-domain`, `shellumi-server-protocol`).
- **Configuration:** Layered resolution (CLI > Env > File > Defaults). Safe defaults enforced (loopback by default, rejection of insecure public listeners).
- **Core Endpoints:**
  - `GET /health/live`: Process liveness check.
  - `GET /health/ready`: System readiness check.
  - `GET /api/v1/capabilities`: Advertised protocol version, features, and bounds.
- **Error Format:** Typed, consistent JSON error responses (`error_code`, `message`, `request_id`).
- **Gates:**
  - `cargo fmt --all -- --check`
  - `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --locked --workspace --all-features`
  - Clean startup and invalid config rejection tests.

### M1 — Storage, Migrations, Tenants & Auth (Complete)
- **Database & Schemas:** Forward-only PostgreSQL migrations (`server_settings`, `users`, `organizations`, `organization_memberships`, `devices`, `sessions`).
- **Storage Abstraction:** Pluggable `Store` and repository traits with `InMemoryStore` implementation.
- **Authentication & Sessions:**
  - Argon2id password hashing and constant-time verification.
  - Signed HMAC-SHA256 bearer tokens.
  - 256-bit cryptographically secure refresh tokens stored as SHA-256 hashes.
  - Refresh token rotation with atomic reuse/theft detection.
- **Endpoints:**
  - `POST /api/v1/bootstrap`: Interactive one-time bootstrap creating initial admin. Duplicate calls return 409 `BOOTSTRAP_ALREADY_CONSUMED`.
  - `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout`.
  - `GET /api/v1/me`.
  - `GET /api/v1/devices`, `POST /api/v1/devices`, `DELETE /api/v1/devices/:id`.
- **Cryptographic Keys:** Device registration validating Ed25519 signing public key and X25519 key-agreement public key.

### M2 — Encrypted Private Vault & Sync v1 (Complete)
- **Vault Data Model:** Stable UUIDs, encrypted record payloads (zero-knowledge: ciphertext envelopes only).
- **Monotonic Change Feed:** Transactional sequence numbers per vault, change pagination via cursors (`since` sequence).
- **Conditional CAS Mutations:** `expected_revision` validation, returning 409 Conflict on stale edits.
- **Idempotency:** Client mutation idempotency key tracking to eliminate duplicate updates.
- **Tombstones:** Soft deletions with durable tombstones propagating across devices.
- **Verification:** Two-device sync convergence, concurrent edits race test, tombstone handling, signature validation.

### M3 — Team Vaults, Invites, RBAC & E2EE Keys (Complete)
- **RBAC Matrix:** Strict permission enforcement for Owner, Administrator, Editor, and Viewer across all vault actions.
- **Recipient-Wrapped DEKs:** Client-wrapped data encryption keys per authorized recipient device (zero plaintext DEK on server).
- **Invitations:** Single-use cryptographically random token invitations with expiry and role scoping.
- **Key Epoch Rotation:** Re-keying on member revocation with validation that only surviving trusted devices obtain wraps.
- **Audit Logging:** Append-only cryptographic audit trail with hash-chain linkage.

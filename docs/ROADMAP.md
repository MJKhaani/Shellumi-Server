# Shellumi Server — Development Roadmap

This document outlines the milestones and progress of Shellumi Server.

## Re-verification status

The 2026-11-16 independent re-verification found production PostgreSQL, snapshot, notification, restart, and CI acceptance gaps. The existing milestone descriptions record earlier implementation claims; M1–M6 and Phase 11 remain partial until their applicable gates are demonstrated against real services. The interrupted remediation is unverified. See [TASK-014](PROGRESS.md#2026-11-16t085011z--task-014--independent-phase-11-re-verification-follow-up).

## Milestone Status Overview

| Milestone | Title | Status | Primary Gates & Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| **M0** | Repository Foundations & Hygiene | **Complete** | Workspace skeleton, configuration parser, `/health/live`, `/health/ready`, `/api/v1/capabilities`, strict config validation, unit/integration tests, CI workflow, docs. |
| **M1** | Storage, Migrations, Tenants & Auth | **Partial** | Real PostgreSQL `PgStore` runtime, forward migrations, atomic bootstrap, CSPRNG signing key, device challenge PoP, universal REST session revocation. |
| **M2** | Encrypted Private Vault & Sync v1 | **Partial** | Atomic CAS (`SELECT FOR UPDATE`), direct-DEK record envelope (`aes256gcm_dek_v1`), unambiguous canonical binary preimages, monotonic per-mutation sequence, anti-replay device counters, consistent watermark snapshots. |
| **M3** | Team Vaults, Invites, RBAC & E2EE Keys | **Partial** | Scoped recipient device discovery (`GET /api/v1/vaults/:id/recipient-devices`), strict epoch bounds (reject future and past), atomic invite redemption, hash-chained audit log. |
| **M4** | Resilience, Operations & Releases | **Partial** | Database-backed readiness probe, doctor DB diagnostic check, CLI admin commands backed by real storage, Prometheus telemetry, backup verification. |
| **M5** | Optional Live Terminal Collaboration | **Partial** | Terminal collaboration SSE & polling relay (opt-in, separate from vault sync notifications). |
| **M6** | Advanced Self-Hosting & Client Polish | **Partial** | Golden contract fixtures, client compatibility matrix alignment, pre-release v1 contract finalization. |
| **Phase 11** | Protocol v1 Hardening & Live Sync Notifications | **Partial** | Standard WSS `/api/v1/events/ws` with `subscribe`/`subscribed`/`vault.changed`/`vault.key_rotated`/`vault.access_revoked` frames, single-server post-commit hints, multi-vault subscriptions, REST recovery and PostgreSQL acceptance; shared-database clustering is optional and experimental. |
| **M7** | Enterprise Integrations (Post-v1) | Planned | OIDC/SSO, optional SMTP notification delivery, S3-compatible large encrypted attachment storage, horizontal clustering enhancements. |

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

### M1 — Storage, Migrations, Tenants & Auth (Partial)
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

### M2 — Encrypted Private Vault & Sync v1 (Partial)
- **Vault Data Model:** Stable UUIDs, encrypted record payloads (zero-knowledge: ciphertext envelopes only).
- **Monotonic Change Feed:** Transactional sequence numbers per vault, change pagination via cursors (`since` sequence).
- **Conditional CAS Mutations:** `expected_revision` validation, returning 409 Conflict on stale edits.
- **Idempotency:** Client mutation idempotency key tracking to eliminate duplicate updates.
- **Tombstones:** Soft deletions with durable tombstones propagating across devices.
- **Verification:** Two-device sync convergence, concurrent edits race test, tombstone handling, signature validation.

### M3 — Team Vaults, Invites, RBAC & E2EE Keys (Partial)
- **RBAC Matrix:** Strict permission enforcement for Owner, Administrator, Editor, and Viewer across all vault actions.
- **Recipient-Wrapped DEKs:** Client-wrapped data encryption keys per authorized recipient device (zero plaintext DEK on server).
- **Invitations:** Single-use cryptographically random token invitations with expiry and role scoping.
- **Key Epoch Rotation:** Re-keying on member revocation with validation that only surviving trusted devices obtain wraps.
- **Audit Logging:** Append-only cryptographic audit trail with hash-chain linkage.

### M4 — Resilience, Operations & Releases (Partial)
- **CLI Subcommands:** Headless administration commands (`serve`, `doctor`, `admin user`, `admin session`, `migrate`, `backup verify`).
- **Rate Limiting:** Sliding-window IP rate limiter on sensitive endpoints (`/api/v1/auth/login`, `/api/v1/bootstrap`, `/api/v1/invites/accept`) returning HTTP 429 with `Retry-After`.
- **Prometheus Telemetry:** Standard Prometheus text exposition at `/metrics` with strictly bounded label cardinality (no UUID leaks).
- **Disaster Recovery:** Comprehensive guide and verification utility in `docs/BACKUP_RESTORE.md` and `shellumi-server backup verify <file>`.
- **Containers & Releases:** Multi-arch Docker container (`linux/amd64`, `linux/arm64`) with non-root security, CI smoke testing, and tag-triggered release workflow in `.github/workflows/release.yml`.

### M5 — Optional Live Terminal Collaboration (Partial)
- **Feature Gating:** Strictly opt-in (`SHELLUMI_SERVER_COLLAB_ENABLED=false` default). When disabled, returns HTTP 403 `COLLAB_DISABLED` and suppresses capability advertisement.
- **Zero Server Plaintext:** Ephemeral E2EE session keys negotiated directly between clients; server operates as a blind ciphertext forwarder. Keystrokes, PTY screens, and SSH credentials never touch server memory in plaintext.
- **Single-Writer Fencing Token:** Monotonically advancing `lease_token` incremented on write control grants and revocations. Frames bearing stale tokens are rejected with HTTP 409 `STALE_LEASE_TOKEN`.
- **Role Enforcement:** Viewers are strictly prohibited from transmitting `TerminalInput` frames; non-hosts cannot emit `TerminalOutput` frames. Read-only sessions prohibit all input and control grants.
- **Host Emergency Override:** Immediate unilateral lease revocation and session termination (`POST /api/v1/collab/sessions/:id/terminate`). Closes active subscriber channels immediately; subsequent frame sends return HTTP 410 `COLLAB_SESSION_TERMINATED`.
- **Transports:** Real-time Server-Sent Events stream (`GET /api/v1/collab/sessions/:id/events`) and cursor-based ordered frame polling (`GET /api/v1/collab/sessions/:id/poll?since_sequence=...`).

### M6 — Advanced Self-Hosting & Client Integration Polish (Partial)
- **Wire Contract Fixtures:** Full golden JSON contract fixtures and deserialization test suite in `crates/shellumi-server/tests/contract_fixtures.rs`.
- **Client Compatibility Matrix:** Complete specification in `docs/COMPATIBILITY.md` mapping client entities (`SyncVault`, `SyncRecord`, `EncryptedEnvelope`, `TeamRole`, `SharedVault`, `TeamMember`) to server endpoints and wire payloads.
- **Migration Paths:** Formalized migration pathway for upgrading legacy client AES-256-GCM + PBKDF2 local/Drive backups to versioned envelopes and stable UUIDs.
- **Architecture & Threat Model:** Synchronized `docs/ARCHITECTURE.md`, `docs/security/THREAT_MODEL.md`, `docs/security/KEY_MANAGEMENT.md`, and `docs/development/TESTING.md`.
- **ADRs:** Authored `docs/adr/0007-m6-self-hosting-and-client-compatibility.md` formalizing self-hosting boundaries and zero-knowledge invariants.

### M7 — Enterprise Integrations (Post-v1 Planning)
- **OIDC/SSO:** Optional enterprise OpenID Connect identity provider integration alongside local Argon2id credentials.
- **Transactional Email:** Optional SMTP provider for asynchronous delivery of invitation links and security notices.
- **Large Encrypted Attachments:** S3-compatible object storage integration for bounded encrypted session recordings and file transfers.
- **Clustered High Availability:** Experimental multi-node horizontal scaling; not yet verified or supported.



Experimental sync WebSocket hints are implemented in the server; client integration,
durable multi-process fanout,
and comprehensive network and authorization tests remain outstanding.

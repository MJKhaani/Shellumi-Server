# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Idempotent commit retries are bound to the originating device; another device cannot replay a copied cached response.
- Change-feed requests now return `CURSOR_EXPIRED` when a required sequence is missing, allowing clients to recover from a latest snapshot. Automatic retention pruning remains unimplemented.
- In-memory batches now apply sequential compare-and-set semantics for repeated edits to the same object, matching PostgreSQL.
- Material changes emit advisory sync hints after success; shared-database multi-process fanout is experimental. Persistent signing-key initialization errors fail startup.
- Historical snapshot revision requests return 422 rather than incorrect state; the PostgreSQL singleton migration preserves one prior installation and rejects duplicate settings rows.
- PostgreSQL acceptance coverage now includes bootstrap, migration, server restart, signed sync and WebSocket scenarios; the full single-server authorization and recovery matrix remains unfinished.

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
- **Milestone M4: Resilience, operations & release engineering**
  - CLI subcommands in `shellumi-server` binary (`serve`, `doctor`, `admin user`, `admin session`, `migrate`, `backup verify`).
  - In-memory sliding-window IP rate limiter on sensitive endpoints (`/api/v1/auth/login`, `/api/v1/bootstrap`, `/api/v1/invites/accept`) returning HTTP 429 Too Many Requests with standard `Retry-After` header.
  - Opt-in Prometheus metrics exposition endpoint `/metrics` (`SHELLUMI_SERVER_METRICS_ENABLED`) adhering to Prometheus 0.0.4 text format with normalized route templates ensuring bounded label cardinality.
  - Comprehensive PostgreSQL backup, restoration, and disaster recovery guide in `docs/BACKUP_RESTORE.md`.
  - Cryptographic database dump verifier (`shellumi-server backup verify <file>`) verifying archive headers, schema signatures, and absence of leaked plaintext private keys.
  - Multi-architecture container build (`Dockerfile`) for `linux/amd64` and `linux/arm64` with non-root security.
  - Tag-triggered release automation workflow (`.github/workflows/release.yml`) with strict SemVer validation, binary matrix compilation, SHA256 checksums, and GHCR publishing.
- **Milestone M5: Optional live terminal collaboration signaling & ciphertext relay**
  - Opt-in feature gating (`SHELLUMI_SERVER_COLLAB_ENABLED=false` default) returning HTTP 403 `COLLAB_DISABLED` when disabled and advertising `terminal_collab_v1` in `/api/v1/capabilities` when enabled.
  - Ephemeral E2EE session models and relay engine enforcing strict zero server plaintext (blind forwarding of client-sealed ciphertext frames).
  - Monotonic single-writer fencing token (`lease_token`) incremented on control grants and revocations; frames with stale tokens rejected with HTTP 409 `STALE_LEASE_TOKEN`.
  - Strict role enforcement: viewers cannot type (`403 NOT_AUTHORIZED_WRITER`), and only session host can emit `TerminalOutput` frames. Read-only sessions reject all input and control grants.
  - Unilateral host emergency control revocation (`/api/v1/collab/sessions/:id/control/revoke`) and session termination (`/api/v1/collab/sessions/:id/terminate`).
  - Real-time Server-Sent Events stream (`/api/v1/collab/sessions/:id/events`) and cursor-based ordered polling fallback (`/api/v1/collab/sessions/:id/poll`).
  - PostgreSQL schema migration `20261111000004_collab_sessions.sql` for session state and enrolled participants.
  - Comprehensive integration test suite in `tests/collab_relay.rs` validating gating, single-writer fencing, emergency termination, and ciphertext preservation.
- **Milestone M6: Advanced self-hosting, integration & client compatibility hardening**
  - Wire protocol v1 contract fixtures test suite (`crates/shellumi-server/tests/contract_fixtures.rs`) validating golden JSON serialization and deserialization for all protocol DTOs.
  - Expanded client compatibility specification in `docs/COMPATIBILITY.md` detailing entity mappings (`SyncVault`, `SyncRecord`, `EncryptedEnvelope`, `TeamRole`, `SharedVault`, `TeamMember`), canonical AAD construction, and provider boundaries.
  - Comprehensive migration strategy for upgrading legacy client AES-256-GCM + PBKDF2 local/Drive snapshots to versioned envelopes and UUID identifiers.
  - Authored ADR `docs/adr/0007-m6-self-hosting-and-client-compatibility.md` formalizing client provider boundaries, zero-knowledge constraints, and CAS conflict semantics.
  - Synchronized and updated documentation deliverables across Architecture, Key Management, Threat Model, Testing, Releases, and Roadmap.

- **Phase 11: Protocol v1 Completion, PostgreSQL Persistence, and Live Sync Notifications**
  - Production PostgreSQL persistence layer (`PgStore` and `AnyStore`) implementing all 11 repository traits (`SettingsRepository`, `UserRepository`, `OrgRepository`, `DeviceRepository`, `SessionRepository`, `VaultRepository`, `InviteRepository`, `KeyEnvelopeRepository`, `AuditRepository`, `SyncRepository`, `CollabRepository`).
  - Executable forward-only database schema migration runner (`shellumi-server migrate run`) executing embedded SQL migrations transactionally with idempotency tracking.
  - Active database readiness probe (`/health/ready`) and self-check diagnostics (`shellumi-server doctor`) probing real PostgreSQL connection and queries.
  - Standard RFC 2104 HMAC-SHA256 token verification with dynamic per-instance signing keys and active session introspection.
  - Cryptographic device proof-of-possession challenge endpoint (`POST /api/v1/devices/challenge`) validating single-use challenge signatures, 32-byte Ed25519 signing keys, and 32-byte X25519 key-agreement keys.
  - Direct-DEK encrypted record envelope support (`aes256gcm_dek_v1`) without mandatory PBKDF2 iterations, length-delimited canonical binary mutation preimage formatting, and strict rejection of past and future key epochs (`FutureKeyEpoch`).
  - Scoped recipient device discovery (`GET /api/v1/vaults/:id/recipient-devices`) restricted to active vault members.
  - Monotonic transaction sequence allocation assigning a unique ordered sequence to each mutation in atomic batch commits.
  - Standard WebSocket instant notifications endpoint (`GET /api/v1/events/ws`) supporting `subscribe`, `subscribed`, `vault.changed`, `vault.key_rotated`, `vault.access_revoked`, `ping`, and `pong` frames with post-commit fan-out.

- **Phase 11 Audit Remediation: Security Hardening & Documentation Truth**
  - Cryptographically secure random token signing key generation using OS CSPRNG (`ring::rand::SystemRandom`) when not explicitly configured, with minimum length validation (>= 32 bytes).
  - Universal active session and device validation across all 38 protected REST route handlers (`extract_auth_claims`), immediately invalidating access tokens upon logout or revocation.
  - Strictly mandatory Ed25519 proof-of-possession challenge and signature verification during device enrollment (`POST /api/v1/devices`).
  - Atomic Compare-And-Swap (CAS) and anti-replay validation within a single PostgreSQL transaction (`SELECT FOR UPDATE`), validating `expected_revision`, idempotency, and monotonic per-device counter (`device_sync_counters`).
  - Atomic bootstrap and invite acceptance preventing partial state mutations.
  - Canonical whole-envelope SHA-256 digest computation binding suite, nonce, salt, iterations, associated data, and ciphertext.
  - Multi-instance cross-process WebSocket and poll notification fan-out via PostgreSQL `LISTEN`/`NOTIFY` (`shellumi_sync_events`).
  - Strict cursor parsing rejecting malformed cursors with `400 INVALID_CURSOR`.
  - Consistent watermark recovery snapshots (`GET /api/v1/vaults/:id/snapshots` and bounded `/snapshots/:revision`).
  - Database-backed migration status reporting (`shellumi-server migrate status`).
  - Complete overhaul of `README.md` with project description, architecture diagrams, operating modes, CLI usage, deployment guides, and status badges.


- Corrected Phase 11 scope to one server process per independent installation; subscription requests are atomic and capped at 128 vaults, and envelope publication emits a change hint rather than claiming a key rotation.

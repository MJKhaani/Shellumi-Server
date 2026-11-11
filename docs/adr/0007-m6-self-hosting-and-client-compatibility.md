# ADR 0007: M6 Self-Hosting Architecture, Client Compatibility & Provider Boundaries

- **Status:** Accepted
- **Date:** 2026-11-11
- **Context:** Shellumi Server Milestone M6 (Advanced Self-Hosting, Integration & Compatibility Hardening).

## Context & Problem Statement

Shellumi is designed as a local-first application capable of operating in three distinct, isolated storage and synchronization modes:
1. **Local-Only:** No server, no external network, local SQLite/Turso database.
2. **Personal Google Drive:** Direct client-side `appDataFolder` integration without intermediate proxies.
3. **Self-Hosted Shellumi Server:** An independently deployed Rust service providing multi-device synchronization, role-based vault sharing, and optional real-time terminal collaboration.

To ensure client autonomy and prevent vendor lock-in or mandatory server dependencies, the boundary between the Shellumi desktop client and Shellumi Server must be strictly defined and validated. Furthermore, the server must provide reliable self-hosting guarantees: zero knowledge of plaintext data, deterministic conflict detection, robust disaster recovery, and wire protocol compatibility across client versions.

## Decision Drivers

1. **Client Autonomy:** Shellumi desktop/CLI clients must never treat Shellumi Server as a mandatory dependency. Offline operation, local credential stores, and Google Drive mode must remain completely unaffected.
2. **Zero Plaintext Guarantees:** Server memory and persistent PostgreSQL tables must never store plaintext vault records, SSH credentials, private keys, sync passphrases, or terminal keystrokes.
3. **Explicit Multi-Tenant Isolation:** All database transactions, change feeds, cursors, and event broadcasts must be strictly scoped to tenant and vault identifiers with defense against Insecure Direct Object Reference (IDOR).
4. **Deterministic Concurrency & Conflict Detection:** Avoid silent data loss or unconditional last-write-wins by assigning transactional monotonic sequence numbers and requiring expected revision (`expected_revision`) checks.
5. **Operational Simplicity:** Deployable as a single static binary or minimal non-root Docker container with PostgreSQL. No mandatory cloud SaaS, Redis, or Kafka dependencies.

## Architectural Boundaries

### 1. The Client-Server Provider Boundary

The Shellumi client interacts with remote backends via a `SyncProvider` abstraction:
- The server exposes a versioned JSON REST API under `/api/v1` and Server-Sent Events / long-polling for real-time collaboration.
- The server does not proxy Google OAuth or access Google Drive data.
- The server does not decrypt, parse, or evaluate SSH host definitions or credentials. All entity payloads are opaque Base64-encoded ciphertexts wrapped in authenticated `EncryptedEnvelope` structures.
- Vault encryption keys (DEKs) are generated client-side and sealed directly to recipient device X25519 public keys (`KeyEnvelopeItem`). Plaintext DEKs never traverse the wire or touch server memory.

### 2. Concurrency and Revision Guarantees

- **Transactional Sequence Allocation:** Every commit within a vault is assigned an authoritative, monotonically increasing `server_sequence` number using database transactions.
- **Conditional CAS Writes:** Mutations submit an `expected_revision`. If the stored object revision does not match the expected revision, the server rejects the commit with HTTP 409 `CONFLICT_STALE_REVISION`.
- **Idempotency Tracking:** Client-provided UUID `idempotency_key` ensures that retransmitted commits (e.g. following network timeouts) return identical acknowledgements without re-applying mutations.
- **Durable Tombstones:** Record deletions generate durable tombstones (`deleted = true`) to prevent silent deletion resurrection.

### 3. Wire Protocol & Version Negotiation

- Wire protocol version is advertised via `GET /api/v1/capabilities`.
- Protocol Version 1 specifies:
  - Envelope suites: `x25519_hkdf_aes256gcm`, `argon2id_aes256gcm_legacy`.
  - Authentication: Argon2id password hashing, HMAC-SHA256 access tokens (15m TTL), SHA-256 hashed refresh tokens (30d TTL).
  - Device keys: Ed25519 signing keys, X25519 agreement keys.
  - Collaboration: Monotonic single-writer lease fencing, emergency host termination.

## Consequences & Security Invariants

### Positive
- Total independence between desktop client offline use and self-hosted server deployments.
- Guaranteed data confidentiality: compromise of server storage or database backups yields only opaque ciphertext envelopes and recipient-wrapped key envelopes.
- Deterministic conflict detection preserves history and allows clients to present visual three-way merge dialogs.
- Clean containerization with non-root runtime, zero external runtime dependencies beyond PostgreSQL, and complete CLI administration tooling.

### Limitations & Trade-offs
- The server cannot perform server-side full-text search across encrypted vault contents. Search is executed client-side over decrypted local caches.
- Historical ciphertext envelopes downloaded by a member prior to revocation remain in their possession; revoking a member prevents future writes and epoch keys, but cannot reach into already exported client storage.

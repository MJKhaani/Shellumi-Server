# Shellumi Server — Architecture & System Design

## 1. Architectural Principles

1. **Self-Hosted First:** Headless, single-binary Rust service, easily deployed via Docker Compose or native systemd services without third-party cloud requirements.
2. **Zero Plaintext on Server:** The server stores opaque, client-encrypted envelopes and recipient-wrapped key envelopes. Plaintext vault data, SSH private keys, passphrases, credentials, and live terminal keystrokes never touch server memory or persistent storage.
3. **Modular Crate Architecture:**
   - `shellumi-server-protocol`: Pure wire types, DTOs, versioning constants, and serialization. No database or web dependencies.
   - `shellumi-server-domain`: Pure business rules, role policies, permission checks, configuration schema, and domain errors.
   - `shellumi-server-crypto`: Cryptographic utilities, Ed25519 signature verification, canonical AAD framing, and envelope structure validation.
   - `shellumi-server-store`: Data storage repository traits (`Store`, `UserRepository`, `DeviceRepository`, `SessionRepository`, `VaultRepository`, `SyncRepository`, `KeyEnvelopeRepository`, `AuditRepository`, `CollabRepository`) and in-memory implementation.
   - `shellumi-server-auth`: Argon2id password verification, HMAC-SHA256 bearer tokens, SHA-256 hashed refresh token rotation, and device management.
   - `shellumi-server-sync`: Transactional change feed sequencing, conditional CAS revision enforcement, idempotency tracking, and tombstones.
   - `shellumi-server`: Axum HTTP/WSS API adapter, routing, rate limiting, Prometheus metrics, live collaboration relay engine (`CollabHub`), CLI commands, and main executable.
4. **Strict Isolation & Authorization:** Every request is authenticated and authorized against tenant, vault, and device scopes. Default deny on all paths.
5. **Deterministic Concurrency:** Optimistic concurrency control via monotonic vault sequence allocation and `expected_revision` conflict detection (`409 Conflict`).

---

## 2. Component Diagram

```text
+---------------------------------------------------------------------------------+
|                                 Shellumi Client                                 |
|                   (GPUI Desktop / CLI / Future Mobile Client)                   |
+----------------------------------------+----------------------------------------+
                                         | HTTPS / Server-Sent Events
                                         v
+---------------------------------------------------------------------------------+
|                                 Shellumi Server                                 |
|                                                                                 |
|  +--------------------+  +--------------------+  +---------------------------+  |
|  |   Health & Ops     |  |   Auth & Devices   |  |     Collab Relay Hub      |  |
|  |  /health, /metrics |  |  Argon2id, Tokens  |  |   SSE, Single-Writer      |  |
|  |  CLI Admin & Doctor|  |  Ed25519 / X25519  |  |   Fencing, Emergency Term |  |
|  +--------------------+  +--------------------+  +---------------------------+  |
|                                                                                 |
|  +--------------------+  +--------------------+  +---------------------------+  |
|  |     Sync & CAS     |  |   Vault & Invites  |  |       Audit Engine        |  |
|  | Delta Feed, Cursor |  | Wrapped Envelopes  |  | Hash-Chained Append Log   |  |
|  | 409 Conflict, Idem |  | RBAC Matrix (4-Tier|  | Predecessor Hash Check    |  |
|  +--------------------+  +--------------------+  +---------------------------+  |
|                                                                                 |
|  +---------------------------------------------------------------------------+  |
|  |                    Domain & Authorization Engine                          |  |
|  |                    (Strict Tenant & Vault Isolation)                      |  |
|  +---------------------------------------------------------------------------+  |
|                                                                                 |
|  +---------------------------------------------------------------------------+  |
|  |               Repository Storage Traits (Store / SQLx Engine)             |  |
|  +---------------------------------------------------------------------------+  |
|                                         |                                       |
|                                         v                                       |
|  +---------------------------------------------------------------------------+  |
|  |                         PostgreSQL Persistence                            |  |
|  |  Forward-only migrations: 001(core), 002(sync), 003(teams), 004(collab)    |  |
|  +---------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------+
```

---

## 3. Trust Zones & Boundaries

- **Client Zone (Trusted):**
  - Manages master keys, OS keychain credentials, and per-device private keys (Ed25519 signing, X25519 key-agreement).
  - Performs all AEAD encryption and decryption of vault records before dispatch.
  - Generates 256-bit vault DEKs and wraps them directly to recipient device public keys.
- **Transport Zone (Encrypted):**
  - TLS 1.3 encryption across network hops.
  - Bounded request size checks (max 10 MiB request body, max 1 MiB record ciphertext).
  - Sliding-window IP rate limiting on unauthenticated/sensitive endpoints.
- **Server Zone (Untrusted for Plaintext):**
  - Authenticates users and devices, authorizes role capabilities, transactionally coordinates revision numbers, and records immutable audit hashes.
  - Blind ciphertext forwarder: even in the event of an arbitrary database dump, the attacker obtains zero plaintext credentials, zero SSH private keys, and zero unencrypted terminal data.

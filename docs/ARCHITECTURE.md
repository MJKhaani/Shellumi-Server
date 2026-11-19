# Shellumi Server — Architecture & System Design

> **Current implementation:** The runtime uses `InMemoryStore`, not PostgreSQL. The diagram below describes the target architecture; data is lost on restart. Notification isolation and recovery tests are incomplete.

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
|  |               Repository Storage Traits (Store / planned SQLx)             |  |
|  +---------------------------------------------------------------------------+  |
|                                         |                                       |
|                                         v                                       |
|  +---------------------------------------------------------------------------+  |
|  |                         Planned PostgreSQL Persistence                            |  |
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

### Experimental sync notifications

The HTTP process maintains a bounded, process-local broadcast channel for team
vault change hints. Each connection rechecks device status and vault membership
before forwarding a hint; the change feed remains authoritative. The channel is
not durable or shared across server processes. Disconnect or receiver lag requires
a full client reconciliation. WebSocket authentication requires a session-bound
access token; a single-session logout signals that session’s sockets to close, and an all-session logout signals all of the user’s sockets, while session validity,
token expiry, and device revocation are checked during delivery and heartbeat. The bounded long-poll fallback uses the same process-local broadcast channel;
it has gaps between requests and requires REST reconciliation.

Each running router has an ephemeral notification origin distinct from the persistent server installation identity. Successful material HTTP operations publish best-effort PostgreSQL NOTIFY hints and dispatch locally; peer listeners suppress only their own origin. NOTIFY is transient, has no durable outbox, and can be lost during disconnects or publication failures. Clients must reconcile from authenticated REST snapshots and change feeds after reconnect or a resync indication; multi-instance recovery is not yet fully tested.

The supported deployment is one server process per independent installation and database. Independent servers do not communicate or replicate. A client maintains a separate authenticated connection per server and may subscribe to multiple vaults on each connection. Shared-database multi-process fanout is experimental and is not a Phase 11 gate.

PostgreSQL commit transactions lock the vault, device, and membership rows through authorization and mutation, including cached retries. Device revocation, role changes and key epoch changes therefore serialize with the affected commit; denied commits do not allocate a sequence.

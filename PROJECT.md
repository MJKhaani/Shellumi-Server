# Shellumi Server — Master Project Specification

**Project:** Shellumi Server  
**Suggested repository:** `github.com/MJKhaani/Shellumi-Server` (new, separate repository; not created by this specification)  
**Implementation:** Rust (Tokio / Axum), API-first, headless, self-hosted  
**License:** MIT  
**Status:** architecture and acceptance specification — **NOT** a claim that the server already exists  
**Client reference:** [`MJKhaani/Shellumi`](https://github.com/MJKhaani/Shellumi), `main` commit `c99a2c2a3239e899ec6e5a1c12823fad3e77d3c6`, inspected 2026-11-10  
**Agent rules:** [`AGENT.md`](AGENT.md), discoverable through [`AGENTS.md`](AGENTS.md)

---

## 1. Executive mandate

Create **Shellumi Server**, a high-quality, MIT-licensed, **optional self-hosted backend** for the existing Shellumi Rust/GPUI SSH and infrastructure client. It supports encrypted cross-device synchronization, team/user organization, vault sharing, granular access, device registration, invitations, revocation, audit, and optional secure real-time collaboration. No user must depend on a Shellumi-hosted cloud. Everything important runs on infrastructure the user or organization controls.

The server is **not** a remote SSH client, a password escrow service, a terminal recording collector, or an obligatory sign-in service. Ordinary SSH connections, local terminal emulation, SFTP and tunnels continue to execute on client devices. The server cannot decrypt user vault content under the documented threat model.

### 1.1 Three first-class client modes

| Mode | Provider / requirements | Primary capabilities | Server involvement |
| --- | --- | --- | --- |
| **Offline / Local** | Embedded client Turso DB | All local management, connections and encrypted backups | None |
| **Personal Google Drive** | User's Google account; `drive.appdata` OAuth scope; client-side encryption | Personal encrypted backup and eventual multi-device sync | **None:** direct client ↔ Google Drive |
| **Self-hosted Shellumi Server** | Explicit HTTPS/WSS endpoint + enrolled account/device | Encrypted personal and shared vault sync; teams; RBAC; invitations; device lifecycle; audit; optional real-time collaboration | User-hosted server only |

A user can have different **vaults** mapped to different providers, but **one authoritative sync provider per vault at a time**. No automatic bidirectional Drive↔Server bridge; any migration requires a user-confirmed export/import, canonical ID mapping, encrypted backup and an explicit cutover. A disabled/unreachable server never blocks offline local client operation. A local-only user must not be nagged to register.

### 1.2 Goals

- Simple self-hosting: single Rust service binary, container image, Docker Compose with PostgreSQL; no Kubernetes required.
- Professional multi-user collaboration with no mandatory external IdP, SMTP server, Google account, or Shellumi-operated infrastructure.
- Secure, data-loss-resistant concurrent synchronization with offline clients.
- Open, documented versioned API usable by current and future desktop/mobile Shellumi clients.
- Secure by default: client-side encryption, least privilege, strong server authentication, tenant isolation, key rotation, idempotent writes, tested recovery.
- Reproducible tag-driven GitHub releases: native binaries, multi-platform OCI image, checksums, SBOM, provenance, release notes.
- Each increment proven by automated tests and recorded in progress logs (see `AGENT.md`).

### 1.3 Explicit non-goals for v1

- No proprietary cloud subscription, forced account, hosted synchronization by the project, tracking, or default telemetry.
- No server-side reading, searching or indexing of plaintext vault items; no password recovery by server administrators.
- No automatic Google Drive proxy or access to a user's general Drive files.
- No server-side SSH executor, SFTP proxy, credential broker, bastion, shell command runner, or mandatory remote access gateway.
- No simultaneous writes of the same vault through separate Drive and Server backends.
- No server-side copy of live terminal I/O or plaintext screen unless a distinct, informed, opt-in design is accepted (default: none).
- No fabricated claims that existing client mock/domain collaboration code is a functioning network service.

---

## 2. Verified client baseline and integration constraints

The reference client is a Rust 2021 Cargo workspace with five members: `shellumi-app` (GPUI), `shellumi-core`, `shellumi-storage` (embedded `turso = 0.9.0-pre.2`), `shellumi-cli`, and `shellumi-terminal`. Shellumi currently declares version `0.0.6-alpha` in the core and storage crates. It already has native desktop features, real SSH/SFTP, and encrypted local backup functionality. **Do not reimplement the desktop in the server.**

### 2.1 Components to reuse *conceptually* (evaluate source before extracting)

| Client source | Existing building blocks | Server implication |
| --- | --- | --- |
| `crates/shellumi-core/src/sync.rs` | `SyncRecord`, `SyncVault`, `SyncEntityType`, `EncryptedEnvelope`, AES-256-GCM/PBKDF2, conflict/diff models, Google Drive API and scheduler | Preserve legacy formats; design new shared wire contracts, persisted revisions, conditional writes; don't import Google transport into server |
| `crates/shellumi-core/src/collaboration.rs` | `SharedVault`, `TeamMember`, `TeamRole` (Owner/Admin/Editor/Viewer), membership, audit and single-writer terminal state machines | Share/align policies and enum serialization, but add real authenticated server enforcement and cryptographic enrollment |
| `crates/shellumi-storage/src/lib.rs` | Local Turso v14 schema, CRUD, encrypted export/import, snapshots, team records | Build separate PostgreSQL server schema and an explicit client-side adapter/migration; do not expose Turso over the network |
| `crates/shellumi-app/src/main.rs` | GUI sync panel, env-token-driven Google Drive sync, conflict dialog, local vault invitation management | Integrate actual server provider, account/device setup, real invites and error states without implying current code is network sharing |
| `crates/shellumi-cli/src/main.rs` | Vault export/import/sync and local collaboration commands | Add optional server commands for login, enroll, status, vault migration and admin management |
| `SYNC_DESIGN.md`, `docs/FEATURE_MATRIX.md`, `docs/GUI_STATUS.md` | Prior design, current limitations, threat model pointers | Keep docs and status matrices synchronized across client/server repositories |
| `.github/workflows/release.yml` | Native tag-triggered release precedent | Build independent server release workflow, with test/attestation/multiarch gates |

### 2.2 Confirmed client sync limitations that server work MUST address

1. `HostStore::export_vault` currently constructs a new vault ID (`vault-{device_id}-{now}`) for each export, which is not a durable remote vault identity.
2. Many exported `SyncRecord` values use `version = 1`, with the current timestamp on each export; keys such as `host.name:hostname` or snippet name are mutable/nonnumeric and can collide. Persist stable UUIDs, revision bases, device identity and tombstones instead of inferring changes from fresh snapshots.
3. Local foreign keys for identities, snippets, hosts and tunnels are integer IDs; a second device can assign different row IDs. Provide stable portable IDs and a migration/reconciliation mapping that preserves all relationships and tests duplicate names/rename/deletion cases.
4. `SyncEntityType` covers hosts, groups, tunnels, snippets, workspaces, shared vaults, team members, audit records, cloud providers and identities, but not every future preference/known-host/session-log category. Add an explicit eligibility matrix; default to **metadata only** and user opt-in for sensitive content.
5. Existing encrypted envelopes use AES-256-GCM with PBKDF2-HMAC-SHA256 (default 600,000 iterations). The old `SYNC_DESIGN.md` also discusses future Argon2id and alternative AEAD algorithms. **Treat code as authoritative for the legacy format**; add an explicit versioned encryption suite and tested migration, not a breaking silent replacement.
6. The currently integrated Google Drive UI needs an externally supplied token and vault passphrase and uses a synchronous system HTTP transport; real-account multi-device safety and OAuth setup remain work items. **Maintain Google Drive as a standalone direct provider** and improve it as a separate client increment; the server must not be an accidental dependency.
7. `SharedVault::rotate_key()` currently increments an epoch; this alone is **not cryptographic key rotation**. Full client-generated epoch keys, recipient wrapping and future ciphertext re-encryption policy are required.
8. Local team invitation currently records a public OpenSSH key and a member locally; it does not authenticate/invite an online user or transport encrypted vault keys. Use dedicated device signing/agreement keys and a server-backed invitation/enrollment protocol.
9. Current `SyncRecord::determine_sync_action` compares versions/timestamps and `execute_cloud_vault_sync` updates Drive without an established server-style revision CAS. New server sync cannot rely on this algorithm as proof of concurrency safety. Preserve a migration path and write adversarial two-client tests.
10. Local session collaboration state models are not network transport. Real-time collaboration requires authenticated WSS signaling/relay, E2EE session keys, per-frame permission gates, bounded queues and reconnect handling.

### 2.3 Client/server integration contract

- Establish a small independent `shellumi-protocol` crate, publishable/versionable or vendored via an intentionally pinned source revision. It contains **only** DTOs, canonical serialization, validation, typed errors, cryptographic envelope descriptions and capability negotiation. Neither GPUI nor local Turso nor Axum/SQLx belongs here.
- Before sharing a crate across repos, specify license, release cadence, optional features and semver compatibility. A dedicated protocol repository or Git submodule is **not** required for the MVP; a vendored generated OpenAPI client can suffice if drift tests cover both sides.
- For each wire version, retain golden JSON/CBOR fixtures and contract tests in both repositories. The server advertises capabilities and minimum/maximum protocol versions. The client displays a clear upgrade error for unsupported versions.
- Keep legacy encrypted file import/export intact; add a deliberate one-way migration with backups and verification instead of rewiring legacy structures silently.

---

## 3. High-level architecture

```text
 +---------------------+      +---------------------+
 | Shellumi GPUI       |      | Shellumi CLI /      |
 | Desktop Client      |      | Future Mobile Client|
 | local Turso + keys  |      | local data + keys   |
 +----+----------+-----+      +----------+----------+
      |          |                       |
      |          +--> Google Drive API   | (personal sync only)
      |               appDataFolder      |
      |                                  |
      +----------- HTTPS/WSS ------------+
                      |
        +-------------v-------------------------------+
        | SHELLUMI SERVER (Rust, self-hosted)          |
        | Axum API / Auth / RBAC / Sync / Invites      |
        | Device registry / encrypted key envelopes  |
        | audit / change feed / optional WS relay    |
        | no vault plaintext, no master keys         |
        +-------------+-------------------------------+
                      |
              PostgreSQL (durable)
              metadata + opaque ciphertext
              snapshots / migrations / audit

   Optional later: S3-compatible encrypted blob storage,
   OIDC, SMTP, Redis-backed horizontal event distribution.
```

**Trust boundaries:** A compromised server may deny service, misreport membership, suppress events or delete ciphertext; encryption alone cannot guarantee availability or prevent rollback. Clients MUST authenticate data and detect stale/forked server state to the extent supported by signed revisions/checkpoints. TLS prevents network interception but does not make the operator trusted with vault plaintext. Opaque ciphertext does **not** conceal member lists, IPs, record sizes, timing or selected metadata unless extra measures are taken.

### 3.1 Architectural modules (suggested Rust workspace)

```text
shellumi-server/
├── Cargo.toml                   # pinned workspace + Rust version
├── Cargo.lock
├── rust-toolchain.toml
├── LICENSE                      # MIT
├── README.md
├── AGENT.md                     # canonical agent rules
├── AGENTS.md                    # Codex/agent-discovery shim
├── PROJECT.md                   # this specification
├── CHANGELOG.md
├── SECURITY.md
├── Dockerfile                    # multi-stage, non-root
├── .dockerignore
├── .github/workflows/
│   ├── ci.yml                    # PR/branch tests (never publishes)
│   ├── release.yml               # tag-only binary + GHCR + release
│   └── security.yml              # dependency/container audit
├── crates/
│   ├── shellumi-server/          # Rust binary: bootstrap, config, API composition, shutdown
│   ├── shellumi-server-domain/   # policies, roles, tenant/vault/sync state, pure logic
│   ├── shellumi-server-protocol/ # versioned public DTOs & validation, OpenAPI fixtures
│   ├── shellumi-server-crypto/   # signature validation, wrapped key envelope validation
│   ├── shellumi-server-store/    # SQLx migrations, repository traits, PostgreSQL impl
│   ├── shellumi-server-auth/     # sessions, tokens, device enrollment, account auth
│   ├── shellumi-server-sync/     # conditional writes, cursors, tombstones, notifications
│   └── shellumi-server-relay/    # optional WSS terminal collaboration relay
├── migrations/                  # forward-only SQL migration history
├── deploy/
│   ├── docker-compose.yml       # secure single-node example
│   ├── .env.example             # no real credentials
│   ├── caddy/Caddyfile          # optional TLS reverse proxy
│   └── test/compose.yml         # ephemeral PostgreSQL for CI
├── docs/
│   ├── PROGRESS.md              # mandatory append-only engineering journal
│   ├── ROADMAP.md
│   ├── ARCHITECTURE.md
│   ├── COMPATIBILITY.md
│   ├── API.md
│   ├── CONFIGURATION.md
│   ├── DEPLOYMENT.md
│   ├── BACKUP_RESTORE.md
│   ├── adr/
│   ├── security/THREAT_MODEL.md
│   ├── security/KEY_MANAGEMENT.md
│   └── development/{TESTING,RELEASES}.md
├── openapi/shellumi-server-v1.yaml
├── tests/{integration,e2e,security,fixtures}/
└── benches/
```

Do not make a separate crate without a real testability or dependency-boundary reason. Prefer a modular monolith over multiple independently deployed microservices in the initial releases.

### 3.2 Preferred dependencies and runtime

- **Rust:** stable, Cargo.lock committed; Tokio for async execution.
- **HTTP:** Axum, Tower middleware; Rustls TLS at reverse proxy (or first-party TLS for non-container use if required).
- **Serialization/API:** Serde, JSON for v1 REST API; canonical bytes for signatures; OpenAPI 3.1 via a maintained generator such as utoipa (validate current crate compatibility).
- **DB:** PostgreSQL + SQLx compile-time checked queries/migrations; nonblocking pool; database constraints and transactions. No runtime requirement for Redis, Kubernetes or message broker at v1.
- **Cryptography:** well-reviewed maintained Rust implementations for Ed25519 signatures, X25519 key agreement, HKDF, AEAD and Argon2id, with documented algorithm IDs and independently generated test vectors. Reuse legacy AES-GCM envelope decoding only when required for migration; **never implement primitives from scratch**.
- **Auth:** short-lived signed or opaque access tokens, rotating refresh tokens stored only as hashes, secure recovery and invalidation; optional WebAuthn/passkeys and OIDC after local user/device auth is working.
- **Monitoring:** tracing structured JSON, Prometheus/OpenMetrics endpoint optional, privacy-preserving traces, health probes. Never include token/ciphertext content in logs.
- **Dependencies:** audit maintenance, licenses, advisories, build reproducibility, MSRV and Linux ARM support before adoption.

---

## 4. Core entities and persistence model

Use UUIDv7 (or UUIDv4 with equivalent uniqueness) for all **public, persistent** resources, separate from local device SQL row numbers. UUIDs are not authorization. All schema rows that carry tenant data include `tenant_id` or an enforceable vault→tenant FK with tenant-scoped queries. Use database constraints and transactions for invariants, not only handler checks.

| Table / entity | Essential fields / invariant |
| --- | --- |
| `server_settings` | install ID, schema version, bootstrap consumed marker, policy flags |
| `users` | ID, display name, normalized account identifier, credential verifier or external IdP subject, status; no vault keys |
| `organizations` / `memberships` | tenant scope, owners/admins, organization membership; no cross-tenant access |
| `devices` | user, dedicated Ed25519 signing key, X25519 agreement key, trust state, last seen, revoke timestamp, monotonic counter |
| `sessions` / `refresh_tokens` | hashed token ID, device, scope, expiry, rotation chain, revocation state |
| `vaults` | ID, tenant, type personal/shared, encrypted display metadata if private, owner, active key epoch, server sequence, retention/quota |
| `vault_members` | user/device, role, enrollment and revocation, effective epoch, server policy |
| `vault_invites` | hashed random one-time secret, vault/role/inviter, expiration, recipient constraints, accepted/revoked state |
| `vault_key_envelopes` | vault ID, epoch, recipient device ID, *client-generated wrapped DEK*, signed sender metadata; no plaintext DEK |
| `records` | vault, entity UUID/type, ciphertext envelope bytes, key epoch, object revision, signed author/device, tombstone, ciphertext digest |
| `change_log` | append-only per-vault sequence, record revision, mutation ID, operation, timestamp; cursor source |
| `mutation_idempotency` | tenant/device/mutation ID, request digest, previous response, retention window |
| `sync_cursors` (optional) | device acknowledged sequence, last handshake; cursor tokens signed/opaque |
| `audit_events` | server-observed action, actor/device, tenant/vault, target, timestamp, hash predecessor + signed checkpoints as designed |
| `collaboration_sessions` | owner device, eligible vault, active state, writer lease/fencing generation, participants and end reason |
| `session_event_offsets` | bounded volatile notification/relay state; no plaintext terminal stream persistence |

### 4.1 DB and storage rules

- PostgreSQL is the **MVP supported database**. A standalone binary may connect to an existing DB or a Compose-managed local DB. SQLite is **not** promised in v1; consider it later only if transactional sequence/lock semantics and migrations are thoroughly implemented/tested.
- Encrypt data on clients before transmission. Use DB encryption at rest/disk controls as defense in depth, not as a substitute for E2EE.
- Start with bounded ciphertext blobs in PostgreSQL (example safe default: ≤1 MiB per record, ≤10 MiB per commit request; tune after benchmark); reject oversize before allocating fully. Add S3-compatible storage in a later milestone for large encrypted attachments, including integrity/digest checks and per-tenant quotas.
- Use server-issued opaque `next_cursor` for change feed; keep cursors bound to vault, device/access scope and snapshot sequence. Cursor expiry/compaction has a defined `resync_required` response and non-destructive snapshot recovery.
- Delete means tombstone, not silent physical erasure until **all** necessary active-device cursors and retention policies permit compaction. Device inactivity thresholds and re-bootstrap semantics must be explicit.
- Never regenerate public object IDs on every export. Preserve local→portable ID mappings and reference integrity across rename, restore and re-enrollment.
- Isolation regression tests must include rogue UUIDs, vault lookups, pagination, notifications, audit and key-envelope reads from unrelated tenants.

---

## 5. End-to-end encryption, device identity and key management

Security-sensitive architecture must be reviewed with explicit threat assumptions and real tests before enabling production sharing. Document all cryptographic field sizes, versioning, signature contexts and failure semantics in `docs/security/KEY_MANAGEMENT.md`.

### 5.1 Keys and content

- Every authorized device generates a **distinct** Ed25519 signing keypair and X25519 agreement keypair locally (native OS protected key store where possible). **Never assume the SSH authentication key can serve either purpose.**
- Each vault owns a random 256-bit data encryption key (DEK) or versioned per-epoch derived content key. All vault records are sealed client-side with a well-reviewed AEAD. New shared-vault suite should use a versioned envelope and a memory-hard Argon2id-based passphrase wrapping scheme *only where passphrases are used*, but no recipient's DEK is derived from or sent with a password to the server.
- Vault DEKs are wrapped to each authorized **device's** X25519 public key using an audited HPKE-style or well-documented X25519+HKDF+AEAD sealed envelope, with sender-authenticated context; never invent a novel key exchange. The recipient unwraps locally.
- All content encryption uses unique nonces for each key; bind immutable, canonical AAD (`protocol_version`, `tenant_id`, `vault_id`, `object_id`, `entity_type`, `epoch`, `content_schema_version`, and optionally record lineage). AAD and signature structure are precisely versioned and included in both client/server test vectors.
- Every commit carries a device signature over canonical serialized mutation fields and ciphertext digest. Verify registered device ownership, signing key, counter, epoch and authorization before DB commit. Signatures cannot replace server RBAC; server RBAC cannot replace E2EE.
- Keep **legacy client AES-256-GCM/PBKDF2** backups readable and authenticated. Avoid silent re-encryption or password/KDF parameter reinterpretation. A versioned migration wizard exports an encrypted backup, verifies import and writes the new suite only after confirmation.

### 5.2 Onboarding and invitation safety

- First-time owner establishes a server account, enrolls the first trusted device and receives an installation/endpoint fingerprint or verifiable trust metadata.
- Device onboarding requires authenticating the user, explicit approval by an already trusted device or recovery mechanism, and verification of new device public keys. Do not automatically grant prior vault keys to every authenticated browser/device.
- Creating an invite produces a cryptographically random high-entropy single-use secret (server stores only hash), bound to vault, role, optional recipient and expiration; optional SMTP merely delivers a link. A secure copyable invite URL works without mail infrastructure.
- Invitation acceptance must verify server identity, authenticated recipient, device key proof of possession, server membership state and owner approval policy. Share a wrapped key only when all checks pass.
- Avoid relying on email or OpenSSH public keys alone as encryption identity. Display verifiable fingerprints/safety codes to humans.

### 5.3 Rotation and revocation

- On member/device revoke, server **immediately** denies new data, key envelopes, change feed, notifications and session inputs to that principal; invalidate/rotate tokens and writer leases.
- A remaining authorized client creates a **new vault epoch key**, re-wraps it to surviving trusted devices, and encrypts subsequent writes under that epoch. The server rejects writes using revoked/stale epochs after the transition commits.
- Define a safe, resumable migration strategy for old objects (re-encrypt at next modification and/or explicit full rekey, depending on confidentiality policy). Ensure offline devices receive new wraps when they next authenticate; prevent mixed-epoch data loss.
- A revoked member may retain ciphertext/plaintext downloaded before revocation. **No design can retroactively erase previously obtained secrets**. For critical SSH secrets, recommend rotating upstream credentials separately; client-side re-encryption alone is insufficient.
- Recovery: recovery key or trusted-device-assisted restore; server administrators cannot reset an E2EE master secret or decrypt vault data. Document the irreversible loss case.

### 5.4 Threat model and anti-rollback

Consider a compromised DB, a malicious server administrator, stolen device, token theft, spoofed invitation, replay, stale device, packet reordering, colluding members and denial of service. Client software must verify AEAD tags and signatures, pin/verify device identities as defined, and persist trusted last-seen revision/checkpoints. A server may suppress newer changes; use signed checkpoints or multiple-device consistency checks to detect detectable rollbacks/forks without pretending to guarantee availability. Explain which metadata remains observable to the administrator.

---

## 6. Accounts, organizations and authorization

### 6.1 Self-hosting-first authentication

- Default **invite-only** installation. First launch requires one-time bootstrap via a CLI command or local bootstrap token; the initial admin is created exactly once, without an insecure reusable default username/password.
- Support local username/email + Argon2id password verifier, secure password policy, login throttling, optional TOTP/MFA, secure reset requiring approved trusted recovery. No open public registration by default.
- Enroll named devices, list last-seen activity, revoke individual devices, and rotate short-lived access/refresh tokens. Store refresh token hashes, rotate on use, detect reuse, terminate sessions promptly.
- OIDC/OAuth2 login with self-hosted provider (e.g., Keycloak, Authentik) may be introduced after core auth. Optional SAML through an external gateway is later scope; do not describe unbuilt SSO as a current feature.
- TLS required except local `127.0.0.1` development/test. Trust a reverse-proxy forwarding header only when the proxy IP is explicitly trusted. Do not expose the bootstrap endpoint publicly after completion.

### 6.2 Permission matrix (initial policy)

| Action | Owner | Administrator | Editor | Viewer |
| --- | :---: | :---: | :---: | :---: |
| Read authorized encrypted vault records | ✓ | ✓ | ✓ | ✓ |
| Create/update/delete encrypted records | ✓ | ✓ | ✓ | — |
| Invite/revoke members | ✓ | ✓ | — | — |
| Assign Editor/Viewer roles | ✓ | ✓* | — | — |
| Promote Administrator or transfer ownership | ✓ | — | — | — |
| Trigger epoch/key rotation | ✓ | ✓ | — | — |
| Read authorization/audit metadata | ✓ | ✓ | — | — |
| Start/host a collaborative session | ✓ | ✓ | ✓ | — |
| Join an invited terminal as viewer | ✓ | ✓ | ✓ | ✓ |
| Become terminal writer | Session-owner grant, subject to role and policy | Session-owner grant | Session-owner grant | — |

\* Administrators cannot grant privileges at or above their own role, remove the last owner, or self-escalate; exact hierarchy must be enforced on the server and verified by tests. The session owner can always revoke writer control, even if an administrator otherwise has administrative rights; define emergency org-admin termination explicitly. Every policy action is audited. Encrypted data visibility also depends on possession of a valid epoch key; RBAC cannot grant retroactive decryption without a client-generated key envelope.

---

## 7. Versioned REST and WebSocket API

Base path: `/api/v1`. API contract is published as OpenAPI 3.1 and available from a well-known endpoint. Every response includes `request_id` and stable machine-readable error codes when applicable. OAuth/OIDC integrations may have explicitly separate callback routes.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health/live` | process liveness; no DB/secret leak |
| GET | `/health/ready` | migrations/DB readiness; restricted details |
| GET | `/api/v1/capabilities` | server version, protocol versions, features, limits, E2EE suite support |
| POST | `/api/v1/bootstrap` | one-time first-admin enrollment, only when explicitly bootstrapping |
| POST | `/api/v1/auth/login` | user authentication; issued access + rotated refresh credentials |
| POST | `/api/v1/auth/refresh` | token rotation, reuse detection |
| POST | `/api/v1/auth/logout` | revoke session/refresh chain |
| GET | `/api/v1/me` | current account and organization memberships |
| GET / POST | `/api/v1/devices` | device inventory / public-key enrollment challenge |
| DELETE | `/api/v1/devices/{id}` | revoke a device and its credentials |
| GET / POST | `/api/v1/orgs` | list/create organization subject to install policy |
| GET / POST | `/api/v1/vaults` | list/create permitted vaults; opaque metadata where needed |
| GET / PATCH / DELETE | `/api/v1/vaults/{vault_id}` | encrypted metadata, policies, archive or delete with safeguards |
| GET / POST | `/api/v1/vaults/{vault_id}/members` | membership listing and permitted changes |
| POST | `/api/v1/vaults/{vault_id}/invites` | scoped, expiring one-time invitations |
| POST | `/api/v1/invites/accept` | verify authenticated recipient and proof-of-key |
| POST | `/api/v1/vaults/{vault_id}/keys/epochs` | commit new epoch and wraps under authorized rotation protocol |
| GET | `/api/v1/vaults/{vault_id}/keys/envelopes` | get wraps for calling device only |
| GET | `/api/v1/vaults/{vault_id}/changes?cursor=...&limit=...` | paginated consistent encrypted delta feed |
| POST | `/api/v1/vaults/{vault_id}/commits` | bounded signed and conditional mutation batch |
| GET | `/api/v1/vaults/{vault_id}/snapshots/{revision}` | encrypted recovery snapshots under policy |
| GET | `/api/v1/vaults/{vault_id}/audit` | scoped paginated audit metadata |
| GET (WSS) | `/api/v1/events` | authenticated change hints / revocations (not authoritative state) |
| POST | `/api/v1/collab/sessions` | create opt-in terminal collaboration session |
| GET (WSS) | `/api/v1/collab/sessions/{id}/connect` | authenticated E2EE session relay |
| POST | `/api/v1/collab/sessions/{id}/writer` | atomic grant/revoke keyboard writer lease |
| DELETE | `/api/v1/collab/sessions/{id}` | terminate and revoke session |
| GET | `/api/v1/admin/status` | access-controlled operational metadata |
| GET | `/metrics` | **disabled or authenticated/internal-only by default** |

### 7.1 Sync record and commit wire format (illustrative, not implemented)

```json
{
  "protocol_version": 1,
  "vault_id": "019abcde-0000-7000-8000-000000000001",
  "base_cursor": "opaque-vault-scoped-token",
  "idempotency_key": "019abcde-0000-7000-8000-000000000099",
  "mutations": [
    {
      "object_id": "019abcde-0000-7000-8000-000000000002",
      "entity_type": "host",
      "expected_revision": 8,
      "deleted": false,
      "key_epoch": 4,
      "device_counter": 104,
      "encrypted_envelope": "BASE64_AUTHENTICATED_CIPHERTEXT",
      "device_signature": "BASE64_SIGNATURE_OVER_CANONICAL_MUTATION"
    }
  ]
}
```

This is a **shape example**, not a cryptographic canonicalization standard. Write a separate normative signed-byte specification and golden fixture set before implementing signatures. `encrypted_envelope` must be a well-defined versioned structure (or canonical byte encoding), not arbitrary unvalidated Base64.

Expected result of a fully applied batch: `200` with `commit_sequence`, assigned per-object revisions and `next_cursor`. If one mutation conflicts, prefer all-or-nothing `409 revision_conflict` with current revisions and no leaked plaintext; do not partially apply unless the protocol explicitly guarantees per-item transactional semantics. Retried identical idempotency keys return the original result; same key + different body returns conflict. Unsupported protocol → versioned upgrade error; stale/compacted cursor → `resync_required` without local data loss.

### 7.2 Change feed behavior

- `GET /changes` returns records in increasing **server-assigned vault sequence**, a signed/opaque continuation cursor, `has_more`, and revision metadata.
- Client applies a page transactionally to local Turso, persists its cursor **only after** durable merge, and preserves unresolved conflicts. The outbound outbox retains local writes until server acknowledgement.
- WSS emits **hints** such as `{vault_id, latest_sequence}`, not authoritative updates. Client still performs authenticated pull. Long-polling fallback is required for hosts without WebSocket support.
- Apply backpressure/connection caps, heartbeat, controlled shutdown and retry with jitter. A disconnected viewer must never receive tenant-foreign notifications.
- A `409` is not automatically resolved by preferring the server's latest timestamp; surface a safe conflict workflow and backup snapshot.

### 7.3 API security discipline

Use TLS, bearer credentials in headers (never URLs), correlation IDs, request limits, strict authentication, explicit content types, no default permissive CORS. Redact `Authorization`, cookies, invitation secrets, device keys, ciphertext and terminal payloads from logs. Replay validation and throttling apply to both HTTP and WS upgrade. Public error messages must not enumerate unrelated account/vault existence. Publish `401`/`403`/`404`/`409`/`413`/`422`/`429` semantics, timeouts and idempotency guarantees.

---

## 8. Synchronization providers and local-client adaptation

### 8.1 Provider abstraction (in the **client**, not the server)

```rust
// Conceptual interface only; exact Rust API is to be designed/tested.
trait SyncProvider {
    async fn capabilities(&self) -> Result<Capabilities, SyncError>;
    async fn pull(&self, vault: VaultId, cursor: Option<Cursor>) -> Result<ChangePage, SyncError>;
    async fn commit(&self, vault: VaultId, batch: SignedMutationBatch) -> Result<CommitAck, SyncError>;
}

// Implementations:
// LocalOnlyProvider (no remote operations)
// GoogleDriveProvider (direct Google appDataFolder; legacy snapshot semantics
//   until redesigned with independent verified concurrency safety)
// ShellumiServerProvider (HTTPS/WSS, delta + conditional writes)
```

This pseudocode does **not** imply that Drive currently offers the same delta/CAS primitives as Shellumi Server. Preserve provider-specific semantics through capabilities and adapters. Do not fake support by adapting a safe API to an unsafe unconditional upload.

### 8.2 Local sync state and records

- Add persistent `device_id`, `vault_id`, `entity_uuid`, `sync_provider`, `server_base_revision`, `last_acknowledged_cursor`, `last_synced_digest`, `change_generation`, deletion tombstone and outbox/inbox tables to the **client** schema via tested migration.
- Use immutable IDs across edits and rename. Persist mapping from legacy Turso `i64` row keys to UUIDs; resolve references transactionally on import (identity IDs, host jump references, snippet references, tunnel host refs and workspaces).
- Local writes commit without network, create a signed/encrypted outbox change, and queue sync with cancellable debounce. After reconnect, pull until caught up, resolve merge conflicts using recorded base revisions, then push conditional mutations. Never mark synced before durable acknowledgement.
- Detect server bootstrap, provider switch, changed server identity/certificate and recovery scenarios; require confirmation for account/vault replacement or divergent histories.
- Sync-on-startup, manual sync, opt-in background periodic sync, progress/error states, last successful sync timestamp and per-vault conflicts. Never silently upload unselected secrets.

### 8.3 Record eligibility and privacy defaults

| Category | Default behavior | Sensitive considerations |
| --- | --- | --- |
| Hosts, groups, tags, snippets, tunnel definitions, workspace templates | Opt-in sync for selected vault | Encrypt metadata and script content; no remote command execution |
| Vault metadata and team membership | Server-backed shared vaults | Metadata may be server-visible for authorization; minimize disclosure |
| Reusable identity metadata | Opt-in | Never transfer local keychain references as usable credentials on another OS; remap per device |
| Passwords/private keys/certificates | **Off by default** | Explicit user choice, source-to-recipient E2EE, recovery and revocation warnings |
| Known hosts/host fingerprints | **Off by default** | Host trust cannot be blindly imported across devices; present fingerprint and approval workflow |
| User preferences | Selected portable settings only | Keep OS-specific paths, font installations and device IDs local |
| Session logs/recordings/audit annotations | **Off by default** | Strong confidentiality/size/retention controls; redaction alone is not sufficient |
| Cloud provider secrets, tokens, MFA material | **Never automatically sync** | Provider keys must be explicitly supported under dedicated encryption/security review |
| Live terminal process/session state, SFTP transfer staging | **Never sync as vault records** | Local runtime-only state |

### 8.4 Drive-specific constraints

The existing direct Google Drive provider remains a client-only option. Use OAuth 2.0 Authorization Code + PKCE, restricted `drive.appdata` scope, OS-protected refresh tokens, explicit E2EE passphrase, expiration/revocation support and real-account acceptance tests. Its `appDataFolder` is **private to the app/user and is not a cross-account team sharing backend**. The server does not proxy Drive or require its API credentials. If Drive is unavailable, local features remain operational.

---

## 9. Shared vaults and team collaboration

### 9.1 Shared vault lifecycle

1. Owner creates a vault on chosen server and locally generates an independent vault DEK/epoch.
2. Owner enrolls and verifies own devices; uploads only client-wrapped epoch key envelopes, encrypted display fields and signed metadata.
3. Owner/Admin invites another account to role Owner/Admin/Editor/Viewer within policy, using expiring one-time link or administrative enrollment (email optional).
4. Invitee signs in, proves control of the requested device keys, reviews scope and verifies inviter/endpoint identity; an authorized client wraps the DEK to invitee device(s).
5. Server verifies invite, role, key proofs and pending key envelope; activates membership atomically and writes auditable event.
6. Client syncs encrypted records; edits use expected revisions and conflict dialogs. Membership/epoch changes trigger push notifications and mandatory revalidation.
7. Revocation denies server access immediately; authorized clients rotate keys and re-encrypt future content, with documented limits for historical data.

### 9.2 Per-vault capabilities

- List/create/update/archive vaults; select local/personal/team type.
- Role assignment and controlled ownership transfer; protect last owner.
- Member invitation (link; optional email), accept/decline/expire/revoke, audit trail.
- Per-device enrollment, authorization scope and revocation.
- Shared host/snippet/group/connection definitions and selected secret envelopes by explicit consent.
- Conflicting edits, version history and encrypted snapshots; user-controlled retention and export/restore.
- Device-local identity paths and OS keychain credentials remain local unless explicitly shared using a safe, supported transport.
- Team session annotations/comments and selected session logs only after explicit enabled retention policy (no default plaintext collection).

### 9.3 Audit model

Log authentication, membership change, invite usage, key epoch changes, RBAC failures and terminal-control changes. Use append-only chronological event IDs and server-side hash chaining with periodically signed checkpoints, so accidental mutation is detectable. **Do not claim that an administrator controlling the server and all backup anchors cannot rewrite history**; offer independent checkpoint export/verification for stronger guarantees. Keep event details minimal and redact secrets. Build retention/export/validation tests.

---

## 10. Optional real-time terminal collaboration

Implement after stable auth, vault sync, authorization and key enrollment. A shared session is **hosted by a user's local Shellumi client**, not by Shellumi Server. The host client retains the SSH connection and PTY. The self-hosted server offers authenticated WSS **signaling/relay**, only if deployment enables it. No open SSH ports or access to local SSH credentials is required on the server.

### Required behavior

- Owner starts a terminal-sharing session intentionally, chooses participants/TTL and output-only vs controllable mode. No automatic session sharing.
- Each participant authenticates/enrolls, verifies session invitation and negotiates a short-lived **E2EE session key** with trusted clients; server forwards ciphertext frames only.
- Only current writer may send input; server enforces role policy and a **monotonic writer fencing token/lease**; host verifies accepted control grants and rejects stale queued keystrokes. Viewer mode has no input or control frames.
- Session owner retains immediate emergency revoke/terminate. Server-side revocation invalidates pending authorization and closes sockets. Local host also stops accepting revoked frames.
- Bounded per-client send queues, heartbeat, max frame size, replay and order checks, reconnect with epoch/lease revalidation, disconnect timeouts, tampering rejection.
- Optional recording requires explicit consent from host and policy-compliant participants; default is no persistence. Support explicit bookmarks/comments only as encrypted, authorized artifacts.
- Terminal traffic must not be advertised as E2EE until protocol integration tests demonstrate that the server cannot read its contents. Without that proof, leave collaboration disabled with an honest error.

**Not in initial MVP:** peer-to-peer media, cloud TURN, remote browser-based terminal, server-managed PTY, session bot, screen-sharing, unattended command execution, or TCP tunnel relay. They need separate designs and threat reviews.

---

## 11. Administration, deployment and operations

### 11.1 First-run requirements

- Single executable: `shellumi-server serve --config /etc/shellumi-server/config.toml` and `shellumi-server admin bootstrap` (CLI syntax finalized in implementation). Also support `--version`, `--help`, `doctor`, `migrate status/up` and `backup verify` with tests.
- Config priority: CLI > dedicated `SHELLUMI_SERVER_*` environment variables > TOML config > documented secure defaults. Validate config at startup; refuse externally reachable plaintext HTTP except explicit developer override that is impossible in release mode.
- DB URL from secret file/env, not command-line arguments if revealing credentials; support PostgreSQL pool limits, timeouts, health queries and graceful shutdown.
- Bootstrap token emitted once to terminal only on an interactive/explicitly local invocation; short TTL, consumed after use and never repeated in logs.
- Registration disabled/invite-only by default; CORS deny-by-default; metrics on private listener or disabled; admin endpoints protected.
- Run as unprivileged OS user; filesystem permissions and no secret dumping on crash. Document systemd hardening and reverse proxy/TLS.

### 11.2 Container and Compose

- Publish an OCI-compliant `ghcr.io/mjkhaani/shellumi-server` manifest for `linux/amd64` and `linux/arm64`.
- Build using a multi-stage pinned Rust build and a minimal distroless/other audited non-root runtime; handle CA bundle, migrations, `SIGTERM`, read-only filesystem, explicit writable temp if needed.
- Provide `deploy/docker-compose.yml`: `server`, healthy `postgres`, optional Caddy/Traefik reverse proxy example. Only reverse proxy exposes external 443; PostgreSQL isolated. Health and restart policies, resource limits and named volumes included.
- Document initialization, firewall, DNS, backup, upgrade, rollback, restore, air-gapped image/binary import and disaster recovery.
- No container privilege, host Docker socket or `--network host` needed. Root filesystem should be read-only where practical and the image must run as non-root.
- Kubernetes/Helm are later-stage optional deployment methods, not a dependency. Support horizontal scale only after external event distribution/locking is proven; **single active application instance is acceptable for MVP** if clear and enforced.

### 11.3 Configuration keys (design contract; exact names verified during coding)

| Key | Suggested default | Notes |
| --- | --- | --- |
| `SHELLUMI_SERVER_LISTEN_ADDR` | `127.0.0.1:8080` (binary); `0.0.0.0:8080` only inside container proxy network | never expose plaintext public listener |
| `SHELLUMI_SERVER_PUBLIC_URL` | required externally | canonical HTTPS URL; check origin and issuer |
| `SHELLUMI_SERVER_DATABASE_URL_FILE` | secret file path | preferred for DB credential in containers |
| `SHELLUMI_SERVER_LOG_LEVEL` | `info` | redacted structured log |
| `SHELLUMI_SERVER_REGISTRATION` | `invite_only` | no unauthenticated public signup |
| `SHELLUMI_SERVER_ACCESS_TOKEN_TTL` | `15m` | enforce bound and tests |
| `SHELLUMI_SERVER_REFRESH_TOKEN_TTL` | `30d` | hashed/rotating with revoke |
| `SHELLUMI_SERVER_MAX_REQUEST_BYTES` | `10MiB` | per-route overrides, document bounds |
| `SHELLUMI_SERVER_MAX_RECORD_BYTES` | `1MiB` | ciphertext-only payload |
| `SHELLUMI_SERVER_COLLAB_ENABLED` | `false` | enables optional relay only when tested |
| `SHELLUMI_SERVER_METRICS_ENABLED` | `false` | private/secure metrics endpoint |
| `SHELLUMI_SERVER_TRUSTED_PROXIES` | empty | never trust arbitrary forwarded headers |
| `SHELLUMI_SERVER_ALLOWED_ORIGINS` | empty | explicit opt-in browser origins |

Do not store application secrets in `.env.example` or commit real `.env`, private keys or database backups. Produce validated example files and clear errors for missing external deployment settings.

### 11.4 Observability and backup/restore

- Structured JSON log lines, request ID, actor/device ID if safe, status and duration; redact PII and all secrets. OpenTelemetry instrumentation optional/disabled by default, exporting only to operator-controlled endpoints.
- `/health/live` independent of DB and `/health/ready` verifies migrations/connectivity; never print stack traces or env values publicly.
- Expose opt-in metrics: request latency/count, active clients, lag of sync queues, DB errors, failed auth/rate limits, WSS queue depth. Never label metrics by unbounded user/vault IDs.
- Document database snapshot consistency (`pg_dump`/physical backup as appropriate), restore on fresh instance, client-held key recovery, encryption-suite compatibility and retention. Backups alone do not contain client private keys needed for decryption.
- A tested backup/restore plan must include rolling back server binaries *within schema compatibility*, validating record/checkpoint hashes and reconnecting a client without data loss.

---

## 12. Versioned compatibility, migration and rollouts

### 12.1 Wire and storage versioning

- Independent versions: server SemVer, protocol version, client minimum compatibility, database migration version, ciphertext suite and content schema version. Do not equate server `v1.2.0` with wire protocol v1.
- `/capabilities` specifies supported protocol and encryption suites and optional features. Fail closed for unknown required suite/epoch, do not reinterpret unknown bytes.
- Design additive protocol evolution where possible; for breaking changes provide negotiation and migration docs. Keep contract fixtures for supported client releases.
- Migrations are transactional/idempotent, applied at controlled startup with advisory lock to prevent two instances racing; fail startup cleanly on unsupported future versions.

### 12.2 Client migration sequence

1. Detect the installed client schema and existing Drive/backup state without modifying it.
2. Save an encrypted local safety backup; ask user to select which vaults/categories move and whether secrets are eligible.
3. Assign stable vault and entity UUIDs and persist local `i64`→UUID mappings; preserve foreign-key references and credential-store pointers.
4. Enroll client device in selected server and verify server identity/trust state.
5. Generate new shared-vault keys locally or deliberately unwrap verified existing ones; upload encrypted records with a baseline cursor and revision.
6. Perform a read-back/decrypt/integrity check on the client; compare record counts and important stable IDs.
7. Mark server provider active only after confirmation. Leave original Drive data untouched by default until user explicitly removes it.
8. Test restart, offline edit, divergent second device, rollback to local-only and failure mid-cutover.

No server migration process is authorized to pull/decrypt content from Google Drive on users' behalf. Never silently change the selected provider.

---

## 13. Test strategy and measurable acceptance criteria

Every feature has **unit**, **integration**, **negative authorization/security**, and where relevant **end-to-end** tests. `AGENT.md` defines the continuous progress and test gates. The examples below are acceptance requirements, not claims of current passing status.

### 13.1 Always-run checks

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo test --locked --doc --workspace
cargo build --locked --workspace --all-features
cargo audit
```

CI additionally executes PostgreSQL-backed integration tests, permission matrix tests, security scans, API fixture validation, Docker/Compose and release-mode health smoke tests. Add reproducible Rust benchmarks and soak tests before announcing scale claims.

### 13.2 Critical end-to-end scenarios (all required)

1. Bootstrap self-hosted installation once; reject second bootstrap; create organization and admin; restart retains state.
2. Register two devices under one account; create vault; sync hosts/groups/snippets; verify decrypted records are identical on authorized clients and remain opaque in captured server DB/network logs.
3. Two devices change **different** objects offline: both changes eventually converge without lost updates.
4. Two devices change the **same** object from an identical base: stale commit returns `409`, both versions remain recoverable, client presents a conflict; user resolution converges.
5. Delete a host offline: tombstone propagates after reconnect, persists across restart and is not resurrected by a stale client.
6. Replay a signed mutation and retry same idempotency key: no duplicate commit; modify reused key body: explicit rejection.
7. Cross-tenant malicious user guesses vault ID/cursor: all reads, writes, metadata, audit and WSS hints denied without data leakage.
8. Owner invites Editor and Viewer; Viewer cannot write or assign role; Admin cannot grant Owner or revoke last Owner.
9. Revoke Editor while online and while offline; no future server read/write or relay access; epoch rotation produces only surviving-device wraps.
10. Corrupt ciphertext, nonce, AAD, signature, recipient or key epoch: authenticated client rejects; server rejects unsupported/unsigned operations and invalid device state.
11. Client loses network during upload, after DB commit and before ACK, and during pagination; reconciliation is idempotent and no data is lost.
12. Upgrade an existing server with migrations and restore its backup to a clean deployment; validate client reconnection and retained data.
13. Explicitly switch from Google Drive to Server after encrypted backup; verify no involuntary uploads and preserved Drive state. Repeat with failed import and rollback.
14. Server unavailable: all normal local SSH/terminal/SFTP work still functions; sync queues and visible errors remain accurate.
15. Optional relay: three authorized participants see encrypted output, a Viewer cannot type, only one writer at a time, owner instantly revokes input; stale/granted-after-revoke frames rejected.
16. Release Docker image starts as non-root with clean Postgres, migrations applied, health endpoint functional; both `amd64` and `arm64` manifests and binaries are verified.

### 13.3 Operational targets (to benchmark, not claim now)

- Default supported deployment: one app instance + PostgreSQL, 100 simultaneously active clients, and at least 100,000 small ciphertext records total.
- API target: p95 of a *cached-small metadata request* under 250 ms at a specified lab environment/load; data transfer latencies must report request size and network conditions rather than hide bandwidth effects.
- No unbounded per-connection queues or memory allocations from untrusted payload size; demonstrate stable memory under disconnect and oversized-message stress.
- A failing or restarted DB never yields a successful write acknowledgement before durable commit; restore and crash tests demonstrate no acknowledged-write loss.
- All claims require published hardware, dataset, test program, command output and measured results in `docs/benchmarks/`.

---

## 14. GitHub Actions and release engineering (mandatory)

This is a **new repository** and needs its own workflows, independent of Shellumi desktop releases. Implement `.github/workflows/ci.yml` and `.github/workflows/release.yml` once the Rust service skeleton exists; do not treat these as satisfied by the client repo's release workflow.

### 14.1 CI workflow (`ci.yml`)

**Triggers:** `push` to `main` and `pull_request` to `main`. Tests are allowed on PRs, **publishing is not**. Use `permissions: contents: read` by default.

Required jobs:

1. **check:** pinned stable Rust, `cargo fmt`, strict Clippy, `cargo test`, docs, build, `cargo audit`, dependency license policy, OpenAPI validation.
2. **db-integration:** ephemeral PostgreSQL service, migrations, all integration/E2E sync/auth/RBAC tests, backup and recovery tests.
3. **contract:** fixture and schema compatibility against expected Shellumi client protocol; smoke compile generated client SDK where practical.
4. **container-smoke:** `docker build` from current commit, Compose with Postgres, non-root/health/migration verification, integration request; no registry push.
5. **security:** CodeQL where supported, dependency checks, secret detection, Rust advisory and Docker vulnerability scan, with documented false positives and enforceable thresholds.

Fail closed if any required test is missing, skipped unexpectedly or red. Use concurrency groups to cancel outdated PR runs but **never** interrupt release publication in a way that leaves partially published mutable artifacts.

### 14.2 Tag release workflow (`release.yml`)

**Trigger:** `on.push.tags: ["v*"]` with strict in-job SemVer validation such as `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`. Reject malformed tags, untrusted sources, dirty/untracked packaging output and crate version mismatch. No `push`/`pull_request` branch publish. Protect tags and require release CI.

**Release pipeline:**

```text
  tag vMAJOR.MINOR.PATCH[-prerelease]
                 |
           validate tag
        and crate version
                 |
      ┌──────────┴──────────┐
      v                     v
 full CI + DB tests     security/contract
      └──────────┬──────────┘
                 v
       native Linux binary
      (amd64 + arm64 matrix)
                 |
     checksum / SBOM / provenance
                 |
        multiarch Docker image
       linux/amd64,linux/arm64
                 |
     smoke test binaries + image
                 |
     GitHub Release + GHCR
       (stable/prerelease tags)
```

**Native binary deliverables:**

- `shellumi-server-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz`
- `shellumi-server-vX.Y.Z-aarch64-unknown-linux-musl.tar.gz`
- If `musl` is incompatible with audited dependencies or cross compilation constraints, document tested `gnu` artifacts explicitly; never label a `gnu` binary `musl`.
- Each archive contains executable `shellumi-server`, `LICENSE`, safe example config, version information, and README. Include `SHA256SUMS.txt` and a machine-readable build/provenance manifest. Release `--version` equals tag.
- Optional later: Windows x86_64 and macOS aarch64/x86_64 native binaries, only after platform smoke tests and demand. The **v1 required** architectures are Linux amd64 and arm64.

**Docker deliverables:**

- OCI image name: `ghcr.io/mjkhaani/shellumi-server` (normalize actual repository owner to lowercase for GHCR).
- Manifest platforms: `linux/amd64`, `linux/arm64`, with a minimal non-root runtime. Build on native runners or verified Buildx multi-platform build; use QEMU only with actual smoke testing where feasible.
- Image tags: `vX.Y.Z`, `X.Y.Z`; optional `X.Y` for stable releases; `latest` **only** for latest stable (never pre-release). Persist immutable digest and OCI source/revision/version labels.
- `packages: write` permission only in image publisher; `contents: write` only in GitHub Release publisher. Use `GITHUB_TOKEN` for GHCR login; no custom PAT unless absolutely required. `id-token:write` and `attestations:write` only for attestations.
- Use maintained `docker/login-action`, `docker/setup-buildx-action`, `docker/metadata-action`, `docker/build-push-action` (pin reviewed action commit SHAs in committed workflow); generate/push OCI SBOM/provenance. Use `actions/attest` for binary/image attestations where available. Optionally cosign keyless sign with OIDC. Never expose secrets to untrusted PRs or tag jobs with writable arbitrary code.

**Publish gates:**

- Every required test, schema migration, build, native architecture smoke test and container smoke test passes.
- Verify *both* binary archives nonempty, format, version and checksums; inspect image manifest for **both platforms** and pull by digest.
- Assemble real SBOM (CycloneDX/SPDX), not merely `cargo metadata` relabeled as an SBOM; generate provenance bound to actual source tag SHA, lockfile and workflow run. Where using attestations, validate their expected subjects.
- Create draft release first or publish only after validated assets exist. Prerelease tags get GitHub prerelease flag. Stable release notes describe compatibility/migrations. Never overwrite published tags silently; correction requires new release or explicitly documented safe recovery.
- Do not let a successful image push with a failed binary release be represented as a complete release. Log partial publication and explicitly reconcile.

### 14.3 Workflow acceptance tests

- Tag `v0.1.0-alpha.1`: builds both binary targets and multiarch image, publishes GitHub prerelease, does **not** move `latest`.
- Tag `v0.1.0`: same, stable release, `latest` updated only after gates pass.
- An intentionally bad tag or version mismatch is rejected without publication.
- PR from a fork can run tests without access to registry credentials or permission to publish.
- A verifier can run `sha256sum -c SHA256SUMS.txt`, inspect OCI manifest and verify the recorded source SHA/attestation. Test runner outputs and download instructions are in `docs/development/RELEASES.md`.

**Authoritative references:** [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations), [GitHub publishing Docker images](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images), [Docker multi-platform CI](https://docs.docker.com/build/ci/github-actions/multi-platform/). Verify the latest documented action versions when implementing; do not copy an outdated workflow unchanged.

---

## 15. Stepwise development roadmap with acceptance gates

Every milestone produces **working code, automated tests, documentation, actual verification and a `docs/PROGRESS.md` entry**. Later milestones must not be represented as complete until their own gates pass.

### M0 — Repository foundations and project hygiene

**Deliver:** Rust workspace/binary, `AGENT.md`+`AGENTS.md`, MIT license, CI skeleton, progress/roadmap/ADR policy, configuration parser, one-time bootstrap design, health endpoints, typed error system.  
**Gate:** `cargo fmt/clippy/test/build`, clean startup, invalid config rejected, README quickstart actually works, docs and progress established.

### M1 — Storage, migrations, tenants and auth

**Deliver:** PostgreSQL schema/migrations, admin bootstrap, user accounts, sessions, devices/signing-key registration, orgs, invite-only enrollment, protected auth, token revocation.  
**Gate:** DB reopen/migration/restore, duplicate bootstrap rejected, token theft/reuse tests, cross-tenant isolation, password verifier/rate limit tests, Compose startup smoke.

### M2 — Encrypted private vault + sync v1

**Deliver:** stable vault and entity IDs, versioned opaque envelopes, server-signed/validated metadata, device-signed writes, transactional change feed, conditional `expected_revision` writes, idempotency keys, tombstones, snapshots, client `ShellumiServerProvider` adapter.  
**Gate:** two real test clients converge, two-client concurrent same-object `409`, offline/retry/restart no-loss, tamper/cursor/auth tests, API golden fixtures, no server plaintext.

### M3 — Team vaults, invites, RBAC and E2EE member keys

**Deliver:** Owner/Admin/Editor/Viewer policy, one-time invites, public-key proof, per-device recipient-wrapped key delivery, key epoch rotation and revoke, owner transfer restrictions, audit and user-facing client workflow.  
**Gate:** complete RBAC matrix, cross-tenant IDOR tests, revoked-member denied, key unwrap on authorized client, new-epoch data unreadable by revoked device, offline key rotation recovery.

### M4 — Resilience, operations and releases

**Deliver:** production-grade CLI/admin commands, encryption/recovery docs, backup/restore automation, metrics, quotas, rate limits, security scan remediation, stable migrations, Docker Compose, Linux arm64/amd64 binaries and GHCR release action.  
**Gate:** clean upgrade+backup restore, load/crash tests, both architectures smoke, checksums/attestations and GHCR manifest verified, tag prerelease and stable runs verified.

### M5 — Optional live terminal collaboration

**Deliver:** WSS signaling/relay, client E2EE ephemeral session key protocol, owner-driven invitation, one-active-writer fencing, revocation, bounded/backpressured streams and reconnect.  
**Gate:** multi-client authorized session test, viewer cannot type, owner revokes instantly, tampering/replay and disconnect tests, server does not persist/view plaintext terminal frames. Relay stays disabled until gate satisfied.

### M6 — Advanced self-hosting and integrations (later)

**Candidate features:** OIDC login/SSO, optional SMTP, large encrypted attachments on S3-compatible backends, horizontal scaling with PostgreSQL coordination/event bus, Kubernetes Helm, audit export/verifiable checkpoints, admin policy, disaster-recovery automation, optional mobile clients.  
**Gate:** scoped ADR and threat review per feature; real acceptance tests before labeling supported. No dependency on proprietary hosted services.

---

## 16. Required documentation and reporting

At inception create and maintain:

- `AGENT.md` / `AGENTS.md` — mandatory agent workflow and tests.
- `docs/PROGRESS.md` — **append-only** log for **every** change, before and after implementation, including commands and actual outcomes.
- `docs/ROADMAP.md` — phase, status, blockers, deliverable links and next task.
- `docs/ARCHITECTURE.md` — module boundaries, diagrams, trust zones, DB and sync flows.
- `docs/COMPATIBILITY.md` — client/server/protocol/envelope/database version table with verified fixtures.
- `docs/API.md` + `openapi/shellumi-server-v1.yaml` — actual endpoints, auth and example errors.
- `docs/CONFIGURATION.md`, `docs/DEPLOYMENT.md`, `docs/BACKUP_RESTORE.md` — install, operations, secrets and recovery.
- `docs/security/THREAT_MODEL.md` and `KEY_MANAGEMENT.md` — threats, keys, assumptions, audits, limits and migration.
- `docs/development/TESTING.md` and `RELEASES.md` — reproducible test suites, release targets, hashes, signing and CI evidence.
- `docs/adr/` — meaningful security/crypto/versioning choices with alternatives and consequences.
- `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, root `README.md` — released behavior, vulnerability reports, contribution standards and examples.

**Every code increment:** document problem → design → implementation → test list → verification commands/results → security/privacy/compatibility implications → outstanding gaps → next step. If any required test fails or cannot run, task is `partial` or `blocked`, not `complete`. Do not make claims of production readiness solely because CI compiles.

---

## 17. Project completion criteria

The first production candidate is acceptable only when:

- An organization can deploy it on its own Linux host with Docker Compose or native binary, with HTTPS, proper secrets, one-time bootstrap and no third-party cloud requirement.
- Existing Shellumi remains fully functional local-only; individual Google Drive sync still works without this server.
- At least two enrolled devices can securely sync the same encrypted vault with durable, conflict-safe offline operation and verified migrations from client data.
- A real owner can invite/revoke a real team member and share only recipient-encrypted keys, with roles enforced server-side and no vault plaintext available to the server.
- All relevant threat and negative tests, actual DB integration tests, crash/restart scenarios and backup/restore pass.
- Native Linux `x86_64` and `aarch64` release binaries and both-platform GHCR image are built from tag and smoke-tested; GitHub Release has hashes, SBOM, provenance, release notes and published test evidence.
- Every change and verification is recorded and current documentation reflects implemented vs planned status.

**Implementation instruction to the coding agent:** Start with M0, inspect the current client source at the pinned commit, write the first `docs/PROGRESS.md` planned entry, implement a runnable minimal server with tests, run the tests, record the exact results, then proceed milestone by milestone. Do not skip test, security, migration or documentation work to make a feature appear finished.

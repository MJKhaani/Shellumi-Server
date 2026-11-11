# Shellumi Server — Threat Model & Security Architecture

## 1. System Overview & Security Boundaries

Shellumi Server is an **untrusted-for-plaintext** synchronization, key-envelope distribution, and collaboration relay service.

```text
[ Client Device A (Trusted) ]  <--- TLS 1.3 --->  [ Shellumi Server (Untrusted for Plaintext) ]
                                                           |
[ Client Device B (Trusted) ]  <--- TLS 1.3 --->          +---> [ PostgreSQL Database ]
```

---

## 2. Threat Actors & Scenarios

### Actor A: Malicious Network Observer (Man-in-the-Middle)
- **Capability:** Intercept, replay, reorder, or alter network traffic.
- **Mitigation:**
  - Mandatory TLS 1.3 encryption (enforced for all non-loopback endpoints).
  - All vault mutations carry client Ed25519 digital signatures verified before commit.
  - AEAD authentication tags with strict canonical Associated Authenticated Data (AAD) prevents payload tampering or cross-vault transplantation.
  - Monotonic `server_sequence` numbers and UUID idempotency keys eliminate packet replay and duplicate applications.

### Actor B: Compromised Server Operator / Malicious Database Administrator
- **Capability:** Full read/write access to PostgreSQL tables, disk storage, and server process memory.
- **Mitigation:**
  - **Zero Server-Side Plaintext:** Vault records are encrypted exclusively on client endpoints using 256-bit symmetric DEKs.
  - **Recipient-Wrapped Keys:** DEKs are sealed directly to recipient devices' X25519 public keys. The server never possesses plaintext DEKs, sync passphrases, SSH keys, or passwords.
  - **Zero Terminal Plaintext:** Real-time collaboration frames are client-encrypted ciphertext envelopes; server memory contains only opaque blobs.
  - **Tamper Evidence:** Audit logs maintain a cryptographic SHA-256 hash chain (`predecessor_hash` -> `event_hash`). Unilateral record deletions or modifications break hash linkage.

### Actor C: Malicious Authenticated Client / Cross-Tenant Attacker
- **Capability:** An authenticated user attempting Insecure Direct Object Reference (IDOR), unauthorized privilege escalation, or race-condition exploits.
- **Mitigation:**
  - Strict tenant and vault scoped queries: every database query explicitly joins against the authenticated user's organization and vault membership.
  - RBAC permission matrix enforced on every read, write, invite, and admin route.
  - Optimistic concurrency control via `expected_revision`: race conditions trigger HTTP 409 Conflict.
  - Monotonic device signing counters prevent rollback attacks.

### Actor D: Malicious or Revoked Collaborator
- **Capability:** A revoked team member or session participant attempting to inject keystrokes, read subsequent updates, or forge write permissions.
- **Mitigation:**
  - **Instant Revocation:** Revoking a vault member immediately blocks all read/write/feed/invite/relay operations.
  - **Key Epoch Rotation:** Surviving active devices rotate the vault DEK to a new epoch, wrapping it only for trusted active devices. Revoked devices cannot decrypt subsequent mutations.
  - **Monotonic Fencing Tokens:** Write control grants issue an incrementing `lease_token`. The server and host reject frames bearing stale tokens (HTTP 409 `STALE_LEASE_TOKEN`).
  - **Viewer Restrictions:** Non-writer participants cannot transmit `input` frames (HTTP 403 `NOT_AUTHORIZED_WRITER`).
  - **Host Emergency Termination:** Hosts can unilaterally terminate collaboration sessions immediately (`POST /api/v1/collab/sessions/{id}/terminate`), dropping subscriber SSE channels and returning HTTP 410 Gone for subsequent frames.

---

## 3. Cryptographic Bounds & Constraints

- **Single Record Max Size:** 1 MiB (`SHELLUMI_SERVER_MAX_RECORD_BYTES`).
- **Batch Commit Max Size:** 10 MiB (`SHELLUMI_SERVER_MAX_REQUEST_BYTES`).
- **Batch Commit Max Mutations:** 1000 items per commit.
- **Rate Limiting:** Sliding-window per-IP rate limiter (default: 10 req/min) on sensitive unauthenticated endpoints (`/api/v1/auth/login`, `/api/v1/bootstrap`, `/api/v1/invites/accept`).
- **Access Token Lifetime:** 15 minutes (900 seconds).
- **Refresh Token Lifetime:** 30 days (2,592,000 seconds) with atomic single-use rotation and theft detection.

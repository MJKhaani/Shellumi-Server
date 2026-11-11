# ADR 0003: M2 Encrypted Vaults, Canonical Mutation Signatures, and Sync Engine

## Status
Accepted

## Context
Shellumi Server provides zero-knowledge synchronization for encrypted vault records between client devices. The server must never possess vault data encryption keys (DEKs) or inspect plaintext data.

The synchronization subsystem must satisfy the following critical requirements:
1. **Zero Server Plaintext:** Store only client-sealed authenticated ciphertext envelopes (`EncryptedEnvelope`) and recipient-wrapped key envelopes. Plaintext vault records, SSH credentials, and passphrases never touch server memory or persistent storage.
2. **Conflict Safety & Concurrency Control:** Support offline local-first editing across multiple devices with optimistic concurrency control. Conditional Compare-And-Swap (CAS) writes using `expected_revision` must atomically succeed or fail with HTTP 409 Conflict.
3. **Cryptographic Provenance:** Every mutation must be cryptographically signed by the originating device using its registered Ed25519 signing key. The server must verify device status, signature, key epoch, and authorization before committing.
4. **Per-Vault Monotonic Ordering:** Transactionally assign strictly increasing sequence numbers per vault to power an append-only change feed.
5. **Mutation Idempotency:** Support network drops and client retries safely without duplicate commits using idempotency keys.
6. **Durable Tombstones:** Deletions must produce durable tombstone records that propagate across offline clients and prevent accidental resurrection.
7. **Consistent Delta Pagination:** Change feeds must support cursor-based pagination so clients can catch up from any previously acknowledged sequence number.

## Decision

### 1. Vault Data Model & Tenant Isolation
- Vaults have persistent stable UUIDs (`UUIDv7` or `UUIDv4`), bound strictly to an organization tenant (`tenant_id`) and an owner user.
- Every read, commit, or delta feed query validates membership and RBAC permissions (`Owner`, `Administrator`, `Editor`, `Viewer`). Viewers are prohibited from committing mutations.

### 2. Normative Canonical Mutation Signature Specification
Each mutation item in a commit batch carries a device signature verifying its contents.
The canonical signing preimage is an ASCII UTF-8 string:
```text
shellumi-v1-mutation:{vault_id}:{object_id}:{entity_type}:{expected_revision}:{deleted}:{key_epoch}:{device_counter}:{ciphertext_digest}
```
Where:
- `ciphertext_digest`: SHA-256 hexadecimal string of the base64-encoded ciphertext payload (or empty string for deletion tombstones without ciphertext).
- `device_signature`: Base64-encoded 64-byte Ed25519 signature over this exact preimage.
The server verifies this signature against the device's registered Ed25519 public key. If verification fails or the device is revoked, the commit is rejected with HTTP 403 Forbidden.

### 3. Atomic Conditional CAS Commits (`POST /api/v1/vaults/{id}/commits`)
- A commit request provides an `idempotency_key`, a `base_cursor`, and a list of `mutations`.
- The server processes the batch atomically within a database transaction:
  1. Checks idempotency: If the key exists for this vault and device, verifies the SHA-256 request digest. If identical, returns the previously cached response. If mismatched, returns HTTP 409 `IDEMPOTENCY_CONFLICT`.
  2. For each mutation:
     - For new objects (`expected_revision == 0`), ensures no active record exists.
     - For existing objects (`expected_revision > 0`), ensures the record exists and `current_revision == expected_revision`. If stale, returns HTTP 409 `REVISION_CONFLICT`.
  3. Increments the vault's `server_sequence` atomically.
  4. Updates the record in `records` to revision `expected_revision + 1` with the new envelope, digest, and tombstone state.
  5. Appends each mutation to the append-only `change_log`.
  6. Records the result in `mutation_idempotency`.

### 4. Monotonic Change Feed (`GET /api/v1/vaults/{id}/changes`)
- Accepts `since` sequence number (or opaque cursor) and an optional `limit` (default 100, max 500).
- Queries `change_log` ordered by `sequence ASC` strictly greater than `since`.
- Returns `records`, `latest_sequence`, `has_more`, and a base64-encoded continuation `next_cursor`.
- Tombstone changes are delivered with `deleted: true` and empty envelope so clients apply deletions locally.

### 5. Encrypted Snapshots (`GET /api/v1/vaults/{id}/snapshots/{revision}`)
- Returns all non-deleted records and active tombstones at the specified revision for disaster recovery and full-vault resynchronization.

## Consequences
- Guaranteed zero-knowledge guarantees: the server cannot read or modify vault content without invalidating cryptographic checks.
- True local-first concurrency: concurrent modifications to different objects merge cleanly without conflict; concurrent modifications to the same object are detected with atomic 409 Conflict.
- Resilient network recovery: idempotent retries ensure dropped responses do not corrupt state or double-apply changes.

# Shellumi Client / Server Compatibility Matrix & Protocol Specification

This document tracks version compatibility, cryptographic suites, data type mappings, and migration paths between Shellumi desktop/CLI clients and Shellumi Server.

---

## 1. Version Compatibility Matrix

| Wire Protocol Version | Server Release | Minimum Client Version | Supported E2EE Suites | Status |
| :---: | :---: | :---: | :---: | :---: |
| **v1** | `0.1.0` | `0.0.7-alpha` | `x25519_hkdf_aes256gcm`, `argon2id_aes256gcm_legacy` | **Current Stable** |

---

## 2. Advertised Capabilities & Limits (`GET /api/v1/capabilities`)

Clients query `/api/v1/capabilities` upon connecting to discover supported features and enforce payload constraints before serialization:

```json
{
  "server_version": "0.1.0",
  "protocol_version": 1,
  "min_protocol_version": 1,
  "supported_features": [
    "argon2id_auth_v1",
    "device_keys_v1",
    "delta_sync_v1",
    "shared_vaults_v1",
    "terminal_collab_v1"
  ],
  "supported_e2ee_suites": [
    "x25519_hkdf_aes256gcm",
    "argon2id_aes256gcm_legacy"
  ],
  "limits": {
    "max_request_bytes": 10485760,
    "max_record_bytes": 1048576,
    "max_mutations_per_commit": 1000
  }
}
```

---

## 3. Client Entity Mapping & Wire Serialization

The table below maps Shellumi desktop client domain models (`crates/shellumi-core`) to Shellumi Server wire protocol types (`crates/shellumi-server-protocol`):

| Desktop Client Entity | Wire Representation | Wire Structure / Endpoint | Notes |
| :--- | :--- | :--- | :--- |
| `SyncVault` | `VaultResponse` | `GET /api/v1/vaults`, `POST /api/v1/vaults` | Distinguishes `personal` vs `team` vaults. |
| `SyncRecord` | `MutationItem` / `SyncChangeItem` | `POST /api/v1/vaults/{id}/commits`, `GET /api/v1/vaults/{id}/changes` | Binds `expected_revision` for CAS. |
| `EncryptedEnvelope` | `EncryptedEnvelope` | JSON object embedded in mutations/changes | Client-sealed AEAD ciphertext; opaque to server. |
| `TeamRole` | `String` enum | `owner`, `admin`, `editor`, `viewer` | Enforced server-side on all endpoints. |
| `SharedVault` | `VaultResponse` (type: `team`) | `POST /api/v1/vaults` (`vault_type: "team"`) | Requires recipient-wrapped DEKs. |
| `TeamMember` | `VaultMemberResponse` | `GET /api/v1/vaults/{id}/members` | Scoped to active organization & vault. |
| `KeyEnvelope` | `KeyEnvelopeResponse` | `GET/POST /api/v1/vaults/{id}/keys/envelopes` | Wrapped DEKs targeted to recipient device X25519 public keys. |
| `CollabSession` | `CollabSessionResponse` | `/api/v1/collab/sessions` | Ephemeral live terminal sharing. |
| `CollabFrame` | `CollabFrame` | `/api/v1/collab/sessions/{id}/frames` | Encrypted keystrokes and PTY output. |

---

## 4. Encrypted Envelope Specification

Ciphertext payloads are encapsulated in the canonical `EncryptedEnvelope`:

```json
{
  "salt": "<base64_encoded_salt>",
  "nonce": "<base64_encoded_nonce>",
  "ciphertext": "<base64_encoded_ciphertext_and_tag>",
  "associated_data": "<canonical_aad_string>",
  "kdf_iterations": 3
}
```

### Canonical Associated Authenticated Data (AAD)
To prevent cross-vault or cross-entity ciphertext transplant attacks, the client binds canonical AAD before computing the AEAD authentication tag:
```text
AAD = "shellumi:v1:" || tenant_id || ":" || vault_id || ":" || object_id || ":" || entity_type || ":" || epoch
```

---

## 5. Storage & Provider Coexistence

Shellumi supports three strictly independent operating modes:

```text
+-------------------------------------------------------------+
|                      Shellumi Client                        |
|                                                             |
|   +-----------------------------------------------------+   |
|   |                 SyncProvider Trait                  |   |
|   +----------+------------------+-------------------+---+   |
|              |                  |                   |       |
|              v                  v                   v       |
|      +---------------+  +---------------+   +---------------+
|      |  Local-Only   |  | Google Drive  |   | Shellumi Srv  |
|      | (Offline DB)  |  | (Direct App)  |   | (Self-Hosted) |
|      +---------------+  +---------------+   +---------------+
+-------------------------------------------------------------+
```

1. **Local-Only Mode:**
   - Complete application functionality offline without accounts, servers, or cloud dependencies.
   - Credentials stored in local OS keychain or local SQLite database.
2. **Personal Google Drive Mode:**
   - Client directly accesses Google Drive's restricted `appDataFolder` using OAuth PKCE.
   - Shellumi Server does not proxy Google OAuth, access Drive files, or store Drive tokens.
3. **Self-Hosted Shellumi Server Mode:**
   - Self-hosted synchronization endpoint for personal and multi-device vaults.
   - Zero plaintext storage: only client-wrapped envelopes and encrypted payloads touch the server.

---

## 6. Legacy Client Snapshot Migration

For existing Shellumi clients upgrading from legacy AES-256-GCM PBKDF2 local/Drive backups:

1. **Safety Backup:** The client produces a timestamped, local encrypted safety snapshot before initiating server migration.
2. **Stable ID Allocation:** Legacy integer database row IDs (`i64`) are mapped to persistent, unique UUIDv4 identifiers.
3. **Device Key Enrollment:** The client generates Ed25519 signing and X25519 key-agreement pairs and registers the device with the server (`POST /api/v1/devices`).
4. **Envelope Ingestion:** Existing records are sealed into versioned `EncryptedEnvelope` structures under key epoch 1.
5. **Initial Batch Commit:** The client submits records via `POST /api/v1/vaults/{id}/commits` with `expected_revision = 0`.
6. **Integrity Verification:** The client performs a read-back check (`GET /api/v1/vaults/{id}/changes?since=0`), verifies digests and counts, and commits the active provider state. Original Google Drive data remains untouched.

# Shellumi Server — Key Management Specification

## 1. Cryptographic Key Taxonomy

Shellumi employs distinct, domain-separated cryptographic keys to guarantee end-to-end confidentiality, non-repudiation, and forward privacy:

```text
+---------------------------------------------------------------------------------+
|                                 Key Taxonomy                                    |
|                                                                                 |
|  1. Device Identity Keys (Per Enrolled Device)                                  |
|     - Ed25519: Digital signing of mutations, change items, and registration     |
|     - X25519: Diffie-Hellman key agreement for receiving wrapped DEKs           |
|                                                                                 |
|  2. Vault Data Encryption Keys (DEKs) (Per Vault & Epoch)                       |
|     - AES-256: 256-bit high-entropy symmetric key generated client-side         |
|     - Never transmitted in plaintext; wrapped via recipient device X25519 PK    |
|                                                                                 |
|  3. Ephemeral Collaboration Session Keys (Per Live Collab Session)             |
|     - AES-256-GCM / ChaCha20-Poly1305: Short-lived session key negotiated      |
|       directly between host and enrolled participants                           |
+---------------------------------------------------------------------------------+
```

### Critical Identity Invariant: Separation from SSH Keys
OpenSSH authentication keys (e.g. `id_ed25519` or `id_rsa`) **MUST NEVER** be reused for device identity signing or key agreement. Shellumi clients generate dedicated device keypairs stored in protected local keyrings or native OS keystores (macOS Keychain, Linux Secret Service, Windows DPAPI).

---

## 2. Vault Data Encryption Key (DEK) Lifecycle

### 2.1 Initialization (Epoch 1)
1. Upon vault creation, the client generates a cryptographically secure 256-bit symmetric key (`DEK_1`).
2. The client seals `DEK_1` to each of its own enrolled devices' registered X25519 public keys.
3. The resulting `KeyEnvelopeItem` payloads are uploaded to `POST /api/v1/vaults/{id}/keys/envelopes`.

### 2.2 Member Onboarding & Envelope Delivery
1. An Owner or Administrator creates a scoped invitation (`POST /api/v1/vaults/{id}/invites`).
2. The invitee registers their device keys (`POST /api/v1/devices`) and accepts the invitation (`POST /api/v1/invites/accept`).
3. An active member device fetches the invitee's registered X25519 public key (`GET /api/v1/devices`).
4. The active member wraps the active epoch DEK to the invitee's device and publishes the envelope (`POST /api/v1/vaults/{id}/keys/envelopes`).
5. The invitee's device downloads its envelope (`GET /api/v1/vaults/{id}/keys/envelopes`), unwraps the DEK locally using its private X25519 key, and begins decrypting vault records.

### 2.3 Member Revocation & Key Epoch Rotation
1. When a member or device is revoked (`DELETE /api/v1/vaults/{id}/members/{user_id}` or device revocation), server authorization immediately terminates access.
2. An authorized surviving member device creates a new epoch key (`DEK_n+1`).
3. The new DEK is wrapped **exclusively** to surviving, trusted devices.
4. The client commits the rotation via `POST /api/v1/vaults/{id}/keys/epochs`.
5. The server advances `active_key_epoch` and immediately rejects mutations tagged with prior/stale epochs (HTTP 409 Conflict).
6. Subsequent record edits are sealed under `DEK_n+1`. Historical records may be re-encrypted lazily on update or through a batch re-keying process.

---

## 3. Ephemeral Terminal Collaboration Keying

1. When a host initiates a live collaboration session (`POST /api/v1/collab/sessions`), an ephemeral session key (`SK_collab`) is generated locally.
2. In controllable or read-only sessions, `SK_collab` is distributed to authorized participants via authenticated signaling frames (`CollabFrameType::Signal`).
3. Live terminal output (`CollabFrameType::Output`) and input keystrokes (`CollabFrameType::Input`) are encrypted under `SK_collab` before transmission to the relay.
4. The server forwards ciphertext frames blindly without possessing `SK_collab`.
5. Upon session termination, the key is wiped from client memory.

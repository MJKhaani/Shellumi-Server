# ADR 0004: M3 Team Vaults, RBAC Matrix, Invitations, and Recipient-Wrapped Key Envelopes

## Status
Accepted

## Context
Milestone M3 enables multi-user and multi-device collaboration through shared team vaults. In self-hosted environments, team collaboration must maintain the server's zero-knowledge posture: the server must enforce authorization policy without ever accessing plaintext vault data or unencrypted vault Data Encryption Keys (DEKs).

The team collaboration subsystem must satisfy the following architectural requirements:
1. **Hierarchical RBAC Matrix:**
   - `Owner`: Full control, can transfer ownership, delete vault, manage all members, and invite Admins. Cannot revoke the last Owner.
   - `Administrator`: Can invite Editors and Viewers, rotate key epochs, view audit logs, and edit vault metadata. Cannot reassign Owner or revoke an Owner.
   - `Editor`: Can read, write, and sync records. Cannot invite members or rotate keys.
   - `Viewer`: Read-only access to records and delta change feeds. Commits are strictly rejected with HTTP 403 Forbidden.
2. **One-Time Scoped Invitations:**
   - Single-use cryptographically secure random token (256 bits).
   - The server stores only the SHA-256 hash of the invite token (`invite_token_hash`).
   - Bound to a specific vault, scoped role, inviter, and expiration timestamp.
   - Acceptance validates the authenticated user, proof of registered device identity, and consumes the invitation atomically.
3. **Recipient-Wrapped Key Envelopes (`vault_key_envelopes`):**
   - Each vault has an active 256-bit DEK generated client-side by an authorized device.
   - For every authorized recipient device, the client wraps the DEK using the recipient's registered X25519 public key.
   - The server stores only opaque `wrapped_dek` payloads.
   - Calling devices are restricted to fetching only key envelopes wrapped specifically for their own registered `device_id`.
4. **Epoch Rotation upon Revocation:**
   - When a member or device is revoked, a surviving authorized device rotates the vault key to a new epoch (`epoch = current_epoch + 1`).
   - The client generates a new DEK and uploads wrapped envelopes only for surviving, trusted devices.
   - Writes using old key epochs are rejected with HTTP 409 Conflict / 403 Forbidden once the epoch transition is committed.
5. **Cryptographic Audit Trail (`audit_events`):**
   - Append-only log recording actor, device, vault, tenant, action, and timestamp.
   - Hash chaining: every event records `predecessor_hash` and computes `event_hash = SHA-256(id, vault_id, actor, action, target, predecessor_hash, timestamp)`.

## Decision

### 1. RBAC Policy Enforcement
Authorization is enforced on the server at every endpoint. Member role checks are evaluated against the persistent `vault_members` mapping:
| Endpoint / Action | Owner | Administrator | Editor | Viewer |
| :--- | :---: | :---: | :---: | :---: |
| `GET /vaults/:id` | Allow | Allow | Allow | Allow |
| `PATCH /vaults/:id` | Allow | Allow | Deny (403) | Deny (403) |
| `DELETE /vaults/:id` | Allow | Deny (403) | Deny (403) | Deny (403) |
| `GET /vaults/:id/members` | Allow | Allow | Allow | Allow |
| `POST /vaults/:id/members` | Allow | Allow (Editor/Viewer) | Deny (403) | Deny (403) |
| `DELETE /vaults/:id/members/:uid` | Allow | Allow (Editor/Viewer) | Deny (403) | Deny (403) |
| `POST /vaults/:id/invites` | Allow | Allow | Deny (403) | Deny (403) |
| `POST /vaults/:id/commits` | Allow | Allow | Allow | Deny (403) |
| `GET /vaults/:id/changes` | Allow | Allow | Allow | Allow |
| `POST /vaults/:id/keys/epochs` | Allow | Allow | Deny (403) | Deny (403) |
| `GET /vaults/:id/keys/envelopes` | Device-only | Device-only | Device-only | Device-only |
| `GET /vaults/:id/audit` | Allow | Allow | Deny (403) | Deny (403) |

### 2. Recipient Key Envelope Isolation
`GET /api/v1/vaults/{id}/keys/envelopes` requires the `X-Device-Id` header and validates that the device belongs to the authenticated user. The server filters envelopes strictly where `recipient_device_id == calling_device_id`. Devices never receive other devices' wrapped keys.

### 3. Invitation Acceptance Flow
`POST /api/v1/invites/accept` receives `{ "invite_token": "..." }`. The server computes `SHA-256(invite_token)`, looks up `vault_invites`, verifies `expires_at > now`, `accepted_at IS NULL`, and `revoked_at IS NULL`. It atomically creates the `vault_member` row with the invite's role, marks the invite as accepted, and emits an audit event.

## Consequences
- Preserves zero-knowledge guarantees: the server cannot decrypt or inspect team vault contents or cryptographic keys.
- Prevents privilege escalation: last owner protection, role hierarchy validation, and device key binding.
- Enables auditable team sharing without requiring third-party cloud infrastructure or external mail delivery.

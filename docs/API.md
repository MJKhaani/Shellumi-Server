# Shellumi Server — API Documentation (v1)

Base Path: `/`

All JSON error responses use standard status codes and the following body structure:

```json
{
  "error_code": "STRING_CODE",
  "message": "Human readable explanation",
  "request_id": "optional-uuid"
}
```

---

## 1. System & Health

### Health Liveness
- **Path:** `GET /health/live`
- **Auth:** None
- **Response:** `200 OK`
```json
{
  "status": "ok",
  "service": "shellumi-server",
  "version": "0.1.0",
  "details": null
}
```

### Health Readiness
- **Path:** `GET /health/ready`
- **Auth:** None
- **Response:** `200 OK`
```json
{
  "status": "ok",
  "service": "shellumi-server",
  "version": "0.1.0",
  "details": "System ready"
}
```

### Server Capabilities
- **Path:** `GET /api/v1/capabilities`
- **Auth:** None
- **Response:** `200 OK`
```json
{
  "server_version": "0.1.0",
  "protocol_version": 1,
  "min_protocol_version": 1,
  "supported_features": ["vault_sync_v1", "device_auth", "team_sharing"],
  "supported_e2ee_suites": ["x25519_hkdf_aes256gcm", "argon2id_aes256gcm_legacy"],
  "limits": {
    "max_request_bytes": 10485760,
    "max_record_bytes": 1048576,
    "max_mutations_per_commit": 100
  }
}
```

---

## 2. Bootstrap & Authentication

### One-Time Bootstrap
- **Path:** `POST /api/v1/bootstrap`
- **Auth:** None (or optional bootstrap token if configured)
- **Request Body:**
```json
{
  "admin_username": "sysadmin",
  "admin_email": "admin@example.com",
  "admin_password": "Password123!",
  "org_name": "My Organization",
  "bootstrap_token": null
}
```
- **Response:** `201 Created`
```json
{
  "org_id": "019abcde-...",
  "user_id": "019abcde-...",
  "username": "sysadmin",
  "email": "admin@example.com",
  "access_token": "ey...",
  "refresh_token": "a1b2...",
  "expires_in_secs": 900
}
```
- **Errors:** `409 Conflict` (`BOOTSTRAP_ALREADY_CONSUMED`) if already bootstrapped.

### User Login
- **Path:** `POST /api/v1/auth/login`
- **Auth:** None
- **Request Body:**
```json
{
  "identifier": "sysadmin",
  "password": "Password123!",
  "device_id": null
}
```
- **Response:** `200 OK`
```json
{
  "user_id": "019abcde-...",
  "username": "sysadmin",
  "email": "admin@example.com",
  "access_token": "ey...",
  "refresh_token": "a1b2...",
  "expires_in_secs": 900
}
```

### Refresh Token Rotation
- **Path:** `POST /api/v1/auth/refresh`
- **Auth:** None
- **Request Body:**
```json
{
  "refresh_token": "a1b2..."
}
```
- **Response:** `200 OK`
```json
{
  "access_token": "ey...",
  "refresh_token": "c3d4...",
  "expires_in_secs": 900
}
```
- **Errors:** `403 Forbidden` (`TOKEN_REUSE_DETECTED`) if an already rotated token is re-presented.

### Logout
- **Path:** `POST /api/v1/auth/logout`
- **Auth:** Bearer Token
- **Request Body:**
```json
{
  "refresh_token": "c3d4..."
}
```
- **Response:** `200 OK`

### Current User Profile
- **Path:** `GET /api/v1/me`
- **Auth:** Bearer Token
- **Response:** `200 OK`
```json
{
  "user_id": "019abcde-...",
  "username": "sysadmin",
  "email": "admin@example.com",
  "organizations": [
    {
      "org_id": "019abcde-...",
      "org_name": "My Organization",
      "role": "owner"
    }
  ]
}
```

---

## 3. Device Management

### List Registered Devices
- **Path:** `GET /api/v1/devices`
- **Auth:** Bearer Token
- **Response:** `200 OK`
```json
[
  {
    "device_id": "019abcde-...",
    "user_id": "019abcde-...",
    "device_name": "MacBook Pro",
    "signing_public_key": "base64-ed25519-public-key",
    "agreement_public_key": "base64-x25519-public-key",
    "created_at": 1700000000,
    "last_seen_at": 1700000000,
    "revoked_at": null
  }
]
```

### Register Device
- **Path:** `POST /api/v1/devices`
- **Auth:** Bearer Token
- **Request Body:**
```json
{
  "device_name": "MacBook Pro",
  "signing_public_key": "base64-ed25519-public-key",
  "agreement_public_key": "base64-x25519-public-key"
}
```
- **Response:** `201 Created`

### Revoke Device
- **Path:** `DELETE /api/v1/devices/{id}`
- **Auth:** Bearer Token
- **Response:** `204 No Content`

---

## 4. Vault Management

### List Accessible Vaults
- **Path:** `GET /api/v1/vaults`
- **Auth:** Bearer Token
- **Response:** `200 OK`
```json
{
  "vaults": [
    {
      "vault_id": "019abcde-...",
      "tenant_id": "019abcde-...",
      "owner_id": "019abcde-...",
      "vault_type": "personal",
      "encrypted_name": "base64-encrypted-metadata",
      "active_key_epoch": 1,
      "server_sequence": 42,
      "role": "owner",
      "created_at": 1700000000,
      "updated_at": 1700000100
    }
  ]
}
```

### Create Vault
- **Path:** `POST /api/v1/vaults`
- **Auth:** Bearer Token
- **Request Body:**
```json
{
  "name": "My Vault",
  "encrypted_name": "base64-metadata",
  "vault_type": "personal"
}
```
- **Response:** `201 Created` (VaultResponse)

### Get Vault Details
- **Path:** `GET /api/v1/vaults/{id}`
- **Auth:** Bearer Token
- **Response:** `200 OK` (VaultResponse)
- **Errors:** `404 Not Found` if inaccessible or deleted.

### Update Vault Metadata
- **Path:** `PATCH /api/v1/vaults/{id}`
- **Auth:** Bearer Token (Owner or Administrator)
- **Request Body:**
```json
{
  "encrypted_name": "new-encrypted-metadata"
}
```
- **Response:** `200 OK` (VaultResponse)

### Delete Vault
- **Path:** `DELETE /api/v1/vaults/{id}`
- **Auth:** Bearer Token (Owner only)
- **Response:** `200 OK` `{"status": "deleted"}`

---

## 5. Synchronization & Commits

### Commit Batch of Mutations
- **Path:** `POST /api/v1/vaults/{id}/commits`
- **Auth:** Bearer Token
- **Headers:** `X-Device-Id: <uuid>`
- **Request Body:**
```json
{
  "protocol_version": 1,
  "vault_id": "019abcde-...",
  "idempotency_key": "unique-client-mutation-uuid",
  "base_cursor": "seq:41",
  "mutations": [
    {
      "object_id": "host-1",
      "entity_type": "host",
      "expected_revision": 0,
      "deleted": false,
      "key_epoch": 1,
      "device_counter": 1,
      "encrypted_envelope": {
        "salt": "base64-salt",
        "nonce": "base64-nonce",
        "ciphertext": "base64-ciphertext-with-tag",
        "associated_data": "host:host-1",
        "kdf_iterations": 600000
      },
      "device_signature": "base64-ed25519-signature"
    }
  ]
}
```
- **Response:** `200 OK`
```json
{
  "vault_id": "019abcde-...",
  "commit_sequence": 42,
  "next_cursor": "seq:42",
  "applied": [
    {
      "object_id": "host-1",
      "assigned_revision": 1,
      "server_sequence": 42,
      "deleted": false
    }
  ]
}
```
- **Errors:**
  - `403 Forbidden` (`INVALID_SIGNATURE`) if device signature does not verify.
  - `409 Conflict` (`REVISION_CONFLICT`) if an object's current revision does not match `expected_revision`.
  - `409 Conflict` (`IDEMPOTENCY_CONFLICT`) if the same idempotency key is reused with a different payload.

### Delta Changes Feed
- **Path:** `GET /api/v1/vaults/{id}/changes?since=0&limit=100`
- **Auth:** Bearer Token
- **Query Parameters:**
  - `since`: Sequence number after which to fetch changes (default 0).
  - `cursor`: Alternative cursor token format `seq:{N}`.
  - `limit`: Number of records to return (1 to 500, default 100).
- **Response:** `200 OK`
```json
{
  "vault_id": "019abcde-...",
  "latest_sequence": 42,
  "next_cursor": "seq:42",
  "has_more": false,
  "records": [
    {
      "sequence": 42,
      "object_id": "host-1",
      "entity_type": "host",
      "revision": 1,
      "deleted": false,
      "author_device_id": "019abcde-...",
      "encrypted_envelope": {
        "salt": "base64-salt",
        "nonce": "base64-nonce",
        "ciphertext": "base64-ciphertext",
        "associated_data": "host:host-1",
        "kdf_iterations": 600000
      },
      "updated_at": 1700000100
    }
  ]
}
```

### Full Recovery Snapshot
- **Path:** `GET /api/v1/vaults/{id}/snapshots/{revision}`
- **Auth:** Bearer Token
- **Response:** `200 OK`
```json
{
  "vault_id": "019abcde-...",
  "server_sequence": 42,
  "records": [ ... ]
}
```


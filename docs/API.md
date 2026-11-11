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

---

## 4. Team Vaults, Collaboration & E2EE Keys

### List Vault Members
- **Path:** `GET /api/v1/vaults/{id}/members`
- **Auth:** Bearer Token (any member: Owner, Administrator, Editor, Viewer)
- **Response:** `200 OK`
```json
{
  "members": [
    {
      "vault_id": "019abcde-...",
      "user_id": "019abcde-...",
      "username": "alice",
      "role": "owner",
      "joined_at": 1700000000
    }
  ]
}
```

### Add or Update Vault Member
- **Path:** `POST /api/v1/vaults/{id}/members`
- **Auth:** Bearer Token (Owner or Administrator)
- **Request Body:**
```json
{
  "user_id": "019abcde-...",
  "role": "editor"
}
```
- **Response:** `200 OK`
- **Errors:**
  - `403 Forbidden` (`PERMISSION_DENIED`) if caller is not an Owner/Administrator or an Administrator attempts to assign Owner/Administrator.
  - `409 Conflict` (`CANNOT_REVOKE_LAST_OWNER`) if updating the sole owner to a non-owner role.

### Remove Vault Member
- **Path:** `DELETE /api/v1/vaults/{id}/members/{user_id}`
- **Auth:** Bearer Token (Owner or Administrator)
- **Response:** `204 No Content`
- **Errors:**
  - `409 Conflict` (`CANNOT_REVOKE_LAST_OWNER`) if attempting to remove the sole owner.
  - `403 Forbidden` (`PERMISSION_DENIED`) if an Administrator attempts to remove an Owner or another Administrator.

### Create One-Time Invitation
- **Path:** `POST /api/v1/vaults/{id}/invites`
- **Auth:** Bearer Token (Owner or Administrator)
- **Request Body:**
```json
{
  "role": "editor",
  "recipient_email": "colleague@example.com",
  "ttl_secs": 86400
}
```
- **Response:** `201 Created`
```json
{
  "invite_id": "019abcde-...",
  "vault_id": "019abcde-...",
  "role": "editor",
  "invite_token": "a1b2c3d4e5f6... (256-bit random hex)",
  "recipient_email": "colleague@example.com",
  "expires_at": 1700086400,
  "created_at": 1700000000
}
```

### List Active Invitations
- **Path:** `GET /api/v1/vaults/{id}/invites`
- **Auth:** Bearer Token (Owner or Administrator)
- **Response:** `200 OK` (Note: `invite_token` is never returned after creation)
```json
{
  "invites": [
    {
      "invite_id": "019abcde-...",
      "vault_id": "019abcde-...",
      "role": "editor",
      "recipient_email": "colleague@example.com",
      "expires_at": 1700086400,
      "created_at": 1700000000
    }
  ]
}
```

### Revoke Invitation
- **Path:** `DELETE /api/v1/vaults/{id}/invites/{invite_id}`
- **Auth:** Bearer Token (Owner or Administrator)
- **Response:** `204 No Content`

### Accept Invitation
- **Path:** `POST /api/v1/invites/accept`
- **Auth:** Bearer Token (Authenticated user)
- **Request Body:**
```json
{
  "invite_token": "a1b2c3d4e5f6..."
}
```
- **Response:** `200 OK`
```json
{
  "vault_id": "019abcde-...",
  "role": "editor"
}
```
- **Errors:**
  - `404 Not Found` (`INVITE_NOT_FOUND`) if token hash does not match.
  - `409 Conflict` (`INVITE_ALREADY_ACCEPTED`) if token was already used.
  - `403 Forbidden` (`INVITE_REVOKED`) if invitation was revoked.
  - `410 Gone` (`INVITE_EXPIRED`) if invitation has expired.

### Publish Recipient-Wrapped Key Envelopes
- **Path:** `POST /api/v1/vaults/{id}/keys/envelopes`
- **Auth:** Bearer Token + `X-Device-Id` header (Editor, Administrator, Owner)
- **Request Body:**
```json
{
  "epoch": 1,
  "envelopes": [
    {
      "recipient_device_id": "019abcde-...",
      "wrapped_dek": "base64-ciphertext-of-wrapped-dek",
      "key_agreement_ephemeral_pk": "optional-ephemeral-pk"
    }
  ]
}
```
- **Response:** `201 Created`
```json
{
  "published": 1
}
```

### Fetch Recipient-Wrapped Key Envelopes
- **Path:** `GET /api/v1/vaults/{id}/keys/envelopes?epoch=1`
- **Auth:** Bearer Token + `X-Device-Id` header (Any vault member)
- **Security Guarantee:** Devices can only fetch key envelopes wrapped specifically for their own registered `device_id`.
- **Response:** `200 OK`
```json
{
  "envelopes": [
    {
      "vault_id": "019abcde-...",
      "epoch": 1,
      "recipient_device_id": "019abcde-...",
      "sender_device_id": "019abcde-...",
      "wrapped_dek": "base64-ciphertext-of-wrapped-dek",
      "key_agreement_ephemeral_pk": "optional-ephemeral-pk",
      "created_at": 1700000000
    }
  ]
}
```

---

## 5. Telemetry, Observability & Rate Limiting

### Prometheus Metrics
- **Path:** `GET /metrics`
- **Auth:** None (Operator/Scraper endpoint)
- **Content-Type:** `text/plain; version=0.0.4; charset=utf-8`
- **Configuration:** Enabled when `metrics_enabled = true` (`SHELLUMI_SERVER_METRICS_ENABLED=true`). Returns `404 Not Found` if disabled.
- **Label Cardinality Guarantee:** Metric labels record only HTTP method, normalized route template (e.g. `/api/v1/vaults/:id/commits`), and status code. High-cardinality values (UUIDs, user IDs, device IDs) are strictly excluded.
- **Example Exposition:**
```prometheus
# HELP shellumi_http_requests_total Total number of HTTP requests processed.
# TYPE shellumi_http_requests_total counter
shellumi_http_requests_total{method="GET",path="/health/live",status="200"} 42
shellumi_http_requests_total{method="POST",path="/api/v1/vaults/:id/commits",status="200"} 15

# HELP shellumi_http_request_duration_seconds_total Total duration of HTTP requests in seconds.
# TYPE shellumi_http_request_duration_seconds_total counter
shellumi_http_request_duration_seconds_total{method="GET",path="/health/live"} 0.084120

# HELP shellumi_rate_limit_exceeded_total Total number of rate-limited requests rejected with HTTP 429.
# TYPE shellumi_rate_limit_exceeded_total counter
shellumi_rate_limit_exceeded_total{category="auth_login"} 3

# HELP shellumi_active_sessions_total Current number of active authenticated user sessions.
# TYPE shellumi_active_sessions_total gauge
shellumi_active_sessions_total 5
```

### Rate Limiting & Abuse Prevention
Sensitive endpoints are protected by in-memory sliding-window rate limiters:
- **Protected Routes:**
  - `POST /api/v1/auth/login` (brute-force password guessing)
  - `POST /api/v1/bootstrap` (bootstrap replay/spamming)
  - `POST /api/v1/invites/accept` (invitation token guessing)
- **Default Limit:** 10 requests per minute per client IP (configurable via `SHELLUMI_SERVER_RATE_LIMIT_PER_MINUTE`).
- **HTTP 429 Response:**
  - Header: `Retry-After: <seconds>`
  - Body:
```json
{
  "error_code": "RATE_LIMIT_EXCEEDED",
  "message": "Too many requests. Please wait 45 seconds before retrying.",
  "request_id": "019abcde-..."
}
```


### Rotate Key Epoch
- **Path:** `POST /api/v1/vaults/{id}/keys/epochs`
- **Auth:** Bearer Token + `X-Device-Id` header (Owner or Administrator)
- **Request Body:**
```json
{
  "new_epoch": 2,
  "envelopes": [
    {
      "recipient_device_id": "019abcde-...",
      "wrapped_dek": "new-wrapped-dek-for-epoch-2"
    }
  ]
}
```
- **Response:** `200 OK`
```json
{
  "vault_id": "019abcde-...",
  "active_key_epoch": 2,
  "enrolled_envelopes": 1
}
```
- **Errors:**
  - `409 Conflict` (`STALE_KEY_EPOCH`) if `new_epoch <= active_key_epoch`.

### Cryptographic Audit Log
- **Path:** `GET /api/v1/vaults/{id}/audit?limit=50&offset=0`
- **Auth:** Bearer Token (Owner or Administrator)
- **Response:** `200 OK`
```json
{
  "vault_id": "019abcde-...",
  "events": [
    {
      "id": 1,
      "vault_id": "019abcde-...",
      "actor_user_id": "019abcde-...",
      "actor_device_id": "019abcde-...",
      "action": "member.add_or_update",
      "target_type": "user",
      "target_id": "019abcde-...",
      "details": "role=editor",
      "predecessor_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "event_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "created_at": 1700000000
    }
  ]
}
```

---

## 5. Telemetry, Observability & Rate Limiting

### Prometheus Metrics
- **Path:** `GET /metrics`
- **Auth:** None (Operator/Scraper endpoint)
- **Content-Type:** `text/plain; version=0.0.4; charset=utf-8`
- **Configuration:** Enabled when `metrics_enabled = true` (`SHELLUMI_SERVER_METRICS_ENABLED=true`). Returns `404 Not Found` if disabled.
- **Label Cardinality Guarantee:** Metric labels record only HTTP method, normalized route template (e.g. `/api/v1/vaults/:id/commits`), and status code. High-cardinality values (UUIDs, user IDs, device IDs) are strictly excluded.
- **Example Exposition:**
```prometheus
# HELP shellumi_http_requests_total Total number of HTTP requests processed.
# TYPE shellumi_http_requests_total counter
shellumi_http_requests_total{method="GET",path="/health/live",status="200"} 42
shellumi_http_requests_total{method="POST",path="/api/v1/vaults/:id/commits",status="200"} 15

# HELP shellumi_http_request_duration_seconds_total Total duration of HTTP requests in seconds.
# TYPE shellumi_http_request_duration_seconds_total counter
shellumi_http_request_duration_seconds_total{method="GET",path="/health/live"} 0.084120

# HELP shellumi_rate_limit_exceeded_total Total number of rate-limited requests rejected with HTTP 429.
# TYPE shellumi_rate_limit_exceeded_total counter
shellumi_rate_limit_exceeded_total{category="auth_login"} 3

# HELP shellumi_active_sessions_total Current number of active authenticated user sessions.
# TYPE shellumi_active_sessions_total gauge
shellumi_active_sessions_total 5
```

### Rate Limiting & Abuse Prevention
Sensitive endpoints are protected by in-memory sliding-window rate limiters:
- **Protected Routes:**
  - `POST /api/v1/auth/login` (brute-force password guessing)
  - `POST /api/v1/bootstrap` (bootstrap replay/spamming)
  - `POST /api/v1/invites/accept` (invitation token guessing)
- **Default Limit:** 10 requests per minute per client IP (configurable via `SHELLUMI_SERVER_RATE_LIMIT_PER_MINUTE`).
- **HTTP 429 Response:**
  - Header: `Retry-After: <seconds>`
  - Body:
```json
{
  "error_code": "RATE_LIMIT_EXCEEDED",
  "message": "Too many requests. Please wait 45 seconds before retrying.",
  "request_id": "019abcde-..."
}
```




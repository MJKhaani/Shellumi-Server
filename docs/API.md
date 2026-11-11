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

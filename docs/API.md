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

## Endpoints

### 1. Health Liveness
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

### 2. Health Readiness
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

### 3. Server Capabilities
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

### 4. Unmapped Route (404 Fallback)
- **Path:** Any undefined route
- **Response:** `404 Not Found`
```json
{
  "error_code": "NOT_FOUND",
  "message": "The requested resource was not found",
  "request_id": null
}
```

# Shellumi Server Protocol v1 — Pre-release Finalization Specification

**Status:** Design / implementation contract for BOTH agents; **not proof of implementation**.  
**Decision:** Neither Shellumi nor Shellumi-Server has shipped a public protocol release. **Keep protocol version 1 and `/api/v1` throughout.** Rewrite incompatible, incomplete v1 DTOs and handlers in place; do not build v2 endpoints, dual-version dispatch, or v1↔v2 migrations. Maintain explicit encrypted-backup/Google Drive data import safety because users may already have unreleased local data.  
**Audited baselines (2026-11-16):** Server [`40f3b4ed`](https://github.com/MJKhaani/Shellumi-Server/tree/40f3b4ed4bfc0e7173baf20e1df48cae728afcba); client [`c90dac42`](https://github.com/MJKhaani/Shellumi/tree/c90dac421651af0d36e98d3359abd7cc4ed38a30). Verify heads again before editing.

## 1. Objectives and non-negotiable invariants

1. A self-hosted server stores **only authenticated opaque vault ciphertext**, recipient-wrapped keys, metadata needed for operations, memberships, audit and event logs. It never receives the vault DEK, passphrase, decrypted SSH secrets or credential material. End-to-end encryption does **not** conceal access patterns, object counts, sizes, memberships or denial-of-service by operators.
2. Standalone Shellumi functions offline. Google Drive personal sync remains a **direct independent provider**, without corporate server accounts. Exactly **one authoritative sync provider per vault**; provider cutover is explicit and verified.
3. Every server installation has a stable `server_instance_id` persisted across process restarts and normal database restores. A replaced installation behind the same URL requires re-verification; no blind association of cached secrets to a new server.
4. Domain identity is `(server_instance_id, tenant_id, vault_id, object_id)`, with additional `(account_id, device_id, local_vault_context_id)` on the client. All object IDs are immutable UUIDs, not host/identity/snippet names or local SQL row numbers.
5. A client only advances its committed sync cursor after all covered events are validated, decrypted (when required), and durably applied **together**. Invalid AEAD tags, unavailable keys, unknown required features and malformed records are explicit failures, never skipped success.
6. No credential token, refresh token, device private key, DEK or passphrase is retained in unencrypted local Turso fields, logs or ordinary preference files. Use secure OS stores or a cryptographically protected user-unlocked fallback.
7. The WebSocket is **instant change notification only**, not the source of truth or a carrier of plaintext vault records. All authoritative changes, snapshots and commits use HTTPS and the durable PostgreSQL change log.
8. New operations from a revoked member/device are denied immediately; offline copies already accessed cannot be retroactively erased. Rotate epochs with fresh client-generated keys for future confidentiality.

## 2. Existing implementation vs target

- Existing server routes (`/api/v1/vaults/{id}/commits`, `/changes`, `/snapshots/{revision}`, `/auth/*`, `/devices`, `/keys/envelopes`) and client DTOs are useful **starting material**, not a completed contract.
- Existing server capability response advertises `vault_sync_v1`, `device_auth`, `team_sharing` and optional `terminal_collab_v1`; existing companion `docs/COMPATIBILITY.md` examples differ from runtime. Normalize to code-backed v1 feature names.
- Existing client `VaultCipher` emits an empty salt and `kdf_iterations=0` for a random DEK, but the existing server crypto validator rejects that envelope. Replace the pre-release record wire envelope **in both projects** with a named suite and strict normative shape.
- The server exposes a vault-change WebSocket route and a separate SSE endpoint for terminal collaboration. Real-service coverage remains incomplete.
- Do not claim implemented, secure or compatible merely because a feature string or OpenAPI schema exists.

## 3. Base transport and capabilities

- Native Rust HTTPS for all API requests; native Rust **WSS** for live notifications. Require chain/hostname validation; only explicit loopback development may use HTTP/WS; no `danger_accept_invalid_certs`, redirects leaking Authorization, or credentials in URL/query/logs.
- JSON over `/api/v1`; typed `ErrorResponse { error_code, message, request_id }` on every failure. Size bounded request and response, timeouts, cancellation and retry classification.
- `GET /api/v1/capabilities` returns **one** current protocol version `1` (and `min_protocol_version: 1` for existing DTO compatibility), immutable `server_instance_id`, server release/version, features, crypto suites, WS availability/endpoint, retention and batch limits, server time. Do not invent features not actually enabled.
- Mandatory features for Phase 11: `vault_sync_v1`, `device_auth_v1`, `device_wrapped_keys_v1`, `signed_mutations_v1`, `delta_sync_v1`, `websocket_notifications_v1`; add `team_sharing_v1` only when implemented. Map or remove older names with coordinated fixture updates.
- A new client checks required features/suites/limits *before* creating or joining a remote vault, and detects server identity changes. Use separate capability flags for optional terminal collaboration.

Illustrative v1 response:

```json
{
  "server_instance_id": "3b21741a-0f47-490f-ac7b-2cedaf8e0ebc",
  "server_version": "0.1.0-dev",
  "protocol_version": 1,
  "min_protocol_version": 1,
  "supported_features": ["vault_sync_v1", "device_auth_v1", "signed_mutations_v1", "device_wrapped_keys_v1", "delta_sync_v1", "websocket_notifications_v1"],
  "supported_e2ee_suites": ["aes256gcm_dek_v1", "hpke_x25519_hkdfsha256_aes256gcm_v1"],
  "websocket": {"endpoint": "/api/v1/events/ws", "heartbeat_seconds": 25},
  "limits": {"max_request_bytes": 10485760, "max_record_bytes": 1048576, "max_mutations_per_commit": 100, "max_change_page": 500}
}
```

## 4. Authentication, devices and key ownership

- Keep Argon2id server-side password verification. Replace static bearer signing secret and custom SHA256(secret || message) with standard authenticated tokens or strongly random opaque tokens keyed to persistent server sessions. Access token claims / introspection must bind `sid`, `sub`, `did`, `iss=server_instance_id`, `aud`, `iat`, `exp`; verify active session/user/device for each privileged call. Enrollment may use a narrowly scoped temporary session before `did` is known.
- Refresh tokens are random, stored only as digests server-side, rotated atomically and bound to a session/device family. A client uses single-flight refresh per `(server_instance_id, account_id)` across windows and WS reconnect. Network-uncertain refresh does not blindly reuse a potentially consumed token; provide an explicit recovery/reauth path.
- Each device has **independent** Ed25519 signing and X25519 key agreement keys, not OpenSSH key material. Validate exact key encodings/lengths and perform challenge/proof-of-possession bound to server identity + account + nonce + expiry. Securely persist private keys in an OS keyring.
- Add `POST /api/v1/devices/challenge` and enhance `POST /api/v1/devices`; expose authenticated `GET /api/v1/vaults/{id}/recipient-devices` limited to current authorized member devices and verified fingerprints. No global directory of public keys.
- Revoking a device invalidates active access and refresh credentials and current subscriptions. Reject access from disabled accounts, revoked membership and devices after server restart.

## 5. Encrypted record envelopes (v1 finalized in place)

- Every vault has a fresh random 256-bit **DEK per key epoch**. AES-256-GCM uses a fresh 96-bit random nonce per record and 128-bit authentication tag.
- Separate `RecordEnvelopeV1` (DEK encrypts records) from `RecoveryEnvelopeV1` (passphrase-derived KEK wraps a DEK). **Do not force a PBKDF2 salt or KDF iterations into direct-DEK record encryption.** Preserve earlier local backup format for explicit import only.
- Proposed record fields: `{format_version:1, suite:"aes256gcm_dek_v1", key_epoch:u32, nonce_b64, ciphertext_b64}`; `ciphertext_b64` includes tag. Authenticated associated data is derived canonically, not trusted from an unverified server field.
- Canonical AAD must bind domain `shellumi.record.v1`, `server_instance_id`, `tenant_id`, `vault_id`, `object_id`, `entity_type`, `target_revision`, `key_epoch`. Use an unambiguous length-delimited byte encoding (e.g. canonical CBOR with pinned encoding rules, or fixed-width network-order fields + length-prefixed UTF-8), not colon-concatenation.
- Do not confuse stored **local vault ID** with remote server's immutable vault UUID when deriving AAD. Cross-server, cross-vault and cross-type transplants must fail AEAD verification.
- Recipient wrapping: reviewed **HPKE RFC 9180** or explicitly reviewed authenticated equivalent with X25519/HKDF-SHA256/AES-256-GCM. Sign provenance by Ed25519; bind server/tenant/vault/epoch, sender and recipient device IDs/key fingerprints. Verify recipient identity; publishing to nonmember or revoked device is forbidden.
- On revocation, generate a new epoch DEK and wraps for surviving verified devices; publish activation transactionally, reject **both older and future** epoch writes. Existing downloaded ciphertext remains potentially readable to former members unless re-encrypted; document this limitation and offer safe historical rekey where needed.

## 6. Signed mutations, transactional commits, change feed and snapshots

- Each mutation has immutable `mutation_id`, UUID `object_id`, stable `entity_type`, `expected_revision`, deterministic `target_revision=expected_revision+1`, `key_epoch`, monotonic `device_counter`, `deleted`, versioned envelope (or none for delete), and Ed25519 signature over canonical **unambiguous** bytes binding server/tenant/vault/device/object/type/revisions/epoch/counter/deletion/whole-envelope digest.
- The client stores the exact signed serialized batch plus idempotency key in a durable encrypted outbox *before* sending; retried uncertain requests reuse every byte, UUID, nonce, counter, signature and idempotency key.
- PostgreSQL commit uses one transaction (vault row lock / serializable policy): verify ownership, device, session, RBAC, epoch, counters, idempotency, all CAS bases and batch bounds **inside the commit transaction**, assign a **different increasing `event_sequence` to each mutation**, persist encrypted objects/tombstones/change log/idempotency and commit atomically. A batch conflict rejects the whole batch without partial writes.
- `GET /api/v1/vaults/{id}/changes?cursor=<opaque>&limit=N`: ordered event rows, unique sequence per event, validated cursor bound to vault + server instance, page `next_cursor` reflects **last included event**; `has_more` requires follow-up. The optional `latest_sequence` is a high-watermark, **not** a cursor that can skip unprocessed pages.
- Expired cursor returns typed `410 CURSOR_EXPIRED` with recovery workflow. `GET /api/v1/vaults/{id}/snapshots` returns a consistent revision/watermark snapshot, paginated if necessary. Do not keep the existing `/snapshots/{revision}` behavior that ignores the requested revision; either implement it correctly or coordinate an intentional `/snapshots` pre-release path change.
- The local client must apply changes + cursor in the same transaction, preserve dirty local versions before incoming updates, handle deletion/update conflicts and never treat a failed decrypt as successful apply. No unconditional last-write-wins for secrets.

## 7. Required **WebSocket instant vault-change notifications**

**This is mandatory in protocol v1, not a later optional enhancement.** The notification plane reduces latency; all data remain in the durable HTTPS sync plane.

### Endpoint and connection

- `GET /api/v1/events/ws` upgrades to WSS; the native Rust client supplies `Authorization: Bearer <access-token>` and `X-Device-Id` in handshake headers; never place access/refresh tokens in query parameters, URL, events or logs. Server checks active user/session/device on handshake and each subscription and closes revoked/expired sessions. Configure TLS proxy upgrades and keepalive (`Connection: Upgrade`, `Upgrade: websocket`) explicitly.
- A client establishes **one WebSocket per `(server_instance_id, account_id, device_id)`**, not one socket per window or vault. It subscribes to all authorized vault IDs currently open or configured for background sync. Multiple local windows share a broker/coordinator.
- On connection/reconnection, client sends a `subscribe` request and receives an authoritative `subscribed` response containing the **current per-vault durable high-watermark**. It then performs `/changes` reconciliation even if no event arrives. Add `unsubscribe`, `ping/pong` and bounded `error` messages; reject oversized/invalid messages with safe close behavior.
- Suggested minimal JSON messages below:

```json
{"action":"subscribe","request_id":"96d9956d-444b-4410-a96b-a2e5ff743ca6","vault_ids":["d888f1ee-0cae-4d64-91b0-bd5e1ee6d326"]}
{"event":"subscribed","request_id":"96d9956d-444b-4410-a96b-a2e5ff743ca6","vaults":[{"vault_id":"d888f1ee-0cae-4d64-91b0-bd5e1ee6d326","latest_sequence":27}]}
{"event":"vault.changed","vault_id":"d888f1ee-0cae-4d64-91b0-bd5e1ee6d326","latest_sequence":28,"notification_id":"aeb63ab6-cf15-422e-a53d-8f4e4bf998fe"}
{"event":"vault.key_rotated","vault_id":"d888f1ee-0cae-4d64-91b0-bd5e1ee6d326","epoch":2,"notification_id":"9a86d8dc-454e-4e43-bb3c-bfdab9baf71e"}
{"event":"vault.access_revoked","vault_id":"d888f1ee-0cae-4d64-91b0-bd5e1ee6d326","notification_id":"16d1636e-5a5f-4141-a1d6-d345a5d433a3"}
```

### Server delivery rules

- Publish `vault.changed` **only after** a successful durable transaction commit (not during validation or rollback). One event per affected vault/commit is sufficient; its `latest_sequence` is authoritative and monotonic. Also notify authorized recipients of membership changes, new wrapped key availability, rotation, invite acceptance, and vault deletion when applicable; define minimally revealing event types.
- In the supported single-process installation, use the bounded in-process broadcast channel for advisory delivery. Independent servers do not communicate; optional shared-database multi-process notification code is experimental and not a Phase 11 requirement. On startup/reconnect, clients reconcile through the change feed. Reject permission changes promptly and remove unauthorized subscriptions before forwarding later events.
- Notifications contain **NO plaintext record content, ciphertext, secrets, key wraps, email addresses or unnecessary object names**. Protect message count/size; enforce per-user connection counts, subscription limits, bounded queues/backpressure, heartbeat timeouts and connection teardown.
- Do not guarantee exactly-once WebSocket event delivery; duplicate/lost/reordered notifications are safe because they are **hints**. Never advance the sync cursor from a WebSocket event.

### Client behavior and fallback

- On `vault.changed`, schedule immediate debounced/single-flight HTTP reconciliation for that exact `(server, account, vault)`; do not use the WS payload as a mutation. Coalesce bursts while retaining maximum notified sequence. Local edits may trigger optimistic HTTP sync independently.
- On disconnected WS, report notifications unavailable but **continue HTTP sync** on startup, resume, manual action, bounded periodic interval, reconnect and outgoing local mutations. Retry WSS with jittered exponential backoff; if access expires, single-flight refresh and reconnect. Avoid busy loops and avoid waking unrelated windows.
- On key event, pause only the affected vault's encrypted commits until proper current DEK is obtained. On revocation, stop remote ops and retain locally encrypted unsent work; do not erase users' local data silently.
- Acceptance: with two independent connected devices, a write by Device A triggers a notification and Device B fetches/applies via HTTP **without manual refresh**; test no lost data after WS disconnect, dropped event, reconnect, token refresh, server restart, queue overflow, subscriber revocation and simultaneous windows. Target a measurable LAN latency budget (e.g. p95 <= 1 second in a controlled local integration environment), not a fabricated guarantee for the public Internet.

## 8. Recommended v1 routes

| Method | Path | Meaning |
|---|---|---|
| GET | `/api/v1/capabilities` | Stable identity, required features, bounds, WSS path |
| POST | `/api/v1/auth/login`, `/auth/refresh`, `/auth/logout` | Session lifecycle |
| POST | `/api/v1/devices/challenge`, `/api/v1/devices` | Verified device enrollment |
| GET/DELETE | `/api/v1/devices`, `/api/v1/devices/{id}` | Device listing/revocation |
| GET/POST | `/api/v1/vaults` | Vault list and create |
| GET/PATCH/DELETE | `/api/v1/vaults/{id}` | Vault details / lifecycle |
| POST | `/api/v1/vaults/{id}/commits` | Atomic signed CAS changes |
| GET | `/api/v1/vaults/{id}/changes` | Durable delta pages |
| GET | `/api/v1/vaults/{id}/snapshots` | Consistent recovery snapshot |
| GET | `/api/v1/vaults/{id}/recipient-devices` | Scoped device key discovery |
| GET/POST | `/api/v1/vaults/{id}/keys/envelopes` | Recipient-wrapped DEKs |
| POST | `/api/v1/vaults/{id}/keys/epochs` | Atomic epoch transition |
| GET/POST | `/api/v1/vaults/{id}/members` | Team membership |
| POST | `/api/v1/invites/accept` | Invitation acceptance |
| WS | `/api/v1/events/ws` | Instant metadata-only notifications |

## 9. Errors and client actions

| Code | HTTP | Client action |
|---|---:|---|
| `UNAUTHENTICATED`, `TOKEN_EXPIRED` | 401 | Single-flight refresh/reconnect once |
| `DEVICE_REVOKED`, `MEMBERSHIP_REVOKED` | 403 | Stop remote work for that identity, protect local queue |
| `REVISION_CONFLICT` | 409 | Preserve both sides, resolve/rebase explicitly |
| `IDEMPOTENCY_CONFLICT` | 409 | Do not create a different retry while outcome unknown |
| `STALE_KEY_EPOCH` | 409 | Obtain current verified DEK, re-encrypt/re-sign new mutation safely |
| `CURSOR_EXPIRED` | 410 | Consistent snapshot restoration and delta continuation |
| `INVALID_SIGNATURE`, `INVALID_ENVELOPE`, `UNSUPPORTED_SUITE` | 400/403/422 | Stop affected operation; never advance cursor |
| `PAYLOAD_TOO_LARGE` | 413 | Respect advertised limits |
| `RATE_LIMITED`, `TEMPORARILY_UNAVAILABLE` | 429/503 | Jittered bounded backoff |

## 10. Golden fixtures, proof and docs required in BOTH repositories

- One canonical source of truth for DTOs/serialization: a pinned shared protocol crate or schema/generated-client pipeline. If keeping two Rust copies temporarily, add **bidirectional golden fixture** and OpenAPI drift tests in CI. Do not let published examples diverge from actual route code.
- Golden fixtures: capability with WSS features, login/refresh/reauth, device challenge, AES-GCM record envelope, recovery envelope, HPKE wrap, signature preimage/tampering, atomic batch, sequence boundary pagination, cursor expiry, 409/conflict, snapshot high watermark, each WS frame type, WS unauthorized subscribe/revocation, replay and server identity mismatch.
- Real acceptance: PostgreSQL-backed server + **two real client instances** + two independent servers + three simultaneous window contexts; server restarts, network partitions, WS drops, race conditions, cross-vault same-name objects, offline edits, backup/restore, 150+ mutations, key rotation and revocation.
- **Required docs sync:** server `docs/API.md`, `docs/COMPATIBILITY.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/PROGRESS.md`, `docs/security/{THREAT_MODEL,KEY_MANAGEMENT}.md`, `openapi/shellumi-server-v1.yaml`; client `docs/ROADMAP.md`, `docs/FEATURE_MATRIX.md`, `docs/GUI_STATUS.md`, `SYNC_DESIGN.md`, `PROJECT.md`, `docs/security/threat-model.md`, and a chronological client progress log. Record actual test commands and results. **No release-version upgrade to v2.**

The revision-specific snapshot route currently accepts only the current watermark; historical and future revisions return 422. Use the latest snapshot for recovery.

An authenticated WebSocket connection belongs to one independent server and may subscribe to multiple vaults there (up to 128). Subscription requests are applied only after all requested vaults pass authorization; a denied request adds none. Envelope publication sends a `vault.changed` reconciliation hint, not `vault.key_rotated`; actual epoch rotation sends `vault.key_rotated`. Hints are advisory; clients reconcile each server/vault through REST after reconnect and periodically.

Mutations in one commit batch are evaluated in order. A later mutation for the same object must use the revision assigned by the preceding mutation; any failure rolls back the entire batch and its sequence and device-counter updates. The PostgreSQL integration test exercises this sequential CAS behavior and paginated change-feed tombstones.

`CURSOR_EXPIRED` (410) is returned for a cursor ahead of the watermark or when the next expected change sequence is unavailable. Automatic feed retention pruning is not implemented; clients recover by taking a latest snapshot and resuming from its watermark.

An idempotency key is bound to the originating device as well as the mutation payload. An exact retry from that device returns the saved acknowledgement; reusing the key from another device returns 409.

# ADR 0006: M5 Optional Live Terminal Collaboration Signaling and Ciphertext Relay

## Status
Accepted

## Context
Milestone M5 implements the optional real-time terminal collaboration signaling and relay subsystem (`PROJECT.md` §10). A shared terminal session is hosted by a user's local Shellumi desktop client, which retains the SSH connection and PTY. Shellumi Server provides an authenticated, low-latency signaling and ciphertext frame relay to connected authorized participants.

The collaboration architecture must satisfy the following invariants:
1. **Server Plaintext Isolation (Zero-Knowledge):**
   - The server acts solely as a blind signaling and frame forwarding broker.
   - All terminal output keystrokes, PTY screens, and control messages are client-encrypted with ephemeral E2EE session keys negotiated directly between the host and participants.
   - The server never possesses session decryption keys, SSH private keys, or terminal plaintext.
2. **Opt-In Feature Gating:**
   - Disabled by default (`SHELLUMI_SERVER_COLLAB_ENABLED=false`).
   - When disabled, all collaboration endpoints reject with HTTP 403 Forbidden (`COLLAB_DISABLED`), and the capability is not advertised.
3. **Single Active Writer & Monotonic Fencing Token:**
   - In controllable sessions, only one participant is designated as the active writer at any time.
   - The host grants write control, transactionally advancing a monotonically increasing `lease_token`.
   - The active writer must supply the current `lease_token` in every `TerminalInput` frame. Frames bearing a stale token are rejected with HTTP 409 Conflict / 403 Forbidden.
   - Viewers are prohibited from transmitting input frames.
4. **Host Emergency Override & Unilateral Revocation:**
   - The session host retains unilateral, instantaneous control to revoke write leases, revoke specific participants, or terminate the entire session.
   - Revocation closes active subscriber streams immediately and rejects future frame submissions.
5. **Transport & Long-Polling Fallback:**
   - Real-time event streaming is supported via Server-Sent Events (`/api/v1/collab/sessions/:id/events`) and frame ingestion (`/api/v1/collab/sessions/:id/frames`).
   - Environments without persistent streaming support utilize cursor-based polling (`/api/v1/collab/sessions/:id/poll?since_sequence=...`).

## Decision

### 1. Data Model & Schema (`20261111000004_collab_sessions.sql`)
- `collab_sessions`: persists session ID, host user and device ID, title, mode (`read_only` or `controllable`), active writer user and device ID, current monotonic `lease_token`, lease expiration, and session lifecycle timestamps (`created_at`, `expires_at`, `terminated_at`).
- `collab_participants`: tracks enrolled user IDs, device IDs, roles (`host`, `writer`, `viewer`), and revocation status (`revoked_at`).

### 2. Message Envelope & Wire Format
Clients exchange structured frames:
- `TerminalOutput`: sequence number, encrypted payload envelope, nonce.
- `TerminalInput`: current `lease_token`, encrypted keystroke envelope, nonce.
- `Signal`: peer-to-peer key exchange and handshake messages between host and participant.
- `GrantControl`: target participant and lease TTL.
- `RevokeControl`: immediate writer lease reset back to host.
- `Terminate`: session shutdown.

### 3. Authorization & Fencing Rules
- Enrolled participant check: caller must be authenticated, belong to the session, and not be revoked.
- Writer check: only `(writer_user_id, writer_device_id)` matching current lease can submit `TerminalInput`.
- Fencing token check: incoming `lease_token` must strictly match the current active session `lease_token`.

## Consequences
- Enables live remote terminal viewing and controlled multi-user pairing in self-hosted environments.
- Zero-knowledge security is preserved: server compromise yields only ciphertext frames and cannot decrypt terminal sessions or steal SSH credentials.
- Strict single-writer fencing token eliminates split-brain races and rogue inputs.

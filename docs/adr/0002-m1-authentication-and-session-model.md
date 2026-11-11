# ADR 0002: M1 Authentication, Session Lifecycle, and Device Registration

## Status
Accepted

## Context
Shellumi Server requires self-hostable identity and enrollment without relying on external cloud identity providers (IdPs), SMTP email servers, or Shellumi-hosted infrastructure.

The authentication and session subsystem must:
1. Prevent open public registration by default (`invite_only` policy).
2. Protect local administrative bootstrapping so that the first administrator can only be configured once.
3. Protect user passwords with memory-hard verifiers (Argon2id).
4. Provide short-lived signed bearer access tokens and rotating refresh tokens with strict theft/reuse detection.
5. Register client devices with independent cryptographic identities (Ed25519 for signing, X25519 for key agreement) separate from SSH authentication keys.
6. Support instant session revocation and device deauthorization.

## Decision
1. **One-Time Bootstrap:**
   - Handled via `POST /api/v1/bootstrap`.
   - Atomically checks and sets `bootstrap_consumed = true` in `server_settings`.
   - Any subsequent call returns `409 Conflict` (`BOOTSTRAP_ALREADY_CONSUMED`).
2. **Password Verification:**
   - Argon2id with memory-hard parameters and OsRng salt.
   - Plaintext passwords never stored or logged.
3. **Session Lifecycle & Refresh Token Rotation:**
   - Bearer access tokens are HMAC-SHA256 signed with a secret key, short-lived (default 15 minutes).
   - Refresh tokens are 256-bit cryptographically secure random values.
   - Refresh tokens are stored strictly as SHA-256 digests in persistence.
   - Every refresh request invalidates the previous refresh token and issues a new one.
   - If an invalidated refresh token is ever presented again (indicating token theft), the server immediately revokes all sessions for that user/device.
4. **Device Registration:**
   - Each device registers its name, Ed25519 signing public key, and X25519 agreement public key.
   - Revoking a device immediately invalidates all active sessions for that device.

## Consequences
- No external email or cloud IdP dependency required for complete self-hosting.
- Immediate defense-in-depth against compromised or stolen refresh tokens.
- Secure, auditable device registry forming the basis for E2EE vault key envelopes in Milestone M2/M3.

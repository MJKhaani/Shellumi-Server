# Shellumi Server — Mandatory Agent & Contributor Instructions

> **Status:** implementation contract for the new `Shellumi Server` Rust repository. Read `PROJECT.md` fully before changing code. Reference client: `https://github.com/MJKhaani/Shellumi`, reviewed against `main` commit `c99a2c2a3239e899ec6e5a1c12823fad3e77d3c6` (2026-11-10). Re-check upstream changes before integration.
>
> **Highest-priority rule:** **Every increment must be documented. Every implemented behavior must have tests.** No undocumented changes, untested features, silent stubs, or fabricated verification results.

## 1. Mission and boundaries

Build a **fully open-source, MIT-licensed, self-hostable, Rust-only server** that enables Shellumi clients to synchronize encrypted vault data, enroll devices and users, share team vaults, enforce collaboration permissions, and optionally relay real-time terminal collaboration. It must never become a mandatory dependency for the Shellumi desktop application.

The supported user modes are:

1. **Local-only:** Shellumi operates without any account, server, or internet access.
2. **Personal Google Drive:** clients use the existing opt-in, direct Google Drive `appDataFolder` provider; Shellumi Server does not proxy Google OAuth or store Google access tokens.
3. **Self-hosted Shellumi Server:** a user/organization configures its own trusted endpoint for encrypted personal/team vault synchronization and sharing.

Keep the three modes separate. Never introduce mandatory hosted identity, telemetry, subscriptions, paywalls, or vendor-controlled infrastructure. No server-side SSH credential decryption and no server-side SSH access for ordinary vault synchronization. The server handles **opaque encrypted payloads**, identities/permissions, versioned storage, notifications, and routing.

## 2. Read before editing

- This repository's `PROJECT.md`, `AGENT.md`, `docs/PROGRESS.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/security/THREAT_MODEL.md`, and relevant ADRs.
- Client baseline: `README.md`, `PROJECT.md` §§4–5, `SYNC_DESIGN.md`, `docs/FEATURE_MATRIX.md`, `docs/GUI_STATUS.md`, `docs/security/threat-model.md`, `crates/shellumi-core/src/{sync,collaboration,credential,identity}.rs`, `crates/shellumi-storage/src/lib.rs`, `crates/shellumi-app/src/main.rs`, `crates/shellumi-cli/src/main.rs`, `.github/workflows/release.yml`.
- Inspect real client code, not only feature aspirational documents. `PROJECT.md` in the client describes desired functionality; it does not prove functionality exists.
- Check compatibility with the currently pinned client contract and document every requested wire-format change. Do **not** copy UI/GPUI or local Turso database into the service; reuse only suitable UI-independent types via a versioned shared contract when justified.

## 3. The mandatory work cycle — EVERY task, even a small fix

**Do not skip any stage.**

1. **Inspect:** read affected implementation, tests, schema, security assumptions, prior progress and compatibility notes. Identify user-visible impact and risks.
2. **Plan:** add or update an entry in `docs/PROGRESS.md` **before implementation** with the task ID, scope, status `planned`, affected components, acceptance criteria, and planned tests. For significant decisions, create an ADR in `docs/adr/`.
3. **Implement:** make a minimal, cohesive, reviewable change. No decorative mock APIs, invented storage, empty handlers, success-by-default fallbacks, or `todo!()` on production paths. If blocked, preserve an explicit unsupported/error response and record it.
4. **Test:** add/modify automated tests for every new or changed behavior, including success, negative, authorization, boundary, concurrent, and failure/recovery paths as applicable. Tests must not require production secrets. Fix defects before declaring success.
5. **Verify:** run the appropriate checks from §5 and record the *actual* command, environment, result, and test counts (or the reason execution was impossible). Never write “passed” without executing it.
6. **Document:** update `docs/PROGRESS.md` with end status and evidence, `docs/ROADMAP.md`, relevant architecture/API/security/deployment docs, migrations, and `CHANGELOG.md` where behavior changed. Update the client-compatibility matrix for any protocol change.
7. **Report:** summarize what changed, every touched path, executed tests and outcomes, known limitations, security implications, and next action. If incomplete, mark `blocked` or `partial`, not `complete`.

**Continuous progress requirement:** write a meaningful log entry after *each* implementation milestone, not only at the end of a larger task. Keep append-only, dated (UTC) entries; do not erase past failed attempts or decisions. Link issue/PR, commit, ADR and CI run URLs when available. Before ending an interrupted session, write current state, commands used, blockers and the next exact step.

### Required `docs/PROGRESS.md` entry format

```markdown
## YYYY-MM-DDTHH:MM:SSZ — TASK-### — Short title
- Status: planned | in_progress | blocked | partial | complete
- Baseline / commit: ...
- Objective and acceptance criteria: ...
- Implementation / files changed: ...
- Data migration or API compatibility: ...
- Security / privacy review: ...
- Tests added (file + test names): ...
- Verification executed (exact commands, OS, counts, pass/fail/skip): ...
- Known limitations / failed attempts: ...
- Next precise step: ...
- Issue / PR / CI evidence: ...
```

Do not use a checklist tick or a comment in code as a substitute for a real test and verifiable entry.

## 4. Non-negotiable engineering rules

- **Rust everywhere in the runtime:** Rust 2021 or newer stable edition, Tokio async runtime, typed HTTP API (Axum preferred), Serde, typed errors, tracing. No Node/Go/Python application server, web UI requirement, or GUI dependency. Shell scripts and workflow YAML are permitted as build tooling.
- **Modular, testable architecture:** `domain`/`protocol` crates do not depend on HTTP, DB, or logging implementations; HTTP adapters do not contain authorization policy; storage is behind traits; use bounded tasks, structured cancellation, timeouts and backpressure.
- **Server does not hold the keys:** no plaintext vault records, SSH credentials/private keys, sync passphrases, vault DEKs, or terminal plaintext in application logs or persisted server data. Store client-generated encrypted envelopes and **recipient-wrapped** vault keys only. Never claim that TLS by itself is end-to-end encryption.
- **Separate authentication and encryption keys:** use dedicated device signing and key-agreement identities; do not silently treat an OpenSSH public key as an X25519 encryption key. Authenticate devices, validate signatures, enforce monotonic counters, and bind every ciphertext to tenant, vault, object, schema and epoch.
- **Authorize on the server for every read/write/notification/session event:** default deny, tenant/vault isolation, role checks, revoked-device checks, least privilege. Client-side button visibility is *not* authorization. Treat IDs and opaque cursors as untrusted.
- **Atomic and conflict-safe:** persistent stable IDs and local revisions; transactionally assign authoritative server revisions; require expected revision / conditional writes; return `409` for stale edits. No unconditional last-write-wins, destructive merge or silent lost updates. Use durable tombstones and idempotency keys.
- **Security by default:** TLS for all non-loopback deployments, secrets via secure file/env/secret manager (never logged), scoped access/refresh tokens, rate limits, size limits, explicit CORS origins, audited administrative actions, secure backup/restore, input validation, dependency audit. Store password verifiers via Argon2id if password auth is enabled.
- **Preserve local-first clients:** server unavailability must not stop local SSH, SFTP, terminals, snippets, or workspaces. No automatic upload of session recordings, SSH key material, known_hosts or OS-specific paths. Default opt-out for sensitive and device-bound fields.
- **Compatibility first:** current Shellumi `SyncVault`, `SyncRecord`, `EncryptedEnvelope`, `TeamRole`, `SharedVault`, and `TeamMember` must be analyzed and consciously adapted with versioning/migration. Existing Google Drive and encrypted backup users must not be broken. Publish a protocol compatibility table.
- **No fabricated functionality:** unfinished integrations must return explicit errors and be reflected in docs/UI; no fake collaboration, dummy invitations, untested successful sync status, or invented benchmarks.
- **No magic migrations:** forward-only, transactional SQL migrations with rollback/recovery procedure, and tests for old-version upgrades. Never silently delete user data.
- **Supply-chain security:** pinned `Cargo.lock`, maintained/license-compatible crates, no unsafe shell interpolation in CI, least-privilege GitHub token, no untrusted PR code in release/publish jobs, immutable tags, artifact checksums and provenance.

## 5. Testing and quality gates — enforced for ALL code

### Minimum checks for every pull request

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo test --locked --doc --workspace
cargo build --locked --workspace --all-features
cargo audit                  # install cargo-audit in CI
```

Also execute integration tests against an **ephemeral real PostgreSQL** instance (`docker compose -f deploy/test/compose.yml ...` or Testcontainers) when DB-backed code changes. Tests that require Docker are tagged/executed in a dedicated CI integration job, not permanently ignored. Use `cargo nextest` if adopted consistently, but maintain `cargo test` compatibility. Include release-mode startup and migration smoke tests before release.

### Test matrix: a test is required for each capability

| Work area | Mandatory automated evidence |
| --- | --- |
| Configuration/bootstrap | parsing, rejected unsafe defaults, one-time bootstrap, migration, restart persistence |
| Users/auth | login/logout, expiry/refresh rotation, revoked tokens, brute-force limits, optional MFA, device binding |
| Organization/team/RBAC | every Owner/Admin/Editor/Viewer × endpoint/action combination, cross-tenant IDOR, invited/uninvited/revoked users |
| Vaults/key envelopes | tampering, replay, signature verification, wrong epoch, key rotation, offline member, unwrapped key never on server |
| Sync | first upload/download, partial batch, idempotent retry, duplicate/out-of-order update, stale ETag, race between two devices, deletion/tombstone, corruption, disconnect and recovery |
| Conflict handling | concurrent same-object conflict, independent-object merge, client resolution, crash/restart and snapshot restore |
| Invitations | invalid/expired/single-use invites, duplicate enrollment, role changes, revoked device, no unauthorized key access |
| WebSocket notifications | authentication, gap/disconnect/reconnect, duplicate messages, backpressure, no visibility across vaults |
| Terminal collaboration | single writer, owner override, outsider blocked, disconnect/lease expiry, encrypted frames, forced termination |
| Audit, retention and backup | append-only hash linkage, pagination, deletion policy, backup+restore, upgrade/downgrade safety |
| API contract | OpenAPI/schema validation, version negotiation, old-client compatibility, exact error codes |
| Deployment and builds | non-root container, healthcheck, clean Docker Compose start/stop, both CPU architectures, checksum verification and image smoke test |

Add unit tests, integration tests, and end-to-end tests as appropriate. **At least one failure-path test is required for every security-sensitive feature.** Property-based tests/fuzz tests should cover parsers, cursors and encrypted envelope decoding; use concurrency/race tests for revision allocation. Do not reduce assertions or mark tests ignored to make a build green. Test doubles are allowed only in automated tests; they are never a substitute for at least one real database/network acceptance test.

### Coverage and exceptions

- Changed business/security logic must be exercised by tests; aim for ≥85% line coverage and maximize branch coverage on authorization/crypto/sync (coverage is a quality signal, not proof of correctness).
- A docs-only change requires link/example validation but no invented Rust test evidence. Changes to workflows/deployment require YAML/schema/lint checks plus a dry-run or smoke test on an appropriate environment.
- If tests cannot run, record why and mark the task `partial`/`blocked`. **Never merge or release a code change while required gates are red.**
- Every bug fix adds a regression test that fails against the old behavior.

## 6. API, schema, data and migration discipline

- Server protocol lives under `/api/v1`; generate/publish OpenAPI 3.1 and fixture-based contract tests for Rust client and server.
- JSON errors use stable codes; use `401` unauthenticated, `403` unauthorized, `404` inaccessible resources without ID enumeration, `409` revision/key-epoch conflict, `413` oversize, `422` invalid schema, `429` rate limited.
- Enforce multi-tenant isolation in every query, transaction, cache lookup, event channel and object-store prefix; include tests for a malicious tenant swapping UUIDs.
- Assign monotonically increasing server sequence numbers *transactionally* per vault; persist client mutation idempotency key and expected object revision; reject replay and equivocation.
- Save protocol fixtures and migrations under version control; maintain `docs/COMPATIBILITY.md` and an upgrade matrix for at least the last two released minor server versions and documented client versions.
- Audit key and authorization changes at the same transactional boundary as the state mutation. Do not describe a mutable database chain as independently tamper-proof; record its threat assumptions and optionally anchor hashes outside the DB.

## 7. Git and release process

- Conventional, focused commits and small reviewable PRs. Main branch requires passing CI and review for sensitive changes. Never force-push release tags.
- `vMAJOR.MINOR.PATCH` (and SemVer pre-release suffixes) is the **only** release trigger; branch/PR builds must never publish to GitHub Releases/GHCR.
- A tag release must pass format, Clippy, unit/integration/security/contract tests and actual architecture-specific smoke tests **before** publishing.
- Publish Linux `x86_64` and `aarch64` binaries (`.tar.gz`, named by target), `SHA256SUMS`, SBOM, release notes and source/provenance; build and publish multi-architecture `ghcr.io/mjkhaani/shellumi-server` image (`linux/amd64`, `linux/arm64`). Include explicit version and immutable digest; publish `latest` **only** for stable releases. Do not claim a container is multi-arch until both architectures have been built and inspected.
- Limit workflows' permissions: `contents:read` for tests, `contents:write` only for release publication, `packages:write` only for GHCR publishing, `id-token:write`/`attestations:write` only for signing/attestations. Pin third-party actions to reviewed commit SHAs before production.
- Ensure tag/crate version equality; reject malformed tags; guard release jobs against replay, version mismatch or incomplete artifacts. Preserve pre-release labeling.
- Use a multi-stage reproducible Dockerfile with a minimal non-root runtime, read-only rootfs compatibility, no embedded secrets, graceful `SIGTERM`, and working health endpoints. Test the actual published image digest.

## 8. Documentation deliverables (must evolve with code)

Maintain `README.md`, `PROJECT.md`, `AGENT.md`, `AGENTS.md` (agent-discovery wrapper), `CHANGELOG.md`, `docs/PROGRESS.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/COMPATIBILITY.md`, `docs/API.md`/OpenAPI, `docs/CONFIGURATION.md`, `docs/DEPLOYMENT.md`, `docs/BACKUP_RESTORE.md`, `docs/security/THREAT_MODEL.md`, `docs/security/KEY_MANAGEMENT.md`, `docs/adr/*.md`, `docs/development/TESTING.md`, `docs/development/RELEASES.md`.

Every shipped configuration option, CLI command, endpoint, database change, failure/recovery mode, migration and security control must be documented with an example and a test. Add release notes when observable behavior changes. Security documentation must distinguish **implemented**, **planned**, **tested**, and **independently audited** controls.

## 9. Definition of done and final response template

A task is **complete** only when functionality exists end-to-end, associated tests were actually run and passed, migrations and API fixtures are updated, relevant docs/progress are current, security/compatibility were considered, and CI is green. If any element is missing, state the limitation clearly.

Every agent response at the end of work must contain:

1. **Implemented** — exact behavior and any deliberate exclusions.
2. **Files changed** — full paths.
3. **Tests added and run** — commands plus actual results; distinguish local from CI and skipped tests.
4. **Documentation/progress** — entry link/date and ADR/roadmap changes.
5. **Security/compatibility** — risks, wire/schema changes, client/Drive consequences.
6. **Remaining issues** — blockers, limitations and next specific action.

**Never say “done”, “secure”, “fully tested”, “production-ready”, or “zero knowledge” unless the measured evidence and documented threat model justify that claim.**

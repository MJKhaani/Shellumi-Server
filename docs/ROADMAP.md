# Shellumi Server — Development Roadmap

This document outlines the milestones and progress of Shellumi Server.

## Milestone Status Overview

| Milestone | Title | Status | Primary Gates & Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| **M0** | Repository Foundations & Hygiene | **In Progress** | Workspace skeleton, configuration parser, `/health/live`, `/health/ready`, `/api/v1/capabilities`, strict config validation, unit/integration tests, CI workflow, docs. |
| **M1** | Storage, Migrations, Tenants & Auth | Planned | PostgreSQL schema, admin bootstrap, accounts, sessions, device key registration, organizations, token revocation, cross-tenant isolation tests. |
| **M2** | Encrypted Private Vault & Sync v1 | Planned | Stable UUIDs, opaque ciphertext envelopes, device signatures, transactional change feed, conditional `expected_revision` writes, conflict resolution (409), tombstones. |
| **M3** | Team Vaults, Invites, RBAC & E2EE Keys | Planned | Owner/Admin/Editor/Viewer permission matrix, one-time invitations, per-device recipient-wrapped DEKs, epoch rotation, audit trail. |
| **M4** | Resilience, Operations & Releases | Planned | CLI admin commands, backup/restore verification, metrics, rate limits, multi-arch Docker image, reproducible release automation. |
| **M5** | Optional Live Terminal Collaboration | Planned | WSS relay, ephemeral E2EE session keys, single-writer fencing token, owner emergency revocation, bounded queues. Relay disabled until gates pass. |
| **M6** | Advanced Self-Hosting & Integrations | Planned | OIDC/SSO, optional SMTP, large encrypted attachments, horizontal PostgreSQL coordination. |

---

## Detailed Milestone Scope

### M0 — Repository Foundations & Hygiene (Current)
- **Rust Workspace:** Modular layout (`shellumi-server`, `shellumi-server-domain`, `shellumi-server-protocol`).
- **Configuration:** Layered resolution (CLI > Env > File > Defaults). Safe defaults enforced (loopback by default, rejection of insecure public listeners).
- **Core Endpoints:**
  - `GET /health/live`: Process liveness check.
  - `GET /health/ready`: System readiness check.
  - `GET /api/v1/capabilities`: Advertised protocol version, features, and bounds.
- **Error Format:** Typed, consistent JSON error responses (`error_code`, `message`, `request_id`).
- **Gates:**
  - `cargo fmt --all -- --check`
  - `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --locked --workspace --all-features`
  - Clean startup and invalid config rejection tests.

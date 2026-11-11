# ADR 0001: M0 Workspace and Runtime Architecture

## Status
Accepted

## Context
Shellumi Server is an optional self-hosted backend enabling encrypted cross-device synchronization, team vault sharing, RBAC, and optional terminal collaboration for Shellumi desktop and CLI clients.

The server must:
1. Be written exclusively in Rust (Tokio, Axum, Serde, SQLx/PostgreSQL).
2. Never store or have access to plaintext vault keys, passwords, or credentials.
3. Be strictly self-hostable with single-binary or Docker Compose deployment.
4. Have a modular, testable crate layout with clear separation between wire protocol, pure domain logic, and HTTP/storage adapters.

## Decision
1. **Workspace Layout:**
   - `crates/shellumi-server-protocol`: Contains strictly versioned DTOs, wire schemas, capability flags, and machine-readable error models. It has no web or database dependencies.
   - `crates/shellumi-server-domain`: Contains pure business logic, permission rules, domain error types, and configuration models.
   - `crates/shellumi-server`: Modular monolith binary providing the Axum HTTP service, CLI arguments parsing via Clap, configuration loading, logging, and graceful shutdown.
2. **Configuration Precedence:**
   - CLI flags > Environment variables (`SHELLUMI_SERVER_*`) > Configuration file (`config.toml`) > Safe defaults.
3. **Safety Defaults:**
   - Loopback listening (`127.0.0.1:8080`) by default.
   - Reject binding to non-loopback without secure public URL / reverse proxy trust.
   - Invite-only registration by default; open public registration is disallowed.
   - Request and record size bounds enforced at HTTP layer (10 MiB request limit, 1 MiB record limit).

## Consequences
- Clean dependency boundaries prevent leaking transport or persistence concerns into domain logic.
- The protocol crate can be tested with golden fixtures or shared with future Rust client SDKs.
- Operators have predictable, hardened-by-default runtime configuration.

# ADR 0005: M4 Resilience, Operations, Rate Limiting, Metrics, and Releases

## Status
Accepted

## Context
Milestone M4 establishes the operational foundation, resilience guarantees, administrative tooling, and release pipelines required for enterprise-ready, self-hosted deployments of Shellumi Server.

The operational architecture must satisfy:
1. **Headless Administrative Tooling (CLI):**
   - Provide direct offline and out-of-band management subcommands (`doctor`, `admin user`, `admin session`, `migrate`, `backup verify`) without requiring a graphical web interface or external scripting language.
   - Maintain compatibility where running `shellumi-server` with no subcommand defaults to `shellumi-server serve`.
   - Ensure administrative operations perform the exact same cryptographic hashing (Argon2id for passwords) and validation rules as the HTTP API.
2. **Brute-Force Protection & Rate Limiting:**
   - Mitigate automated credential stuffing against `/api/v1/auth/login`, bootstrap replay attacks against `/api/v1/bootstrap`, and invite token brute-forcing against `/api/v1/invites/accept`.
   - Enforce sliding-window / token-bucket limits per client IP (respecting `trusted_proxies` for reverse proxies).
   - Return standard HTTP 429 Too Many Requests with JSON error payloads and a normative `Retry-After` header indicating wait duration.
3. **Observability & Prometheus Telemetry:**
   - Provide an opt-in `/metrics` endpoint adhering to Prometheus text exposition format (`text/plain; version=0.0.4; charset=utf-8`).
   - Enforce strictly bounded label cardinality: metric labels record HTTP method, canonical route template (e.g. `/api/v1/vaults/:id/commits`), and status code. High-cardinality identifiers (user IDs, device IDs, vault UUIDs, client IPs) are strictly prohibited from Prometheus labels to prevent memory exhaustion and privacy leaks.
4. **Disaster Recovery & Backup Verification:**
   - Detail operational procedures for consistent PostgreSQL backups via `pg_dump` and physical WAL archiving.
   - Implement `shellumi-server backup verify <file>` to validate backup archive headers, table signatures, schema integrity, and SHA-256 checksums without requiring decryption keys.
   - Reiterate the zero-knowledge invariant: server database backups contain only opaque client ciphertext and wrapped DEK envelopes; server backups alone never expose client plaintext.
5. **Release Engineering & Container Supply Chain:**
   - Ensure reproducible multi-stage Docker builds running as an unprivileged non-root user (`UID 10001`) with read-only filesystem compatibility.
   - Support multi-architecture builds for both `linux/amd64` and `linux/arm64`.
   - Define a tag-triggered GitHub Actions release pipeline (`.github/workflows/release.yml`) enforcing SemVer validation, binary matrix compilation, SHA256 checksums, and GHCR container publishing.

## Decision

### 1. CLI Subcommand Structure
`clap` is configured with top-level options that preserve backward compatibility while routing to specific subcommands:
- `shellumi-server [OPTIONS] [COMMAND]`
- Commands:
  - `serve`: Launch the HTTP REST/WSS synchronization daemon.
  - `doctor`: Validate environment, configuration validity, database connectivity, directory permissions, and TLS settings.
  - `admin user create | disable | enable | reset-password | list`: Manage user identities offline.
  - `admin session list | revoke | revoke-all`: Inspect and terminate authenticated sessions.
  - `migrate status | run`: Inspect and execute forward-only SQL migrations.
  - `backup verify <path>`: Verify database dump integrity and schema signatures.

### 2. Rate Limiting Middleware
An in-memory sliding-window rate limiter is attached to sensitive endpoints:
- Evaluates client IP from request connection info or `X-Forwarded-For` if the immediate peer matches `trusted_proxies`.
- Limits: 10 requests per minute per IP for `/api/v1/auth/login`, `/api/v1/bootstrap`, and `/api/v1/invites/accept`.
- Exceeded limits emit:
  - HTTP 429 Too Many Requests
  - Header `Retry-After: <seconds>`
  - Body: `{ "error_code": "RATE_LIMIT_EXCEEDED", "message": "Too many requests. Please try again later.", "request_id": "<uuid>" }`

### 3. Prometheus Telemetry (`/metrics`)
Controlled by configuration `metrics_enabled` (env `SHELLUMI_SERVER_METRICS_ENABLED`):
- When enabled, exposes:
  - `shellumi_http_requests_total{method="...",path="...",status="..."}`
  - `shellumi_http_request_duration_seconds{method="...",path="..."}`
  - `shellumi_active_sessions_total`
  - `shellumi_registered_devices_total`
  - `shellumi_vaults_total`
  - `shellumi_rate_limit_exceeded_total`
- When disabled, returns HTTP 404 Not Found.

### 4. Release Automation
Tag trigger pattern `v*` (e.g. `v0.1.0`) triggers `.github/workflows/release.yml`:
- Compiles native binaries for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (or Linux GNU).
- Packages archives with README and LICENSE, generates `SHA256SUMS.txt`.
- Builds and pushes multi-platform OCI images to `ghcr.io/mjkhaani/shellumi-server`.

## Consequences
- Operations teams can inspect, administer, migrate, and diagnose Shellumi Server deployments directly from the terminal.
- Production deployments are hardened against brute-force attacks on credentials and invite tokens.
- Telemetry enables Prometheus/Grafana monitoring without privacy disclosures or memory leaks from unbounded label cardinality.

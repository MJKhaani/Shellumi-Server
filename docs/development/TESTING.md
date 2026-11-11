# Shellumi Server — Testing Guide & Quality Gates

Every code change must satisfy the quality gates defined in `AGENTS.md` and `PROJECT.md`. No undocumented changes, untested features, silent stubs, or fabricated verification results are permitted.

---

## 1. Mandatory Pre-Commit & PR Quality Gates

Execute the following commands before submitting or merging any changes:

```bash
# 1. Code formatting check
cargo fmt --all -- --check

# 2. Strict compiler linting (all warnings denied)
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

# 3. Unit and integration test execution
cargo test --locked --workspace --all-features

# 4. Documentation tests
cargo test --locked --doc --workspace

# 5. Full workspace release build
cargo build --locked --workspace --all-features
```

---

## 2. Test Architecture & Coverage

The test suite spans unit, component, repository, integration, and wire contract tests:

### 2.1 Workspace Unit Tests
- `crates/shellumi-server/src/config.rs`: Precedence hierarchy, environment variables, default configs, and validation errors (unsafe public listeners, invalid TTLs).
- `crates/shellumi-server/src/rate_limit.rs`: Sliding-window IP rate limiter, window sliding, cleanup, and trusted proxy forwarding.
- `crates/shellumi-server/src/metrics.rs`: Prometheus metrics registry, path normalization (scrubbing UUIDs/revisions to bounded cardinality), and text format rendering.
- `crates/shellumi-server/src/cli/`: Headless CLI subcommands (`doctor`, `admin user`, `admin session`, `migrate status`, `backup verify`).

### 2.2 Domain & Crate Unit Tests
- `crates/shellumi-server-auth`: Argon2id password hashing, constant-time verification, access token signing/validation, refresh token rotation, and theft detection.
- `crates/shellumi-server-crypto`: Canonical preimage formatting, Ed25519 signature verification, tampering detection, and envelope validation.
- `crates/shellumi-server-store`: In-memory repository implementations (`UserRepository`, `DeviceRepository`, `SessionRepository`, `VaultRepository`, `SyncRepository`, `KeyEnvelopeRepository`, `AuditRepository`, `CollabRepository`).
- `crates/shellumi-server-sync`: Commit batch processing, sequence assignment, CAS revision conflicts, idempotency caching, and tombstone propagation.

### 2.3 Integration Test Suites (`crates/shellumi-server/tests/`)
- `health_and_capabilities.rs`: `/health/live`, `/health/ready`, `/api/v1/capabilities`, and 404 JSON error handler.
- `auth_and_devices.rs`: One-time bootstrap flow, duplicate bootstrap rejection (409), user login, refresh rotation, and device registration/revocation.
- `sync_and_vaults.rs`: Vault CRUD, two-device offline convergence, concurrent same-object CAS revision conflicts (409), tombstone propagation, and idempotency replay.
- `team_and_keys.rs`: RBAC matrix (Owner, Admin, Editor, Viewer), one-time invitations, recipient-wrapped DEKs, key epoch rotation, and cryptographic audit hash chaining.
- `ops_and_resilience.rs`: Sliding-window rate limiting on login (429), `/metrics` telemetry, CLI diagnostics, migration status, and backup verification.
- `collab_relay.rs`: Terminal collaboration feature gating, real-time SSE streaming, single-writer lease fencing, stale token rejection (409), and owner emergency revocation/termination (410).
- `contract_fixtures.rs`: Golden JSON serialization and deserialization matching Shellumi desktop client wire types.

---

## 3. Database Integration Testing (PostgreSQL)

To run integration tests against a live PostgreSQL database:

```bash
# Launch ephemeral PostgreSQL container
docker compose -f deploy/test/compose.yml up -d

# Run migrations and integration tests
export SHELLUMI_SERVER_DATABASE_URL="postgres://postgres:testpassword@127.0.0.1:5433/shellumi_test"
cargo test --test ops_and_resilience -- --nocapture

# Tear down test database
docker compose -f deploy/test/compose.yml down -v
```

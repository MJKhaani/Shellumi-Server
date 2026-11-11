# Shellumi Server — Testing Guide & Quality Gates

Every code change must satisfy the quality gates defined in `AGENT.md` and `PROJECT.md`.

## Mandatory PR Checks

```bash
# 1. Format check
cargo fmt --all -- --check

# 2. Strict Clippy linting
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

# 3. Unit and integration tests
cargo test --locked --workspace --all-features

# 4. Documentation tests
cargo test --locked --doc --workspace

# 5. Full workspace build
cargo build --locked --workspace --all-features
```

## Test Structure
- `crates/shellumi-server/src/config.rs`: Unit tests for precedence, parsing, and security validations.
- `crates/shellumi-server/tests/`: Integration tests testing actual HTTP routes via in-memory Axum router invocation.
- `tests/`: End-to-end multi-crate integration tests.

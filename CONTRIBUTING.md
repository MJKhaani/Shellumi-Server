# Contributing to Shellumi Server

Thank you for your interest in contributing to Shellumi Server!

## Mandatory Guidelines

Before contributing, read `PROJECT.md` and `AGENT.md` (or `AGENTS.md`).
All contributions must adhere to the following non-negotiable standards:

1. **Every increment must have tests:** We require unit, integration, and security negative-path tests for all implemented behaviors.
2. **Every increment must be documented:** Maintain `docs/PROGRESS.md` in chronological, append-only order using the required format.
3. **No server-side secrets:** Never store or process plaintext vault contents, SSH credentials, private keys, or master encryption keys on the server.
4. **All quality gates must pass:**
   ```bash
   cargo fmt --all -- --check
   cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
   cargo test --locked --workspace --all-features
   cargo test --locked --doc --workspace
   cargo build --locked --workspace --all-features
   ```

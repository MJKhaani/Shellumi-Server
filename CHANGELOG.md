# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Milestone M0: Repository foundations and project hygiene**
  - Modular Rust workspace layout (`shellumi-server`, `shellumi-server-protocol`, `shellumi-server-domain`).
  - Layered configuration loader with strict precedence: CLI flags > environment variables (`SHELLUMI_SERVER_*`) > config file (`config.toml`) > secure defaults.
  - Security validation: automated rejection of non-loopback plaintext listeners without HTTPS or explicit trusted proxies.
  - Health endpoints: `/health/live` (process liveness) and `/health/ready` (system readiness).
  - Versioned API capabilities endpoint: `/api/v1/capabilities`.
  - Machine-readable JSON error responses for unmapped routes (404).
  - Integration and unit tests for configuration, health, and capability negotiation.
  - CI workflow skeleton (`.github/workflows/ci.yml`).
  - Documentation suite: Architecture, Roadmap, Configuration, Progress Journal, and ADRs.

# Shellumi Server — Release Engineering & Publication

## Release Trigger & SemVer Policy

Releases are triggered **exclusively** by git tags matching `vMAJOR.MINOR.PATCH` (e.g. `v0.1.0` or `v0.1.0-alpha.1`). Branch and pull request builds must never publish releases or push container images to registries.

## Deliverables
- Native Linux binaries (`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`).
- Multi-architecture OCI container image: `ghcr.io/mjkhaani/shellumi-server` (`linux/amd64`, `linux/arm64`).
- `SHA256SUMS.txt` cryptographic checksum manifest.
- Software Bill of Materials (SBOM) and build provenance.

## Publishing Gates
1. Full test suite, integration tests, and formatting checks pass.
2. Binary archive smoke tests verify version output matches tag.
3. Multi-platform image builds succeed and non-root runtime healthcheck is verified.

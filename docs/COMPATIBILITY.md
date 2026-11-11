# Shellumi Client / Server Compatibility Matrix

This document tracks version compatibility between the Shellumi desktop/CLI clients and Shellumi Server.

## Compatibility Table

| Protocol Version | Server Release | Minimum Client Version | Supported E2EE Suites | Status |
| :--- | :--- | :--- | :--- | :--- |
| **1** | `0.1.0` | `0.0.7-alpha` | `x25519_hkdf_aes256gcm`, `argon2id_aes256gcm_legacy` | **Current** |

## Wire Protocol Evolution
- **v1:** Initial baseline for health, capabilities, device authentication, and encrypted vault synchronization.
- Legacy AES-256-GCM + PBKDF2 snapshots from Shellumi client are supported via explicit migration.

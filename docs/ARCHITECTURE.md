# Shellumi Server — Architecture & System Design

## 1. Architectural Principles

1. **Self-Hosted First:** Headless, single-binary Rust service, easily managed via Docker Compose or native systemd services.
2. **Zero Plaintext on Server:** The server stores opaque, client-encrypted envelopes and client-wrapped key envelopes. Plaintext vault data, SSH private keys, passphrases, and credentials never touch server memory or persistent storage.
3. **Modular Crate Architecture:**
   - `shellumi-server-protocol`: Pure wire types, DTOs, versioning constants, and serialization. No database or web dependencies.
   - `shellumi-server-domain`: Pure business rules, role policies, permission checks, configuration schema, and domain errors.
   - `shellumi-server`: Axum HTTP/WSS API adapter, routing, configuration loader, middleware, metrics, and binary entrypoint.
   - Future milestones: `shellumi-server-crypto`, `shellumi-server-store`, `shellumi-server-auth`, `shellumi-server-sync`, `shellumi-server-relay`.
4. **Strict Isolation & Authorization:** Every request is authenticated and authorized against tenant, vault, and device scopes. Default deny on all paths.

## 2. Component Diagram

```text
+-----------------------------------------------------------+
|                      Shellumi Client                      |
|       (GPUI Desktop / CLI / Future Mobile Client)        |
+-----------------------------+-----------------------------+
                              | HTTPS / WSS
                              v
+-----------------------------------------------------------+
|                      Shellumi Server                      |
|                                                           |
|  +--------------------+  +--------------------+           |
|  |   Health & Admin   |  |   Auth & Devices   |           |
|  |  /health, /caps    |  |  Tokens, Key Proof |           |
|  +--------------------+  +--------------------+           |
|                                                           |
|  +--------------------+  +--------------------+           |
|  |     Sync & CAS     |  |   Vault & Invites  |           |
|  |  Deltas, Revisions |  | Wrapped Envelopes  |           |
|  +--------------------+  +--------------------+           |
|                                                           |
|  +--------------------------------------------+           |
|  |       Domain & Authorization Engine        |           |
|  +--------------------------------------------+           |
|                                                           |
|  +--------------------------------------------+           |
|  |        PostgreSQL Persistence Layer        |           |
|  +--------------------------------------------+           |
+-----------------------------------------------------------+
```

## 3. Trust Zones & Boundaries

- **Client Zone:** Manages private cryptographic keys (Ed25519 signing keys, X25519 agreement keys, vault DEKs). Encrypts all vault records before dispatch.
- **Transport Zone:** TLS 1.3 encryption for network transit.
- **Server Zone:** Authorizes requests, coordinates revisions, tracks cursors, and stores opaque ciphertext payloads. Even under complete server database compromise, attacker gains only ciphertext blobs and recipient-wrapped keys.

# Shellumi Server — Threat Model

## 1. System Overview & Security Boundaries

Shellumi Server is an untrusted-for-plaintext relay and storage backend for Shellumi clients.

```text
[ Client Device A (Trusted) ]  <--- TLS 1.3 --->  [ Shellumi Server (Untrusted for Plaintext) ]
                                                          |
[ Client Device B (Trusted) ]  <--- TLS 1.3 --->          +---> [ PostgreSQL Database ]
```

## 2. Threat Actors & Scenarios

### Actor A: Malicious Network Observer (Man-in-the-Middle)
- **Capability:** Intercept, replay, or alter network traffic.
- **Mitigation:** Mandatory TLS (enforced except for local loopback development). All client writes include cryptographic Ed25519 signatures and AEAD authentication tags.

### Actor B: Compromised Server Operator / Malicious Database Administrator
- **Capability:** Full read/write access to PostgreSQL and server memory.
- **Mitigation:**
  - Zero plaintext storage: Vault records are encrypted end-to-end on clients using random 256-bit DEKs.
  - DEKs are wrapped only to recipient devices' X25519 public keys.
  - Server cannot decrypt payloads, SSH keys, passwords, or snippets.
  - Rollback / deletion: Server can drop records or deny service, but clients authenticate state using signed revision sequences and cryptographic checkpoints.

### Actor C: Malicious Tenant / Malicious Authenticated Client
- **Capability:** Attempt IDOR (Insecure Direct Object Reference) to access foreign vaults or tamper with other users' records.
- **Mitigation:**
  - Strict tenant and vault scoped queries.
  - Monotonic revision counters checked transactionally.
  - Cryptographic verification of author device signatures.

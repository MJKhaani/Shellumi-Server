# Shellumi Server — Key Management Specification

## 1. Key Types & Allocations

1. **Device Identity Keys:**
   - **Signing:** Ed25519 keypair per enrolled device. Used to sign mutations, commits, and enrollment challenges.
   - **Key Agreement:** X25519 keypair per enrolled device. Used for Diffie-Hellman / sealed key delivery of vault data encryption keys.
   - **Distinction from SSH:** OpenSSH authentication keys MUST NOT be reused for device signing or key agreement.

2. **Vault Data Encryption Keys (DEKs):**
   - High-entropy 256-bit random symmetric key generated locally on the creator client.
   - Never transmitted to the server in plaintext.
   - Wrapped individually to each authorized member device's X25519 public key.

3. **Key Epochs & Rotation:**
   - When a member or device is revoked, an active member device generates a new epoch DEK and wraps it only to surviving active devices.
   - The server rejects writes tagged with stale or revoked epochs.

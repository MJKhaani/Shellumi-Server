# Shellumi Server — Backup, Verification & Disaster Recovery Guide

> **Zero-Knowledge Invariant:** All vault records, item payloads, and sync mutations stored on Shellumi Server are client-encrypted envelopes (`EncryptedEnvelope`) with client-wrapped Data Encryption Keys (`wrapped_dek`). Database backups contain **only opaque ciphertext**. Server-side database backups **never** contain plaintext credentials, unencrypted vault keys, or SSH private keys.

---

## 1. Overview & Operational Responsibilities

A self-hosted Shellumi Server deployment persists:
1. **Server Metadata & Settings:** Installation ID, schema version, bootstrap state.
2. **Tenancy & Identities:** Organizations, users, Argon2id password verifiers, active sessions, and registered client device public keys (Ed25519 signing and X25519 key-agreement).
3. **Vault Metadata & Permissions:** Vault records, RBAC memberships (`Owner`, `Administrator`, `Editor`, `Viewer`), active key epoch numbers, and single-use invitation hashes.
4. **Recipient Key Envelopes:** Client-wrapped DEKs encrypted specifically for registered recipient devices.
5. **Sync Data & History:** Encrypted records, monotonically sequenced change log entries (`change_log`), mutation idempotency records, and cryptographic audit events.

### Operator vs. User Keys
- **The Operator (Server):** Controls database availability, backups, and restores. The operator cannot read or decrypt vault contents.
- **The User (Client):** Holds local private keys and device identities. Decryption of restored backups requires authorized client devices.

---

## 2. Taking Consistent PostgreSQL Backups

### 2.1 Logical Snapshots via `pg_dump` (Recommended)

Logical backups can be created in either PostgreSQL Custom Archive format (`.dump`) or plain SQL format (`.sql`).

#### Custom Compressed Archive Format (Recommended for Production)
```bash
# Docker Compose environment:
docker compose exec -T postgres pg_dump \
  -U shellumi \
  -d shellumi_server \
  -F c \
  -b \
  -v \
  -f /tmp/shellumi_$(date +%Y%m%d_%H%M%S).dump

# Copy archive to persistent off-host backup storage:
docker compose cp postgres:/tmp/shellumi_*.dump ./backups/
```

#### Plaintext SQL Format
```bash
docker compose exec -T postgres pg_dump \
  -U shellumi \
  -d shellumi_server \
  --clean \
  --if-exists \
  --quote-all-identifiers > ./backups/shellumi_$(date +%Y%m%d_%H%M%S).sql
```

### 2.2 Physical WAL Archiving & Point-in-Time Recovery (PITR)
For enterprise high-availability deployments requiring low RPO (Recovery Point Objective):
- Enable PostgreSQL Write-Ahead Logging: `wal_level = replica`, `archive_mode = on`.
- Configure `archive_command` to ship continuous WAL segments to encrypted remote S3/NFS storage.
- Combine daily base backups with continuous WAL archiving to enable restore to any precise millisecond before an operational incident.

---

## 3. Cryptographic Backup Verification (`shellumi-server backup verify`)

Operators must verify database backup integrity immediately after export, before archiving offsite.

Shellumi Server provides an integrated verification utility:
```bash
shellumi-server backup verify /path/to/shellumi_backup.dump
```

### What `backup verify` Validates:
1. **File Accessibility & Size:** Confirms file exists, is readable, and non-empty.
2. **Cryptographic Checksum:** Calculates and outputs the SHA-256 digest of the backup file.
3. **Format Detection:** Identifies PostgreSQL Custom Archive (`PGDMP` header) or SQL text format.
4. **Schema Signatures:** Scans for all mandatory Shellumi Server tables:
   - `server_settings`
   - `users`
   - `organizations`
   - `devices`
   - `sessions`
   - `vaults`
   - `vault_members`
   - `records`
   - `change_log`
   - `vault_key_envelopes`
   - `audit_events`
5. **Zero-Knowledge Safety Check:** Scans the dump for any accidental inclusion of unencrypted SSH or RSA private keys (`BEGIN OPENSSH PRIVATE KEY`, etc.). If any unencrypted private key signature is detected, verification aborts with a critical security violation.

### Example Output:
```text
=== Shellumi Server Backup Verification ===

File:       ./backups/shellumi_20261111_120000.sql
Size:       452918 bytes
SHA-256:    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Format:     PostgreSQL Plaintext SQL (pg_dump)
Tables:     11/11 detected
Zero-E2EE:  [OK] No plaintext private keys found

[ OK ] Backup integrity VERIFIED successfully.
```

---

## 4. Disaster Recovery & Restoration Procedure

Follow these steps to recover a Shellumi Server deployment onto a clean host or fresh database:

### Step 1: Prepare Clean Infrastructure
Ensure the target server has Docker and Docker Compose installed:
```bash
git clone https://github.com/MJKhaani/Shellumi-Server.git
cd Shellumi-Server
cp deploy/.env.example deploy/.env
# Configure secure passwords and environment variables in deploy/.env
```

### Step 2: Start PostgreSQL Database Service
Start only the PostgreSQL container to prepare the clean database:
```bash
docker compose -f deploy/docker-compose.yml up -d postgres
```
Wait until the PostgreSQL healthcheck reports healthy:
```bash
docker compose -f deploy/docker-compose.yml ps
```

### Step 3: Restore Database Snapshot
Copy the verified backup archive into the container and execute restoration:

#### From Custom Archive (`.dump`):
```bash
docker compose -f deploy/docker-compose.yml cp ./backups/shellumi_verified.dump postgres:/tmp/restore.dump

docker compose -f deploy/docker-compose.yml exec -T postgres pg_restore \
  -U shellumi \
  -d shellumi_server \
  --clean \
  --if-exists \
  --no-owner \
  --no-privileges \
  /tmp/restore.dump
```

#### From SQL Plaintext (`.sql`):
```bash
cat ./backups/shellumi_verified.sql | docker compose -f deploy/docker-compose.yml exec -T postgres psql -U shellumi -d shellumi_server
```

### Step 4: Run Database Migration Check
Verify that the database schema matches the expected server version:
```bash
docker compose -f deploy/docker-compose.yml run --rm server /app/shellumi-server migrate status
```

### Step 5: Start Application Server
Start the server daemon:
```bash
docker compose -f deploy/docker-compose.yml up -d server
```

### Step 6: Verify Service Health
Verify process liveness and readiness:
```bash
curl -f http://127.0.0.1:8080/health/live
curl -f http://127.0.0.1:8080/health/ready
```
Both endpoints must return HTTP 200 OK with `{"status":"ok"}`.

---

## 5. Client Reconnection & Data Continuity Validation

Once the server is restored:
1. **Client Identity Preservation:** Authorized desktop clients reconnect using their existing refresh tokens or sign in with their existing credentials.
2. **Device Identity Validation:** Devices retain their registered Ed25519 signing keys and X25519 agreement keys.
3. **Change Feed Resumption:**
   - Clients pull changes from `/api/v1/vaults/:id/changes?since=<last_acknowledged_cursor>`.
   - If the restored backup represents a past snapshot (data rollback), clients detect that server sequence numbers are behind their outbox generation, flag Divergent History, and prompt the operator/user to safely replay pending outbox mutations without data loss.
4. **Key Envelopes:** Client devices download their respective recipient-wrapped key envelopes for the active epoch and decrypt records locally.

---

## 6. Schema Rollback & Emergency Version Compatibility

- All migrations in `migrations/` are strictly forward-only.
- If upgrading a server binary introduces issues, operators can safely downgrade to the previous minor server binary **provided the database schema version is supported**.
- Check `docs/COMPATIBILITY.md` for the server binary and database migration compatibility matrix before rolling back binaries.

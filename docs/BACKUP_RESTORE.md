# Shellumi Server — Backup & Disaster Recovery Guide

## Backup Strategy

Shellumi Server persists:
1. Server metadata and configuration.
2. Tenant, user, and device records.
3. Vault memberships and recipient-wrapped key envelopes.
4. Encrypted ciphertext records and change feed sequences.

Because all vault records are encrypted client-side, a backup of the server's database does not expose user credentials or SSH keys.

## Automated PostgreSQL Backup

Use `pg_dump` to create point-in-time snapshots:

```bash
docker compose exec postgres pg_dump -U shellumi -d shellumi_server -F c -f /tmp/shellumi_backup_$(date +%Y%m%d_%H%M%S).dump
```

## Restoration Procedure

1. Stop application server:
   ```bash
   docker compose stop server
   ```

2. Restore database:
   ```bash
   docker compose exec -T postgres pg_restore -U shellumi -d shellumi_server --clean /tmp/shellumi_backup.dump
   ```

3. Restart server:
   ```bash
   docker compose start server
   ```

4. Verify health:
   ```bash
   curl http://127.0.0.1:8080/health/ready
   ```

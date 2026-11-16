-- Forward-only migration: Anti-replay device sync counters per vault and device
-- Version: 20261116000001

CREATE TABLE IF NOT EXISTS device_sync_counters (
    vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    last_device_counter BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_device_sync_counters_vault ON device_sync_counters(vault_id);

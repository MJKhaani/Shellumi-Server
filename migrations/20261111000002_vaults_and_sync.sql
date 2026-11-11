-- Forward-only migration: Vaults, records, change log, mutation idempotency, and cursors
-- Version: 20261111000002

-- 1. Vaults table
CREATE TABLE IF NOT EXISTS vaults (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vault_type VARCHAR(32) NOT NULL DEFAULT 'personal', -- 'personal', 'team'
    encrypted_name TEXT,
    active_key_epoch INT NOT NULL DEFAULT 1,
    server_sequence BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_vaults_tenant_id ON vaults(tenant_id);
CREATE INDEX IF NOT EXISTS idx_vaults_owner_id ON vaults(owner_id);

-- 2. Vault members table (RBAC)
CREATE TABLE IF NOT EXISTS vault_members (
    vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL DEFAULT 'owner', -- 'owner', 'administrator', 'editor', 'viewer'
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_vault_members_user_id ON vault_members(user_id);

-- 3. Records table (current authoritative state of each object in a vault)
CREATE TABLE IF NOT EXISTS records (
    vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    object_id VARCHAR(64) NOT NULL,
    entity_type VARCHAR(32) NOT NULL,
    current_revision BIGINT NOT NULL DEFAULT 1,
    key_epoch INT NOT NULL DEFAULT 1,
    author_device_id UUID NOT NULL REFERENCES devices(id),
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    encrypted_envelope JSONB, -- opaque ciphertext envelope (salt, nonce, ciphertext, associated_data, kdf_iterations)
    ciphertext_digest VARCHAR(64) NOT NULL,
    last_server_sequence BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_id, object_id)
);

CREATE INDEX IF NOT EXISTS idx_records_vault_updated ON records(vault_id, updated_at DESC);

-- 4. Change log table (monotonic append-only delta feed per vault)
CREATE TABLE IF NOT EXISTS change_log (
    vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    sequence BIGINT NOT NULL,
    object_id VARCHAR(64) NOT NULL,
    entity_type VARCHAR(32) NOT NULL,
    revision BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    author_device_id UUID NOT NULL REFERENCES devices(id),
    encrypted_envelope JSONB,
    ciphertext_digest VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_change_log_feed ON change_log(vault_id, sequence ASC);

-- 5. Mutation idempotency table
CREATE TABLE IF NOT EXISTS mutation_idempotency (
    vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    idempotency_key VARCHAR(128) NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    request_hash VARCHAR(64) NOT NULL,
    response_payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_mutation_idempotency_created ON mutation_idempotency(created_at);

-- 6. Sync cursors table (optional device acknowledgement tracking)
CREATE TABLE IF NOT EXISTS sync_cursors (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    last_acknowledged_sequence BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (device_id, vault_id)
);

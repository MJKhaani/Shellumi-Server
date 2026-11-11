-- Forward-only migration: Vault invitations, recipient-wrapped key envelopes, and audit events
-- Version: 20261111000003

-- 1. Vault invitations
CREATE TABLE IF NOT EXISTS vault_invites (
    id UUID PRIMARY KEY,
    vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    inviter_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL DEFAULT 'editor', -- 'administrator', 'editor', 'viewer'
    invite_token_hash VARCHAR(64) NOT NULL UNIQUE,
    recipient_email VARCHAR(255),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    accepted_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vault_invites_vault ON vault_invites(vault_id);
CREATE INDEX IF NOT EXISTS idx_vault_invites_token ON vault_invites(invite_token_hash);

-- 2. Recipient-wrapped key envelopes
CREATE TABLE IF NOT EXISTS vault_key_envelopes (
    vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    epoch INT NOT NULL,
    recipient_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sender_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    wrapped_dek TEXT NOT NULL,
    key_agreement_ephemeral_pk TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_id, epoch, recipient_device_id)
);

CREATE INDEX IF NOT EXISTS idx_key_envelopes_device ON vault_key_envelopes(recipient_device_id, epoch);

-- 3. Cryptographic hash-chained audit events
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    actor_device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    action VARCHAR(64) NOT NULL,
    target_type VARCHAR(32) NOT NULL,
    target_id VARCHAR(64) NOT NULL,
    details JSONB,
    predecessor_hash VARCHAR(64) NOT NULL,
    event_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_vault ON audit_events(vault_id, id ASC);
CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at DESC);

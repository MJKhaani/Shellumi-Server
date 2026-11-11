-- Forward-only migration: Live terminal collaboration sessions and participants
-- Version: 20261111000004

-- 1. Collaboration sessions
CREATE TABLE IF NOT EXISTS collab_sessions (
    id UUID PRIMARY KEY,
    host_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    mode VARCHAR(32) NOT NULL DEFAULT 'read_only', -- 'read_only', 'controllable'
    active_writer_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    active_writer_device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    lease_token BIGINT NOT NULL DEFAULT 1,
    lease_expires_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    terminated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_collab_sessions_host ON collab_sessions(host_user_id);
CREATE INDEX IF NOT EXISTS idx_collab_sessions_active ON collab_sessions(expires_at, terminated_at);

-- 2. Collaboration participants
CREATE TABLE IF NOT EXISTS collab_participants (
    session_id UUID NOT NULL REFERENCES collab_sessions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer', -- 'host', 'writer', 'viewer'
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (session_id, user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_collab_participants_user ON collab_participants(user_id);
CREATE INDEX IF NOT EXISTS idx_collab_participants_session ON collab_participants(session_id);

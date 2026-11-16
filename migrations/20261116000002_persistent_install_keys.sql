-- Forward-only migration 006: Add persistent token signing key to server_settings
ALTER TABLE server_settings ADD COLUMN IF NOT EXISTS token_signing_key TEXT;

-- Preserve an existing installation and fail closed if previous races created duplicates.
DO $$
BEGIN
    IF (SELECT count(*) FROM server_settings) > 1 THEN
        RAISE EXCEPTION 'multiple server_settings rows require operator reconciliation';
    END IF;
END $$;
UPDATE server_settings SET id = '7368656c-6c75-6d69-5f73-657474696e67';
ALTER TABLE server_settings ADD CONSTRAINT server_settings_singleton
    CHECK (id = '7368656c-6c75-6d69-5f73-657474696e67');

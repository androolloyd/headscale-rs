-- Headscale-go-compatible users table for Postgres.
--
-- This mirrors the upstream GORM shape for hscontrol/types/users.go and keeps
-- the same uniqueness rules used by the SQLite compatibility path.
CREATE TABLE IF NOT EXISTS users (
    id                  BIGSERIAL PRIMARY KEY,
    created_at          TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ,
    deleted_at          TIMESTAMPTZ,
    name                TEXT,
    display_name        TEXT,
    email               TEXT,
    provider_identifier TEXT,
    provider            TEXT,
    profile_pic_url     TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_identifier
    ON users(provider_identifier)
    WHERE provider_identifier IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_name_provider_identifier
    ON users(name, provider_identifier);
CREATE UNIQUE INDEX IF NOT EXISTS idx_name_no_provider_identifier
    ON users(name)
    WHERE provider_identifier IS NULL;

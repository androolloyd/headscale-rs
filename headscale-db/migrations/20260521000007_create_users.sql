-- Users table — mirrors juanfont/headscale v0.28.0 hscontrol/types/users.go.
--
-- The indexes intentionally match the upstream GORM migration:
--   * provider_identifier is globally unique when set
--   * CLI users, which have NULL provider_identifier, are unique by name
--   * OIDC users can share a name only when provider_identifier differs
CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT,
    display_name        TEXT,
    email               TEXT,
    provider_identifier TEXT,
    provider            TEXT,
    profile_pic_url     TEXT,
    created_at          DATETIME,
    updated_at          DATETIME,
    deleted_at          DATETIME
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

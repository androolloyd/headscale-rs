-- Pre-auth keys table — mirrors juanfont/headscale v0.28.0
-- hscontrol/types/preauth_key.go.
--
-- Upstream plaintext shape is:
--   hskey-auth-<12 urlsafe chars>-<64 urlsafe chars>
--
-- `key` is kept for legacy plaintext rows; new rows store `prefix`
-- and a bcrypt hash of the 64-character secret in `hash`.
CREATE TABLE IF NOT EXISTS pre_auth_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT,
    prefix     TEXT,
    hash       BLOB,
    user_id    INTEGER,
    reusable   NUMERIC DEFAULT false,
    ephemeral  NUMERIC DEFAULT false,
    used       NUMERIC DEFAULT false,
    tags       TEXT,
    expiration DATETIME,
    created_at DATETIME
);

-- Index the user filter — `list_by_user` is the hot read.
CREATE INDEX IF NOT EXISTS idx_pre_auth_keys_user_id ON pre_auth_keys(user_id);

-- Expiry sweeper / "is this key still live?" query path.
CREATE INDEX IF NOT EXISTS idx_pre_auth_keys_expiration ON pre_auth_keys(expiration);

-- Match headscale-go's partial unique index: legacy rows can have an
-- empty prefix, modern rows cannot collide.
CREATE UNIQUE INDEX IF NOT EXISTS idx_pre_auth_keys_prefix
    ON pre_auth_keys(prefix)
    WHERE prefix IS NOT NULL AND prefix != '';

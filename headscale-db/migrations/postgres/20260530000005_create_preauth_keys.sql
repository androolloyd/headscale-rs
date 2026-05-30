-- Headscale-go-compatible pre-auth keys table for Postgres.
--
-- Modern plaintext keys have shape
-- `hskey-auth-<12 urlsafe chars>-<64 urlsafe chars>`. The public prefix is
-- stored plainly and the secret is bcrypt hashed in `hash`; legacy imported
-- rows may still use plaintext `key`.
CREATE TABLE IF NOT EXISTS pre_auth_keys (
    id         BIGSERIAL PRIMARY KEY,
    key        TEXT,
    prefix     TEXT,
    hash       BYTEA,
    user_id    BIGINT,
    reusable   BOOLEAN DEFAULT FALSE,
    ephemeral  BOOLEAN DEFAULT FALSE,
    used       BOOLEAN DEFAULT FALSE,
    tags       TEXT,
    expiration TIMESTAMPTZ,
    created_at TIMESTAMPTZ,
    CONSTRAINT fk_pre_auth_keys_user
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pre_auth_keys_prefix
    ON pre_auth_keys(prefix)
    WHERE prefix IS NOT NULL AND prefix != '';
CREATE INDEX IF NOT EXISTS idx_pre_auth_keys_user_id ON pre_auth_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_pre_auth_keys_expiration ON pre_auth_keys(expiration);

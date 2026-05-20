-- Pre-auth keys table — mirrors juanfont/headscale@main:hscontrol/types/preauth_key.go.
--
-- Differences from the Go schema we intentionally take:
--   * `key_hash` is a bcrypt hash of the bearer token (Go calls the
--     column `Key`); we picked the explicit name to make it clear the
--     row never stores plaintext.
--   * `tags` is a JSON-encoded array (Go uses GORM's `gorm.io/datatypes`
--     JSON column). Same on-the-wire shape, different SQL hint.
--   * `used_at` carries the redemption stamp (single-use keys flip it
--     to a non-NULL value on `try_use`; reusable keys leave it NULL).
--     The Go layer uses a separate `Used bool` flag; we collapse the
--     two by treating `used_at IS NOT NULL` as "has been redeemed at
--     least once" — for reusable keys this column is *also* NULL because
--     the reusable bit overrides single-use semantics.
CREATE TABLE IF NOT EXISTS preauth_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash    TEXT NOT NULL UNIQUE,         -- bcrypt hash of `octrapreauth-<hex>`
    user_id     TEXT NOT NULL,                -- owning user (string; we don't have a `users` FK yet)
    reusable    INTEGER NOT NULL DEFAULT 0,   -- 0/1 SQLite boolean
    ephemeral   INTEGER NOT NULL DEFAULT 0,
    tags        TEXT NOT NULL DEFAULT '[]',   -- JSON array of strings
    expiration  INTEGER,                      -- unix seconds; NULL = never expires
    created_at  INTEGER NOT NULL,             -- unix seconds
    used_at     INTEGER                       -- unix seconds; NULL = unused
);

-- Index the user filter — `list_by_user` is the hot read.
CREATE INDEX IF NOT EXISTS idx_preauth_keys_user_id ON preauth_keys(user_id);

-- Expiry sweeper / "is this key still live?" query path.
CREATE INDEX IF NOT EXISTS idx_preauth_keys_expiration ON preauth_keys(expiration);

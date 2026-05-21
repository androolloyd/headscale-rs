-- Headscale-go v0.28-compatible policy history table.
--
-- GORM creates `policies` from hscontrol/types/policy.go with the
-- standard soft-delete columns and raw HuJSON `data`. SetPolicy appends
-- a row; GetPolicy reads the newest non-deleted row by id.
CREATE TABLE IF NOT EXISTS policies (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME,
    data       TEXT
);

CREATE INDEX IF NOT EXISTS idx_policies_deleted_at ON policies(deleted_at);

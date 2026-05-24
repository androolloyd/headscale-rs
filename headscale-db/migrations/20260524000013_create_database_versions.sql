-- headscale-go creates database_versions for version-gating. Rust-managed
-- SQLite keeps the table empty so it does not claim to be headscale-go,
-- but the table exists for schema parity and future import policy checks.
CREATE TABLE IF NOT EXISTS database_versions (
    id INTEGER PRIMARY KEY,
    version TEXT NOT NULL,
    updated_at DATETIME
);

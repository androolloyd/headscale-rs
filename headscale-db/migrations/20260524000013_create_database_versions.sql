-- headscale-go creates database_versions for version-gating. Rust-managed
-- SQLite stamps the single upstream row after migrations succeed so imported
-- databases follow headscale-go's post-migration version-update behavior.
CREATE TABLE IF NOT EXISTS database_versions (
    id INTEGER PRIMARY KEY,
    version TEXT NOT NULL,
    updated_at DATETIME
);

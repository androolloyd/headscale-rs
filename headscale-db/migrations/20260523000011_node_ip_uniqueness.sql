-- Keep manually assigned node addresses race-proof at the database layer.
-- SQLite and Postgres both allow multiple NULLs in a unique index; the
-- explicit predicate also leaves legacy empty-string rows importable.
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_ipv4
    ON nodes(ipv4)
    WHERE ipv4 IS NOT NULL AND ipv4 != '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_ipv6
    ON nodes(ipv6)
    WHERE ipv6 IS NOT NULL AND ipv6 != '';

-- Keep live NodeStore node-key lookups one-to-one.
--
-- Headscale-go's schema does not declare node_key unique, but its runtime
-- node store indexes live nodes by node_key. Limit the invariant to live,
-- non-empty keys so legacy NULL/empty and soft-deleted rows remain importable.
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_node_key_live
    ON nodes(node_key)
    WHERE node_key IS NOT NULL AND node_key != '' AND deleted_at IS NULL;

-- Match headscale-go: live nodes can share a node_key.
--
-- Headscale-go's DB schema does not mark node_key unique, and current
-- upstream reauth tests create two live rows with the same NodeKey when the
-- same machine registers as a different user. NodeKey lookups remain
-- deterministic in Rust query helpers, but storage must not reject these rows.
DROP INDEX IF EXISTS idx_nodes_node_key_live;

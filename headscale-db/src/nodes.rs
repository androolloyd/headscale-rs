//! Node persistence operations.

use crate::{DbError, Result, models::NodeRow};
use headscale_core::node::Node;
use sqlx::SqlitePool;

/// Insert or update a node.
pub async fn upsert_node(pool: &SqlitePool, node: &Node) -> Result<()> {
    let addresses = serde_json::to_string(&node.addresses)?;
    let endpoints = serde_json::to_string(&node.endpoints)?;

    sqlx::query(
        r"
        INSERT INTO octra_nodes (
            id, name, wg_pubkey, addresses, endpoints, last_seen, online,
            cap_relay, cap_inference, cap_storage, cap_compute, cap_seed,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch())
        ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            wg_pubkey = excluded.wg_pubkey,
            addresses = excluded.addresses,
            endpoints = excluded.endpoints,
            last_seen = excluded.last_seen,
            online = excluded.online,
            cap_relay = excluded.cap_relay,
            cap_inference = excluded.cap_inference,
            cap_storage = excluded.cap_storage,
            cap_compute = excluded.cap_compute,
            cap_seed = excluded.cap_seed,
            updated_at = unixepoch()
        ",
    )
    .bind(&node.id)
    .bind(&node.name)
    .bind(&node.wg_pubkey)
    .bind(&addresses)
    .bind(&endpoints)
    .bind(node.last_seen as i64)
    .bind(node.online)
    .bind(node.capabilities.relay)
    .bind(node.capabilities.inference)
    .bind(node.capabilities.storage)
    .bind(node.capabilities.compute)
    .bind(node.capabilities.seed)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get a node by ID.
pub async fn get_node(pool: &SqlitePool, id: &str) -> Result<Node> {
    let row = sqlx::query_as::<_, NodeRow>(
        r"
        SELECT
            id, name, wg_pubkey, addresses, endpoints, last_seen, online,
            cap_relay, cap_inference, cap_storage, cap_compute, cap_seed,
            created_at, updated_at
        FROM octra_nodes
        WHERE id = ?
        ",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => DbError::NotFound(format!("Node not found: {id}")),
        e => DbError::from(e),
    })?;

    row.to_node()
}

/// Get all nodes.
pub async fn list_nodes(pool: &SqlitePool) -> Result<Vec<Node>> {
    let rows = sqlx::query_as::<_, NodeRow>(
        r"
        SELECT
            id, name, wg_pubkey, addresses, endpoints, last_seen, online,
            cap_relay, cap_inference, cap_storage, cap_compute, cap_seed,
            created_at, updated_at
        FROM octra_nodes
        ORDER BY last_seen DESC
        ",
    )
    .fetch_all(pool)
    .await?;

    rows.iter()
        .map(super::models::NodeRow::to_node)
        .collect::<Result<Vec<_>>>()
}

/// Get nodes with a specific capability.
pub async fn list_nodes_with_capability(pool: &SqlitePool, capability: &str) -> Result<Vec<Node>> {
    let query = match capability {
        "relay" => {
            "SELECT * FROM octra_nodes WHERE cap_relay = 1 AND online = 1 ORDER BY last_seen DESC"
        }
        "inference" => {
            "SELECT * FROM octra_nodes WHERE cap_inference = 1 AND online = 1 ORDER BY last_seen DESC"
        }
        "storage" => {
            "SELECT * FROM octra_nodes WHERE cap_storage = 1 AND online = 1 ORDER BY last_seen DESC"
        }
        "compute" => {
            "SELECT * FROM octra_nodes WHERE cap_compute = 1 AND online = 1 ORDER BY last_seen DESC"
        }
        "seed" => {
            "SELECT * FROM octra_nodes WHERE cap_seed = 1 AND online = 1 ORDER BY last_seen DESC"
        }
        _ => return Ok(Vec::new()),
    };

    let rows = sqlx::query_as::<_, NodeRow>(query).fetch_all(pool).await?;

    rows.iter()
        .map(super::models::NodeRow::to_node)
        .collect::<Result<Vec<_>>>()
}

/// Update node heartbeat.
pub async fn update_heartbeat(pool: &SqlitePool, node_id: &str) -> Result<()> {
    let result = sqlx::query(
        r"
        UPDATE octra_nodes
        SET last_seen = unixepoch(), online = 1, updated_at = unixepoch()
        WHERE id = ?
        ",
    )
    .bind(node_id)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(DbError::NotFound(format!("Node not found: {node_id}")));
    }

    Ok(())
}

/// Mark a node as offline.
pub async fn mark_offline(pool: &SqlitePool, node_id: &str) -> Result<()> {
    sqlx::query(
        r"
        UPDATE octra_nodes
        SET online = 0, updated_at = unixepoch()
        WHERE id = ?
        ",
    )
    .bind(node_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a node.
pub async fn delete_node(pool: &SqlitePool, node_id: &str) -> Result<()> {
    sqlx::query(
        r"
        DELETE FROM octra_nodes WHERE id = ?
        ",
    )
    .bind(node_id)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use headscale_core::node::NodeCapabilities;

    #[tokio::test]
    async fn test_node_crud() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let node = Node {
            id: "did:example:123".to_string(),
            name: "Test Node".to_string(),
            wg_pubkey: "test-pubkey".to_string(),
            addresses: vec!["10.0.0.1".parse().unwrap()],
            endpoints: vec!["endpoint1".to_string()],
            last_seen: 1_234_567_890,
            online: true,
            capabilities: NodeCapabilities {
                relay: true,
                inference: false,
                storage: true,
                compute: false,
                seed: false,
            },
        };

        // Insert
        upsert_node(db.pool(), &node).await.unwrap();

        // Get
        let retrieved = get_node(db.pool(), &node.id).await.unwrap();
        assert_eq!(retrieved.id, node.id);
        assert_eq!(retrieved.name, node.name);

        // Update heartbeat
        update_heartbeat(db.pool(), &node.id).await.unwrap();

        // List
        let nodes = list_nodes(db.pool()).await.unwrap();
        assert_eq!(nodes.len(), 1);

        // List with capability
        let relay_nodes = list_nodes_with_capability(db.pool(), "relay")
            .await
            .unwrap();
        assert_eq!(relay_nodes.len(), 1);

        // Delete
        delete_node(db.pool(), &node.id).await.unwrap();
        let result = get_node(db.pool(), &node.id).await;
        assert!(result.is_err());
    }
}

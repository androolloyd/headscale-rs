//! Resource registry persistence operations.

use crate::{
    Result,
    models::{ResourceRow, ResourceUsageRow},
};
use headscale_resources::{
    registry::ProviderResource,
    types::{ResourcePricing, ResourceType, ResourceUsage},
};
use sqlx::SqlitePool;

/// Register a resource from a provider.
pub async fn register_resource(
    pool: &SqlitePool,
    provider: &str,
    resource_type: &ResourceType,
    pricing: &ResourcePricing,
) -> Result<i64> {
    let resource_spec = serde_json::to_string(resource_type)?;
    let pricing_json = serde_json::to_string(pricing)?;
    let type_name = get_resource_type_name(resource_type);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let result = sqlx::query(
        r"
        INSERT INTO resources (
            provider, resource_type, resource_spec, pricing, available, last_updated
        )
        VALUES (?, ?, ?, ?, 1, ?)
        ",
    )
    .bind(provider)
    .bind(&type_name)
    .bind(&resource_spec)
    .bind(&pricing_json)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Find providers for a resource type.
pub async fn find_providers(
    pool: &SqlitePool,
    resource_type_name: &str,
) -> Result<Vec<ProviderResource>> {
    let rows = sqlx::query_as::<_, ResourceRow>(
        r"
        SELECT id, provider, resource_type, resource_spec, pricing,
               available, last_updated, created_at, updated_at
        FROM resources
        WHERE resource_type = ? AND available = 1
        ORDER BY id DESC
        ",
    )
    .bind(resource_type_name)
    .fetch_all(pool)
    .await?;

    rows.iter()
        .map(super::models::ResourceRow::to_provider_resource)
        .collect::<Result<Vec<_>>>()
}

/// Get all resources from a provider.
pub async fn get_provider_resources(
    pool: &SqlitePool,
    provider: &str,
) -> Result<Vec<ProviderResource>> {
    let rows = sqlx::query_as::<_, ResourceRow>(
        r"
        SELECT id, provider, resource_type, resource_spec, pricing,
               available, last_updated, created_at, updated_at
        FROM resources
        WHERE provider = ?
        ORDER BY id DESC
        ",
    )
    .bind(provider)
    .fetch_all(pool)
    .await?;

    rows.iter()
        .map(super::models::ResourceRow::to_provider_resource)
        .collect::<Result<Vec<_>>>()
}

/// Mark a resource as unavailable.
pub async fn mark_resource_unavailable(
    pool: &SqlitePool,
    provider: &str,
    resource_type_name: &str,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    sqlx::query(
        r"
        UPDATE resources
        SET available = 0, last_updated = ?, updated_at = unixepoch()
        WHERE provider = ? AND resource_type = ?
        ",
    )
    .bind(now)
    .bind(provider)
    .bind(resource_type_name)
    .execute(pool)
    .await?;

    Ok(())
}

/// Mark a resource as available.
pub async fn mark_resource_available(
    pool: &SqlitePool,
    provider: &str,
    resource_type_name: &str,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    sqlx::query(
        r"
        UPDATE resources
        SET available = 1, last_updated = ?, updated_at = unixepoch()
        WHERE provider = ? AND resource_type = ?
        ",
    )
    .bind(now)
    .bind(provider)
    .bind(resource_type_name)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a resource.
pub async fn delete_resource(pool: &SqlitePool, resource_id: i64) -> Result<()> {
    sqlx::query(
        r"
        DELETE FROM resources WHERE id = ?
        ",
    )
    .bind(resource_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Record resource usage.
pub async fn record_usage(
    pool: &SqlitePool,
    resource_type: &ResourceType,
    consumer: &str,
    provider: &str,
) -> Result<i64> {
    let type_name = get_resource_type_name(resource_type);
    let resource_spec = serde_json::to_string(resource_type)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let result = sqlx::query(
        r"
        INSERT INTO resource_usage (
            resource_type, resource_spec, consumer, provider, started_at, units_consumed, cost_millitokens
        )
        VALUES (?, ?, ?, ?, ?, 0, 0)
        ",
    )
    .bind(&type_name)
    .bind(&resource_spec)
    .bind(consumer)
    .bind(provider)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Complete resource usage.
pub async fn complete_usage(
    pool: &SqlitePool,
    usage_id: i64,
    units_consumed: u64,
    cost_millitokens: u64,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    sqlx::query(
        r"
        UPDATE resource_usage
        SET ended_at = ?, units_consumed = ?, cost_millitokens = ?
        WHERE id = ?
        ",
    )
    .bind(now)
    .bind(units_consumed as i64)
    .bind(cost_millitokens as i64)
    .bind(usage_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get resource usage history for a consumer.
pub async fn get_consumer_usage(
    pool: &SqlitePool,
    consumer: &str,
    limit: Option<i64>,
) -> Result<Vec<ResourceUsage>> {
    let limit = limit.unwrap_or(100);

    let rows = sqlx::query_as::<_, ResourceUsageRow>(
        r"
        SELECT id, resource_type, resource_spec, consumer, provider,
               started_at, ended_at, units_consumed, cost_millitokens, created_at
        FROM resource_usage
        WHERE consumer = ?
        ORDER BY started_at DESC
        LIMIT ?
        ",
    )
    .bind(consumer)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    rows.iter()
        .map(super::models::ResourceUsageRow::to_resource_usage)
        .collect::<Result<Vec<_>>>()
}

/// Get resource usage history for a provider.
pub async fn get_provider_usage(
    pool: &SqlitePool,
    provider: &str,
    limit: Option<i64>,
) -> Result<Vec<ResourceUsage>> {
    let limit = limit.unwrap_or(100);

    let rows = sqlx::query_as::<_, ResourceUsageRow>(
        r"
        SELECT id, resource_type, resource_spec, consumer, provider,
               started_at, ended_at, units_consumed, cost_millitokens, created_at
        FROM resource_usage
        WHERE provider = ?
        ORDER BY started_at DESC
        LIMIT ?
        ",
    )
    .bind(provider)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    rows.iter()
        .map(super::models::ResourceUsageRow::to_resource_usage)
        .collect::<Result<Vec<_>>>()
}

/// Get active resource usage (not yet completed).
pub async fn get_active_usage(pool: &SqlitePool) -> Result<Vec<ResourceUsage>> {
    let rows = sqlx::query_as::<_, ResourceUsageRow>(
        r"
        SELECT id, resource_type, resource_spec, consumer, provider,
               started_at, ended_at, units_consumed, cost_millitokens, created_at
        FROM resource_usage
        WHERE ended_at IS NULL
        ORDER BY started_at DESC
        ",
    )
    .fetch_all(pool)
    .await?;

    rows.iter()
        .map(super::models::ResourceUsageRow::to_resource_usage)
        .collect::<Result<Vec<_>>>()
}

/// Helper function to get resource type name as string.
fn get_resource_type_name(resource_type: &ResourceType) -> String {
    match resource_type {
        ResourceType::Inference(_) => "inference".to_string(),
        ResourceType::Storage(_) => "storage".to_string(),
        ResourceType::Compute(_) => "compute".to_string(),
        ResourceType::Bandwidth(_) => "bandwidth".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use headscale_resources::types::InferenceSpec;

    #[tokio::test]
    async fn test_resource_operations() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let provider = "did:example:provider";
        let consumer = "did:example:consumer";

        let resource_type = ResourceType::Inference(InferenceSpec {
            model: "llama3".to_string(),
            max_context: 8192,
            tokens_per_second: 100,
        });

        let pricing = ResourcePricing {
            resource_type: resource_type.clone(),
            price_per_unit: 10,
            unit_description: "per 1000 tokens".to_string(),
            minimum_units: 1,
        };

        // Register resource
        let resource_id = register_resource(db.pool(), provider, &resource_type, &pricing)
            .await
            .unwrap();
        assert!(resource_id > 0);

        // Find providers
        let providers = find_providers(db.pool(), "inference").await.unwrap();
        assert_eq!(providers.len(), 1);

        // Record usage
        let usage_id = record_usage(db.pool(), &resource_type, consumer, provider)
            .await
            .unwrap();

        // Complete usage
        complete_usage(db.pool(), usage_id, 1000, 10).await.unwrap();

        // Get usage history
        let usage = get_consumer_usage(db.pool(), consumer, None).await.unwrap();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].units_consumed, 1000);

        // Mark unavailable
        mark_resource_unavailable(db.pool(), provider, "inference")
            .await
            .unwrap();

        let providers = find_providers(db.pool(), "inference").await.unwrap();
        assert_eq!(providers.len(), 0);
    }
}

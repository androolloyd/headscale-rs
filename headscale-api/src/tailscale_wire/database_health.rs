//! Database liveness probe shared by `GET /health` and the gRPC `Health` RPC.
//!
//! Headscale-go answers both from `State.PingDB`, which bounds the ping at one
//! second (`hsdb.PingDB`: `context.WithTimeout(ctx, time.Second)`).

use std::{future::Future, time::Duration};

use async_trait::async_trait;

/// Go's `PingDB` deadline. A pool whose connections are all busy or whose
/// server has stopped answering is therefore reported unhealthy after one
/// second instead of hanging the health route.
pub const DATABASE_PING_TIMEOUT: Duration = Duration::from_secs(1);

/// A backing database that can be pinged for liveness.
#[async_trait]
pub trait DatabaseHealthCheck: Send + Sync {
    async fn ping(&self) -> Result<(), String>;
}

/// Run `ping` under [`DATABASE_PING_TIMEOUT`], reporting a timeout the way a
/// Go `context.DeadlineExceeded` reads.
pub async fn ping_with_timeout<F>(ping: F) -> Result<(), String>
where
    F: Future<Output = Result<(), String>> + Send,
{
    tokio::time::timeout(DATABASE_PING_TIMEOUT, ping)
        .await
        .unwrap_or_else(|_| Err("context deadline exceeded".to_string()))
}

#[cfg(feature = "admin")]
#[async_trait]
impl DatabaseHealthCheck for sqlx::SqlitePool {
    async fn ping(&self) -> Result<(), String> {
        sqlx::query("SELECT 1")
            .execute(self)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[cfg(all(feature = "admin", feature = "postgres-sqlx"))]
#[async_trait]
impl DatabaseHealthCheck for sqlx::PgPool {
    async fn ping(&self) -> Result<(), String> {
        headscale_db::check_postgres_health(self)
            .await
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ping_with_timeout_passes_results_through() {
        assert_eq!(ping_with_timeout(async { Ok(()) }).await, Ok(()));
        assert_eq!(
            ping_with_timeout(async { Err("offline".to_string()) }).await,
            Err("offline".to_string())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ping_with_timeout_gives_up_after_one_second() {
        let started = tokio::time::Instant::now();
        let result = ping_with_timeout(std::future::pending()).await;
        assert_eq!(result, Err("context deadline exceeded".to_string()));
        assert_eq!(started.elapsed(), Duration::from_secs(1));
    }
}

//! Session persistence operations.

use crate::{models::SessionRow, DbError, Result};
use headscale_identity::session::Session;
use sqlx::SqlitePool;

/// Create a new session.
pub async fn create_session(pool: &SqlitePool, session: &Session) -> Result<()> {
    let capabilities = serde_json::to_string(&session.capabilities)?;

    sqlx::query(
        r#"
        INSERT INTO sessions (token, did, created_at, expires_at, capabilities)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&session.token)
    .bind(session.did.as_str())
    .bind(session.created_at as i64)
    .bind(session.expires_at as i64)
    .bind(&capabilities)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get a session by token.
pub async fn get_session(pool: &SqlitePool, token: &str) -> Result<Session> {
    let row = sqlx::query_as::<_, SessionRow>(
        r#"
        SELECT token, did, created_at, expires_at, capabilities
        FROM sessions
        WHERE token = ?
        "#,
    )
    .bind(token)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => DbError::NotFound(format!("Session not found: {}", token)),
        e => DbError::from(e),
    })?;

    row.to_session()
}

/// Get all sessions for a DID.
pub async fn get_sessions_by_did(pool: &SqlitePool, did: &str) -> Result<Vec<Session>> {
    let rows = sqlx::query_as::<_, SessionRow>(
        r#"
        SELECT token, did, created_at, expires_at, capabilities
        FROM sessions
        WHERE did = ? AND expires_at > unixepoch()
        ORDER BY created_at DESC
        "#,
    )
    .bind(did)
    .fetch_all(pool)
    .await?;

    rows.iter()
        .map(|row| row.to_session())
        .collect::<Result<Vec<_>>>()
}

/// Delete a session.
pub async fn delete_session(pool: &SqlitePool, token: &str) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM sessions WHERE token = ?
        "#,
    )
    .bind(token)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete all sessions for a DID.
pub async fn delete_sessions_by_did(pool: &SqlitePool, did: &str) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM sessions WHERE did = ?
        "#,
    )
    .bind(did)
    .execute(pool)
    .await?;

    Ok(())
}

/// Cleanup expired sessions.
pub async fn cleanup_expired_sessions(pool: &SqlitePool) -> Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM sessions WHERE expires_at < unixepoch()
        "#,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Check if a session is valid (exists and not expired).
pub async fn is_session_valid(pool: &SqlitePool, token: &str) -> Result<bool> {
    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) as count
        FROM sessions
        WHERE token = ? AND expires_at > unixepoch()
        "#,
    )
    .bind(token)
    .fetch_one(pool)
    .await?;

    Ok(count.0 > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use headscale_identity::did::Did;

    #[tokio::test]
    async fn test_session_operations() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let did_alice = Did::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        let did_bob = Did::parse("did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2").unwrap();

        let session = Session {
            did: did_alice.clone(),
            token: "test-token-123".to_string(),
            created_at: now,
            expires_at: now + 3600,
            capabilities: vec!["read".to_string(), "write".to_string()],
        };

        // Create session
        create_session(db.pool(), &session).await.unwrap();

        // Get session
        let retrieved = get_session(db.pool(), &session.token).await.unwrap();
        assert_eq!(retrieved.token, session.token);
        assert_eq!(retrieved.did.as_str(), session.did.as_str());
        assert_eq!(retrieved.capabilities.len(), 2);

        // Check validity
        let valid = is_session_valid(db.pool(), &session.token).await.unwrap();
        assert!(valid);

        // Get sessions by DID
        let sessions = get_sessions_by_did(db.pool(), session.did.as_str())
            .await
            .unwrap();
        assert_eq!(sessions.len(), 1);

        // Delete session
        delete_session(db.pool(), &session.token).await.unwrap();
        let result = get_session(db.pool(), &session.token).await;
        assert!(result.is_err());

        // Test expired session - the trigger auto-cleans expired sessions on insert,
        // so we verify that the expired session is not valid after insert
        let expired_session = Session {
            did: did_bob,
            token: "expired-token".to_string(),
            created_at: now - 7200,
            expires_at: now - 3600,
            capabilities: vec![],
        };

        create_session(db.pool(), &expired_session).await.unwrap();

        // The trigger should have already cleaned up the expired session
        let valid = is_session_valid(db.pool(), &expired_session.token)
            .await
            .unwrap();
        assert!(!valid);

        // Verify cleanup function works when there's nothing to clean
        let cleaned = cleanup_expired_sessions(db.pool()).await.unwrap();
        assert_eq!(cleaned, 0); // Trigger already cleaned it
    }
}

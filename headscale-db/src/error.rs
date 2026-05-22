//! Error types for database operations.

use thiserror::Error;

/// Database error types.
#[derive(Debug, Error)]
pub enum DbError {
    /// SQLx database error
    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// Migration error
    #[error("Migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Not found error
    #[error("Record not found: {0}")]
    NotFound(String),

    /// Constraint violation
    #[error("Constraint violation: {0}")]
    Constraint(String),

    /// Unsupported headscale-go database version or migration history
    #[error("Unsupported headscale-go database: {0}")]
    UnsupportedHeadscaleGoDatabaseVersion(String),

    /// General error
    #[error("Database operation failed: {0}")]
    General(String),
}

/// Result type for database operations.
pub type Result<T> = std::result::Result<T, DbError>;

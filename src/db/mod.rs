//! Database access.
//!
//! Uses sqlx's runtime `Any` driver so the backend is chosen at startup from
//! the `database_url` (SQLite by default, Postgres or MySQL by URL). To stay
//! portable across all three, the schema uses only `VARCHAR`/`TEXT`/`INTEGER`:
//! certificate DER is stored base64-encoded and timestamps as RFC 3339 strings.
//! The database holds only issued-certificate, transaction and revocation
//! state; CAs and profiles come from config.

pub mod repo;

use sqlx::any::AnyPoolOptions;
use sqlx::AnyPool;

use crate::error::AppResult;

/// Portable DDL executed at startup (idempotent).
const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS issued_certificate (
        serial VARCHAR(64) PRIMARY KEY,
        ca_id VARCHAR(128) NOT NULL,
        subject VARCHAR(1024) NOT NULL,
        not_before VARCHAR(40) NOT NULL,
        not_after VARCHAR(40) NOT NULL,
        der_b64 TEXT NOT NULL,
        thumbprint_sha1 VARCHAR(64) NOT NULL,
        transaction_id VARCHAR(128),
        profile VARCHAR(128),
        status VARCHAR(16) NOT NULL,
        created_at VARCHAR(40) NOT NULL,
        revoked_at VARCHAR(40),
        revocation_reason INTEGER
    )",
    "CREATE TABLE IF NOT EXISTS scep_transaction (
        transaction_id VARCHAR(128) PRIMARY KEY,
        profile VARCHAR(128),
        status VARCHAR(32) NOT NULL,
        message_type VARCHAR(16),
        created_at VARCHAR(40) NOT NULL
    )",
];

/// Connect to the database and ensure the schema exists.
pub async fn connect(url: &str) -> AppResult<AnyPool> {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await?;
    migrate(&pool).await?;
    Ok(pool)
}

/// Create tables if they do not yet exist.
pub async fn migrate(pool: &AnyPool) -> AppResult<()> {
    for stmt in SCHEMA {
        sqlx::query(stmt).execute(pool).await?;
    }
    Ok(())
}

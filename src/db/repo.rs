//! Repository functions over the issued-certificate and transaction tables.

use sqlx::{AnyPool, Row};

use crate::error::AppResult;

/// Certificate status values.
pub const STATUS_VALID: &str = "valid";
pub const STATUS_REVOKED: &str = "revoked";

/// A record of a certificate this server issued.
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub serial: String,
    pub ca_id: String,
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    pub der_b64: String,
    pub thumbprint_sha1: String,
    pub transaction_id: Option<String>,
    pub profile: Option<String>,
    pub status: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<i64>,
}

/// Insert a newly issued certificate.
pub async fn insert_issued(pool: &AnyPool, cert: &IssuedCertificate) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO issued_certificate
         (serial, ca_id, subject, not_before, not_after, der_b64, thumbprint_sha1,
          transaction_id, profile, status, created_at, revoked_at, revocation_reason)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&cert.serial)
    .bind(&cert.ca_id)
    .bind(&cert.subject)
    .bind(&cert.not_before)
    .bind(&cert.not_after)
    .bind(&cert.der_b64)
    .bind(&cert.thumbprint_sha1)
    .bind(&cert.transaction_id)
    .bind(&cert.profile)
    .bind(&cert.status)
    .bind(&cert.created_at)
    .bind(&cert.revoked_at)
    .bind(cert.revocation_reason)
    .execute(pool)
    .await?;
    Ok(())
}

/// The revocation status of a serial, for OCSP.
pub enum RevocationStatus {
    Good,
    Revoked {
        revoked_at: Option<String>,
        reason: Option<i64>,
    },
    Unknown,
}

/// Look up the status of a certificate by serial (hex, lowercase) within a CA.
pub async fn status_by_serial(
    pool: &AnyPool,
    ca_id: &str,
    serial: &str,
) -> AppResult<RevocationStatus> {
    let row = sqlx::query(
        "SELECT status, revoked_at, revocation_reason
         FROM issued_certificate WHERE ca_id = ? AND serial = ?",
    )
    .bind(ca_id)
    .bind(serial)
    .fetch_optional(pool)
    .await?;

    Ok(match row {
        None => RevocationStatus::Unknown,
        Some(row) => {
            let status: String = row.try_get("status")?;
            if status == STATUS_REVOKED {
                RevocationStatus::Revoked {
                    revoked_at: row.try_get("revoked_at").ok(),
                    reason: row.try_get("revocation_reason").ok(),
                }
            } else {
                RevocationStatus::Good
            }
        }
    })
}

/// A revoked entry for building a CRL.
pub struct RevokedEntry {
    pub serial: String,
    pub revoked_at: Option<String>,
    pub reason: Option<i64>,
}

/// List all revoked certificates for a CA.
pub async fn list_revoked(pool: &AnyPool, ca_id: &str) -> AppResult<Vec<RevokedEntry>> {
    let rows = sqlx::query(
        "SELECT serial, revoked_at, revocation_reason
         FROM issued_certificate WHERE ca_id = ? AND status = ?",
    )
    .bind(ca_id)
    .bind(STATUS_REVOKED)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| RevokedEntry {
            serial: row.try_get("serial").unwrap_or_default(),
            revoked_at: row.try_get("revoked_at").ok(),
            reason: row.try_get("revocation_reason").ok(),
        })
        .collect())
}

/// Mark a certificate revoked.
pub async fn revoke(
    pool: &AnyPool,
    ca_id: &str,
    serial: &str,
    reason: i64,
    revoked_at: &str,
) -> AppResult<bool> {
    let result = sqlx::query(
        "UPDATE issued_certificate
         SET status = ?, revoked_at = ?, revocation_reason = ?
         WHERE ca_id = ? AND serial = ? AND status = ?",
    )
    .bind(STATUS_REVOKED)
    .bind(revoked_at)
    .bind(reason)
    .bind(ca_id)
    .bind(serial)
    .bind(STATUS_VALID)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Record a SCEP transaction (best-effort audit trail).
pub async fn record_transaction(
    pool: &AnyPool,
    transaction_id: &str,
    profile: &str,
    status: &str,
    message_type: &str,
    created_at: &str,
) -> AppResult<()> {
    // Upsert-ish: ignore if the transaction id already exists.
    let existing =
        sqlx::query("SELECT transaction_id FROM scep_transaction WHERE transaction_id = ?")
            .bind(transaction_id)
            .fetch_optional(pool)
            .await?;
    if existing.is_some() {
        sqlx::query(
            "UPDATE scep_transaction SET status = ?, message_type = ? WHERE transaction_id = ?",
        )
        .bind(status)
        .bind(message_type)
        .bind(transaction_id)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO scep_transaction (transaction_id, profile, status, message_type, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(transaction_id)
        .bind(profile)
        .bind(status)
        .bind(message_type)
        .bind(created_at)
        .execute(pool)
        .await?;
    }
    Ok(())
}

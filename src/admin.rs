//! Operator commands run from the command line (`blapki revoke ...`).
//!
//! There is deliberately no HTTP admin API: revocation is done by someone with
//! shell access to the host, using the same configuration as the server.

use crate::config::Settings;
use crate::db::{self, repo};
use crate::error::{AppError, AppResult};

/// Usage text for the command line.
pub const USAGE: &str = "\
Usage:
  blapki                              run the server
  blapki revoke <ca> <serial> [reason]  revoke an issued certificate

<serial> is the certificate serial in hex (colons and a 0x prefix are allowed).
[reason] is an RFC 5280 reason name or code; it defaults to 'unspecified':
  unspecified (0), keyCompromise (1), caCompromise (2), affiliationChanged (3),
  superseded (4), cessationOfOperation (5), privilegeWithdrawn (9)";

/// Revoke a certificate. Returns `false` if no valid certificate with that
/// serial exists for the CA (unknown serial, or already revoked).
pub async fn revoke(
    settings: &Settings,
    ca_id: &str,
    serial: &str,
    reason: Option<&str>,
) -> AppResult<bool> {
    if settings.ca(ca_id).is_none() {
        return Err(AppError::Config(format!("unknown ca '{ca_id}'")));
    }
    let serial = normalize_serial(serial)?;
    let reason = parse_reason(reason.unwrap_or("unspecified"))?;
    let pool = db::connect(&settings.server.database_url).await?;
    repo::revoke(&pool, ca_id, &serial, reason, &crate::http::now_utc()).await
}

/// Bring a serial as printed by common tools (`3A:BC:..`, `0x3abc..`,
/// upper case) into the lower-case hex form stored in the database.
pub fn normalize_serial(input: &str) -> AppResult<String> {
    let trimmed = input.trim();
    let trimmed = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let mut hex: String = trimmed
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::bad_request(format!(
            "'{input}' is not a hex serial number"
        )));
    }
    if hex.len() % 2 == 1 {
        hex.insert(0, '0');
    }
    Ok(hex)
}

/// Parse an RFC 5280 CRL reason given by name or by number.
pub fn parse_reason(input: &str) -> AppResult<i64> {
    let code = match input.trim().to_ascii_lowercase().as_str() {
        "0" | "unspecified" => 0,
        "1" | "keycompromise" => 1,
        "2" | "cacompromise" => 2,
        "3" | "affiliationchanged" => 3,
        "4" | "superseded" => 4,
        "5" | "cessationofoperation" => 5,
        "9" | "privilegewithdrawn" => 9,
        other => {
            return Err(AppError::bad_request(format!(
                "unknown revocation reason '{other}'"
            )))
        }
    };
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serials_are_normalised() {
        assert_eq!(normalize_serial("3A:BC:01").unwrap(), "3abc01");
        assert_eq!(normalize_serial("0xABC").unwrap(), "0abc");
        assert_eq!(normalize_serial(" 00ff ").unwrap(), "00ff");
        assert!(normalize_serial("").is_err());
        assert!(normalize_serial("xyz").is_err());
        assert!(normalize_serial("12; DROP TABLE x").is_err());
    }

    #[test]
    fn reasons_parse_by_name_and_code() {
        assert_eq!(parse_reason("keyCompromise").unwrap(), 1);
        assert_eq!(parse_reason("4").unwrap(), 4);
        assert_eq!(parse_reason("unspecified").unwrap(), 0);
        assert!(parse_reason("7").is_err());
        assert!(parse_reason("bored").is_err());
    }
}

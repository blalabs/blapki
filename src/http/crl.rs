//! CRL endpoint (RFC 5280).
//!
//! Builds and signs a `CertificateList` from the revoked rows for a CA. There
//! is no high-level CRL builder in `x509-cert`, so the `TbsCertList` is
//! assembled and signed directly with the CA key.

use std::time::{Duration, SystemTime};

use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use der::asn1::{GeneralizedTime, UtcTime};
use der::{DateTime, Encode};
use signature::Signer;
use spki::{DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding};
use x509_cert::certificate::Version;
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Time;

use crate::crypto::CaSigningKey;
use crate::db::repo;
use crate::error::{AppError, AppResult};
use crate::http::Shared;

const CT_CRL: &str = "application/pkix-crl";
const CRL_LIFETIME_SECS: u64 = 24 * 3600;

/// `GET /crl/{ca}`: the current CRL in DER form.
pub async fn crl(State(state): State<Shared>, Path(ca): Path<String>) -> Response {
    match build_crl(&state, &ca).await {
        Ok(der) => ([(CONTENT_TYPE, CT_CRL)], der).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn build_crl(state: &Shared, ca_id: &str) -> AppResult<Vec<u8>> {
    let ca = state
        .cas
        .get(ca_id)
        .ok_or_else(|| AppError::NotFound(format!("unknown CA '{ca_id}'")))?;

    let revoked_rows = repo::list_revoked(&state.db, ca_id).await?;
    let now = SystemTime::now();

    let mut revoked_certificates = Vec::new();
    for row in revoked_rows {
        let Ok(bytes) = hex::decode(&row.serial) else {
            continue;
        };
        let Ok(serial_number) = SerialNumber::new(&bytes) else {
            continue;
        };
        let revocation_date = row
            .revoked_at
            .as_deref()
            .and_then(parse_rfc3339)
            .map(to_time)
            .transpose()?
            .unwrap_or(to_time(now)?);
        revoked_certificates.push(RevokedCert {
            serial_number,
            revocation_date,
            crl_entry_extensions: None,
        });
    }

    let signer = CaSigningKey::new(ca.private_key.clone());
    let signature_algorithm = signer
        .signature_algorithm_identifier()
        .map_err(|e| AppError::crypto(format!("CRL signature alg: {e}")))?;

    let tbs = TbsCertList {
        version: Version::V2,
        signature: signature_algorithm.clone(),
        issuer: ca.cert.tbs_certificate.subject.clone(),
        this_update: to_time(now)?,
        next_update: Some(to_time(now + Duration::from_secs(CRL_LIFETIME_SECS))?),
        revoked_certificates: if revoked_certificates.is_empty() {
            None
        } else {
            Some(revoked_certificates)
        },
        crl_extensions: None,
    };

    let tbs_der = tbs
        .to_der()
        .map_err(|e| AppError::crypto(format!("encode TBS CRL: {e}")))?;
    let signature = signer
        .try_sign(&tbs_der)
        .map_err(|e| AppError::crypto(format!("sign CRL: {e}")))?
        .to_bitstring()
        .map_err(|e| AppError::crypto(format!("encode CRL signature: {e}")))?;

    let crl = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm,
        signature,
    };
    crl.to_der()
        .map_err(|e| AppError::crypto(format!("encode CRL: {e}")))
}

fn to_time(st: SystemTime) -> AppResult<Time> {
    let dt =
        DateTime::from_system_time(st).map_err(|e| AppError::crypto(format!("bad time: {e}")))?;
    // RFC 5280: dates before 2050 use UTCTime, otherwise GeneralizedTime.
    if dt.year() < 2050 {
        Ok(Time::UtcTime(
            UtcTime::from_date_time(dt).map_err(|e| AppError::crypto(format!("utc time: {e}")))?,
        ))
    } else {
        Ok(Time::GeneralTime(GeneralizedTime::from_date_time(dt)))
    }
}

fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(s, &Rfc3339)
        .ok()
        .map(SystemTime::from)
}

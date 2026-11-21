//! CRL endpoint (RFC 5280).
//!
//! Builds and signs a `CertificateList` from the revoked rows for a CA. There
//! is no high-level CRL builder in `x509-cert`, so the `TbsCertList` is
//! assembled and signed directly with the CA key.

use std::time::{Duration, SystemTime};

use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use const_oid::AssociatedOid;
use der::asn1::{GeneralizedTime, OctetString, Uint, UtcTime};
use der::{DateTime, Encode};
use signature::Signer;
use spki::{DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding};
use x509_cert::certificate::Version;
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::pkix::{CrlNumber, CrlReason};
use x509_cert::ext::Extension;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Time;

use crate::db::repo;
use crate::error::{AppError, AppResult};
use crate::http::ocsp::crl_reason;
use crate::http::{blocking, Shared};

const CT_CRL: &str = "application/pkix-crl";

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
        .ok_or_else(|| AppError::NotFound(format!("unknown CA '{ca_id}'")))?
        .clone();

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
        // reasonCode is omitted for `unspecified` (RFC 5280 5.3.1).
        let crl_entry_extensions = match row.reason.and_then(crl_reason) {
            Some(reason) if reason != CrlReason::Unspecified => Some(vec![extension(&reason)?]),
            _ => None,
        };
        revoked_certificates.push(RevokedCert {
            serial_number,
            revocation_date,
            crl_entry_extensions,
        });
    }

    let lifetime = Duration::from_secs(ca.crl_lifetime_hours.max(1) * 3600);
    // RFC 5280 5.2 requires both extensions. The CRL is regenerated on every
    // request, so the number is derived from the clock to stay monotonic.
    let unix_secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let crl_number = CrlNumber(
        Uint::new(&unix_secs.to_be_bytes())
            .map_err(|e| AppError::crypto(format!("CRL number: {e}")))?,
    );
    let crl_extensions = vec![
        extension(&ca.authority_key_identifier()?)?,
        extension(&crl_number)?,
    ];

    let this_update = to_time(now)?;
    let next_update = to_time(now + lifetime)?;

    blocking(move || {
        let signer = &ca.signing_key;
        let signature_algorithm = signer
            .signature_algorithm_identifier()
            .map_err(|e| AppError::crypto(format!("CRL signature alg: {e}")))?;

        let tbs = TbsCertList {
            version: Version::V2,
            signature: signature_algorithm.clone(),
            issuer: ca.cert.tbs_certificate.subject.clone(),
            this_update,
            next_update: Some(next_update),
            revoked_certificates: if revoked_certificates.is_empty() {
                None
            } else {
                Some(revoked_certificates)
            },
            crl_extensions: Some(crl_extensions),
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
    })
    .await
}

/// Wrap a value as a non-critical X.509 extension.
fn extension<T: AssociatedOid + Encode>(value: &T) -> AppResult<Extension> {
    let der = value
        .to_der()
        .map_err(|e| AppError::crypto(format!("encode CRL extension: {e}")))?;
    Ok(Extension {
        extn_id: T::OID,
        critical: false,
        extn_value: OctetString::new(der)
            .map_err(|e| AppError::crypto(format!("encode CRL extension: {e}")))?,
    })
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

//! OCSP responder (RFC 6960).
//!
//! Looks each requested serial up in the issued-certificate table and returns a
//! `BasicOCSPResponse` signed directly by the CA key. Certificates we never
//! issued are reported `unknown`.

use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use der::{Decode, Encode};
use x509_cert::ext::pkix::CrlReason;
use x509_ocsp::builder::OcspResponseBuilder;
use x509_ocsp::{
    CertId, CertStatus, OcspGeneralizedTime, OcspRequest, RevokedInfo, SingleResponse,
};

use crate::ca::CertificateAuthority;
use crate::crypto::HashAlg;
use crate::db::repo::{self, RevocationStatus};
use crate::error::{AppError, AppResult};
use crate::http::{blocking, Shared};

const CT_OCSP: &str = "application/ocsp-response";
/// How long a response is valid before a client should re-check.
const NEXT_UPDATE_SECS: u64 = 3600;
/// Most certificates one request may ask about (each costs a database query).
const MAX_REQUESTS: usize = 32;
/// Largest nonce echoed back (RFC 8954).
const MAX_NONCE_LEN: usize = 32;

/// `POST /ocsp/{ca}`: request body is a DER OCSPRequest.
pub async fn ocsp_post(
    State(state): State<Shared>,
    Path(ca): Path<String>,
    body: Bytes,
) -> Response {
    respond(&state, &ca, &body).await
}

/// `GET /ocsp/{ca}/{b64}`: base64-encoded OCSPRequest in the path.
pub async fn ocsp_get(
    State(state): State<Shared>,
    Path((ca, b64)): Path<(String, String)>,
) -> Response {
    // A client that did not percent-encode the base64 has its '+' intact here
    // (paths are not form-decoded) and its '/' captured by the wildcard.
    match base64::engine::general_purpose::STANDARD.decode(b64.trim_matches('/').as_bytes()) {
        Ok(der) => respond(&state, &ca, &der).await,
        Err(_) => (StatusCode::BAD_REQUEST, "invalid base64 OCSP request").into_response(),
    }
}

/// `GET /ocsp/{ca}` with no request: not valid, but return a hint.
pub async fn ocsp_get_root(State(_state): State<Shared>, Path(_ca): Path<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        "OCSP: POST a request body or append the base64 request to the path",
    )
        .into_response()
}

async fn respond(state: &Shared, ca_id: &str, req_der: &[u8]) -> Response {
    match build_response(state, ca_id, req_der).await {
        Ok(der) => ([(CONTENT_TYPE, CT_OCSP)], der).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn build_response(state: &Shared, ca_id: &str, req_der: &[u8]) -> AppResult<Vec<u8>> {
    let ca = state
        .cas
        .get(ca_id)
        .ok_or_else(|| AppError::NotFound(format!("unknown CA '{ca_id}'")))?
        .clone();

    let request = OcspRequest::from_der(req_der)
        .map_err(|e| AppError::bad_request(format!("invalid OCSP request: {e}")))?;
    let entries = &request.tbs_request.request_list;
    if entries.len() > MAX_REQUESTS {
        return Err(AppError::bad_request(format!(
            "OCSP request asks about {} certificates; at most {MAX_REQUESTS} are allowed",
            entries.len()
        )));
    }

    let this_update = ocsp_now();
    let next_update =
        OcspGeneralizedTime::try_from(SystemTime::now() + Duration::from_secs(NEXT_UPDATE_SECS))
            .unwrap_or(this_update);

    let mut builder = OcspResponseBuilder::new(ca.cert.tbs_certificate.subject.clone());

    for entry in entries {
        // Only answer for certificates of this CA: a CertID naming another
        // issuer is `unknown`, whatever its serial.
        let status = if cert_id_names_ca(&entry.req_cert, &ca) {
            let serial_hex = hex::encode(entry.req_cert.serial_number.as_bytes());
            repo::status_by_serial(&state.db, ca_id, &serial_hex).await?
        } else {
            RevocationStatus::Unknown
        };
        let cert_status = to_cert_status(&status);
        let single = SingleResponse::new(entry.req_cert.clone(), cert_status, this_update)
            .with_next_update(next_update);
        builder = builder.with_single_response(single);
    }

    if let Some(nonce) = request.nonce() {
        // RFC 8954 limits the nonce to 32 octets; do not sign larger blobs.
        if nonce.0.as_bytes().len() <= MAX_NONCE_LEN {
            builder = builder
                .with_extension(nonce)
                .map_err(|e| AppError::crypto(format!("OCSP nonce: {e}")))?;
        }
    }

    blocking(move || {
        let mut signer = ca.signing_key.clone();
        let response = builder
            .sign(&mut signer, Some(vec![ca.cert.clone()]), this_update)
            .map_err(|e| AppError::crypto(format!("signing OCSP response: {e}")))?;
        response
            .to_der()
            .map_err(|e| AppError::crypto(format!("encode OCSP response: {e}")))
    })
    .await
}

/// Whether a request's `CertID` identifies `ca` as the issuer (RFC 6960
/// 4.1.1): the hashes of the issuer's name and public key must both match.
fn cert_id_names_ca(id: &CertId, ca: &CertificateAuthority) -> bool {
    let Some(alg) = HashAlg::from_digest_oid(id.hash_algorithm.oid) else {
        return false;
    };
    let tbs = &ca.cert.tbs_certificate;
    let Ok(name_der) = tbs.subject.to_der() else {
        return false;
    };
    let key_bytes = tbs.subject_public_key_info.subject_public_key.raw_bytes();
    id.issuer_name_hash.as_bytes() == alg.digest(&name_der).as_slice()
        && id.issuer_key_hash.as_bytes() == alg.digest(key_bytes).as_slice()
}

fn to_cert_status(status: &RevocationStatus) -> CertStatus {
    match status {
        RevocationStatus::Good => CertStatus::good(),
        RevocationStatus::Unknown => CertStatus::unknown(),
        RevocationStatus::Revoked { revoked_at, reason } => {
            let revocation_time = revoked_at
                .as_deref()
                .and_then(parse_rfc3339)
                .and_then(|st| OcspGeneralizedTime::try_from(st).ok())
                .unwrap_or_else(ocsp_now);
            CertStatus::Revoked(RevokedInfo {
                revocation_time,
                revocation_reason: reason.and_then(crl_reason),
            })
        }
    }
}

/// Map a stored RFC 5280 reason code to the OCSP/CRL enum.
pub(crate) fn crl_reason(code: i64) -> Option<CrlReason> {
    Some(match code {
        0 => CrlReason::Unspecified,
        1 => CrlReason::KeyCompromise,
        2 => CrlReason::CaCompromise,
        3 => CrlReason::AffiliationChanged,
        4 => CrlReason::Superseded,
        5 => CrlReason::CessationOfOperation,
        6 => CrlReason::CertificateHold,
        9 => CrlReason::PrivilegeWithdrawn,
        10 => CrlReason::AaCompromise,
        _ => return None,
    })
}

fn ocsp_now() -> OcspGeneralizedTime {
    OcspGeneralizedTime::try_from(SystemTime::now())
        .unwrap_or_else(|_| OcspGeneralizedTime::from(der::DateTime::INFINITY))
}

fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(s, &Rfc3339)
        .ok()
        .map(SystemTime::from)
}

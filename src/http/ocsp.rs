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
use x509_ocsp::builder::OcspResponseBuilder;
use x509_ocsp::{CertStatus, OcspGeneralizedTime, OcspRequest, RevokedInfo, SingleResponse};

use crate::ca::CertificateAuthority;
use crate::crypto::CaSigningKey;
use crate::db::repo::{self, RevocationStatus};
use crate::error::{AppError, AppResult};
use crate::http::Shared;

const CT_OCSP: &str = "application/ocsp-response";
/// How long a response is valid before a client should re-check.
const NEXT_UPDATE_SECS: u64 = 3600;

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
    match base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
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
        .ok_or_else(|| AppError::NotFound(format!("unknown CA '{ca_id}'")))?;

    let request = OcspRequest::from_der(req_der)
        .map_err(|e| AppError::bad_request(format!("invalid OCSP request: {e}")))?;

    let this_update = ocsp_now();
    let next_update =
        OcspGeneralizedTime::try_from(SystemTime::now() + Duration::from_secs(NEXT_UPDATE_SECS))
            .unwrap_or(this_update);

    let mut builder = OcspResponseBuilder::new(ca.cert.tbs_certificate.subject.clone());

    for entry in &request.tbs_request.request_list {
        let serial_hex = hex::encode(entry.req_cert.serial_number.as_bytes());
        let status = repo::status_by_serial(&state.db, ca_id, &serial_hex).await?;
        let cert_status = to_cert_status(&status);
        let single = SingleResponse::new(entry.req_cert.clone(), cert_status, this_update)
            .with_next_update(next_update);
        builder = builder.with_single_response(single);
    }

    if let Some(nonce) = request.nonce() {
        builder = builder
            .with_extension(nonce)
            .map_err(|e| AppError::crypto(format!("OCSP nonce: {e}")))?;
    }

    let mut signer = signer_for(ca);
    let response = builder
        .sign(&mut signer, Some(vec![ca.cert.clone()]), this_update)
        .map_err(|e| AppError::crypto(format!("signing OCSP response: {e}")))?;
    response
        .to_der()
        .map_err(|e| AppError::crypto(format!("encode OCSP response: {e}")))
}

fn to_cert_status(status: &RevocationStatus) -> CertStatus {
    match status {
        RevocationStatus::Good => CertStatus::good(),
        RevocationStatus::Unknown => CertStatus::unknown(),
        RevocationStatus::Revoked { revoked_at, .. } => {
            let revocation_time = revoked_at
                .as_deref()
                .and_then(parse_rfc3339)
                .and_then(|st| OcspGeneralizedTime::try_from(st).ok())
                .unwrap_or_else(ocsp_now);
            CertStatus::Revoked(RevokedInfo {
                revocation_time,
                revocation_reason: None,
            })
        }
    }
}

fn signer_for(ca: &CertificateAuthority) -> CaSigningKey {
    CaSigningKey::new(ca.private_key.clone())
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

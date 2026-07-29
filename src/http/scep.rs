//! SCEP endpoint: `GetCACaps`, `GetCACert`, and `PKIOperation`.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use der::Encode;
use sha1::{Digest, Sha1};

use crate::ca::{csr, CertificateAuthority, IssueOptions};
use crate::challenge::ValidationInput;
use crate::crypto::verify::ParsedRequest;
use crate::crypto::{degenerate, envelope, sign, verify};
use crate::db::repo::{self, IssuedCertificate};
use crate::error::{AppError, AppResult};
use crate::http::{ProfileRuntime, Shared};
use crate::intune::IssuedInfo;
use crate::scep::attributes::{FailInfo, MessageType};
use crate::scep::protocol;

const CT_CA_CERT: &str = "application/x-x509-ca-cert";
const CT_PKI_MESSAGE: &str = "application/x-pki-message";

/// `GET /scep/{profile}?operation=...`
pub async fn scep_get(
    State(state): State<Shared>,
    Path(profile): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> AppResult<Response> {
    let operation = params
        .get("operation")
        .map(String::as_str)
        .unwrap_or_default();

    match operation {
        "GetCACaps" => Ok(text_response(protocol::CA_CAPS)),
        "GetCACert" => get_ca_cert(&state, &profile),
        "PKIOperation" => {
            let message = params
                .get("message")
                .ok_or_else(|| AppError::bad_request("missing 'message' parameter"))?;
            let body = base64::engine::general_purpose::STANDARD
                .decode(message.as_bytes())
                .map_err(|e| AppError::bad_request(format!("bad base64 message: {e}")))?;
            let der = pki_operation(&state, &profile, &body).await?;
            Ok(bytes_response(CT_PKI_MESSAGE, der))
        }
        other => Err(AppError::bad_request(format!(
            "unsupported SCEP operation '{other}'"
        ))),
    }
}

/// `POST /scep/{profile}`: the body is the DER PKIMessage.
pub async fn scep_post(
    State(state): State<Shared>,
    Path(profile): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    body: Bytes,
) -> AppResult<Response> {
    let operation = params
        .get("operation")
        .map(String::as_str)
        .unwrap_or("PKIOperation");
    if operation != "PKIOperation" {
        return Err(AppError::bad_request(format!(
            "POST only supports PKIOperation, not '{operation}'"
        )));
    }
    let der = pki_operation(&state, &profile, &body).await?;
    Ok(bytes_response(CT_PKI_MESSAGE, der))
}

fn get_ca_cert(state: &Shared, profile: &str) -> AppResult<Response> {
    let ca = state
        .ca_for_profile(profile)
        .ok_or_else(|| AppError::NotFound(format!("unknown SCEP profile '{profile}'")))?;
    let der = ca
        .cert
        .to_der()
        .map_err(|e| AppError::crypto(format!("encode CA cert: {e}")))?;
    Ok(bytes_response(CT_CA_CERT, der))
}

/// Handle a `PKIOperation`: verify, decrypt, validate, issue, and respond.
///
/// SCEP failures are reported in band: a signed `CertRep` with
/// `pkiStatus = FAILURE` returned with HTTP 200. Most error paths here
/// build a failure response instead of returning `Err`.
async fn pki_operation(state: &Shared, profile: &str, body: &[u8]) -> AppResult<Vec<u8>> {
    let rt = state
        .profiles
        .get(profile)
        .ok_or_else(|| AppError::NotFound(format!("unknown SCEP profile '{profile}'")))?;
    let ca = state
        .cas
        .get(&rt.ca_id)
        .ok_or_else(|| AppError::Config(format!("profile '{profile}' has no CA")))?;

    let parsed = verify::parse_and_verify(body)?;

    match parsed.message_type {
        MessageType::PkcsReq | MessageType::RenewalReq => {}
        other => {
            return Err(AppError::bad_request(format!(
                "unsupported SCEP messageType {:?} in v1",
                other
            )));
        }
    }

    // Decrypt the enveloped CSR.
    let enveloped = parsed
        .enveloped
        .as_ref()
        .ok_or_else(|| AppError::bad_request("enrolment request carries no envelope"))?;
    let csr_der = envelope::open(enveloped, &ca.cert, &ca.private_key)?;
    let parsed_csr = csr::parse(&csr_der)?;

    let input = ValidationInput {
        transaction_id: &parsed.transaction_id,
        csr_der: &csr_der,
        challenge_password: parsed_csr.challenge_password.as_deref(),
    };

    // Challenge validation (static secret / Intune / none).
    if let Err(e) = rt.validator.validate(&input).await {
        tracing::warn!(profile, txn = %parsed.transaction_id, error = %e, "challenge validation failed");
        let _ = rt.validator.on_failure(&input, &e.to_string()).await;
        let _ = record(state, rt, &parsed, "failed", "PKCSReq").await;
        return build_failure(ca, &parsed, FailInfo::BadRequest);
    }

    // Issue.
    let opts = IssueOptions {
        validity_days: rt.validity_days,
        key_usage: rt.key_usage.clone(),
        extended_key_usage: rt.extended_key_usage.clone(),
        ocsp_url: Some(state.ocsp_url(&rt.ca_id)),
        crl_url: Some(state.crl_url(&rt.ca_id)),
    };
    let issued = match ca.issue(&parsed_csr.req, &opts) {
        Ok(cert) => cert,
        Err(e) => {
            tracing::error!(error = %e, "certificate issuance failed");
            let _ = rt.validator.on_failure(&input, &e.to_string()).await;
            return build_failure(ca, &parsed, FailInfo::BadRequest);
        }
    };
    let issued_der = issued
        .to_der()
        .map_err(|e| AppError::crypto(format!("encode issued cert: {e}")))?;

    // Persist and notify (best effort; a certificate was issued regardless).
    if let Err(e) = persist(state, rt, ca, &parsed, &issued, &issued_der).await {
        tracing::error!(error = %e, "failed to persist issued certificate");
    }
    let info = issued_info(ca, &issued, &issued_der);
    if let Err(e) = rt.validator.on_issued(&input, &info).await {
        tracing::error!(error = %e, "Intune success notification failed");
    }

    // Build the signed + enveloped CertRep for the device.
    let certs_only = degenerate::certs_only(&issued)?;
    let recipient = envelope::Recipient {
        public_key: &parsed.recipient.public_key,
        issuer: &parsed.recipient.issuer,
        serial: &parsed.recipient.serial,
    };
    let reply_env_der = envelope::build_for(&certs_only, &recipient)?;
    let attrs = protocol::success_attrs(&parsed.transaction_id, &parsed.sender_nonce)?;
    sign::build_cert_rep(&ca.signing_key, &ca.cert, Some(&reply_env_der), attrs)
}

fn build_failure(
    ca: &CertificateAuthority,
    parsed: &ParsedRequest,
    fail: FailInfo,
) -> AppResult<Vec<u8>> {
    let attrs = protocol::failure_attrs(&parsed.transaction_id, &parsed.sender_nonce, fail)?;
    sign::build_cert_rep(&ca.signing_key, &ca.cert, None, attrs)
}

async fn persist(
    state: &Shared,
    rt: &ProfileRuntime,
    ca: &CertificateAuthority,
    parsed: &ParsedRequest,
    issued: &x509_cert::Certificate,
    issued_der: &[u8],
) -> AppResult<()> {
    let record = IssuedCertificate {
        serial: serial_hex(issued),
        ca_id: ca.id.clone(),
        subject: issued.tbs_certificate.subject.to_string(),
        not_before: time_to_utc(&issued.tbs_certificate.validity.not_before),
        not_after: time_to_utc(&issued.tbs_certificate.validity.not_after),
        der_b64: base64::engine::general_purpose::STANDARD.encode(issued_der),
        thumbprint_sha1: thumbprint(issued_der),
        transaction_id: Some(parsed.transaction_id.clone()),
        profile: Some(rt.name.clone()),
        status: repo::STATUS_VALID.to_string(),
        created_at: now_utc(),
        revoked_at: None,
        revocation_reason: None,
    };
    repo::insert_issued(&state.db, &record).await?;
    let _ = record_ok(state, rt, parsed).await;
    Ok(())
}

async fn record(
    state: &Shared,
    rt: &ProfileRuntime,
    parsed: &ParsedRequest,
    status: &str,
    message_type: &str,
) -> AppResult<()> {
    repo::record_transaction(
        &state.db,
        &parsed.transaction_id,
        &rt.name,
        status,
        message_type,
        &now_utc(),
    )
    .await
}

async fn record_ok(state: &Shared, rt: &ProfileRuntime, parsed: &ParsedRequest) -> AppResult<()> {
    record(state, rt, parsed, "issued", "PKCSReq").await
}

fn issued_info(
    ca: &CertificateAuthority,
    issued: &x509_cert::Certificate,
    issued_der: &[u8],
) -> IssuedInfo {
    IssuedInfo {
        thumbprint_sha1: thumbprint(issued_der),
        serial_decimal: serial_decimal(issued),
        not_after_utc: time_to_utc(&issued.tbs_certificate.validity.not_after),
        issuer_cn: common_name(&ca.cert.tbs_certificate.subject.to_string()),
    }
}

// --- small helpers ---

fn text_response(body: &str) -> Response {
    ([(CONTENT_TYPE, "text/plain")], body.to_owned()).into_response()
}

fn bytes_response(content_type: &'static str, body: Vec<u8>) -> Response {
    ([(CONTENT_TYPE, content_type)], body).into_response()
}

fn thumbprint(der: &[u8]) -> String {
    hex::encode_upper(Sha1::digest(der))
}

fn serial_hex(cert: &x509_cert::Certificate) -> String {
    hex::encode(cert.tbs_certificate.serial_number.as_bytes())
}

/// Decimal representation of the serial (Intune expects decimal). Serials we
/// issue are <= 16 bytes with the top bit cleared, so they fit in a u128.
fn serial_decimal(cert: &x509_cert::Certificate) -> String {
    let bytes = cert.tbs_certificate.serial_number.as_bytes();
    if bytes.len() <= 16 {
        let mut v: u128 = 0;
        for b in bytes {
            v = (v << 8) | *b as u128;
        }
        v.to_string()
    } else {
        // Fallback for unusually large serials.
        hex::encode(bytes)
    }
}

fn time_to_utc(t: &x509_cert::time::Time) -> String {
    let dt = t.to_date_time();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minutes(),
        dt.seconds()
    )
}

fn now_utc() -> String {
    let dt = der::DateTime::from_system_time(std::time::SystemTime::now())
        .unwrap_or(der::DateTime::INFINITY);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minutes(),
        dt.seconds()
    )
}

fn common_name(dn: &str) -> String {
    // Extract the CN component from an RFC 4514 DN string.
    for part in dn.split(',') {
        let part = part.trim();
        if let Some(cn) = part.strip_prefix("CN=") {
            return cn.to_string();
        }
    }
    dn.to_string()
}

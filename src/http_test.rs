//! End-to-end enrolment test through the HTTP handler: builds a real PKCSReq,
//! drives `scep_post`, and checks the CertRep, DB persistence, and the
//! static-challenge failure path. Uses a temp-file SQLite database.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use axum::body::{to_bytes, Bytes};
use axum::extract::{Path, Query, State};
use der::Encode;
use sqlx::Row;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::ext::pkix::name::DirectoryString;
use x509_cert::name::Name;
use x509_cert::request::attributes::ChallengePassword;

use crate::ca::CertificateAuthority;
use crate::challenge::StaticSecretValidator;
use crate::crypto::{envelope, sign, verify};
use crate::db;
use crate::http::scep::scep_post;
use crate::http::{AppState, ProfileRuntime, Shared};
use crate::scep::attributes::{self as attr, MessageType};
use crate::scep::nonce;

const SECRET: &str = "secret123";

fn build_csr(device: &CertificateAuthority, subject: &str, challenge: &str) -> Vec<u8> {
    let name = Name::from_str(subject).unwrap();
    let mut builder = RequestBuilder::new(name, &device.signing_key).unwrap();
    builder
        .add_attribute(&ChallengePassword(DirectoryString::Utf8String(
            challenge.to_string(),
        )))
        .unwrap();
    builder
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap()
        .to_der()
        .unwrap()
}

fn build_pkcsreq(
    device: &CertificateAuthority,
    ca: &CertificateAuthority,
    csr_der: &[u8],
    txn: &str,
) -> Vec<u8> {
    let env = envelope::build(csr_der, &ca.cert).unwrap();
    let env_der = envelope::to_content_info_der(&env).unwrap();
    let attrs = vec![
        attr::printable_attribute(attr::ID_MESSAGE_TYPE, MessageType::PkcsReq.as_value()).unwrap(),
        attr::printable_attribute(attr::ID_TRANSACTION_ID, txn).unwrap(),
        attr::octet_attribute(attr::ID_SENDER_NONCE, &nonce::generate()).unwrap(),
    ];
    sign::build_cert_rep(&device.signing_key, &device.cert, Some(&env_der), attrs).unwrap()
}

async fn test_state(db_name: &str) -> (Shared, Arc<CertificateAuthority>) {
    let ca = Arc::new(
        CertificateAuthority::generate_self_signed("default", "HTTP Test CA", 2048).unwrap(),
    );
    let path = std::env::temp_dir().join(db_name);
    let _ = std::fs::remove_file(&path);
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let pool = db::connect(&url).await.unwrap();

    let mut cas = HashMap::new();
    cas.insert("default".to_string(), ca.clone());
    let mut profiles = HashMap::new();
    profiles.insert(
        "test".to_string(),
        ProfileRuntime {
            name: "test".to_string(),
            ca_id: "default".to_string(),
            validator: Arc::new(StaticSecretValidator::new(SECRET.to_string())),
            validity_days: 90,
            key_usage: vec!["digitalSignature".into(), "keyEncipherment".into()],
            extended_key_usage: vec!["clientAuth".into()],
        },
    );
    let state = Arc::new(AppState {
        cas,
        profiles,
        db: pool,
        base_url: "http://localhost".to_string(),
    });
    (state, ca)
}

async fn post(state: &Shared, body: Vec<u8>) -> (u16, Vec<u8>) {
    let resp = scep_post(
        State(state.clone()),
        Path("test".to_string()),
        Query(HashMap::new()),
        Bytes::from(body),
    )
    .await
    .expect("handler returned Err");
    let status = resp.status().as_u16();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

#[tokio::test]
async fn http_enrollment_success_and_persists() {
    let (state, ca) = test_state("blapki_http_ok.db").await;
    let device = CertificateAuthority::generate_self_signed("dev", "dev", 2048).unwrap();
    let csr = build_csr(&device, "CN=device-http-01", SECRET);
    let request = build_pkcsreq(&device, &ca, &csr, "txn-ok-1");

    let (status, body) = post(&state, request).await;
    assert_eq!(status, 200);

    let reply = verify::parse_and_verify(&body).unwrap();
    assert_eq!(reply.message_type, MessageType::CertRep);
    let env = reply
        .enveloped
        .as_ref()
        .expect("success reply is enveloped");
    let certs_only = envelope::open(env, &device.cert, &device.private_key).unwrap();
    assert!(!certs_only.is_empty());

    // The issued certificate was recorded.
    let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM issued_certificate")
        .fetch_one(&state.db)
        .await
        .unwrap()
        .try_get("n")
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn http_enrollment_wrong_challenge_fails_in_band() {
    let (state, ca) = test_state("blapki_http_bad.db").await;
    let device = CertificateAuthority::generate_self_signed("dev", "dev", 2048).unwrap();
    let csr = build_csr(&device, "CN=device-http-02", "wrong-secret");
    let request = build_pkcsreq(&device, &ca, &csr, "txn-bad-1");

    let (status, body) = post(&state, request).await;
    // SCEP failures are returned in-band with HTTP 200.
    assert_eq!(status, 200);

    let reply = verify::parse_and_verify(&body).unwrap();
    assert_eq!(reply.message_type, MessageType::CertRep);
    // A FAILURE CertRep carries no enveloped certificate.
    assert!(reply.enveloped.is_none(), "failure reply must have no cert");

    let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM issued_certificate")
        .fetch_one(&state.db)
        .await
        .unwrap()
        .try_get("n")
        .unwrap();
    assert_eq!(count, 0, "no certificate should be issued on failure");
}
